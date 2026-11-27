import { loadPackCrypto } from './pack-crypto';
import { DAV_PACK_ROOT, davPackPackageName, davPackProbeName, davPackRecordName, davPresets, isDavPackProbeIn,
  WebDavClient, WebDavContentError, WebDavHttpError, WebDavLimitError, WebDavNetworkError, WebDavStop,
  type DavContext, type DavEntry, type WebDavConfig } from './webdav';

export const MAX_PACK_BYTES = 16 * 1024 * 1024;
const MAX_HEAD_BYTES = 8 * 1024;
const MAX_RECORD_BYTES = 16 * 1024;
const MAX_TOTAL_RECORD_BYTES = 4 * 1024 * 1024;
const MAX_VERSIONS = 2048;
const MAX_PARENTS = 64;
const WRITE_RESERVE = MAX_PARENTS;
const MAX_JOIN_HEADS = 8;
const packId = /^[0-9a-f]{32}$/;
const vaultUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const sha256Hex = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const jsonPrefix = encoder.encode('{"ciphertext":"');
const jsonSuffix = encoder.encode('"}');
// A multiple of three keeps Base64 padding at the very end.
const base64ChunkBytes = 12 * 1024;
const base64ChunkChars = base64ChunkBytes / 3 * 4;
const packageExtension = (encoding: PackVersion['packageEncoding']) => encoding === 'json' ? 'json' : 'bin';
const packagePath = (version: PackVersion) => `packages/p_${version.id}.${packageExtension(version.packageEncoding)}`;
const recordPath = (id: string) => `versions/v_${id}.txt`;

export interface PackVersion {
  id: string;
  vaultId: string;
  parents: string[];
  sha256: string;
  bytes: number;
  createdAt: number;
  keyEpoch: number;
  packageEncoding?: 'json';
  head?: Uint8Array<ArrayBuffer>;
  recordAuth?: { etag: string; mac: string };
}

export interface PackListing {
  root: PackVersion;
  versions: PackVersion[];
  tips: PackVersion[];
  offsetSeconds: number | null;
}

export class PackIntegrityError extends Error {}
class UnsupportedPackRecord extends Error {
  constructor() { super('整包版本记录包含当前客户端不支持的格式，请升级后重试。已保留本机修改。'); }
}

type VersionData = Omit<PackVersion, 'head' | 'recordAuth'> & { head?: Uint8Array };
type RecordData = [1 | 2, string, string, string[], string, number, number, number, string | null];

const malformed = () => new Error('整包版本记录无效或目录不完整。未修改本机密码库。');
const invalidRecord = () => new PackIntegrityError(malformed().message);
const untrusted = () => new PackIntegrityError('无法认证同一密码库的整包版本记录。未修改本机密码库。');
const rollback = () => new PackIntegrityError('网盘缺少已验证的版本或共同版本，已保留本机修改。');
const badRecordLength = () => new PackIntegrityError('版本目录声明的文件长度与版本记录不符。已保留本机修改。');
const occupied = () => new Error('目录已有文件或另一台设备已建库。已保留本机密码库。');
const corrupted = (detail?: string | WebDavContentError) => new PackIntegrityError(
  `整包读回不完整或密文哈希不符。${typeof detail === 'string' ? detail : detail?.message ?? ''}已保留本机修改。`,
  typeof detail === 'object' ? { cause: detail } : undefined,
);
const invalidLocalPack = () => new Error('本机待发布的整包与其版本记录不符。已保留本机修改。');
const bounded = () => new Error('整包版本记录超过自动检查上限。已保留本机修改。');
const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const decode64 = (text: string) => Uint8Array.from(atob(text), char => char.charCodeAt(0));
const equals = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, at) => byte === b[at]);
export const sameVersion = (a: PackVersion, b: PackVersion) => JSON.stringify(versionData(a)) === JSON.stringify(versionData(b));

function packageWireLength(bytes: number, encoding: PackVersion['packageEncoding']) {
  return encoding === 'json' ? jsonPrefix.length + Math.ceil(bytes / 3) * 4 + jsonSuffix.length : bytes;
}

function encodePackage(ciphertext: Uint8Array<ArrayBuffer>, encoding: PackVersion['packageEncoding']) {
  if (encoding !== 'json') return ciphertext;
  const wire = new Uint8Array(packageWireLength(ciphertext.length, encoding));
  wire.set(jsonPrefix);
  let written = jsonPrefix.length;
  for (let at = 0; at < ciphertext.length; at += base64ChunkBytes) {
    const chunk = base64(ciphertext.subarray(at, at + base64ChunkBytes));
    written += encoder.encodeInto(chunk, wire.subarray(written)).written;
  }
  wire.set(jsonSuffix, written);
  return wire;
}

function decodePackage(version: PackVersion, wire: Uint8Array<ArrayBuffer>) {
  if (version.packageEncoding !== 'json') return wire;
  if (wire.length !== packageWireLength(version.bytes, version.packageEncoding))
    throw corrupted(`JSON 整包应有 ${packageWireLength(version.bytes, version.packageEncoding)} 字节，实际收到 ${wire.length} 字节。`);
  const payloadEnd = wire.length - jsonSuffix.length;
  const invalid = () => corrupted('JSON 整包格式无效。');
  if (!equals(wire.subarray(0, jsonPrefix.length), jsonPrefix) || !equals(wire.subarray(payloadEnd), jsonSuffix)) throw invalid();
  const ciphertext = new Uint8Array(version.bytes);
  let written = 0;
  for (let at = jsonPrefix.length; at < payloadEnd; at += base64ChunkChars) {
    let chunk: string, binary: string;
    try {
      chunk = decoder.decode(wire.subarray(at, Math.min(at + base64ChunkChars, payloadEnd)));
      binary = atob(chunk);
    } catch { throw invalid(); }
    // atob accepts whitespace and noncanonical padding. Require the exact encoding.
    if (binary.length !== Math.min(base64ChunkBytes, ciphertext.length - written) || btoa(binary) !== chunk) throw invalid();
    for (let offset = 0; offset < binary.length; offset++) ciphertext[written++] = binary.charCodeAt(offset);
  }
  return ciphertext;
}

export const newPackVersionId = () => crypto.randomUUID().replaceAll('-', '');

function versionData(version: VersionData): RecordData {
  if (!packId.test(version.id) || !vaultUuid.test(version.vaultId) || !sha256Hex.test(version.sha256) ||
      !Number.isSafeInteger(version.bytes) || version.bytes < 1 || version.bytes > MAX_PACK_BYTES ||
      !Number.isSafeInteger(version.createdAt) || version.createdAt < 1 ||
      !Number.isSafeInteger(version.keyEpoch) || version.keyEpoch < 1 ||
      (version.packageEncoding !== undefined && version.packageEncoding !== 'json') ||
      version.parents.length > MAX_PARENTS || version.parents.some((parent, at, parents) =>
        !packId.test(parent) || parent === version.id || at > 0 && parent <= parents[at - 1]!) ||
      (version.head !== undefined && (version.head.length === 0 || version.head.length > MAX_HEAD_BYTES))) throw malformed();
  return [version.packageEncoding === 'json' ? 2 : 1, version.id, version.vaultId, version.parents, version.sha256, version.bytes, version.createdAt,
    version.keyEpoch, version.head ? base64(version.head) : null];
}

async function digest(bytes: Uint8Array<ArrayBuffer>) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

export async function preparePackVersion(input: Omit<VersionData, 'sha256' | 'bytes'>, ciphertext: Uint8Array) {
  if (!ciphertext.length || ciphertext.length > MAX_PACK_BYTES) throw invalidLocalPack();
  const version: PackVersion = { ...input, parents: [...input.parents].sort(), sha256: await digest(asBuffer(ciphertext)),
    bytes: ciphertext.length, head: input.head ? new Uint8Array(input.head) : undefined };
  versionData(version);
  return version;
}

function asBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer ? bytes as Uint8Array<ArrayBuffer> : new Uint8Array(bytes);
}

async function encodeRecord(material: Uint8Array, version: PackVersion) {
  if (material.length !== 32) throw untrusted();
  const data = versionData(version);
  const { wasm_sync_pack_record_sign } = await loadPackCrypto();
  const tag = wasm_sync_pack_record_sign(material, version.vaultId, encoder.encode(JSON.stringify(data)));
  return encoder.encode(JSON.stringify([data, base64(tag)]));
}

function parseRecord(bytes: Uint8Array<ArrayBuffer>, expectId?: string, etag?: string) {
  try {
    const text = decoder.decode(bytes);
    const outer: unknown = JSON.parse(text);
    if (!Array.isArray(outer)) throw malformed();
    const fields: unknown = outer[0];
    if (Array.isArray(fields) && (Number.isSafeInteger(fields[0]) && fields[0] > 2 ||
        (fields[0] === 1 || fields[0] === 2) && (fields.length > 9 || outer.length > 2))) throw new UnsupportedPackRecord();
    if (outer.length !== 2 || typeof outer[1] !== 'string' || outer[1].length !== 44) throw malformed();
    const mac = decode64(outer[1]);
    if (!Array.isArray(fields) || fields.length !== 9 || (fields[0] !== 1 && fields[0] !== 2) || !Array.isArray(fields[3]) ||
        fields[3].some(parent => typeof parent !== 'string') || !(fields[8] === null || typeof fields[8] === 'string') ||
        (fields[8]?.length ?? 0) > Math.ceil(MAX_HEAD_BYTES / 3) * 4 ||
        typeof fields[1] !== 'string' || typeof fields[2] !== 'string' || typeof fields[4] !== 'string' ||
        mac.length !== 32) throw malformed();
    const version: PackVersion = { id: fields[1], vaultId: fields[2], parents: fields[3], sha256: fields[4],
      bytes: fields[5], createdAt: fields[6], keyEpoch: fields[7], head: fields[8] === null ? undefined : decode64(fields[8]) };
    if (fields[0] === 2) version.packageEncoding = 'json';
    if (expectId !== undefined ? version.id !== expectId || !version.parents.length : version.parents.length || !version.head) throw malformed();
    const data = versionData(version);
    if (JSON.stringify([data, base64(mac)]) !== text) throw malformed();
    if (etag) version.recordAuth = { etag, mac: outer[1] };
    return { version, mac, data: encoder.encode(JSON.stringify(data)), length: bytes.length };
  } catch (error) {
    if (error instanceof UnsupportedPackRecord) throw error;
    throw invalidRecord();
  }
}

function cachedRecord(version: PackVersion) {
  if (!version.recordAuth) return undefined;
  const { mac, etag } = version.recordAuth;
  if (typeof mac !== 'string' || mac.length !== 44 || typeof etag !== 'string') throw untrusted();
  const wire = encoder.encode(JSON.stringify([versionData(version), mac]));
  return parseRecord(wire, version.parents.length ? version.id : undefined, etag);
}

const rootContents = (entries: readonly DavEntry[]) => entries.filter(entry => entry.collection || !davPackProbeName.test(entry.name));
const packContents = (entries: readonly DavEntry[], directory: 'versions/' | 'packages/') =>
  entries.filter(entry => entry.collection || !isDavPackProbeIn(entry.name, directory));

function rootLayout(raw: readonly DavEntry[]) {
  const entries = rootContents(raw);
  return entries.length === 3 &&
    entries.some(entry => entry.name === DAV_PACK_ROOT && !entry.collection) &&
    ['versions', 'packages'].every(name => entries.some(entry => entry.name === name && entry.collection));
}

function buildGraph(root: PackVersion, versions: PackVersion[], known: readonly PackVersion[]) {
  const byId = new Map([[root.id, root]]);
  for (const version of versions) {
    if (byId.has(version.id) || version.vaultId !== root.vaultId || version.packageEncoding !== root.packageEncoding) throw untrusted();
    byId.set(version.id, version);
  }
  for (const version of known) {
    const remote = byId.get(version.id);
    if (!remote || !sameVersion(remote, version)) throw rollback();
  }
  const childIds = new Map<string, string[]>();
  const missingParents = new Map<string, number>();
  for (const version of versions) {
    const parents = version.parents.map(id => byId.get(id));
    if (parents.some(parent => !parent)) throw rollback();
    const parentEpoch = Math.max(...parents.map(parent => parent!.keyEpoch));
    if (version.keyEpoch < parentEpoch || version.keyEpoch > parentEpoch + 1 ||
        version.keyEpoch > parentEpoch && !version.head) throw invalidRecord();
    missingParents.set(version.id, parents.length);
    for (const id of version.parents) {
      if (!childIds.has(id)) childIds.set(id, []);
      childIds.get(id)!.push(version.id);
    }
  }
  // Every version must be reachable from the single root, including across merges.
  const ordered = [root], tips: PackVersion[] = [];
  for (let at = 0; at < ordered.length; at++) {
    const version = ordered[at]!;
    const children = childIds.get(version.id);
    if (!children) tips.push(version);
    for (const id of children ?? []) {
      const remaining = missingParents.get(id)! - 1;
      missingParents.set(id, remaining);
      if (!remaining) ordered.push(byId.get(id)!);
    }
  }
  if (ordered.length !== byId.size) throw invalidRecord();
  return { versions: ordered, tips };
}

type PackWriteMode = 'put' | 'move';
const proofFailure = (details: string) => new Error(`网盘未通过整包写入验证。${details}密码库目录仍只读。`);
class PutDidNotProtectDestination extends Error {}

async function provePackWrites(config: WebDavConfig, context: DavContext, request: typeof fetch, encoding: PackVersion['packageEncoding'],
  previous?: PackWriteMode): Promise<PackWriteMode> {
  if (previous !== 'move') {
    try {
      await provePackMethod(config, context, request, encoding, 'put');
      return 'put';
    } catch (error) {
      if (!(error instanceof PutDidNotProtectDestination)) throw error;
    }
  }
  try {
    await provePackMethod(config, context, request, encoding, 'move');
    return 'move';
  } catch (error) {
    if (error instanceof WebDavContentError)
      throw proofFailure(`网盘未能用 MOVE 安全创建文件。${error.message}`);
    if (error instanceof WebDavHttpError && [405, 501].includes(error.status))
      throw proofFailure(`网盘拒绝了禁止覆盖的 MOVE（HTTP ${error.status}）。`);
    throw error;
  }
}

async function provePackMethod(config: WebDavConfig, context: DavContext, request: typeof fetch,
  encoding: PackVersion['packageEncoding'], mode: PackWriteMode) {
  let stopped: WebDavStop | undefined;
  let canClean = true;
  const client = new WebDavClient(config, { ...context,
    check: () => { if (stopped) throw stopped; context.check?.(); },
    stop: status => {
      if (stopped) return;
      stopped = new WebDavStop(status);
      return context.stop?.(status);
    },
  }, request);
  const failure = proofFailure;
  const duplicate = () => mode === 'put' ? new PutDidNotProtectDestination() :
    failure('网盘未能通过禁止覆盖的 MOVE 保留已有测试文件。');
  const probes = new Map<string, { expected: Uint8Array<ArrayBuffer>; limit: number; etag?: string }>();
  const create = (path: string, bytes: Uint8Array<ArrayBuffer>) => mode === 'put' ?
    client.put(path, bytes, { absent: true }) : client.createByMove(path, bytes, (source, etag) => {
      probes.set(source, { expected: bytes, limit: bytes.length, etag });
    });
  const text = () => encoder.encode(`Vault WebDAV pack test ${crypto.randomUUID()}\n`);
  const sample = () => crypto.getRandomValues(new Uint8Array(32));
  const packageExt = packageExtension(encoding);
  const nameOf = (id: string, extension: 'txt' | 'bin' | 'json') => `pack_verify_${id}.${extension}`;
  const probe = async (id: string, directory: '' | 'versions/' | 'packages/', expected: Uint8Array<ArrayBuffer>) => {
    const extension = directory === 'packages/' ? packageExt : 'txt';
    const name = `${directory}${nameOf(id, extension)}`;
    const alternate = extension === 'txt' ? text() : encodePackage(sample(), encoding);
    const limit = Math.max(64, expected.length);
    const read = async () => {
      try { return await client.get(name, limit); }
      catch (error) {
        if (error instanceof WebDavContentError) throw failure(error.message);
        throw error;
      }
    };
    if (await read() !== undefined || !await create(name, expected))
      throw failure('网盘报告同名测试文件已存在。');
    // A lost initial PUT response leaves an unowned object; never clean it by name alone.
    const owned = { expected, limit, etag: undefined as string | undefined };
    probes.set(name, owned);
    const first = await read();
    if (!first || first === 'unchanged') throw failure('无法读回测试文件。');
    if (first.bytes.length !== expected.length)
      throw failure(`读回应有 ${expected.length} 字节，实际收到 ${first.bytes.length} 字节。`);
    if (!equals(first.bytes, expected)) throw failure('测试文件读回内容不符。');
    if (!first.etag) throw failure('网盘未返回探针的强版本标签（ETag）。');
    owned.etag = first.etag;
    try {
      if (await create(name, alternate)) {
        owned.expected = alternate;
        owned.etag = undefined;
        throw duplicate();
      }
    } catch (error) {
      if (error instanceof WebDavHttpError && error.status >= 200 && error.status < 300) throw duplicate();
      throw error;
    }
    const after = await read();
    if (!after || after === 'unchanged' || after.etag !== first.etag || !equals(after.bytes, expected)) throw duplicate();
    // Koofr deletes even when If-Match is wrong, so sending this probe would remove the
    // file and could never pass. Exclusive MOVE already refused the second create.
    // Versions are merged before a later upload; concurrent sync is not expected.
    if (!config.url.startsWith(davPresets.koofr) && await client.delete(name, `"never-${id}"`)) {
      canClean = false;
      throw failure('网盘允许用错误版本标签删除测试文件。');
    }
  };
  const remove = async (name: string, etag: string, limit: number) => {
    if (!await client.delete(name, etag) || await client.get(name, limit) !== undefined)
      throw failure('无法确认测试文件已删除。');
  };
  // Use a separate one-time vault identity and MAC key. Nothing published here
  // can be accepted as a version of the actual vault.
  const proofVault = crypto.randomUUID();
  const initial = sample(), staged = sample(), another = sample();
  const root = await preparePackVersion({ id: newPackVersionId(), vaultId: proofVault, keyEpoch: 1,
    createdAt: Date.now(), parents: [], head: crypto.getRandomValues(new Uint8Array(384)), packageEncoding: encoding }, initial);
  const branch = (bytes: Uint8Array<ArrayBuffer>) => preparePackVersion({
    id: newPackVersionId(), vaultId: proofVault, keyEpoch: 1, createdAt: Date.now(), parents: [root.id], packageEncoding: encoding,
  }, bytes);
  const [left, right] = [await branch(staged), await branch(another)];
  const rootName = nameOf(root.id, 'txt');
  const previousPack = `packages/${nameOf(root.id, packageExt)}`;
  const ownRecords = new Set([left, right].map(version => nameOf(version.id, 'txt')));
  const recordProbePath = (version: PackVersion) => version.id === root.id ? rootName : `versions/${nameOf(version.id, 'txt')}`;
  const { wasm_sync_pack_record_verify } = await loadPackCrypto();
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const discover = async (expected: PackVersion[]) => {
    const rootEntries = (await client.list())?.entries;
    const entries = (await client.list('versions/'))?.entries;
    const versionEntries = entries?.filter(entry => !entry.collection && ownRecords.has(entry.name));
    const children = expected.slice(1);
    if (!rootEntries?.some(entry => !entry.collection && entry.name === rootName) ||
      !versionEntries || versionEntries.length !== children.length || !children.every(version =>
      versionEntries.some(entry => entry.name === nameOf(version.id, 'txt'))))
      throw failure('网盘无法完整列出独立版本记录。');
    const verified: PackVersion[] = [];
    for (const version of expected) {
      const object = await client.get(recordProbePath(version), MAX_RECORD_BYTES);
      if (!object || object === 'unchanged') throw failure('无法读回独立版本记录。');
      const record = parseRecord(object.bytes, version.id === root.id ? undefined : version.id);
      if (!sameVersion(record.version, version) || !wasm_sync_pack_record_verify(seed, proofVault, record.data, record.mac))
        throw failure('无法认证独立版本记录。');
      verified.push(record.version);
    }
    buildGraph(verified[0]!, verified.slice(1), expected);
  };
  try {
    const records = await Promise.all([root, left, right].map(version => encodeRecord(seed, version)));
    const initialWire = encodePackage(initial, encoding);
    await probe(root.id, '', records[0]!);
    await probe(root.id, 'packages/', initialWire);
    await probe(left.id, 'packages/', encodePackage(staged, encoding));
    await discover([root]);
    const previous = await client.get(previousPack, initialWire.length);
    if (!previous || previous === 'unchanged' || !equals(previous.bytes, initialWire))
      throw failure('暂存新整包后无法验证上一版。');
    await probe(right.id, 'packages/', encodePackage(another, encoding));
    const commits = await Promise.allSettled([probe(left.id, 'versions/', records[1]!), probe(right.id, 'versions/', records[2]!)]);
    const rejected = commits.find(result => result.status === 'rejected');
    if (rejected) {
      const serious = commits.find(result => result.status === 'rejected' && !(result.reason instanceof PutDidNotProtectDestination));
      throw stopped ?? (serious?.status === 'rejected' ? serious.reason : rejected.reason);
    }
    if (await create(recordProbePath(left), records[1]!)) throw duplicate();
    await discover([root, left, right]);
    for (const [name, object] of probes) {
      await remove(name, object.etag!, object.limit);
      probes.delete(name);
    }
  } finally {
    seed.fill(0);
    for (const [name, object] of probes) {
      if (!canClean || stopped || context.signal?.aborted) break;
      try {
        const own = await client.get(name, object.limit);
        if (own && own !== 'unchanged' && own.etag && (!object.etag || own.etag === object.etag) && equals(own.bytes, object.expected))
          await remove(name, own.etag, object.limit);
      } catch { /* Keep the probe when its bytes and version cannot be verified. */ }
    }
  }
}

function uncertainWrite(error: unknown) {
  return error instanceof WebDavNetworkError || error instanceof WebDavHttpError &&
    (error.status === 408 || error.status >= 500 || error.status >= 200 && error.status < 300);
}

async function readMetadata<T>(request: Promise<T>, knownRecord = false): Promise<T> {
  try { return await request; }
  catch (error) {
    if (error instanceof WebDavLimitError) throw knownRecord ? badRecordLength() : bounded();
    if (error instanceof WebDavContentError) throw new PackIntegrityError(error.message, { cause: error });
    throw error;
  }
}

export class PackTransport {
  readonly stats = { metadataBytes: 0, packageDownloadBytes: 0, packageUploadBytes: 0 };
  private readonly client: WebDavClient;
  private writeMode?: PackWriteMode;
  private verified = new Map<string, PackVersion>();
  private verifiedBytes = 0;

  constructor(private readonly config: WebDavConfig, private readonly context: DavContext, private readonly request = fetch) {
    if (config.writeVerified === true) this.writeMode = config.packWriteMode === 'move' ? 'move' : 'put';
    this.client = new WebDavClient(config, { ...context, observeRead: (path, bytes) => {
      if (path.startsWith('packages/') && path !== 'packages/') this.stats.packageDownloadBytes += bytes;
      else this.stats.metadataBytes += bytes;
      context.observeRead?.(path, bytes);
    } }, request);
  }

  get newPackageEncoding(): PackVersion['packageEncoding'] {
    return this.config.url.startsWith(davPresets.koofr) ? 'json' : undefined;
  }

  get verifiedWriteMode() { return this.writeMode; }

  private async root(allowLegacy: boolean, hasKnown = false, knownRoot?: PackVersion) {
    // A previously authenticated root supplies the directory identity. Check it
    // directly, and use its cached bytes only if the server returns 304.
    if (knownRoot) {
      const cached = cachedRecord(knownRoot);
      const object = await readMetadata(this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES, cached?.version.recordAuth?.etag), true);
      if (!object || object === 'unchanged' && !cached) throw rollback();
      const record = object === 'unchanged' ? cached! : parseRecord(object.bytes, undefined, object.etag);
      if (!sameVersion(record.version, knownRoot)) throw rollback();
      return { record, offsetSeconds: null };
    }
    const rootFolder = await readMetadata(this.client.list());
    if (allowLegacy && !rootFolder?.entries.some(entry => entry.name === DAV_PACK_ROOT)) return undefined;
    if (!rootFolder || !rootLayout(rootFolder.entries)) throw hasKnown ? rollback() : malformed();
    const record = await readMetadata(this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES));
    if (!record || record === 'unchanged') throw hasKnown ? rollback() : malformed();
    return { record: parseRecord(record.bytes, undefined, record.etag), offsetSeconds: rootFolder.offsetSeconds };
  }

  private async *records(bytes: number, known = new Map<string, PackVersion>()) {
    const folder = await readMetadata(this.client.list('versions/'));
    if (!folder) throw known.size ? rollback() : malformed();
    const entries = packContents(folder.entries, 'versions/');
    if (entries.length >= MAX_VERSIONS) throw bounded();
    const names = new Set(entries.filter(entry => !entry.collection).map(entry => entry.name));
    for (const version of known.values()) {
      if (version.parents.length && !names.has(`v_${version.id}.txt`)) throw rollback();
    }
    let remaining = MAX_TOTAL_RECORD_BYTES - bytes;
    for (const entry of entries.sort((a, b) => a.name < b.name ? -1 : a.name === b.name ? 0 : 1)) {
      if (entry.collection || !davPackRecordName.test(entry.name)) throw malformed();
      const id = entry.name.slice(2, -4);
      const prior = known.get(id);
      if (prior && entry.bytes !== undefined && entry.bytes > MAX_RECORD_BYTES) throw badRecordLength();
      const limit = Math.min(remaining, MAX_RECORD_BYTES);
      if (limit <= 0 || entry.bytes !== undefined && entry.bytes > limit) throw bounded();
      if (entry.etag && prior?.recordAuth?.etag === entry.etag) {
        const cached = cachedRecord(prior)!;
        if (entry.bytes !== undefined && entry.bytes !== cached.length) throw badRecordLength();
        if (cached.length > remaining) throw bounded();
        remaining -= cached.length;
        yield cached;
        continue;
      }
      const object = await readMetadata(this.client.get(recordPath(id), limit), !!prior && limit === MAX_RECORD_BYTES);
      if (!object || object === 'unchanged') throw rollback();
      if (entry.bytes !== undefined && object.bytes.length !== entry.bytes) throw badRecordLength();
      remaining -= object.bytes.length;
      yield parseRecord(object.bytes, id, object.etag);
    }
  }

  async list(material: Uint8Array, vaultId: string, known: readonly PackVersion[] = []): Promise<PackListing> {
    if (material.length !== 32 || !vaultUuid.test(vaultId)) throw untrusted();
    const trusted = new Map([...this.verified].filter(([, version]) => version.vaultId === vaultId));
    for (const version of known) {
      const prior = trusted.get(version.id);
      if (prior && !sameVersion(prior, version)) throw rollback();
      if (!prior?.recordAuth) trusted.set(version.id, version);
    }
    const knownRoot = [...trusted.values()].find(version => !version.parents.length);
    const genesis = await this.root(false, !!trusted.size, knownRoot);
    if (!genesis) throw malformed();
    const { wasm_sync_pack_record_verify } = await loadPackCrypto();
    const root = genesis.record;
    if (root.version.vaultId !== vaultId || !wasm_sync_pack_record_verify(material, vaultId, root.data, root.mac)) throw untrusted();
    const versions: PackVersion[] = [];
    let verifiedBytes = root.length;
    for await (const item of this.records(root.length, trusted)) {
      if (item.version.vaultId !== vaultId || !wasm_sync_pack_record_verify(material, vaultId, item.data, item.mac)) throw untrusted();
      verifiedBytes += item.length;
      versions.push(item.version);
    }
    const graph = buildGraph(root.version, versions, [...trusted.values()]);
    this.verified = new Map(graph.versions.map(version => [version.id, version]));
    this.verifiedBytes = verifiedBytes;
    return { root: root.version, offsetSeconds: genesis.offsetSeconds, ...graph };
  }

  // These headers are unauthenticated. The caller must verify a complete listing
  // using the unlocked DEK and match the same wrapping version before adoption.
  async joinCandidates(): Promise<PackVersion[]> {
    const genesis = await this.root(true);
    if (!genesis) return [];
    const versions: PackVersion[] = [];
    for await (const { version } of this.records(genesis.record.length)) {
      const { recordAuth: _auth, ...candidate } = version;
      versions.push(candidate);
    }
    const { recordAuth: _rootAuth, ...root } = genesis.record.version;
    const graph = buildGraph(root, versions, []);
    const epoch = Math.max(...graph.tips.map(version => version.keyEpoch));
    const distinct = new Map<string, PackVersion>();
    for (const version of graph.versions) {
      if (version.keyEpoch === epoch && version.head) distinct.set(base64(version.head), version);
    }
    if (!distinct.size || distinct.size > MAX_JOIN_HEADS) throw malformed();
    return [...distinct.values()];
  }

  // Setup routing only; creation still compares the authenticated root wire bytes.
  async matchesGenesis(genesis: PackVersion): Promise<boolean> {
    const object = await this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES);
    return !!object && object !== 'unchanged' && sameVersion(parseRecord(object.bytes).version, genesis);
  }

  private async checkPackage(version: PackVersion, ciphertext: Uint8Array<ArrayBuffer>, source: 'local' | 'remote') {
    if (ciphertext.length !== version.bytes)
      throw source === 'local' ? invalidLocalPack() : corrupted(`应有 ${version.bytes} 字节，实际收到 ${ciphertext.length} 字节。`);
    if (await digest(ciphertext) !== version.sha256) throw source === 'local' ? invalidLocalPack() : corrupted();
  }

  private async readPackage(version: PackVersion) {
    const object = await this.client.get(packagePath(version), packageWireLength(version.bytes, version.packageEncoding)).catch((error: unknown) => {
      if (error instanceof WebDavContentError) throw corrupted(error);
      throw error;
    });
    if (object === 'unchanged') throw corrupted();
    if (!object) return undefined;
    const ciphertext = decodePackage(version, object.bytes);
    await this.checkPackage(version, ciphertext, 'remote');
    return ciphertext;
  }

  async download(version: PackVersion) {
    versionData(version);
    const ciphertext = await this.readPackage(version);
    if (!ciphertext) throw corrupted();
    return ciphertext;
  }

  private async createFile(name: string, bytes: Uint8Array<ArrayBuffer>, mode: PackWriteMode) {
    if (mode === 'put') return this.client.put(name, bytes, { absent: true });
    try { return await this.client.createByMove(name, bytes); }
    catch (error) {
      if (error instanceof WebDavContentError) throw new PackIntegrityError(error.message, { cause: error });
      throw error;
    }
  }

  private async stage(version: PackVersion, ciphertext: Uint8Array<ArrayBuffer>, mode: PackWriteMode) {
    // A timeout or partial startup may leave the uniquely named package behind.
    // Read it before issuing an exclusive PUT, even if PROPFIND missed it.
    if (await this.readPackage(version)) return;
    const wire = encodePackage(ciphertext, version.packageEncoding);
    if (await this.createFile(packagePath(version), wire, mode)) {
      this.stats.packageUploadBytes += wire.length;
      // MOVE has already compared the destination to this verified wire representation.
      if (mode === 'move') return;
    }
    await this.download(version);
  }

  async verifyWrites(material: Uint8Array, version: PackVersion) {
    const previous = this.writeMode;
    this.writeMode = undefined;
    const folder = await this.client.list();
    if (!folder || !rootLayout(folder.entries)) throw malformed();
    await this.list(material, version.vaultId, [version]);
    await this.download(version);
    this.writeMode = await provePackWrites(this.config, this.context, this.request, version.packageEncoding, previous);
    return true;
  }

  async publish(material: Uint8Array, version: PackVersion, ciphertext: Uint8Array<ArrayBuffer>) {
    const mode = this.writeMode;
    if (!mode) throw new Error('网盘尚未通过整包写入验证，密码库目录仍只读。');
    if (!version.parents.length) throw malformed();
    versionData(version);
    await this.checkPackage(version, ciphertext, 'local');
    const listing = await this.list(material, version.vaultId);
    const existing = listing.versions.find(item => item.id === version.id);
    if (existing) {
      if (!sameVersion(existing, version)) throw untrusted();
      return existing;
    }
    buildGraph(listing.root, [...listing.versions.slice(1), version], []);
    const record = await encodeRecord(material, version);
    // Reserve room for other devices that are already preparing independent commits.
    if (listing.versions.length + WRITE_RESERVE >= MAX_VERSIONS ||
        this.verifiedBytes + record.length + WRITE_RESERVE * MAX_RECORD_BYTES > MAX_TOTAL_RECORD_BYTES) throw bounded();
    await this.stage(version, ciphertext, mode);
    const path = recordPath(version.id);
    await this.createFile(path, record, mode);
    const committed = await readMetadata(this.client.get(path, MAX_RECORD_BYTES), true);
    if (!committed || committed === 'unchanged' || !equals(committed.bytes, record))
      throw new PackIntegrityError('无法认证刚发布的整包版本记录。已保留本机修改。');
    const versions = await readMetadata(this.client.list('versions/'));
    if (!versions?.entries.some(entry => !entry.collection && `versions/${entry.name}` === path))
      throw new PackIntegrityError('网盘无法列出刚发布的整包版本记录。已保留本机修改。');
    const authenticated = parseRecord(committed.bytes, version.id, committed.etag).version;
    this.verified.set(version.id, authenticated);
    this.verifiedBytes += committed.bytes.length;
    return authenticated;
  }

  async create(material: Uint8Array, genesis: PackVersion, ciphertext: Uint8Array<ArrayBuffer>) {
    if (genesis.parents.length || !genesis.head) throw malformed();
    const bytes = await encodeRecord(material, genesis);
    await this.checkPackage(genesis, ciphertext, 'local');
    const previousMode = this.writeMode;
    this.writeMode = undefined;
    const proof = () => provePackWrites(this.config, this.context, this.request, genesis.packageEncoding, previousMode);
    const checkChildren = async (entries: readonly DavEntry[], requireBoth: boolean) => {
      const has = (name: string) => entries.some(entry => entry.collection && entry.name === name);
      if (requireBoth || has('versions')) {
        const versions = await this.client.list('versions/');
        if (!versions || packContents(versions.entries, 'versions/').length) throw occupied();
      }
      if (requireBoth || has('packages')) {
        const packages = await this.client.list('packages/');
        if (!packages || packContents(packages.entries, 'packages/').some(entry => entry.collection || !davPackPackageName.test(entry.name)))
          throw occupied();
      }
    };
    const inspect = async () => {
      const folder = await this.client.list();
      if (folder?.entries.some(entry => entry.name === DAV_PACK_ROOT && !entry.collection)) {
        if (!rootLayout(folder.entries)) throw occupied();
        const current = await this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES);
        if (!current || current === 'unchanged' || !equals(current.bytes, bytes)) throw occupied();
        await this.download(genesis);
        return { folder, committed: true };
      }
      if (folder && rootContents(folder.entries).some(entry => !entry.collection || !['versions', 'packages'].includes(entry.name)))
        throw occupied();
      return { folder, committed: false };
    };
    const confirmExisting = async (offsetSeconds: number | null) => {
      this.writeMode = previousMode ?? await proof();
      return { offsetSeconds };
    };
    let before = await inspect();
    if (!before.folder) {
      await this.client.makeVaultDirectory();
      before = await inspect();
      if (!before.folder) throw malformed();
    }
    if (before.committed) return confirmExisting(before.folder.offsetSeconds);
    const existing = rootContents(before.folder.entries);
    await checkChildren(existing, false);
    let initialized = false;
    for (const name of ['versions', 'packages'] as const) {
      if (existing.some(entry => entry.name === name)) continue;
      await this.client.makePackDirectory(`${name}/`);
      initialized = true;
    }
    if (initialized) {
      const prepared = await inspect();
      if (prepared.committed) return confirmExisting(prepared.folder!.offsetSeconds);
      await checkChildren(prepared.folder?.entries ?? [], true);
    }
    const mode = await proof();
    const after = await inspect();
    if (after.committed) {
      this.writeMode = mode;
      return { offsetSeconds: after.folder!.offsetSeconds };
    }
    if (!after.folder) throw malformed();
    const versions = await this.client.list('versions/');
    if (!versions || packContents(versions.entries, 'versions/').length) throw occupied();
    await this.stage(genesis, ciphertext, mode);
    let uncertain: unknown;
    try { await this.createFile(DAV_PACK_ROOT, bytes, mode); }
    catch (error) {
      if (!uncertainWrite(error)) throw error;
      uncertain = error;
    }
    const current = await this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES);
    if (!current) throw uncertain ?? occupied();
    if (current === 'unchanged' || !equals(current.bytes, bytes)) throw occupied();
    const committed = await this.client.list();
    if (!committed || !rootLayout(committed.entries)) throw malformed();
    this.writeMode = mode;
    return { offsetSeconds: committed.offsetSeconds };
  }
}
