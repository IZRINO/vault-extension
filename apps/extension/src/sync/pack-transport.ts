import { loadPackCrypto } from './pack-crypto';
import { DAV_PACK_ROOT, davPackPackageName, davPackRecordName, webDavConfig,
  WebDavClient, WebDavContentError, WebDavHttpError, WebDavNetworkError, WebDavStop,
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
const packagePath = (id: string) => `packages/p_${id}.bin`;
const recordPath = (id: string) => `versions/v_${id}.txt`;

export interface PackVersion {
  id: string;
  vaultId: string;
  parents: string[];
  sha256: string;
  bytes: number;
  createdAt: number;
  keyEpoch: number;
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

type VersionData = Omit<PackVersion, 'head' | 'recordAuth'> & { head?: Uint8Array };
type RecordData = [1, string, string, string[], string, number, number, number, string | null];

const malformed = () => new Error('整包版本记录无效或目录不完整。未修改本机密码库。');
const untrusted = () => new Error('无法认证同一密码库的整包版本记录。未修改本机密码库。');
const rollback = () => new Error('网盘缺少已验证的版本或共同版本，已保留本机修改。');
const occupied = () => new Error('目录已有文件或另一台设备已建库。已保留本机密码库。');
const corrupted = (cause?: WebDavContentError) => new PackIntegrityError(
  `整包读回不完整或密文哈希不符。${cause?.message ?? ''}已保留本机修改。`, { cause },
);
const bounded = () => new Error('整包版本记录超过自动检查上限。已保留本机修改。');
const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const decode64 = (text: string) => Uint8Array.from(atob(text), char => char.charCodeAt(0));
const equals = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, at) => byte === b[at]);
const sameVersion = (a: PackVersion, b: PackVersion) => JSON.stringify(versionData(a)) === JSON.stringify(versionData(b));

export const newPackVersionId = () => crypto.randomUUID().replaceAll('-', '');

function versionData(version: VersionData): RecordData {
  if (!packId.test(version.id) || !vaultUuid.test(version.vaultId) || !sha256Hex.test(version.sha256) ||
      !Number.isSafeInteger(version.bytes) || version.bytes < 1 || version.bytes > MAX_PACK_BYTES ||
      !Number.isSafeInteger(version.createdAt) || version.createdAt < 1 ||
      !Number.isSafeInteger(version.keyEpoch) || version.keyEpoch < 1 ||
      version.parents.length > MAX_PARENTS || version.parents.some((parent, at, parents) =>
        !packId.test(parent) || parent === version.id || at > 0 && parent <= parents[at - 1]!) ||
      (version.head !== undefined && (version.head.length === 0 || version.head.length > MAX_HEAD_BYTES))) throw malformed();
  return [1, version.id, version.vaultId, version.parents, version.sha256, version.bytes, version.createdAt,
    version.keyEpoch, version.head ? base64(version.head) : null];
}

async function digest(bytes: Uint8Array<ArrayBuffer>) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

export async function preparePackVersion(input: Omit<VersionData, 'sha256' | 'bytes'>, ciphertext: Uint8Array) {
  if (!ciphertext.length || ciphertext.length > MAX_PACK_BYTES) throw corrupted();
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
    if (!Array.isArray(outer) || outer.length !== 2 || typeof outer[1] !== 'string' || outer[1].length !== 44) throw malformed();
    const fields: unknown = outer[0], mac = decode64(outer[1]);
    if (!Array.isArray(fields) || fields.length !== 9 || fields[0] !== 1 || !Array.isArray(fields[3]) ||
        fields[3].some(parent => typeof parent !== 'string') || !(fields[8] === null || typeof fields[8] === 'string') ||
        (fields[8]?.length ?? 0) > Math.ceil(MAX_HEAD_BYTES / 3) * 4 ||
        typeof fields[1] !== 'string' || typeof fields[2] !== 'string' || typeof fields[4] !== 'string' ||
        mac.length !== 32) throw malformed();
    const version: PackVersion = { id: fields[1], vaultId: fields[2], parents: fields[3], sha256: fields[4],
      bytes: fields[5], createdAt: fields[6], keyEpoch: fields[7], head: fields[8] === null ? undefined : decode64(fields[8]) };
    if (expectId !== undefined ? version.id !== expectId || !version.parents.length : version.parents.length || !version.head) throw malformed();
    const data = versionData(version);
    if (JSON.stringify([data, base64(mac)]) !== text) throw malformed();
    if (etag) version.recordAuth = { etag, mac: outer[1] };
    return { version, mac, data: encoder.encode(JSON.stringify(data)), length: bytes.length };
  } catch { throw malformed(); }
}

function cachedRecord(version: PackVersion) {
  if (!version.recordAuth) return undefined;
  const { mac, etag } = version.recordAuth;
  if (typeof mac !== 'string' || mac.length !== 44 || typeof etag !== 'string') throw untrusted();
  const wire = encoder.encode(JSON.stringify([versionData(version), mac]));
  return parseRecord(wire, version.parents.length ? version.id : undefined, etag);
}

function rootLayout(entries: readonly DavEntry[]) {
  return entries.length === 3 &&
    entries.some(entry => entry.name === DAV_PACK_ROOT && !entry.collection) &&
    ['versions', 'packages'].every(name => entries.some(entry => entry.name === name && entry.collection));
}

function buildGraph(root: PackVersion, versions: PackVersion[], known: readonly PackVersion[]) {
  const byId = new Map([[root.id, root]]);
  for (const version of versions) {
    if (byId.has(version.id) || version.vaultId !== root.vaultId) throw untrusted();
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
        version.keyEpoch > parentEpoch && !version.head) throw malformed();
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
  if (ordered.length !== byId.size) throw malformed();
  return { versions: ordered, tips };
}

async function provePackWrites(config: WebDavConfig, scratchFolder: string, context: DavContext, request: typeof fetch,
  ciphertext: Uint8Array<ArrayBuffer>,
) {
  const target = new URL(config.url);
  const scratch = webDavConfig({ provider: 'custom', base: new URL('..', target).href, folder: scratchFolder,
    username: config.username, password: config.password, confirmHttp: target.protocol === 'http:' });
  if (scratch.url === target.href) throw new Error('测试目录必须和同步目录分开。');
  let stopped: WebDavStop | undefined;
  const client = new WebDavClient(scratch, { ...context,
    check: () => { if (stopped) throw stopped; context.check?.(); },
    stop: status => {
      if (stopped) return;
      stopped = new WebDavStop(status);
      return context.stop?.(status);
    },
  }, request);
  const listed = await client.list();
  if (!listed || listed.entries.length) throw new Error('请准备独立的空测试目录。扩展不会创建测试目录。');
  const failure = (details: string) => new Error(`网盘未通过整包写入验证。${details}密码库目录仍只读。`);
  const duplicate = () => failure('网盘允许重复创建已有测试文件，可能覆盖其他设备的写入。');
  const probes = new Map<string, { expected: Uint8Array<ArrayBuffer>; alternate: Uint8Array<ArrayBuffer>; limit: number; etag?: string }>();
  const text = () => encoder.encode(`Vault WebDAV pack test ${crypto.randomUUID()}\n`);
  const nameOf = (id: string, extension: 'txt' | 'bin') => `pack_verify_${id}.${extension}`;
  const probe = async (id: string, extension: 'txt' | 'bin', expected: Uint8Array<ArrayBuffer>) => {
    const name = nameOf(id, extension);
    const alternate = extension === 'txt' ? text() : crypto.getRandomValues(new Uint8Array(32));
    const limit = Math.max(64, expected.length);
    const read = async () => {
      try { return await client.get(name, limit); }
      catch (error) {
        if (error instanceof WebDavContentError) throw failure(error.message);
        throw error;
      }
    };
    if (!await client.put(name, expected, { absent: true })) throw failure('网盘报告同名测试文件已存在。');
    probes.set(name, { expected, alternate, limit });
    const first = await read();
    if (!first || first === 'unchanged') throw failure('无法读回测试文件。');
    if (first.bytes.length !== expected.length)
      throw failure(`读回应有 ${expected.length} 字节，实际收到 ${first.bytes.length} 字节。`);
    if (!equals(first.bytes, expected) || !first.etag) throw failure('测试文件内容不符或缺少强版本标签。');
    try {
      if (await client.put(name, alternate, { absent: true })) throw duplicate();
    } catch (error) {
      if (error instanceof WebDavHttpError && error.status >= 200 && error.status < 300) throw duplicate();
      throw error;
    }
    const after = await read();
    if (!after || after === 'unchanged' || after.etag !== first.etag || !equals(after.bytes, expected)) throw duplicate();
    if (await client.delete(name, `"never-${id}"`)) throw failure('网盘允许用错误版本标签删除测试文件。');
    probes.get(name)!.etag = first.etag;
  };
  const remove = async (name: string, etag: string, limit: number) => {
    if (!await client.delete(name, etag) || await client.get(name, limit) !== undefined)
      throw failure('无法确认测试文件已删除。');
  };
  // Use a separate one-time vault identity and MAC key. Nothing published here
  // can be accepted as a version of the actual vault.
  const proofVault = crypto.randomUUID();
  const sample = () => crypto.getRandomValues(new Uint8Array(32));
  const initial = sample(), another = sample();
  const root = await preparePackVersion({ id: newPackVersionId(), vaultId: proofVault, keyEpoch: 1,
    createdAt: Date.now(), parents: [], head: crypto.getRandomValues(new Uint8Array(384)) }, initial);
  const branch = (bytes: Uint8Array<ArrayBuffer>) => preparePackVersion({
    id: newPackVersionId(), vaultId: proofVault, keyEpoch: 1, createdAt: Date.now(), parents: [root.id],
  }, bytes);
  const [left, right] = [await branch(ciphertext), await branch(another)];
  const { wasm_sync_pack_record_verify } = await loadPackCrypto();
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const discover = async (expected: PackVersion[]) => {
    const entries = (await client.list())?.entries;
    const versionEntries = entries?.filter(entry => !entry.collection && entry.name.endsWith('.txt'));
    if (!versionEntries || versionEntries.length !== expected.length || !expected.every(version =>
      versionEntries.some(entry => entry.name === nameOf(version.id, 'txt'))))
      throw failure('网盘无法完整列出独立版本记录。');
    const verified: PackVersion[] = [];
    for (const version of expected) {
      const object = await client.get(nameOf(version.id, 'txt'), MAX_RECORD_BYTES);
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
    await probe(root.id, 'bin', initial);
    await probe(root.id, 'txt', records[0]!);
    await probe(left.id, 'bin', ciphertext);
    await discover([root]);
    const previous = await client.get(nameOf(root.id, 'bin'), root.bytes);
    if (!previous || previous === 'unchanged' || previous.bytes.length !== root.bytes || await digest(previous.bytes) !== root.sha256)
      throw failure('暂存新整包后无法验证上一版。');
    await probe(right.id, 'bin', another);
    const commits = await Promise.allSettled([probe(left.id, 'txt', records[1]!), probe(right.id, 'txt', records[2]!)]);
    const rejected = commits.find(result => result.status === 'rejected');
    if (rejected) throw stopped ?? rejected.reason;
    if (await client.put(nameOf(left.id, 'txt'), records[1]!, { absent: true })) throw duplicate();
    await discover([root, left, right]);
    for (const [name, object] of probes) {
      await remove(name, object.etag!, object.limit);
      probes.delete(name);
    }
  } finally {
    seed.fill(0);
    for (const [name, object] of probes) {
      if (stopped || context.signal?.aborted) break;
      try {
        const own = await client.get(name, object.limit);
        if (own && own !== 'unchanged' && own.etag && (equals(own.bytes, object.expected) || equals(own.bytes, object.alternate)))
          await remove(name, own.etag, object.limit);
      } catch { /* Keep the probe when its bytes and version cannot be verified. */ }
    }
  }
}

function uncertainWrite(error: unknown) {
  return error instanceof WebDavNetworkError || error instanceof WebDavHttpError &&
    (error.status === 408 || error.status >= 500 || error.status >= 200 && error.status < 300);
}

export class PackTransport {
  readonly stats = { metadataBytes: 0, packageDownloadBytes: 0, packageUploadBytes: 0 };
  private readonly client: WebDavClient;
  private writeAllowed: boolean;
  private verified = new Map<string, PackVersion>();
  private verifiedBytes = 0;

  constructor(private readonly config: WebDavConfig, private readonly context: DavContext, private readonly request = fetch) {
    this.writeAllowed = config.writeVerified === true;
    this.client = new WebDavClient(config, { ...context, observeRead: (path, bytes) => {
      if (path.startsWith('packages/') && path !== 'packages/') this.stats.packageDownloadBytes += bytes;
      else this.stats.metadataBytes += bytes;
      context.observeRead?.(path, bytes);
    } }, request);
  }

  private async root(allowLegacy: boolean, hasKnown = false, knownRoot?: PackVersion) {
    // A previously authenticated root supplies the directory identity. Check it
    // directly, and use its cached bytes only if the server returns 304.
    if (knownRoot) {
      const cached = cachedRecord(knownRoot);
      const object = await this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES, cached?.version.recordAuth?.etag);
      if (!object || object === 'unchanged' && !cached) throw rollback();
      const record = object === 'unchanged' ? cached! : parseRecord(object.bytes, undefined, object.etag);
      if (!sameVersion(record.version, knownRoot)) throw rollback();
      return { record, offsetSeconds: null };
    }
    const rootFolder = await this.client.list();
    if (allowLegacy && !rootFolder?.entries.some(entry => entry.name === DAV_PACK_ROOT)) return undefined;
    if (!rootFolder || !rootLayout(rootFolder.entries)) throw hasKnown ? rollback() : malformed();
    const record = await this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES);
    if (!record || record === 'unchanged') throw hasKnown ? rollback() : malformed();
    return { record: parseRecord(record.bytes, undefined, record.etag), offsetSeconds: rootFolder.offsetSeconds };
  }

  private async *records(bytes: number, known = new Map<string, PackVersion>()) {
    const folder = await this.client.list('versions/');
    if (!folder) throw known.size ? rollback() : malformed();
    if (folder.entries.length >= MAX_VERSIONS) throw bounded();
    const names = new Set(folder.entries.filter(entry => !entry.collection).map(entry => entry.name));
    for (const version of known.values()) {
      if (version.parents.length && !names.has(`v_${version.id}.txt`)) throw rollback();
    }
    let remaining = MAX_TOTAL_RECORD_BYTES - bytes;
    for (const entry of folder.entries.sort((a, b) => a.name < b.name ? -1 : a.name === b.name ? 0 : 1)) {
      if (entry.collection || !davPackRecordName.test(entry.name)) throw malformed();
      if (remaining <= 0 || entry.bytes !== undefined && entry.bytes > Math.min(remaining, MAX_RECORD_BYTES)) throw bounded();
      const id = entry.name.slice(2, -4);
      const prior = known.get(id);
      if (entry.etag && prior?.recordAuth?.etag === entry.etag) {
        const cached = cachedRecord(prior)!;
        if (entry.bytes === undefined || entry.bytes === cached.length) {
          if (cached.length > remaining) throw bounded();
          remaining -= cached.length;
          yield cached;
          continue;
        }
      }
      const object = await this.client.get(recordPath(id), Math.min(remaining, MAX_RECORD_BYTES));
      if (!object || object === 'unchanged') throw rollback();
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

  private async checkPackage(version: PackVersion, ciphertext: Uint8Array<ArrayBuffer>) {
    if (ciphertext.length !== version.bytes || await digest(ciphertext) !== version.sha256) throw corrupted();
  }

  async download(version: PackVersion) {
    versionData(version);
    const object = await this.client.get(packagePath(version.id), version.bytes).catch((error: unknown) => {
      if (error instanceof WebDavContentError) throw corrupted(error);
      throw error;
    });
    if (!object || object === 'unchanged') throw corrupted();
    await this.checkPackage(version, object.bytes);
    return object.bytes;
  }

  private async stage(version: PackVersion, ciphertext: Uint8Array<ArrayBuffer>) {
    if (await this.client.put(packagePath(version.id), ciphertext, { absent: true }))
      this.stats.packageUploadBytes += ciphertext.length;
    await this.download(version);
  }

  async verifyWrites(material: Uint8Array, version: PackVersion, ciphertext: Uint8Array<ArrayBuffer>, scratchFolder: string) {
    this.writeAllowed = false;
    await this.checkPackage(version, ciphertext);
    await this.list(material, version.vaultId, [version]);
    await provePackWrites(this.config, scratchFolder, this.context, this.request, ciphertext);
    this.writeAllowed = true;
    return true;
  }

  async publish(material: Uint8Array, version: PackVersion, ciphertext: Uint8Array<ArrayBuffer>) {
    if (!this.writeAllowed) throw new Error('网盘尚未通过整包写入验证，密码库目录仍只读。');
    if (!version.parents.length) throw malformed();
    versionData(version);
    await this.checkPackage(version, ciphertext);
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
    await this.stage(version, ciphertext);
    const path = recordPath(version.id);
    await this.client.put(path, record, { absent: true });
    const committed = await this.client.get(path, MAX_RECORD_BYTES).catch((error: unknown) => {
      if (error instanceof WebDavContentError) throw new PackIntegrityError(error.message, { cause: error });
      throw error;
    });
    if (!committed || committed === 'unchanged' || !equals(committed.bytes, record))
      throw new PackIntegrityError('无法认证刚发布的整包版本记录。已保留本机修改。');
    const versions = await this.client.list('versions/');
    if (!versions?.entries.some(entry => !entry.collection && `versions/${entry.name}` === path))
      throw new PackIntegrityError('网盘无法列出刚发布的整包版本记录。已保留本机修改。');
    const authenticated = parseRecord(committed.bytes, version.id, committed.etag).version;
    this.verified.set(version.id, authenticated);
    this.verifiedBytes += committed.bytes.length;
    return authenticated;
  }

  async create(material: Uint8Array, genesis: PackVersion, ciphertext: Uint8Array<ArrayBuffer>, scratchFolder: string) {
    if (genesis.parents.length || !genesis.head) throw malformed();
    const bytes = await encodeRecord(material, genesis);
    await this.checkPackage(genesis, ciphertext);
    const proof = () => provePackWrites(this.config, scratchFolder, this.context, this.request, ciphertext);
    const inspect = async () => {
      const folder = await this.client.list();
      if (folder?.entries.some(entry => entry.name === DAV_PACK_ROOT && !entry.collection)) {
        if (!rootLayout(folder.entries)) throw occupied();
        const current = await this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES);
        if (!current || current === 'unchanged' || !equals(current.bytes, bytes)) throw occupied();
        await this.download(genesis);
        return { folder, committed: true };
      }
      if (folder?.entries.some(entry => !entry.collection || !['versions', 'packages'].includes(entry.name))) throw occupied();
      return { folder, committed: false };
    };
    const before = await inspect();
    if (before.committed) {
      if (!this.writeAllowed) await proof();
      this.writeAllowed = true;
      return { offsetSeconds: before.folder!.offsetSeconds };
    }
    await proof();
    const after = await inspect();
    if (after.committed) {
      this.writeAllowed = true;
      return { offsetSeconds: after.folder!.offsetSeconds };
    }
    if (!after.folder) await this.client.makeVaultDirectory();
    await this.client.makePackDirectory('versions/');
    await this.client.makePackDirectory('packages/');
    const [versions, packages] = [await this.client.list('versions/'), await this.client.list('packages/')];
    if (!versions || versions.entries.length || !packages ||
      packages.entries.some(entry => entry.collection || !davPackPackageName.test(entry.name))) throw occupied();
    await this.stage(genesis, ciphertext);
    let uncertain: unknown;
    try { await this.client.put(DAV_PACK_ROOT, bytes, { absent: true }); }
    catch (error) {
      if (!uncertainWrite(error)) throw error;
      uncertain = error;
    }
    const current = await this.client.get(DAV_PACK_ROOT, MAX_RECORD_BYTES);
    if (!current) throw uncertain ?? occupied();
    if (current === 'unchanged' || !equals(current.bytes, bytes)) throw occupied();
    const committed = await this.client.list();
    if (!committed || !rootLayout(committed.entries)) throw malformed();
    this.writeAllowed = true;
    return { offsetSeconds: committed.offsetSeconds };
  }
}
