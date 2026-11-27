import { SaxesParser } from 'saxes';

export const davPresets = {
  nutstore: 'https://dav.jianguoyun.com/dav/',
  koofr: 'https://app.koofr.net/dav/Koofr/',
} as const;

export interface WebDavInput {
  provider: keyof typeof davPresets | 'custom';
  base: string;
  folder: string;
  username: string;
  password: string;
  confirmHttp?: boolean;
}

export interface WebDavConfig { url: string; username: string; password: string; writeVerified?: boolean; packWriteMode?: 'move' }
export type DavStopStatus = 401 | 403 | 429;
export type DavProbe = { kind: 'empty' | 'existing' | 'incomplete' | 'missing'; offsetSeconds: number | null; writeAllowed: false; format?: 'pack' };
export interface DavEntry { name: string; collection: boolean; etag?: string; bytes?: number }
export interface DavContext {
  signal?: AbortSignal;
  check?(): void;
  observeClock?(offsetSeconds: number | null, receivedAt: number): Promise<void>;
  observeRead?(path: string, bytes: number): void;
  stop?(status: DavStopStatus): void | Promise<void>;
}

export interface DavObject { bytes: Uint8Array<ArrayBuffer>; etag?: string }
type PutCondition = { absent: true } | { match: string };
export const davSnapshotName = /^snap_[0-9a-f]{14}_[0-9a-f]{8}_[0-9a-f]{14}\.bin$/;
export const davWalName = /^[0-9a-f]{14}_[0-9a-f]{8}_[0-9a-f]{14}\.bin$/;
export const davPackRecordName = /^v_[0-9a-f]{32}\.txt$/;
export const davPackPackageName = /^p_[0-9a-f]{32}\.(?:bin|json)$/;
export const davPackProbeName = /^pack_verify_[0-9a-f]{32}\.(?:bin|txt)$/;
export const DAV_PACK_ROOT = 'pack-root.txt';
const legacyProbeName = /^verify_[0-9a-f]{32}\.(?:bin|txt)$/;
const davPackJsonProbeName = /^pack_verify_[0-9a-f]{32}\.json$/;
export const isDavPackProbeIn = (name: string, directory: 'versions/' | 'packages/') =>
  directory === 'versions/' ? davPackProbeName.test(name) && name.endsWith('.txt')
    : (davPackProbeName.test(name) && name.endsWith('.bin')) || davPackJsonProbeName.test(name);

const davObjectPath = (name: string) => name === 'head.bin' || name === 'wal-budget.bin' || davSnapshotName.test(name) ||
  (name.startsWith('wal/') && davWalName.test(name.slice(4))) || legacyProbeName.test(name) || davPackProbeName.test(name) || name === DAV_PACK_ROOT ||
  (name.startsWith('versions/') && (davPackRecordName.test(name.slice(9)) || isDavPackProbeIn(name.slice(9), 'versions/'))) ||
  (name.startsWith('packages/') && (davPackPackageName.test(name.slice(9)) || isDavPackProbeIn(name.slice(9), 'packages/')));
const strongTag = (value: string | null) => value && /^"[\x21\x23-\x7e]{1,512}"$/.test(value) ? value : undefined;
const discard = (response: Response) => { void response.body?.cancel().catch(() => undefined); };
export class WebDavHttpError extends Error {
  constructor(readonly status: number) { super(`WebDAV 请求未完成（HTTP ${status}）。`); }
}
const unexpected = (response: Response) => new WebDavHttpError(response.status);

export class WebDavContentError extends Error {}
export class WebDavLimitError extends WebDavContentError {}
export class WebDavNetworkError extends Error {}
const incompleteMoveRead = (status: number) => new WebDavContentError(`移动校验未收到完整文件响应（HTTP ${status}）。`);

class WebDavReadError extends WebDavContentError {
  constructor(readonly declared: number, readonly received: number, hint = '') {
    super(`WebDAV 文件读回不完整。服务器声明 ${declared} 字节，实际收到 ${received} 字节。${hint}`);
  }
}

function koofrReadHint(response: Response) {
  const requestId = response.headers.get('X-Request-ID') ?? '';
  const reference = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(requestId)
    ? `请求编号 ${requestId}。` : '';
  return `Koofr 免费账户的 WebDAV 有文件类型限制，可请 Koofr 支持核查这次下载。${reference}`;
}

function fileLength(response: Response) {
  // Fetch decodes content encodings before exposing the stream; Content-Length measures the encoded body.
  const encoding = response.headers.get('Content-Encoding');
  const length = response.headers.get('Content-Length');
  if (encoding && encoding.toLowerCase() !== 'identity') return undefined;
  return length !== null && /^\d+$/.test(length) ? Number(length) : undefined;
}

const statusHint: Record<DavStopStatus, string> = {
  401: '网盘拒绝了登录。请核对账户和应用专用密码后手动测试。',
  403: '网盘拒绝访问。请核对目录权限后手动测试。',
  429: '网盘请求过于频繁，已停止自动连接。请稍后手动测试。',
};
const maxListingBytes = 1024 * 1024;
const propfind = '<?xml version="1.0" encoding="UTF-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getetag/><D:getcontentlength/></D:prop></D:propfind>';
const malformed = () => new WebDavContentError('WebDAV 目录响应不完整或格式无效。');

export class WebDavStop extends Error {
  constructor(readonly status: DavStopStatus) { super(statusHint[status]); }
}

function stopStatus(status: number): status is DavStopStatus {
  return status === 401 || status === 403 || status === 429;
}

function canonicalPath(url: URL) {
  return url.pathname.split('/').map(segment => {
    const plain = decodeURIComponent(segment);
    if (/[\\/\u0000-\u001f\u007f]/.test(plain) || plain === '.' || plain === '..') throw malformed();
    return encodeURIComponent(plain);
  }).join('/');
}

export function webDavConfig(input: WebDavInput): WebDavConfig {
  if (!input || !['nutstore', 'koofr', 'custom'].includes(input.provider) ||
      typeof input.folder !== 'string' || typeof input.base !== 'string' || input.base.length > 2048) throw new Error('WebDAV 连接设置无效。');
  const folder = input.folder.trim();
  if (!folder || folder.length > 100 || folder === '.' || folder === '..' || /[\\/%?#\u0000-\u001f\u007f]/.test(folder)) {
    throw new Error('请填写单独的同步目录名，不要包含路径或特殊分隔符。');
  }
  if (typeof input.username !== 'string' || !input.username.trim() || input.username.length > 320 || /[:\u0000-\u001f\u007f]/.test(input.username) ||
      typeof input.password !== 'string' || !input.password || input.password.length > 1024 || /[\u0000-\u001f\u007f]/.test(input.password)) {
    throw new Error('请核对网盘账户和应用专用密码。');
  }
  const raw = input.provider === 'custom' ? input.base.trim() : davPresets[input.provider];
  let url: URL;
  try {
    if (!/^https?:\/\/[^/]/i.test(raw) || /[\\?#\u0000-\u0020\u007f]/.test(raw)) throw malformed();
    url = new URL(raw);
    if (url.username || url.password || url.search || url.hash || raw.slice(raw.indexOf('//') + 2).split('/')[0]!.includes('@')) throw malformed();
    url.pathname = canonicalPath(url).replace(/\/+$/, '') + '/' + encodeURIComponent(folder) + '/';
  } catch { throw new Error('WebDAV 地址无效，不要在地址中填写账号、密码或查询参数。'); }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback && input.provider === 'custom' && input.confirmHttp === true)) {
    throw new Error('WebDAV 必须使用 HTTPS。HTTP 只可用于明确同意的本机调试。');
  }
  return { url: url.href, username: input.username.trim(), password: input.password };
}

export async function boundedBody(response: Response, limit: number, expectedLength?: number): Promise<Uint8Array<ArrayBuffer>> {
  const declared = fileLength(response);
  if (declared !== undefined && declared > limit) {
    void response.body?.cancel().catch(() => undefined);
    throw new WebDavLimitError('WebDAV 响应超过大小限制。');
  }
  if (!response.body) {
    if (expectedLength) throw new WebDavReadError(expectedLength, 0);
    return new Uint8Array();
  }
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read().catch((error: unknown) => {
        const detail = expectedLength === undefined ? '' : `服务器声明 ${expectedLength} 字节，实际收到 ${size} 字节。`;
        throw new WebDavNetworkError(`WebDAV 文件传输中断。${detail}`, { cause: error });
      });
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        void reader.cancel().catch(() => undefined);
        throw new WebDavLimitError('WebDAV 响应超过大小限制。');
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  if (expectedLength !== undefined && size !== expectedLength) throw new WebDavReadError(expectedLength, size);
  const joined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.length; }
  return joined;
}

interface Prop { status: number; collection?: boolean; etag?: string; bytes?: number }
interface DavRow { href?: string; status?: number; properties: Prop[] }
function parseResponses(xml: string): DavRow[] {
  const rows: DavRow[] = [], path: string[] = [];
  const parser = new SaxesParser({ xmlns: true });
  let row: DavRow | undefined, prop: Prop | undefined, captured = '', text = '';
  const statusOf = (value: string) => {
    const match = /^HTTP\/\d+(?:\.\d+)?\s+([1-5]\d\d)(?:\s|$)/i.exec(value);
    if (!match) throw malformed();
    return Number(match[1]);
  };
  parser.on('doctype', () => { throw malformed(); });
  parser.on('error', () => { throw malformed(); });
  parser.on('opentag', tag => {
    path.push(tag.uri === 'DAV:' ? tag.local : '');
    if (path.length > 24) throw malformed();
    const place = path.join('/');
    if (path.length === 1 && place !== 'multistatus') throw malformed();
    if (place === 'multistatus/response') row = { properties: [] };
    if (place === 'multistatus/response/propstat') prop = { status: 0 };
    if (place === 'multistatus/response/propstat/prop/resourcetype' && prop) prop.collection = false;
    if (place === 'multistatus/response/propstat/prop/resourcetype/collection' && prop) prop.collection = true;
    if (['multistatus/response/href', 'multistatus/response/status', 'multistatus/response/propstat/status',
      'multistatus/response/propstat/prop/getetag', 'multistatus/response/propstat/prop/getcontentlength'].includes(place)) {
      captured = place; text = '';
    } else if (captured) throw malformed();
  });
  const append = (value: string) => {
    if (captured) {
      text += value;
      if (text.length > 4096) throw malformed();
    }
  };
  parser.on('text', append);
  parser.on('cdata', append);
  parser.on('closetag', () => {
    const place = path.join('/');
    if (captured === place) {
      const value = text.trim();
      if (place === 'multistatus/response/href' && row) {
        if (row.href !== undefined || !value) throw malformed();
        row.href = value;
      } else if (place === 'multistatus/response/status' && row) row.status = statusOf(value);
      else if (place.endsWith('/status') && prop) prop.status = statusOf(value);
      else if (place.endsWith('/getetag') && prop && /^"[\x21\x23-\x7e]{1,512}"$/.test(value)) prop.etag = value;
      else if (place.endsWith('/getcontentlength') && prop && /^\d{1,12}$/.test(value)) prop.bytes = Number(value);
      captured = ''; text = '';
    }
    if (place === 'multistatus/response/propstat' && row && prop) {
      if (!prop.status) throw malformed();
      row.properties.push(prop); prop = undefined;
    }
    if (place === 'multistatus/response' && row) {
      if (!row.href || (!row.status && !row.properties.length) || rows.length >= 4096) throw malformed();
      rows.push(row); row = undefined;
    }
    path.pop();
  });
  parser.write(xml).close();
  return rows;
}

function checkDav(context: DavContext) {
  if (context.signal?.aborted) throw new Error('密码库已锁定，已停止 WebDAV 请求。');
  context.check?.();
}

export class WebDavClient {
  constructor(readonly config: WebDavConfig, private readonly context: DavContext, private readonly request = fetch, private readonly now = Date.now) {}

  private async stop(status: DavStopStatus): Promise<never> {
    await this.context.stop?.(status);
    throw new WebDavStop(status);
  }

  private async send(relative: string, method: string, headers: Record<string, string>, body?: BodyInit): Promise<Response> {
    const target = new URL(relative, this.config.url);
    checkDav(this.context);
    const login = new TextEncoder().encode(`${this.config.username}:${this.config.password}`);
    let response: Response;
    const timeout = AbortSignal.timeout(12_000);
    try {
      // Chrome's native fetch requires its WorkerGlobalScope receiver.
      response = await this.request.call(globalThis, target.href, {
        method, redirect: 'error', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
        signal: this.context.signal ? AbortSignal.any([timeout, this.context.signal]) : timeout,
        headers: { Authorization: 'Basic ' + btoa(String.fromCharCode(...login)), ...headers },
        body,
      });
    } catch {
      checkDav(this.context);
      throw new WebDavNetworkError('无法连接 WebDAV。请核对地址、网络和证书，连接不跟随重定向。');
    } finally { login.fill(0); }
    if (this.context.signal?.aborted) { discard(response); checkDav(this.context); }
    if (stopStatus(response.status)) { discard(response); return this.stop(response.status); }
    return response;
  }

  async get(name: string, limit: number, knownTag?: string): Promise<DavObject | 'unchanged' | undefined> {
    if (!davObjectPath(name)) throw malformed();
    const tag = strongTag(knownTag ?? null);
    const response = await this.send(name, 'GET', tag ? { 'If-None-Match': tag } : {});
    if (response.status === 404) { discard(response); return undefined; }
    if (response.status === 304 && tag) { discard(response); return 'unchanged'; }
    if (response.status !== 200) { discard(response); throw unexpected(response); }
    let bytes: Uint8Array<ArrayBuffer>;
    try { bytes = await boundedBody(response, limit, fileLength(response)); }
    catch (error) {
      checkDav(this.context);
      if (error instanceof WebDavReadError && error.received === 0 && this.config.url.startsWith(davPresets.koofr)) {
        throw new WebDavReadError(error.declared, error.received, koofrReadHint(response));
      }
      throw error;
    }
    checkDav(this.context);
    this.context.observeRead?.(name, bytes.length);
    return { bytes, etag: strongTag(response.headers.get('ETag')) };
  }

  private async conditionalPut(name: string, bytes: Uint8Array<ArrayBuffer>, condition: PutCondition) {
    if (!davObjectPath(name) || ('match' in condition && !strongTag(condition.match))) throw malformed();
    const contentType = name.endsWith('.json') ? 'application/json; charset=utf-8'
      : name.endsWith('.txt') ? 'text/plain; charset=utf-8' : 'application/octet-stream';
    const response = await this.send(name, 'PUT', { 'Content-Type': contentType,
      ...('match' in condition ? { 'If-Match': condition.match } : { 'If-None-Match': '*' }) }, bytes);
    discard(response);
    return response;
  }

  async put(name: string, bytes: Uint8Array<ArrayBuffer>, condition: PutCondition) {
    const response = await this.conditionalPut(name, bytes, condition);
    if (response.status === 412) return false;
    if (![200, 201, 204].includes(response.status)) throw unexpected(response);
    return true;
  }

  private async moveFileExists(name: string) {
    const response = await this.send(name, 'HEAD', {});
    discard(response);
    checkDav(this.context);
    if (response.status === 404) return false;
    if (response.status !== 200) throw response.ok ? incompleteMoveRead(response.status) : unexpected(response);
    return true;
  }

  private async verifyMoveBytes(name: string, bytes: Uint8Array<ArrayBuffer>) {
    try {
      const object = await this.get(name, bytes.length);
      checkDav(this.context);
      if (!object || object === 'unchanged' || !sameBytes(object.bytes, bytes))
        throw new WebDavContentError('网盘移动时读回的文件与预期内容不符。');
      return object.etag;
    } catch (error) {
      if (error instanceof WebDavHttpError && error.status >= 200 && error.status < 300) throw incompleteMoveRead(error.status);
      throw error;
    }
  }

  async createByMove(name: string, bytes: Uint8Array<ArrayBuffer>,
    onRetainedSource?: (name: string, etag: string) => void): Promise<boolean> {
    const slash = name.lastIndexOf('/') + 1, directory = name.slice(0, slash), file = name.slice(slash);
    const permitted = name === DAV_PACK_ROOT || (!directory && davPackProbeName.test(file)) ||
      (directory === 'versions/' && (davPackRecordName.test(file) || isDavPackProbeIn(file, directory))) ||
      (directory === 'packages/' && (davPackPackageName.test(file) || isDavPackProbeIn(file, directory)));
    if (!permitted) throw malformed();
    const source = `${directory}pack_verify_${crypto.randomUUID().replaceAll('-', '')}${file.slice(file.lastIndexOf('.'))}`;
    const occupied = () => new WebDavContentError('网盘的临时文件名已被占用。');
    if (source === name || await this.moveFileExists(source)) throw occupied();
    const upload = await this.conditionalPut(source, bytes, { absent: true });
    checkDav(this.context);
    if (upload.status !== 201) {
      if (upload.status === 412) throw occupied();
      if (upload.ok) throw new WebDavContentError(`网盘未确认新建临时文件（HTTP ${upload.status}）。`);
      throw unexpected(upload);
    }
    const etag = await this.verifyMoveBytes(source, bytes);
    if (!etag) throw new WebDavContentError('临时文件缺少强版本标签（ETag）。');
    const response = await this.send(source, 'MOVE', {
      Destination: new URL(name, this.config.url).href, Overwrite: 'F', 'If-Match': etag,
    });
    discard(response);
    checkDav(this.context);
    if (response.status === 412) {
      // If-Match on the source can also fail. A 412 alone does not prove a competing creation.
      if (await this.verifyMoveBytes(source, bytes) !== etag || !await this.moveFileExists(name))
        throw new WebDavContentError('网盘拒绝移动，但无法验证原临时文件和已存在的目标。');
      onRetainedSource?.(source, etag);
      return false;
    }
    if (response.status !== 201) {
      if (response.ok) throw new WebDavContentError(`网盘未确认独占创建移动目标（HTTP ${response.status}）。`);
      throw unexpected(response);
    }
    if (await this.moveFileExists(source)) throw new WebDavContentError('网盘报告移动成功，但临时文件仍然存在。');
    await this.verifyMoveBytes(name, bytes);
    return true;
  }

  async delete(name: string, etag: string) {
    if (!davObjectPath(name) || !strongTag(etag)) throw malformed();
    const response = await this.send(name, 'DELETE', { 'If-Match': etag });
    discard(response);
    if (response.status === 412) return false;
    if (![200, 204, 404].includes(response.status)) throw unexpected(response);
    return true;
  }

  async makeWalDirectory() {
    const response = await this.send('wal/', 'MKCOL', {});
    discard(response);
    if (![201, 405].includes(response.status)) throw unexpected(response);
  }

  async makeVaultDirectory() {
    const response = await this.send('', 'MKCOL', {});
    discard(response);
    if (![201, 405].includes(response.status)) throw unexpected(response);
  }

  async makePackDirectory(relative: 'versions/' | 'packages/') {
    if (relative !== 'versions/' && relative !== 'packages/') throw malformed();
    const response = await this.send(relative, 'MKCOL', {});
    discard(response);
    if (![201, 405].includes(response.status)) throw unexpected(response);
  }

  async list(relative = ''): Promise<{ entries: DavEntry[]; offsetSeconds: number | null } | undefined> {
    if (!['', 'wal/', 'versions/', 'packages/'].includes(relative)) throw malformed();
    const target = new URL(relative, this.config.url);
    const started = this.now();
    const response = await this.send(relative, 'PROPFIND', { Depth: '1', 'Content-Type': 'application/xml; charset=utf-8' }, propfind);
    const received = this.now();
    if (response.status === 404) { discard(response); return undefined; }
    if (response.status !== 207) { discard(response); throw new Error(`服务器未返回可验证的 WebDAV 目录（HTTP ${response.status}）。`); }
    let rows: DavRow[];
    try {
      const bytes = await boundedBody(response, maxListingBytes, fileLength(response));
      this.context.observeRead?.(relative, bytes.length);
      rows = parseResponses(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    }
    catch (error) {
      checkDav(this.context);
      if (error instanceof WebDavNetworkError || error instanceof WebDavContentError) throw error;
      throw malformed();
    }
    for (const row of rows) {
      for (const status of [row.status, ...row.properties.map(p => p.status)]) {
        if (status && stopStatus(status)) return this.stop(status);
      }
    }
    checkDav(this.context);
    const base = canonicalPath(target), names = new Set<string>(), entries: DavEntry[] = [];
    let selfCollection = false;
    for (const row of rows) {
      if (row.status && !(row.status >= 200 && row.status < 300)) throw new WebDavHttpError(row.status);
      const url = new URL(row.href!, target);
      const pathname = canonicalPath(url);
      if (url.origin !== target.origin || url.username || url.password || url.search || url.hash) throw malformed();
      const props = row.properties.filter(p => p.status >= 200 && p.status < 300);
      const types = props.filter(p => p.collection != null).map(p => p.collection);
      const unavailable = !types.length && row.properties.find(p => p.status === 408 || p.status >= 500);
      if (unavailable) throw new WebDavHttpError(unavailable.status);
      if (!types.length || types.some(type => type !== types[0])) throw malformed();
      const collection = types[0]!;
      if (pathname === base || pathname === base.slice(0, -1)) {
        if (selfCollection || !collection) throw malformed();
        selfCollection = true;
        continue;
      }
      if (!pathname.startsWith(base)) throw malformed();
      const path = pathname.slice(base.length).replace(/\/$/, '');
      if (!path || path.includes('/') || names.has(path)) throw malformed();
      names.add(path);
      entries.push({ name: decodeURIComponent(path), collection, etag: props.find(p => p.etag)?.etag, bytes: props.find(p => p.bytes !== undefined)?.bytes });
    }
    if (!selfCollection) throw malformed();
    let offsetSeconds: number | null = null;
    if (target.protocol === 'https:' && received >= started && received - started <= 5_000) {
      const date = response.headers.get('Date') ?? '';
      const server = Date.parse(date);
      if (Number.isFinite(server) && new Date(server).toUTCString() === date) {
        const seconds = (server - (started + received) / 2) / 1000;
        if (Math.abs(seconds) >= 15 && Math.abs(seconds) <= 86400) offsetSeconds = Math.round(seconds);
      }
    }
    if ((relative === 'wal/' || relative === 'versions/') && this.context.observeClock) {
      await this.context.observeClock(offsetSeconds, received);
      checkDav(this.context);
    }
    return { entries, offsetSeconds };
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function writeProbeClient(config: WebDavConfig, context: DavContext, request: typeof fetch) {
  let stopped = false;
  const client = new WebDavClient(config, { ...context, stop: status => { stopped = true; return context.stop?.(status); } }, request);
  return { client, canCleanUp: () => !stopped && !context.signal?.aborted };
}

export async function proveConditionalWrites(config: WebDavConfig, scratchFolder: string, context: DavContext, request = fetch) {
  const selected = new URL(config.url);
  const parent = new URL('..', selected);
  const scratch = webDavConfig({ provider: 'custom', base: parent.href, folder: scratchFolder,
    username: config.username, password: config.password, confirmHttp: selected.protocol === 'http:' });
  if (scratch.url === selected.href) throw new Error('测试目录必须和同步目录分开。');
  const { client, canCleanUp } = writeProbeClient(scratch, context, request);
  const listed = await client.list();
  if (!listed || listed.entries.length) throw new Error('请准备一个独立的空测试目录。这里不会创建测试目录。');
  if (selected.href.startsWith(davPresets.koofr) && scratch.url.startsWith(davPresets.koofr))
    await proveProbeObject(client, 'txt', canCleanUp);
  await proveProbeObject(client, 'bin', canCleanUp);
  return true;
}

/** Verify write support after the caller has authenticated the existing legacy vault. */
export async function proveLegacyWritesInVault(config: WebDavConfig, context: DavContext, request = fetch) {
  const { client, canCleanUp } = writeProbeClient(config, context, request);
  if (config.url.startsWith(davPresets.koofr)) await proveProbeObject(client, 'txt', canCleanUp, true);
  await proveProbeObject(client, 'bin', canCleanUp, true);
  return true;
}

async function proveProbeObject(client: WebDavClient, kind: 'txt' | 'bin', canCleanUp: () => boolean, inVault = false) {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const name = `verify_${nonce}.${kind}`;
  const payload = (label: string) => kind === 'txt'
    ? new TextEncoder().encode(`Vault WebDAV test ${label} ${crypto.randomUUID()}\n`)
    : crypto.getRandomValues(new Uint8Array(32));
  const a = payload('A'), b = payload('B');
  const failure = (reason: string) => new Error(`网盘未通过条件写验证。${reason}密码库目录仍只读。`);
  const duplicate = () => failure('网盘允许重复创建已有测试文件，可能覆盖其他设备的写入。请使用支持条件写入的 WebDAV。');
  const readBack = async (stage: string) => {
    try { return await client.get(name, 64); }
    catch (error) {
      if (error instanceof WebDavReadError) throw failure(`${stage}失败。${error.message}`);
      throw error;
    }
  };
  const readProbe = async (stage: string, expected: Uint8Array) => {
    const object = await readBack(stage);
    if (!object || object === 'unchanged') throw failure(`${stage}未取得测试文件。`);
    if (object.bytes.length !== expected.length)
      throw failure(`${stage}应有 ${expected.length} 字节，实际收到 ${object.bytes.length} 字节。`);
    if (!sameBytes(object.bytes, expected)) throw failure(`${stage}的内容与写入内容不符。`);
    if (!object.etag) throw failure(`${stage}缺少强版本标签（ETag）。`);
    return object.etag;
  };
  const removeAndVerify = async (etag: string) => {
    if (!await client.delete(name, etag)) throw failure('网盘拒绝用当前版本标签删除测试文件。');
    if (await readBack('删除后复查') !== undefined) throw failure('删除后复查仍能读到测试文件。');
  };
  let created = false;
  try {
    if (inVault && await readBack('检查测试文件名') !== undefined) throw failure('网盘报告同名测试文件已存在。');
    created = await client.put(name, a, { absent: true });
    if (!created) throw failure('网盘报告同名测试文件已存在。');
    const firstTag = await readProbe(kind === 'txt' ? '文本首次读回' : '首次读回', a);
    try {
      if (await client.put(name, b, { absent: true })) throw duplicate();
    } catch (error) {
      if (kind === 'txt' && error instanceof WebDavHttpError && error.status >= 200 && error.status < 300) throw duplicate();
      throw error;
    }
    if (kind === 'txt') {
      const original = await readBack('重复创建后读回');
      if (!original || original === 'unchanged' || original.etag !== firstTag || !sameBytes(original.bytes, a)) throw duplicate();
      await removeAndVerify(firstTag);
    } else {
      const wrongTag = `"never-${nonce}"`;
      if (await client.put(name, b, { match: wrongTag })) throw failure('网盘允许用错误版本标签覆盖测试文件。');
      if (await client.delete(name, wrongTag)) throw failure('网盘允许用错误版本标签删除测试文件。');
      if (await readProbe('错误标签检查后读回', a) !== firstTag) throw failure('网盘拒绝错误版本标签后，测试文件的版本仍发生了变化。');
      if (!await client.put(name, b, { match: firstTag })) throw failure('网盘拒绝用当前版本标签更新测试文件。');
      const secondTag = await readProbe('更新后读回', b);
      if (secondTag === firstTag) throw failure('更新后读回的版本标签仍和更新前相同。');
      if (await client.put(name, a, { match: firstTag })) throw failure('网盘允许用过期版本标签覆盖测试文件。');
      if (await client.delete(name, firstTag)) throw failure('网盘允许用过期版本标签删除测试文件。');
      if (await readProbe('过期标签检查后读回', b) !== secondTag) throw failure('网盘拒绝过期版本标签后，测试文件的版本仍发生了变化。');
      await removeAndVerify(secondTag);
    }
    created = false;
  } finally {
    if (created && canCleanUp()) {
      try {
        const own = await client.get(name, 64);
        if (own && own !== 'unchanged' && own.etag && (sameBytes(own.bytes, a) || sameBytes(own.bytes, b))) {
          if (kind === 'txt' || inVault) await removeAndVerify(own.etag);
          else await client.delete(name, own.etag);
        }
      } catch { /* Leave the test file rather than repeat or clean by path prefix. */ }
    }
  }
}

export async function probeWebDav(config: WebDavConfig, context: DavContext, request = fetch, now = Date.now): Promise<DavProbe> {
  const listed = await new WebDavClient(config, context, request, now).list();
  if (!listed) return { kind: 'missing', offsetSeconds: null, writeAllowed: false };
  const { offsetSeconds } = listed;
  const entries = listed.entries.filter(entry => entry.collection || !davPackProbeName.test(entry.name));
  if (entries.length === 3 && entries.some(entry => entry.name === DAV_PACK_ROOT && !entry.collection) &&
    ['versions', 'packages'].every(name => entries.some(entry => entry.name === name && entry.collection)))
    return { kind: 'existing', format: 'pack', offsetSeconds, writeAllowed: false };
  const head = entries.some(entry => entry.name === 'head.bin' && !entry.collection);
  const snap = entries.some(entry => /^snap_[A-Za-z0-9_-]{1,128}\.bin$/.test(entry.name) && !entry.collection);
  const wal = entries.some(entry => entry.name === 'wal' && entry.collection);
  const kind = head && snap && wal ? 'existing' : entries.length ? 'incomplete' : 'empty';
  return { kind, offsetSeconds, writeAllowed: false };
}
