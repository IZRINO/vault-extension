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

export interface WebDavConfig { url: string; username: string; password: string; writeVerified?: boolean }
export type DavStopStatus = 401 | 403 | 429;
export type DavProbe = { kind: 'empty' | 'existing' | 'incomplete' | 'missing'; offsetSeconds: number | null; writeAllowed: false };
export interface DavEntry { name: string; collection: boolean; etag?: string; bytes?: number }
export interface DavContext {
  signal?: AbortSignal;
  check?(): void;
  stop?(status: DavStopStatus): void | Promise<void>;
}

export interface DavObject { bytes: Uint8Array<ArrayBuffer>; etag?: string }
export const davSnapshotName = /^snap_[0-9a-f]{14}_[0-9a-f]{8}_[0-9a-f]{14}\.bin$/;
export const davWalName = /^[0-9a-f]{14}_[0-9a-f]{8}_[0-9a-f]{14}\.bin$/;
const probeName = /^verify_[0-9a-f]{32}\.bin$/;
const davObjectPath = (name: string) => name === 'head.bin' || davSnapshotName.test(name) ||
  (name.startsWith('wal/') && davWalName.test(name.slice(4))) || probeName.test(name);
const strongTag = (value: string | null) => value && /^"[\x21\x23-\x7e]{1,512}"$/.test(value) ? value : undefined;
const discard = (response: Response) => { void response.body?.cancel().catch(() => undefined); };
const unexpected = (response: Response) => new Error(`WebDAV 请求未完成（HTTP ${response.status}）。`);

const statusHint: Record<DavStopStatus, string> = {
  401: '网盘拒绝了登录。请核对账户和应用专用密码后手动测试。',
  403: '网盘拒绝访问。请核对目录权限后手动测试。',
  429: '网盘请求过于频繁，已停止自动连接。请稍后手动测试。',
};
const maxListingBytes = 1024 * 1024;
const propfind = '<?xml version="1.0" encoding="UTF-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getetag/><D:getcontentlength/></D:prop></D:propfind>';
const malformed = () => new Error('WebDAV 目录响应不完整或格式无效。');

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

export async function boundedBody(response: Response, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  if (Number(response.headers.get('Content-Length')) > limit) {
    void response.body?.cancel().catch(() => undefined);
    throw new Error('WebDAV 响应超过大小限制。');
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        void reader.cancel().catch(() => undefined);
        throw new Error('WebDAV 响应超过大小限制。');
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
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
      throw new Error('无法连接 WebDAV。请核对地址、网络和证书，连接不跟随重定向。');
    } finally { login.fill(0); }
    if (stopStatus(response.status)) { discard(response); return this.stop(response.status); }
    if (this.context.signal?.aborted) { discard(response); checkDav(this.context); }
    return response;
  }

  async get(name: string, limit: number, knownTag?: string): Promise<DavObject | 'unchanged' | undefined> {
    if (!davObjectPath(name)) throw malformed();
    const response = await this.send(name, 'GET', knownTag && strongTag(knownTag) ? { 'If-None-Match': knownTag } : {});
    if (response.status === 404) { discard(response); return undefined; }
    if (response.status === 304 && knownTag) { discard(response); return 'unchanged'; }
    if (response.status !== 200) { discard(response); throw unexpected(response); }
    let bytes: Uint8Array<ArrayBuffer>;
    try { bytes = await boundedBody(response, limit); }
    catch (error) { checkDav(this.context); throw error; }
    checkDav(this.context);
    return { bytes, etag: strongTag(response.headers.get('ETag')) };
  }

  async put(name: string, bytes: Uint8Array<ArrayBuffer>, condition: { absent: true } | { match: string }) {
    if (!davObjectPath(name) || ('match' in condition && !strongTag(condition.match))) throw malformed();
    const response = await this.send(name, 'PUT', { 'Content-Type': 'application/octet-stream',
      ...('match' in condition ? { 'If-Match': condition.match } : { 'If-None-Match': '*' }) }, bytes);
    discard(response);
    if (response.status === 412) return false;
    if (![200, 201, 204].includes(response.status)) throw unexpected(response);
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

  async list(relative = ''): Promise<{ entries: DavEntry[]; offsetSeconds: number | null } | undefined> {
    if (relative !== '' && relative !== 'wal/') throw malformed();
    const target = new URL(relative, this.config.url);
    const started = this.now();
    const response = await this.send(relative, 'PROPFIND', { Depth: '1', 'Content-Type': 'application/xml; charset=utf-8' }, propfind);
    const received = this.now();
    if (response.status === 404) { discard(response); return undefined; }
    if (response.status !== 207) { discard(response); throw new Error(`服务器未返回可验证的 WebDAV 目录（HTTP ${response.status}）。`); }
    let rows: DavRow[];
    try { rows = parseResponses(new TextDecoder('utf-8', { fatal: true }).decode(await boundedBody(response, maxListingBytes))); }
    catch { checkDav(this.context); throw malformed(); }
    for (const row of rows) {
      for (const status of [row.status, ...row.properties.map(p => p.status)]) {
        if (status && stopStatus(status)) return this.stop(status);
      }
    }
    checkDav(this.context);
    const base = canonicalPath(target), names = new Set<string>(), entries: DavEntry[] = [];
    let selfCollection = false;
    for (const row of rows) {
      if (row.status && !(row.status >= 200 && row.status < 300)) throw malformed();
      const url = new URL(row.href!, target);
      const pathname = canonicalPath(url);
      if (url.origin !== target.origin || url.username || url.password || url.search || url.hash) throw malformed();
      const props = row.properties.filter(p => p.status >= 200 && p.status < 300);
      const types = props.filter(p => p.collection != null).map(p => p.collection);
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
    return { entries, offsetSeconds };
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

export async function proveConditionalWrites(config: WebDavConfig, scratchFolder: string, context: DavContext, request = fetch) {
  const selected = new URL(config.url);
  const parent = new URL('..', selected);
  const scratch = webDavConfig({ provider: 'custom', base: parent.href, folder: scratchFolder,
    username: config.username, password: config.password, confirmHttp: selected.protocol === 'http:' });
  if (scratch.url === selected.href) throw new Error('测试目录必须和同步目录分开。');
  let stopped = false;
  const client = new WebDavClient(scratch, { ...context, stop: status => { stopped = true; return context.stop?.(status); } }, request);
  const listed = await client.list();
  if (!listed || listed.entries.length) throw new Error('请准备一个独立的空测试目录。这里不会创建测试目录。');
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const name = `verify_${nonce}.bin`;
  const a = crypto.getRandomValues(new Uint8Array(32));
  const b = crypto.getRandomValues(new Uint8Array(32));
  const failure = () => new Error('网盘未通过条件写验证。密码库目录仍只读。');
  let created = false;
  try {
    created = await client.put(name, a, { absent: true });
    if (!created) throw failure();
    const first = await client.get(name, 64);
    if (!first || first === 'unchanged' || !first.etag || !sameBytes(first.bytes, a)) throw failure();
    if (await client.put(name, b, { absent: true })) throw failure();
    const wrongTag = `"never-${nonce}"`;
    if (await client.put(name, b, { match: wrongTag })) throw failure();
    if (await client.delete(name, wrongTag)) throw failure();
    const unchanged = await client.get(name, 64);
    if (!unchanged || unchanged === 'unchanged' || unchanged.etag !== first.etag || !sameBytes(unchanged.bytes, a)) throw failure();
    if (!await client.put(name, b, { match: first.etag })) throw failure();
    const second = await client.get(name, 64);
    if (!second || second === 'unchanged' || !second.etag || second.etag === first.etag || !sameBytes(second.bytes, b)) throw failure();
    if (await client.put(name, a, { match: first.etag })) throw failure();
    if (await client.delete(name, first.etag)) throw failure();
    const current = await client.get(name, 64);
    if (!current || current === 'unchanged' || current.etag !== second.etag || !sameBytes(current.bytes, b)) throw failure();
    if (!await client.delete(name, second.etag) || await client.get(name, 64) !== undefined) throw failure();
    created = false;
    return true;
  } finally {
    if (created && !stopped && !context.signal?.aborted) {
      try {
        const own = await client.get(name, 64);
        if (own && own !== 'unchanged' && own.etag && (sameBytes(own.bytes, a) || sameBytes(own.bytes, b))) await client.delete(name, own.etag);
      } catch { /* Leave the scratch file rather than repeat or clean by path prefix. */ }
    }
  }
}

export async function probeWebDav(config: WebDavConfig, context: DavContext, request = fetch, now = Date.now): Promise<DavProbe> {
  const listed = await new WebDavClient(config, context, request, now).list();
  if (!listed) return { kind: 'missing', offsetSeconds: null, writeAllowed: false };
  const { entries, offsetSeconds } = listed;
  const head = entries.some(entry => entry.name === 'head.bin' && !entry.collection);
  const snap = entries.some(entry => /^snap_[A-Za-z0-9_-]{1,128}\.bin$/.test(entry.name) && !entry.collection);
  const wal = entries.some(entry => entry.name === 'wal' && entry.collection);
  const kind = head && snap && wal ? 'existing' : entries.length ? 'incomplete' : 'empty';
  return { kind, offsetSeconds, writeAllowed: false };
}
