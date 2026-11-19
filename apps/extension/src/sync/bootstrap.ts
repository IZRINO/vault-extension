import { davSnapshotName, davWalName, proveConditionalWrites, WebDavClient, type DavContext, type DavObject, type WebDavConfig } from './webdav';

export const HEAD_LIMIT = 64 * 1024;
export const SNAPSHOT_LIMIT = 16 * 1024 * 1024;
export const WAL_LIMIT = 16 * 1024 * 1024;
export const MAX_REMOTE_WALS = 750;
export const MAX_REMOTE_WAL_BYTES = 8 * 1024 * 1024;

export interface RemoteHeadInfo {
  localHead: number[]; wrap: number[]; vaultId: string; keyEpoch: number;
  snapshotId: string; snapshotEpoch: number; root: number[]; history: string[];
}
export interface RemoteWal { id: string; bytes: Uint8Array; etag?: string }
export interface ReplayOutput { head: number[]; snap: number[]; hlc: number; count: number; included: string[];
  conflicts: number[]; conflictCount: number; draftCount: number; receipts: number[]; compacted: string[] }
export interface SnapshotOutput { head: number[]; snap: number[]; root: number[] }
const notEmpty = () => new Error('目录已有文件或另一台设备正在建库。请重测并尝试读取已有密码库。');
const incomplete = () => new Error('远端密码库缺少文件或在读取期间发生变化。未修改本机密码库，请重试。');
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, index) => byte === b[index]);

export async function createRemoteVault<T extends { snapshotId: string; head: Uint8Array<ArrayBuffer>; snap: Uint8Array<ArrayBuffer> }>(
  config: WebDavConfig, scratchFolder: string, context: DavContext, create: () => Promise<T>, request = fetch,
) {
  const client = new WebDavClient(config, context, request);
  if ((await client.list())?.entries.length) throw notEmpty();
  await proveConditionalWrites(config, scratchFolder, context, request);
  const genesis = await create();
  const name = `${genesis.snapshotId}.bin`;
  if (!davSnapshotName.test(name)) throw incomplete();
  const located = await client.list();
  if (located?.entries.length) throw notEmpty();
  if (!located) {
    await client.makeVaultDirectory();
    const initialized = await client.list();
    if (!initialized || initialized.entries.length) throw notEmpty();
  }
  await client.makeWalDirectory();
  const walFolder = await client.list('wal/');
  if (!walFolder || walFolder.entries.length) throw notEmpty();
  if (!await client.put(name, genesis.snap, { absent: true })) throw notEmpty();
  const staged = await client.get(name, SNAPSHOT_LIMIT);
  if (!staged || staged === 'unchanged' || !staged.etag || !sameBytes(staged.bytes, genesis.snap)) throw incomplete();
  if (!await client.put('head.bin', genesis.head, { absent: true })) {
    // This unique snapshot has not been published in a head. Never remove the winner's files.
    await client.delete(name, staged.etag);
    throw notEmpty();
  }
  const head = await client.get('head.bin', HEAD_LIMIT);
  if (!head || head === 'unchanged' || !head.etag || !sameBytes(head.bytes, genesis.head)) throw incomplete();
  return { genesis, head, offsetSeconds: located?.offsetSeconds ?? null };
}

export type WalListing = { id: string; etag?: string; bytes?: number }[];
export async function listRemoteWal(client: WebDavClient): Promise<WalListing> {
  const wal = await client.list('wal/');
  if (!wal || wal.entries.some(entry => entry.collection || !davWalName.test(entry.name))) throw incomplete();
  if (wal.entries.length > MAX_REMOTE_WALS) throw new Error('远端增量数量超出限制，未修改本机密码库。');
  return wal.entries.map(({ name, etag, bytes }) => ({ id: name.slice(0, -4), etag, bytes }))
    .sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

export async function fetchRemoteWal(client: WebDavClient, entries: WalListing, cached: readonly RemoteWal[] = []): Promise<RemoteWal[]> {
  const cache = new Map(cached.map(wal => [wal.id, wal]));
  let remaining = MAX_REMOTE_WAL_BYTES;
  const objects: RemoteWal[] = [];
  for (const entry of entries) {
    const existing = cache.get(entry.id);
    if (existing && existing.etag && entry.etag && existing.etag !== entry.etag) throw incomplete();
    const object = existing && (existing.etag || !entry.etag) ? existing :
      await client.get(`wal/${entry.id}.bin`, Math.min(remaining, WAL_LIMIT));
    if (!object || object === 'unchanged' || object.bytes.length === 0 || object.bytes.length > remaining) throw incomplete();
    if (existing && !sameBytes(existing.bytes, object.bytes)) throw incomplete();
    remaining -= object.bytes.length;
    objects.push({ id: entry.id, bytes: object.bytes, etag: object.etag });
  }
  return objects;
}

export async function getSyncHistory(client: WebDavClient, info: RemoteHeadInfo, cached: readonly RemoteWal[] = []) {
  const objects: RemoteWal[] = [];
  let remaining = 8 * 1024 * 1024;
  for (const name of info.history.slice(1)) {
    if (!davSnapshotName.test(`${name}.bin`)) throw incomplete();
    const id = name.slice(5);
    if (cached.some(object => object.id === id)) continue;
    if (!remaining) throw new Error('远端历史超过自动回放容量。请先导出或恢复可验证数据。');
    const object = await client.get(`${name}.bin`, Math.min(SNAPSHOT_LIMIT, remaining));
    if (!object || object === 'unchanged') continue;
    remaining -= object.bytes.length;
    objects.push({ id, bytes: object.bytes, etag: object.etag });
  }
  return [...cached, ...objects];
}

export function packSyncFrames(objects: readonly RemoteWal[]) {
  const out = new Uint8Array(objects.reduce((bytes, object) => bytes + 42 + object.bytes.length, 0));
  const view = new DataView(out.buffer);
  const encoder = new TextEncoder();
  let offset = 0;
  for (const object of objects) {
    if (!davWalName.test(`${object.id}.bin`)) throw incomplete();
    encoder.encodeInto(object.id, out.subarray(offset, offset + 38));
    view.setUint32(offset + 38, object.bytes.length, true);
    out.set(object.bytes, offset + 42);
    offset += 42 + object.bytes.length;
  }
  return out;
}

export async function davHeadForHistory(client: WebDavClient): Promise<DavObject> {
  const object = await client.get('head.bin', HEAD_LIMIT);
  if (!object || object === 'unchanged') throw incomplete();
  return object;
}

export async function readRemoteVault<T>(client: WebDavClient, unlock: (head: DavObject) => Promise<RemoteHeadInfo>,
  replay: (head: RemoteHeadInfo, snap: Uint8Array, wal: RemoteWal[], history: RemoteWal[]) => Promise<T>) {
  const target = await client.list();
  if (!target?.entries.some(entry => entry.name === 'head.bin' && !entry.collection)) throw incomplete();
  const head = await client.get('head.bin', HEAD_LIMIT);
  if (!head || head === 'unchanged') throw incomplete();
  const authenticated = await unlock(head);
  const name = `${authenticated.snapshotId}.bin`;
  if (!davSnapshotName.test(name)) throw incomplete();
  const snap = await client.get(name, SNAPSHOT_LIMIT);
  if (!snap || snap === 'unchanged') throw incomplete();
  const objects = await fetchRemoteWal(client, await listRemoteWal(client));
  const history = objects.length && authenticated.history.length > 1 ? await getSyncHistory(client, authenticated) : [];
  const result = await replay(authenticated, snap.bytes, objects, history);
  // A compaction may publish while recovery downloads. Commit only against a stable authenticated head.
  const latest = await client.get('head.bin', HEAD_LIMIT, head.etag);
  if (!latest || latest !== 'unchanged' && !sameBytes(head.bytes, latest.bytes)) throw incomplete();
  return { authenticated, head, snap, objects, result, offsetSeconds: target.offsetSeconds };
}

export async function endpointFingerprint(url: string) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url)));
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
