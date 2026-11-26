import type { RemoteWal } from './bootstrap';
import { HEAD_LIMIT, SNAPSHOT_LIMIT, WAL_LIMIT } from './bootstrap';
import { retireReservations } from './capacity';
import { WebDavClient } from './webdav';

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, index) => value === b[index]);

export async function publishSnapshot(client: WebDavClient, id: string, previousTag: string,
  head: Uint8Array<ArrayBuffer>, snap: Uint8Array<ArrayBuffer>) {
  const name = `snap_${id}.bin`;
  if (!await client.put(name, snap, { absent: true })) return undefined;
  const staged = await client.get(name, SNAPSHOT_LIMIT);
  if (!staged || staged === 'unchanged' || !sameBytes(staged.bytes, snap)) throw new Error('网盘快照无法验证，未更新远端头。');
  if (!await client.put('head.bin', head, { match: previousTag })) {
    if (staged.etag) await client.delete(name, staged.etag);
    return undefined;
  }
  const committed = await client.get('head.bin', HEAD_LIMIT);
  if (!committed || committed === 'unchanged' || !committed.etag || !sameBytes(head, committed.bytes))
    throw new Error('无法确认远端快照已提交。此轮未清理任何旧数据。');
  return committed;
}

export async function cleanAbsorbedWal(client: WebDavClient, consumed: readonly RemoteWal[], included: readonly string[]) {
  const absorbed = new Set(included);
  const confirmed = consumed.filter(object => absorbed.has(object.id));
  await retireReservations(client, confirmed);
  for (const object of confirmed) {
    const name = `wal/${object.id}.bin`;
    let tag = object.etag;
    if (!tag) {
      const current = await client.get(name, WAL_LIMIT);
      if (!current || current === 'unchanged' || !current.etag || !sameBytes(current.bytes, object.bytes)) continue;
      tag = current.etag;
    }
    await client.delete(name, tag);
  }
}

export async function cleanOldHistory(client: WebDavClient, safeHistory: readonly string[]) {
  for (const name of safeHistory) {
    const object = await client.get(`${name}.bin`, SNAPSHOT_LIMIT);
    if (object && object !== 'unchanged' && object.etag) await client.delete(`${name}.bin`, object.etag);
  }
}

export async function snapshotDigest(bytes: Uint8Array) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes))),
    byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function cleanAbandonedSnapshot(client: WebDavClient, id: string, digest: string) {
  const name = `snap_${id}.bin`;
  const object = await client.get(name, SNAPSHOT_LIMIT);
  if (object && object !== 'unchanged' && object.etag && await snapshotDigest(object.bytes) === digest)
    await client.delete(name, object.etag);
}
