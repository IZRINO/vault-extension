import { derive } from '../bridge';
import type { RemoteAnchor, SessionState, VaultFiles } from '../vault-storage';
import type { SyncHistoryEntry, SyncRestorePreview } from '../vault-messages';
import {
  davHeadForHistory, getSyncHistory, listRemoteWal, SNAPSHOT_LIMIT,
  type ReplayOutput, type RemoteHeadInfo, type SnapshotOutput,
} from './bootstrap';
import { cleanAbsorbedWal, cleanOldHistory, publishSnapshot, snapshotDigest } from './publish';
import { nextJournalVersion, type JournalClock } from './journal-device';
import { WebDavClient } from './webdav';

type Encrypted = Pick<VaultFiles, 'head' | 'snap'>;
type Guard = { before: number; after: number; removed: number; stamp: string; blocked: boolean };
const changed = () => new Error('网盘或本机状态已变化。请先同步，再重新预览。');
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, index) => value === b[index]);

export async function listHistory(client: WebDavClient, anchor: RemoteAnchor, session: SessionState, files: VaultFiles) {
  const head = await requireCurrentHead(client, anchor, session, files);
  const history = await getSyncHistory(client, head.info);
  const entries: SyncHistoryEntry[] = [];
  for (const object of [{ id: head.info.snapshotId.slice(5), bytes: anchor.snap }, ...history]) {
    const id = `snap_${object.id}`;
    const [epoch, count] = await derive<number[]>('sync:history-metadata', [session.key, session.wrap, id, object.bytes]);
    if (epoch == null || count == null) throw new Error('无法验证历史版本。');
    entries.push({ id, time: Number.parseInt(object.id.slice(0, 14), 16), epoch, count, current: id === head.info.snapshotId });
  }
  return entries;
}

async function requireCurrentHead(client: WebDavClient, anchor: RemoteAnchor, session: SessionState, files: VaultFiles) {
  const object = await davHeadForHistory(client);
  if (!sameBytes(object.bytes, anchor.head)) throw changed();
  const info = await derive<RemoteHeadInfo>('sync:authenticate-head', [object.bytes, session.key, session.wrap]);
  if (info.vaultId !== files.vaultId || info.keyEpoch !== files.keyEpoch) throw changed();
  return { object, info };
}

async function stableDirectory(client: WebDavClient, anchor: RemoteAnchor) {
  const listing = await listRemoteWal(client);
  if (listing.length !== anchor.objects.length || listing.some(entry => {
    const known = anchor.objects.find(object => object.id === entry.id);
    return !known || (entry.etag && known.etag !== entry.etag);
  })) throw changed();
}

export async function prepareRestore(client: WebDavClient, anchor: RemoteAnchor, session: SessionState, files: VaultFiles, id: string) {
  const { object, info } = await requireCurrentHead(client, anchor, session, files);
  if (!info.history.includes(id) || anchor.conflicts?.length || anchor.conflictCount || anchor.rotationFrom || anchor.outbox) throw changed();
  await stableDirectory(client, anchor);
  const history = await client.get(`${id}.bin`, SNAPSHOT_LIMIT);
  if (!history || history === 'unchanged') throw new Error('找不到要恢复的历史快照。');
  const { key, wrap } = session;
  const proposed = await derive<ReplayOutput>('sync:restore-content', [key, wrap, object.bytes, files.head, files.snap, id, history.bytes]);
  const view = { head: new Uint8Array(proposed.head), snap: new Uint8Array(proposed.snap) } satisfies Encrypted;
  const guard = await derive<Guard>('sync:write-guard', [key, wrap, files.head, files.snap, view.head, view.snap, anchor.hasRecords || files.everHadRecords === true]);
  const readOnly = !client.config.writeVerified || !object.etag || !!anchor.localRestoreHeld;
  const stampInput = new TextEncoder().encode(JSON.stringify([id, object.etag ?? null, readOnly, guard.stamp,
    await snapshotDigest(object.bytes), await snapshotDigest(files.snap), await snapshotDigest(history.bytes), anchor.objects.map(wal => wal.id)]));
  const preview: SyncRestorePreview = { id, before: guard.before, after: guard.after, removed: guard.removed,
    blocked: guard.blocked, bulk: !!guard.stamp, stamp: await snapshotDigest(stampInput), readOnly };
  return { object, info, preview, proposed, view };
}

async function confirmRestore(client: WebDavClient, anchor: RemoteAnchor, prepared: Awaited<ReturnType<typeof prepareRestore>>, check: () => void) {
  check();
  await stableDirectory(client, anchor);
  const latest = await davHeadForHistory(client);
  if (latest.etag !== prepared.object.etag || !sameBytes(latest.bytes, prepared.object.bytes)) throw changed();
  check();
}

export async function restoreHistoryLocally(client: WebDavClient, anchor: RemoteAnchor, files: VaultFiles,
  prepared: Awaited<ReturnType<typeof prepareRestore>>, stamp: string, check: () => void,
  save: (anchor: RemoteAnchor, files: VaultFiles) => Promise<void>) {
  if (prepared.preview.stamp !== stamp || !prepared.preview.readOnly) throw changed();
  await confirmRestore(client, anchor, prepared, check);
  await save({ ...anchor, localRestoreHeld: true }, { ...files, ...prepared.view, updatedAtMs: Date.now(),
    changesSinceBackup: files.changesSinceBackup + 1, everHadRecords: files.everHadRecords || prepared.preview.after > 0 });
  return prepared.preview.after;
}

export async function restoreHistory(client: WebDavClient, anchor: RemoteAnchor, session: SessionState, files: VaultFiles,
  prepared: Awaited<ReturnType<typeof prepareRestore>>, clock: JournalClock | undefined, stamp: string, check: () => void,
  reserve: (clock: JournalClock, pending: NonNullable<RemoteAnchor['pendingCompaction']>) => Promise<void>,
  save: (anchor: RemoteAnchor, files: VaultFiles) => Promise<void>) {
  if (prepared.preview.stamp !== stamp) throw changed();
  if (prepared.preview.blocked) throw new Error('恢复结果为空库，已拦截向网盘发布。');
  if (prepared.preview.readOnly || !prepared.object.etag) throw new Error('网盘仍是只读，不能发布历史恢复。');
  const { key, wrap } = session;
  const version = nextJournalVersion(clock, Date.now(), prepared.proposed.hlc);
  const output = await derive<SnapshotOutput>('sync:compact', [key, wrap, prepared.object.bytes, prepared.view.head, prepared.view.snap, version.id]);
  const snap = new Uint8Array(output.snap);
  const pending = { id: version.id, digest: await snapshotDigest(snap), priorHistory: prepared.info.history };
  await confirmRestore(client, anchor, prepared, check);
  await reserve(version.state, pending);
  const published = await publishSnapshot(client, version.id, prepared.object.etag, new Uint8Array(output.head), snap);
  if (!published) throw changed();
  const info = await derive<RemoteHeadInfo>('sync:authenticate-head', [published.bytes, key, wrap]);
  check();
  const head = new Uint8Array(info.localHead);
  const next = { ...files, head, snap, updatedAtMs: Date.now(), changesSinceBackup: files.changesSinceBackup + 1 };
  const committed = { ...anchor, head: published.bytes, etag: published.etag, snap, appliedHead: head, appliedSnap: snap, checkedAt: Date.now() };
  await save({ ...committed, pendingCompaction: pending }, next);
  await cleanAbsorbedWal(client, anchor.objects, prepared.proposed.included);
  await cleanOldHistory(client, prepared.info.history.filter(name => !info.history.includes(name)));
  check();
  await save({ ...committed, pendingCompaction: undefined }, next);
  return prepared.preview.after;
}
