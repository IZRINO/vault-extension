import { derive } from '../bridge';
import type { SessionState, RemoteAnchor, VaultFiles } from '../vault-storage';
import {
  endpointFingerprint, fetchRemoteWal, getSyncHistory, HEAD_LIMIT, listRemoteWal, packSyncFrames, SNAPSHOT_LIMIT, WAL_LIMIT,
  type RemoteHeadInfo, type RemoteWal, type ReplayOutput, type SnapshotOutput,
} from './bootstrap';
import { nextJournalVersion, type JournalClock } from './journal-device';
import { cleanAbandonedSnapshot, cleanAbsorbedWal, cleanOldHistory, publishSnapshot, snapshotDigest } from './publish';
import { WebDavClient, type DavContext, type WebDavConfig } from './webdav';

const VERIFY_HEAD_EVERY_MS = 10 * 60_000;
const rejectHistory = () => new Error('远端返回了旧版本或缺少已经确认的变更。本机数据未覆盖（RollbackDetected）。');
const requireUpdate = () => new Error('远端主密码已更新。请用新主密码重新验证；未上传的编辑仍在本机。');
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, index) => byte === b[index]);

type CipherState = Pick<VaultFiles, 'head' | 'snap'>;
type Verification = { before: number; after: number; removed: number; stamp: string; blocked: boolean };
export type SyncResult =
  | { kind: 'synced' | 'unchanged' | 'read-only' | 'unlinked' | 'locked' | 'paused' | 'empty'; pending: boolean }
  | { kind: 'conflicts'; pending: boolean; count: number }
  | { kind: 'key-update'; pending: boolean; epoch: number }
  | { kind: 'confirm-deletion'; pending: true; before: number; after: number; removed: number; stamp: string };

interface RunOptions {
  session: SessionState;
  files: VaultFiles;
  anchor: RemoteAnchor;
  clock?: JournalClock;
  pending: boolean;
  forceHead: boolean;
  compactWhenIdle?: boolean;
  context: DavContext;
  commit(anchor: RemoteAnchor, files: VaultFiles, consume: boolean, clock?: JournalClock): Promise<void>;
  authorize(stamp: string): Promise<boolean>;
}

function fromOutput(output: ReplayOutput): CipherState {
  return { head: new Uint8Array(output.head), snap: new Uint8Array(output.snap) };
}

function matchedReceipts(saved: Uint8Array | undefined, current: number[]): Uint8Array {
  if (!saved?.length || !current.length) return new Uint8Array();
  const id = (bytes: Uint8Array) => Array.from(bytes).join(',');
  const active = new Uint8Array(current), keys = new Set<string>();
  for (let i = 0; i < active.length; i += 32) keys.add(id(active.subarray(i, i + 32)));
  const result = new Uint8Array(saved.length);
  let size = 0;
  for (let i = 0; i + 32 <= saved.length; i += 32) {
    const key = saved.subarray(i, i + 32);
    if (keys.delete(id(key))) { result.set(key, size); size += 32; }
  }
  return result.subarray(0, size);
}

export async function runDavSync(config: WebDavConfig, options: RunOptions, request = fetch): Promise<SyncResult> {
  const { files, session, clock, pending, context, forceHead } = options;
  let anchor = options.anchor;
  const writeVerified = config.writeVerified && !anchor.localRestoreHeld;
  if (anchor.endpoint !== await endpointFingerprint(config.url)) {
    throw new Error('连接地址与已验证的库不同。未从新地址恢复或写入数据。');
  }
  const check = () => context.check?.();
  const client = new WebDavClient(config, context, request);
  const listing = await listRemoteWal(client);
  const listed = new Set(listing.map(({ id }) => id));
  const cached = new Set(anchor.objects.map(({ id }) => id));
  const directoryChanged = listing.length !== cached.size || listing.some(({ id, etag }) =>
    !cached.has(id) || (etag && anchor.objects.find(object => object.id === id)?.etag !== etag));
  const headDue = !anchor.checkedAt || Date.now() < anchor.checkedAt || Date.now() - anchor.checkedAt >= VERIFY_HEAD_EVERY_MS;
  const shouldCompact = !!(options.compactWhenIdle && writeVerified && !anchor.conflictCount && (
    listing.length >= 20 || (listing.length > 0 && anchor.objects.reduce((size, object) => size + object.bytes.length, 0) > anchor.snap.length / 4)));
  if (!directoryChanged && !headDue && !shouldCompact && !forceHead && !anchor.outbox &&
      !(writeVerified && anchor.pendingCompaction) && anchor.rotationFrom == null &&
      (!pending || !writeVerified)) {
    if (anchor.conflictCount) return { kind: 'conflicts', pending, count: anchor.conflictCount };
    return { kind: pending ? 'read-only' : 'unchanged', pending };
  }
  const { key, wrap } = session;
  const oldHead = await derive<RemoteHeadInfo>('sync:authenticate-head', [anchor.head, key, wrap]);
  check();
  const read = await client.get('head.bin', HEAD_LIMIT, forceHead || shouldCompact || pending || anchor.outbox || anchor.rotationFrom != null ? undefined : anchor.etag);
  if (!read) throw rejectHistory();
  let head = read === 'unchanged' ? { bytes: anchor.head, etag: anchor.etag } : read;
  const unchangedHead = sameBytes(head.bytes, anchor.head);
  let info = unchangedHead ? oldHead : await derive<RemoteHeadInfo>('sync:authenticate-head', [head.bytes, key, wrap]);
  check();
  if (info.keyEpoch < oldHead.keyEpoch || info.snapshotEpoch < oldHead.snapshotEpoch ||
      (info.snapshotEpoch === oldHead.snapshotEpoch &&
       (info.snapshotId !== oldHead.snapshotId || info.root.some((value, index) => oldHead.root[index] !== value))) ||
      (info.snapshotEpoch > oldHead.snapshotEpoch && !info.history.includes(oldHead.snapshotId))) throw rejectHistory();
  if (anchor.rotationFrom === info.keyEpoch && files.keyEpoch === info.keyEpoch + 1) {
    if (!writeVerified || !head.etag) return { kind: 'read-only', pending: true };
    const proposed = new Uint8Array(await derive<number[]>('sync:publish-wrap', [key, wrap, head.bytes, files.head]));
    check();
    if (!await client.put('head.bin', proposed, { match: head.etag })) return { kind: 'unchanged', pending: true };
    const confirmed = await client.get('head.bin', HEAD_LIMIT);
    if (!confirmed || confirmed === 'unchanged' || !sameBytes(confirmed.bytes, proposed)) throw requireUpdate();
    head = confirmed;
    info = await derive<RemoteHeadInfo>('sync:authenticate-head', [head.bytes, key, wrap]);
    check();
  }
  if (info.keyEpoch === files.keyEpoch && anchor.rotationFrom != null) {
    if (!await derive<boolean>('sync:same-wrap', [key, wrap, head.bytes, files.head])) {
      await options.commit({ ...anchor, observedKeyEpoch: info.keyEpoch, observedHead: head.bytes }, files, false);
      return { kind: 'key-update', epoch: info.keyEpoch, pending: true };
    }
  }
  if (info.keyEpoch > files.keyEpoch) {
    await options.commit({ ...anchor, observedKeyEpoch: info.keyEpoch, observedHead: head.bytes }, files, false);
    return { kind: 'key-update', epoch: info.keyEpoch, pending };
  }
  if (info.keyEpoch < files.keyEpoch) throw rejectHistory();
  let appliedHead = anchor.appliedHead;
  if (info.keyEpoch !== oldHead.keyEpoch) {
    appliedHead = new Uint8Array(await derive<number[]>('sync:rebase-wrap', [key, wrap, new Uint8Array(info.localHead), anchor.appliedHead, anchor.appliedSnap]));
    check();
  }
  const cache = anchor.objects;
  const snapChanged = info.snapshotId !== oldHead.snapshotId;
  const missing = cache.filter(({ id }) => !listed.has(id));
  let remoteSnap = anchor.snap;
  let history: RemoteWal[] = [];
  if (snapChanged) {
    const latest = await client.get(`${info.snapshotId}.bin`, SNAPSHOT_LIMIT);
    if (!latest || latest === 'unchanged') throw rejectHistory();
    remoteSnap = latest.bytes;
    history.push({ id: oldHead.snapshotId.slice(5), bytes: anchor.snap });
  }
  const remoteWals = await fetchRemoteWal(client, listing, cache);
  let outbox = anchor.outbox;
  const localHead = new Uint8Array(info.localHead);
  let fetchedHistory = false;
  async function replay(wal: RemoteWal[]) {
    const packed = packSyncFrames(wal);
    const decode = () => derive<ReplayOutput>('sync:replay', [key, wrap, localHead, remoteSnap, packed, packSyncFrames(history)]);
    try { return await decode(); }
    catch (error) {
      if (fetchedHistory || info.history.length <= 1 || !String(error).includes('SyncAncestorRequired')) throw error;
      check();
      fetchedHistory = true;
      history = await getSyncHistory(client, info, history);
      return decode();
    }
  }
  const remote = await replay(remoteWals);
  check();
  const absorbed = new Set(remote.included);
  if (missing.some(({ id }) => !absorbed.has(id))) throw rejectHistory();
  const realized = outbox && absorbed.has(outbox.id);
  if (realized) {
    const copy = remoteWals.find(({ id }) => id === outbox!.id);
    if (copy && !sameBytes(copy.bytes, outbox!.bytes)) throw rejectHistory();
  }
  const remoteView = fromOutput(remote);
  const cleanup = anchor.pendingCompaction;
  if (cleanup && writeVerified && head.etag) {
    if (!info.history.includes(`snap_${cleanup.id}`)) await cleanAbandonedSnapshot(client, cleanup.id, cleanup.digest);
    await cleanAbsorbedWal(client, remoteWals, remote.compacted);
    await cleanOldHistory(client, cleanup.priorHistory.filter(name => !info.history.includes(name)));
    check();
    anchor = { ...anchor, pendingCompaction: undefined };
  }
  const compactedIds = new Set(remote.compacted);
  const uncompacted = remoteWals.filter(({ id }) => !compactedIds.has(id));
  const resolutions = matchedReceipts(anchor.pendingResolutions, remote.receipts);
  const ready = (view: CipherState, conflicts: ReplayOutput, uploaded?: RemoteWal): RemoteAnchor => {
    const observed = uploaded ? [...remoteWals, uploaded].sort((a, b) => a.id < b.id ? -1 : 1) : remoteWals;
    return { ...anchor, head: head.bytes, snap: remoteSnap, etag: head.etag, objects: observed,
      appliedHead: view.head, appliedSnap: view.snap, hasRecords: anchor.hasRecords || remote.count > 0,
      outbox: undefined, pendingResolutions: undefined, checkedAt: Date.now(), conflicts: new Uint8Array(conflicts.conflicts), conflictCount: conflicts.conflictCount,
      rotationFrom: undefined, observedKeyEpoch: undefined, observedHead: undefined };
  };
  const nextFiles = (view: CipherState, count: number): VaultFiles => ({ ...files, ...view, updatedAtMs: Date.now(),
    everHadRecords: files.everHadRecords || count > 0 });
  if (!pending && !outbox && !anchor.conflictCount) {
    if (!remote.conflictCount && writeVerified && head.etag && options.compactWhenIdle && uncompacted.length > 0 &&
        (uncompacted.length >= 20 || uncompacted.reduce((size, object) => size + object.bytes.length, 0) > remoteSnap.length / 4) &&
        (remote.count > 0 || !anchor.hasRecords)) {
      const now = Date.now(), next = nextJournalVersion(clock, now, remote.hlc);
      const output = await derive<SnapshotOutput>('sync:compact', [key, wrap, head.bytes, remoteView.head, remoteView.snap, next.id, now - 30 * 86_400_000]);
      const nextSnap = new Uint8Array(output.snap);
      const reservation = { id: next.id, digest: await snapshotDigest(nextSnap), priorHistory: info.history };
      check();
      // Reserve the ID before sending it. Do not reuse it after an interrupted compaction.
      await options.commit({ ...ready(remoteView, remote), pendingCompaction: reservation }, nextFiles(remoteView, remote.count), false, next.state);
      const compacted = await publishSnapshot(client, next.id, head.etag, new Uint8Array(output.head), nextSnap);
      if (!compacted) return { kind: 'synced', pending: false };
      const latest = await derive<RemoteHeadInfo>('sync:authenticate-head', [compacted.bytes, key, wrap]);
      check();
      const view = { head: new Uint8Array(latest.localHead), snap: new Uint8Array(output.snap) };
      const current = { ...ready(view, remote), head: compacted.bytes, snap: view.snap, etag: compacted.etag, pendingCompaction: reservation };
      await options.commit(current, nextFiles(view, remote.count), false);
      await cleanAbsorbedWal(client, remoteWals, remote.included);
      await cleanOldHistory(client, info.history.filter(name => !latest.history.includes(name)));
      check();
      await options.commit({ ...current, pendingCompaction: undefined }, nextFiles(view, remote.count), false);
      return { kind: 'synced', pending: false };
    }
    const updated = directoryChanged || !unchangedHead;
    await options.commit(ready(remoteView, remote), updated ? nextFiles(remoteView, remote.count) : files, false);
    if (remote.conflictCount) return { kind: 'conflicts', pending: false, count: remote.conflictCount };
    return { kind: updated ? 'synced' : writeVerified ? 'unchanged' : 'read-only', pending: false };
  }

  const common = realized ? { head: outbox!.source.head, snap: outbox!.source.snap }
    : { head: appliedHead, snap: anchor.appliedSnap };
  if (realized && outbox!.source.keyEpoch !== files.keyEpoch) {
    common.head = new Uint8Array(await derive<number[]>('sync:rebase-wrap', [key, wrap, new Uint8Array(info.localHead), common.head, common.snap]));
    check();
  }
  const merged = await derive<ReplayOutput>('sync:reconcile', [key, wrap, common.head, common.snap,
    files.head, files.snap, remoteView.head, remoteView.snap, anchor.conflicts ?? new Uint8Array(),
    new Uint8Array(remote.conflicts), resolutions]);
  check();
  let mergedView = fromOutput(merged);
  const version = nextJournalVersion(clock, Date.now(), Math.max(remote.hlc, merged.hlc));
  if (clock && pending && !outbox && writeVerified) {
    const heartbeat = await derive<ReplayOutput>('sync:device-change', [key, wrap, mergedView.head, mergedView.snap,
      JSON.stringify({ id: clock.deviceId, tag: clock.tag, action: 'seen', time: Date.now() })]);
    check();
    mergedView = fromOutput(heartbeat);
  }

  const identicalDraft = outbox && !realized && sameBytes(files.snap, outbox.source.snap) &&
    unchangedHead && outbox.priorIds.length === listed.size && outbox.priorIds.every(id => listed.has(id));
  const id = identicalDraft ? outbox!.id : version.id;
  const delta = identicalDraft ? new Uint8Array(outbox!.bytes) : new Uint8Array(await derive<number[]>('sync:make-batch',
    [key, wrap, localHead, remoteSnap, remoteView.head, remoteView.snap, mergedView.head, mergedView.snap, id, version.state.deviceId, resolutions]));
  check();
  if (!delta.length) {
    await options.commit(ready(remoteView, merged), nextFiles(mergedView, merged.count), true);
    return merged.conflictCount ? { kind: 'conflicts', pending: false, count: merged.conflictCount } : { kind: 'synced', pending: false };
  }
  if (!writeVerified || !head.etag) {
    // Pull and merge while retaining unsent edits. An outstanding PUT with unknown
    // outcome keeps its original anchor until the immutable bytes can be confirmed.
    if (!outbox || realized) {
      await options.commit({ ...ready(remoteView, merged), pendingResolutions: resolutions },
        nextFiles(mergedView, merged.count), false);
    }
    return { kind: 'read-only', pending: true };
  }
  const hadRecords = anchor.hasRecords || files.everHadRecords === true || (files.backedUpChangeCount ?? 0) + files.changesSinceBackup > 0;
  const localCount = await derive<number>('sync:verify-snapshot', [key, wrap, files.head, files.snap]);
  check();
  if (localCount === 0 && (hadRecords || remote.count > 0)) return { kind: 'empty', pending: true };
  const guard = await derive<Verification>('sync:write-guard', [key, wrap, remoteView.head, remoteView.snap, mergedView.head, mergedView.snap, hadRecords]);
  check();
  if (guard.blocked) return { kind: 'empty', pending: true };
  if (guard.stamp && !await options.authorize(guard.stamp)) {
    return { kind: 'confirm-deletion', pending: true, before: guard.before, after: guard.after, removed: guard.removed, stamp: guard.stamp };
  }
  check();
  if (!identicalDraft) {
    const source = nextFiles(mergedView, merged.count);
    outbox = { id, bytes: delta, priorIds: [...listed], source };
    anchor = { ...ready(remoteView, merged), outbox, pendingResolutions: resolutions };
    await options.commit(anchor, source, false, version.state);
  }
  check();
  const name = `wal/${id}.bin`;
  let etag: string | undefined;
  await client.put(name, delta, { absent: true });
  // A lost response can leave this exact WAL on the server. Do not apply a stranger's bytes.
  const accepted = await client.get(name, WAL_LIMIT);
  if (!accepted || accepted === 'unchanged' || !sameBytes(accepted.bytes, delta)) throw rejectHistory();
  etag = accepted.etag;
  // Anchor the exact replay result, not the pre-append state used to generate the WAL.
  const appended: RemoteWal = { id, bytes: delta, etag };
  const final = await replay([...remoteWals, appended]);
  check();
  const view = fromOutput(final);
  const review = final.conflictCount ? await derive<ReplayOutput>('sync:reconcile', [key, wrap, mergedView.head, mergedView.snap,
    mergedView.head, mergedView.snap, view.head, view.snap, new Uint8Array(merged.conflicts), new Uint8Array(final.conflicts)]) : merged;
  check();
  await options.commit({ ...ready(view, review, appended), hasRecords: anchor.hasRecords || final.count > 0 },
    nextFiles(final.conflictCount ? fromOutput(review) : view, final.conflictCount ? review.count : final.count), true);
  return review.conflictCount ? { kind: 'conflicts', pending: false, count: review.conflictCount } : { kind: 'synced', pending: false };
}
