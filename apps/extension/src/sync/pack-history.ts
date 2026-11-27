import { derive } from '../bridge';
import type { SyncHistoryEntry, SyncRestorePreview } from '../vault-messages';
import type { RemoteAnchor, SessionState, VaultFiles } from '../vault-storage';
import type { ReplayOutput } from './bootstrap';
import { fromPackMerge, latestPackWrap, loadPackContent, packGraph, packGuard, storedPack } from './pack-sync';
import type { PackListing, PackTransport, PackVersion } from './pack-transport';
import type { PackView } from './pack-sync';
import { restorePackRules } from './pack-settings';

const changed = () => new Error('网盘或本机状态已变化，请先完成同步，再重新预览历史。');

function* mergedHistory(listing: PackListing) {
  const graph = packGraph(listing);
  let candidates = listing.tips;
  while (candidates.length) {
    const [first, ...rest] = candidates;
    const common = graph.ancestors([first!.id]);
    for (const branch of rest) {
      const other = graph.ancestors([branch.id]);
      for (const id of common) if (!other.has(id)) common.delete(id);
    }
    const parents = new Set([...common].flatMap(id => graph.byId.get(id)!.parents));
    const newest = [...common].filter(id => !parents.has(id)).sort()[0];
    if (!newest) break;
    const version = graph.byId.get(newest)!;
    yield version;
    candidates = version.parents.map(id => graph.byId.get(id)!);
  }
}

export async function wholeHistory(
  transport: PackTransport, material: Uint8Array<ArrayBuffer>, anchor: RemoteAnchor, session: SessionState, files: VaultFiles,
  writable: boolean, check: () => void, restored?: string,
) {
  const listing = await transport.list(material, files.vaultId, anchor.pack!.known);
  check();
  const wrap = await latestPackWrap(listing, session, files.vaultId);
  if (files.keyEpoch !== wrap.info.keyEpoch) throw changed();
  check();
  async function* recent() {
    let eligible = 0, inspected = 0;
    for (const version of mergedHistory(listing)) {
      const view = await loadPackContent(transport, material, version, session, files.keyEpoch, files.head, check);
      if (++inspected > 64) throw new Error('尚未完成裁决的历史太多，请先完成裁决再查看历史。');
      if (view.conflictCount || view.draftCount || view.ruleConflicts) continue;
      yield { version, view };
      if (++eligible === 5) return;
    }
  }
  async function list(): Promise<SyncHistoryEntry[]> {
    const entries: SyncHistoryEntry[] = [];
    const graph = packGraph(listing);
    for await (const { version, view: { count } } of recent()) {
      entries.push({ id: version.id, time: version.createdAt, count, current: listing.tips.length === 1 && listing.tips[0]?.id === version.id,
        epoch: graph.ancestors([version.id]).size });
    }
    return entries;
  }
  async function preview() {
    if (listing.tips.length !== 1 || listing.tips[0]!.id !== anchor.pack!.base ||
        anchor.pack!.dirty || anchor.pack!.outbox || anchor.rotationFrom) throw changed();
    let selected: { version: PackVersion; view: PackView } | undefined;
    for await (const candidate of recent()) if (candidate.version.id === restored) { selected = candidate; break; }
    if (!selected) throw changed();
    const { version: target, view: previous } = selected;
    const current = storedPack(files, anchor);
    const result = await derive<ReplayOutput>('sync:pack-restore', [session.key, session.wrap, files.head, files.snap,
      previous.head, previous.snap, current.conflicts, previous.conflicts]);
    check();
    const { rules, ruleConflicts } = await restorePackRules(session, current.rules, previous.rules);
    const view = { ...fromPackMerge(result, rules), ruleConflicts };
    const guard = await packGuard(session, current, view, anchor.hasRecords);
    check();
    const readOnly = !writable || !!anchor.localRestoreHeld;
    const binding = new TextEncoder().encode(JSON.stringify([listing.tips[0]!.id, target.id, target.sha256,
      readOnly, guard.stamp, guard.before, guard.after, guard.removed]));
    const stamp = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', binding)), byte => byte.toString(16).padStart(2, '0')).join('');
    const preview: SyncRestorePreview = { id: target.id, before: guard.before, after: guard.after, removed: guard.removed,
      blocked: guard.blocked, bulk: !!guard.stamp, stamp, readOnly };
    return { view, guard, preview };
  }
  return { list, preview };
}
