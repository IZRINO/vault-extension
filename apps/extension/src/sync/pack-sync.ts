import { derive } from '../bridge';
import type { RemoteAnchor, SessionState, VaultFiles } from '../vault-storage';
import type { RemoteHeadInfo, ReplayOutput } from './bootstrap';
import { openPackContent, sealPackContent, type PackContent } from './pack-content';
import { mergePackRules, openPackRules } from './pack-settings';
import { newPackVersionId, preparePackVersion, sameVersion, type PackListing, type PackTransport, type PackVersion } from './pack-transport';
import type { SyncResult } from './run';

export interface WholePackState {
  base: string;
  known: PackVersion[];
  dirty: boolean;
  /** The most recent sync check failed. Never persist untrusted remote error text. */
  checkFailed?: boolean;
  siteRules: 'pending' | 'applied' | 'skipped';
  baseRules: Uint8Array;
  baseConflicts: Uint8Array;
  ruleConflicts?: number;
  /** Remote branches already composed on this read-only device. */
  integrated?: string[];
  outbox?: { version: PackVersion; ciphertext: Uint8Array<ArrayBuffer> };
}

export interface PackView extends PackContent { count: number; conflictCount: number; draftCount: number; ruleConflicts?: number }
type Counts = Pick<PackView, 'count' | 'conflictCount' | 'draftCount'>;
export type PackGuard = { before: number; after: number; removed: number; stamp: string; blocked: boolean };
type PackSyncTransport = Pick<PackTransport, 'list' | 'download' | 'publish'>;
const missingBase = () => new Error('没有可验证的共同版本。本机编辑仍保留，请先恢复可信的同步历史。');
const invalidWrap = () => new Error('远端主密码包装存在分歧，请重新验证。本机编辑仍保留。');
const nothing = new Uint8Array();
export const equalPackBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, i) => value === b[i]);

export function hasPendingPackWork(anchor: RemoteAnchor) {
  const state = anchor.pack!;
  if (state.dirty || state.outbox || state.integrated?.length || state.ruleConflicts || state.checkFailed ||
      anchor.conflictCount || anchor.draftCount || anchor.observedHead) return true;
  // The acknowledged local publication is only settled if it is the sole known tip.
  const parents = new Set(state.known.flatMap(version => version.parents));
  return state.known.some(version => version.id !== state.base && !parents.has(version.id));
}

export async function packMaterial(session: SessionState) {
  const raw = await derive<number[]>('sync-pack-material', [session.key, session.wrap]);
  try { return new Uint8Array(raw); }
  finally { raw.fill(0); }
}

export function storedPack(files: VaultFiles, anchor: RemoteAnchor): PackContent {
  if (!files.packRules?.length) throw missingBase();
  return { head: files.head, snap: files.snap, conflicts: anchor.conflicts ?? nothing, rules: files.packRules };
}

export async function inspectPack(session: SessionState, content: PackContent): Promise<PackView> {
  const counts = await derive<Counts>('sync:pack-inspect', [session.key, session.wrap, content.head, content.snap, content.conflicts]);
  const rules = await openPackRules(session, content.rules);
  return { ...content, ...counts, ruleConflicts: rules.domainConflicts?.length ?? 0 };
}

export function fromPackMerge(output: ReplayOutput, rules: Uint8Array): PackView {
  return { head: new Uint8Array(output.head), snap: new Uint8Array(output.snap), conflicts: new Uint8Array(output.conflicts), rules,
    count: output.count, conflictCount: output.conflictCount, draftCount: output.draftCount };
}

export async function loadPackContent(
  transport: Pick<PackTransport, 'download'>, material: Uint8Array<ArrayBuffer>, version: PackVersion,
  session: SessionState, keyEpoch: number, currentHead: Uint8Array, check: () => void,
): Promise<PackView> {
  const cipher = await transport.download(version);
  const content = await openPackContent(material, version, cipher);
  check();
  if (version.keyEpoch !== keyEpoch) {
    content.head = new Uint8Array(await derive<number[]>('sync:rebase-wrap', [
      session.key, session.wrap, currentHead, content.head, content.snap,
    ]));
  }
  check();
  const view = await inspectPack(session, content);
  check();
  return view;
}

export async function latestPackWrap(listing: PackListing, session: SessionState, vaultId: string) {
  const records = [listing.root, ...listing.versions].filter(record => !!record.head);
  const keyEpoch = Math.max(...records.map(record => record.keyEpoch));
  const heads = records.filter(record => record.keyEpoch === keyEpoch);
  const head = heads[0]?.head;
  if (!head || heads.some(record => !equalPackBytes(record.head!, head))) throw invalidWrap();
  const info = await derive<RemoteHeadInfo>('sync:authenticate-head', [head, session.key, session.wrap]);
  if (info.vaultId !== vaultId || info.keyEpoch !== keyEpoch) throw invalidWrap();
  return { head, info };
}

type Graph = ReturnType<typeof packGraph>;
export function packGraph(listing: PackListing) {
  const versions = [listing.root, ...listing.versions];
  const byId = new Map(versions.map(version => [version.id, version]));
  const ancestors = (ids: readonly string[]) => {
    const result = new Set<string>(), next = [...ids];
    while (next.length) {
      const id = next.pop()!;
      if (result.has(id)) continue;
      const version = byId.get(id);
      if (!version) throw missingBase();
      result.add(id);
      for (const parent of version.parents) next.push(parent);
    }
    return result;
  };
  return { versions: [...byId.values()], byId, ancestors };
}

function commonVersions(graph: Graph, left: readonly string[], right: string): string[] {
  const rightAncestors = graph.ancestors([right]);
  const common = new Set([...graph.ancestors(left)].filter(id => rightAncestors.has(id)));
  const parents = new Set<string>();
  for (const id of common) for (const parent of graph.byId.get(id)!.parents) parents.add(parent);
  const nearest = [...common].filter(candidate => !parents.has(candidate)).sort();
  if (!nearest.length) throw missingBase();
  return nearest;
}

export async function combinePacks(
  listing: PackListing, initial: PackView, baseId: string, branches: readonly PackVersion[],
  load: (version: PackVersion) => Promise<PackView>, session: SessionState, check: () => void, device?: string, integrated: readonly string[] = [],
) {
  const graph = packGraph(listing);
  const virtual = new Map<string, Promise<PackView>>();
  async function commonBase(parents: readonly string[], branch: string): Promise<PackView> {
    const ids = commonVersions(graph, parents, branch);
    if (ids.length === 1) return load(graph.byId.get(ids[0]!)!);
    const key = ids.join(',');
    const memo = virtual.get(key);
    if (memo) return memo;
    if (virtual.size >= 64) throw missingBase();
    const [first, ...rest] = ids.map(id => graph.byId.get(id)!);
    const calculated = load(first!).then(async firstView => {
      const view = await fold(firstView, [first!.id], rest);
      if (view.conflictCount || view.draftCount || view.ruleConflicts) throw missingBase();
      return view;
    });
    virtual.set(key, calculated);
    return calculated;
  }
  async function fold(start: PackView, parents: string[], versions: readonly PackVersion[], device?: string) {
    let view = start;
    for (const branch of versions) {
      if (graph.ancestors(parents).has(branch.id)) continue;
      const [common, remote] = await Promise.all([commonBase(parents, branch.id), load(branch)]);
      view = await mergePackViews(session, common, view, remote, check, device);
      parents.push(branch.id);
    }
    return view;
  }
  // Two clients can independently merge the same fork. Reconstruct all nearest
  // common versions so a later edit that restores an older value is still an edit.
  return fold(initial, [baseId, ...integrated], [...branches].sort((a, b) => a.id.localeCompare(b.id)), device);
}

async function mergePackViews(session: SessionState, base: PackContent, local: PackContent, remote: PackContent, check: () => void, device?: string) {
  const rules = equalPackBytes(local.rules, remote.rules) || equalPackBytes(base.rules, remote.rules) ? local.rules
    : equalPackBytes(base.rules, local.rules) ? remote.rules : await mergePackRules(session, base.rules, local.rules, remote.rules);
  check();
  const result = await derive<ReplayOutput>('sync:pack-merge', [session.key, session.wrap,
    base.head, base.snap, local.head, local.snap, remote.head, remote.snap, base.conflicts, local.conflicts, remote.conflicts, device]);
  const options = await openPackRules(session, rules);
  check();
  return { ...fromPackMerge(result, rules), ruleConflicts: options.domainConflicts?.length ?? 0 };
}

export function applyPackFiles(files: VaultFiles, view: PackView): VaultFiles {
  return { ...files, head: view.head, snap: view.snap, packRules: view.rules, updatedAtMs: Date.now(),
    everHadRecords: files.everHadRecords || view.count > 0 };
}

export function applyPackView(anchor: RemoteAnchor, view: PackView): RemoteAnchor {
  return { ...anchor, conflicts: view.conflicts, conflictCount: view.conflictCount, draftCount: view.draftCount,
    ...(anchor.pack && view.ruleConflicts !== undefined && { pack: { ...anchor.pack, ruleConflicts: view.ruleConflicts } }),
    hasRecords: anchor.hasRecords || view.count > 0 };
}

export function confirmedPack(
  anchor: RemoteAnchor, listing: PackListing, version: PackVersion, view: PackView, wrap: Uint8Array, dirty = false,
): RemoteAnchor {
  return { ...anchor, head: wrap, appliedHead: view.head, appliedSnap: view.snap,
    pack: { ...anchor.pack!, base: version.id, known: packGraph(listing).versions, dirty, baseRules: view.rules,
      baseConflicts: view.conflicts, outbox: undefined, integrated: undefined }, checkedAt: Date.now(),
    rotationFrom: undefined, observedHead: undefined, observedKeyEpoch: undefined };
}

export function newPackAnchor(
  endpoint: string, listing: PackListing, version: PackVersion, view: PackView, wrap: Uint8Array, siteRules: WholePackState['siteRules'],
) {
  const pack = { base: version.id, known: packGraph(listing).versions, dirty: false, siteRules,
    baseRules: view.rules, baseConflicts: view.conflicts };
  return applyPackView({ vaultId: version.vaultId, endpoint, head: wrap, snap: nothing, objects: [],
    appliedHead: view.head, appliedSnap: view.snap, checkedAt: Date.now(), hasRecords: false, pack }, view);
}

export function packGuard(session: SessionState, before: PackContent, after: PackContent, hadRecords: boolean) {
  return derive<PackGuard>('sync:write-guard', [session.key, session.wrap, before.head, before.snap, after.head, after.snap, hadRecords]);
}

interface WholeSyncOptions {
  files: VaultFiles;
  session: SessionState;
  anchor: RemoteAnchor;
  transport: PackSyncTransport;
  material: Uint8Array<ArrayBuffer>;
  writable: boolean;
  device?: string;
  check(): void;
  commit(anchor: RemoteAnchor, files: VaultFiles): Promise<void>;
  authorize(stamp: string): Promise<boolean>;
}

export async function runWholeSync(options: WholeSyncOptions): Promise<SyncResult> {
  const { files, session, transport, material, check, writable } = options;
  let anchor = options.anchor;
  let state = anchor.pack!;
  let listing = await transport.list(material, files.vaultId, state.known);
  check();
  const discovered = packGraph(listing).versions;
  if (discovered.length !== state.known.length || discovered.some(record =>
    state.known.find(known => known.id === record.id)?.recordAuth?.etag !== record.recordAuth?.etag)) {
    state = { ...state, known: discovered };
    anchor = { ...anchor, pack: state };
    await options.commit(anchor, files);
    check();
  }
  const wrap = await latestPackWrap(listing, session, files.vaultId);
  check();
  const pending = state.dirty || !!state.outbox;
  if (wrap.info.keyEpoch > files.keyEpoch) {
    await options.commit({ ...anchor, observedHead: wrap.head, observedKeyEpoch: wrap.info.keyEpoch }, files);
    return { kind: 'key-update', epoch: wrap.info.keyEpoch, pending };
  }
  if (wrap.info.keyEpoch < files.keyEpoch && anchor.rotationFrom !== wrap.info.keyEpoch) throw invalidWrap();
  if (wrap.info.keyEpoch === files.keyEpoch && !equalPackBytes(wrap.head, anchor.head) &&
      !await derive<boolean>('sync:same-wrap', [session.key, session.wrap, wrap.head, files.head])) {
    await options.commit({ ...anchor, observedHead: wrap.head, observedKeyEpoch: wrap.info.keyEpoch }, files);
    return { kind: 'key-update', epoch: wrap.info.keyEpoch, pending };
  }
  if (state.outbox) {
    const { version, ciphertext } = state.outbox;
    const found = packGraph(listing).byId.get(version.id);
    if (!found) {
      if (!writable) return { kind: 'read-only', pending: true };
      await transport.publish(material, version, ciphertext);
      listing = await transport.list(material, files.vaultId, [...state.known, version]);
      check();
    } else {
      if (!sameVersion(found, version)) throw missingBase();
      await transport.download(found);
      check();
    }
    const staged = await openPackContent(material, version, ciphertext);
    if (version.keyEpoch !== files.keyEpoch) staged.head = new Uint8Array(await derive<number[]>('sync:rebase-wrap',
      [session.key, session.wrap, files.head, staged.head, staged.snap]));
    check();
    const clean = !state.dirty && listing.tips.length === 1 && listing.tips[0]!.id === version.id;
    const activeWrap = version.head && version.keyEpoch >= wrap.info.keyEpoch ? version.head : wrap.head;
    const confirmed = confirmedPack(anchor, listing, version, await inspectPack(session, staged), activeWrap, state.dirty);
    await options.commit(confirmed, files);
    if (!clean) return { kind: 'deferred', pending: true };
    return settled(confirmed, 'synced');
  }

  const graph = packGraph(listing);
  const base = graph.byId.get(state.base);
  if (!base) throw missingBase();
  const [tip] = listing.tips;
  const one = listing.tips.length === 1 && tip;
  if (one && one.id === base.id && !state.dirty) return settled(anchor, 'unchanged');
  if (anchor.localRestoreHeld) return { kind: 'read-only', pending: true };
  const tipIds = listing.tips.map(version => version.id).sort();
  if (!writable && (state.dirty || state.integrated?.join(',') === tipIds.join(','))) {
    return settled(anchor, 'read-only', true);
  }

  const cached = new Map<string, Promise<PackView>>();
  const load = (version: PackVersion): Promise<PackView> => {
    let promise = cached.get(version.id);
    if (!promise) {
      promise = loadPackContent(transport, material, version, session, files.keyEpoch, files.head, check);
      cached.set(version.id, promise);
    }
    return promise;
  };
  const local = storedPack(files, anchor);
  if (one && !state.dirty && graph.ancestors([one.id]).has(base.id)) {
    const view = await load(one);
    if (!view.count && anchor.hasRecords) return { kind: 'empty', pending: true };
    const next = applyPackView(confirmedPack(anchor, listing, one, view, wrap.head), view);
    await options.commit(next, applyPackFiles(files, view));
    return settled(next, 'synced');
  }
  const prior: PackContent = { head: anchor.appliedHead, snap: anchor.appliedSnap, rules: state.baseRules, conflicts: state.baseConflicts };
  if (base.keyEpoch !== files.keyEpoch) prior.head = new Uint8Array(await derive<number[]>('sync:rebase-wrap',
    [session.key, session.wrap, files.head, prior.head, prior.snap]));
  check();
  const previous = await inspectPack(session, prior);
  cached.set(base.id, Promise.resolve(previous));
  // Normalize local hard deletions even if the only remote tip is unchanged.
  const tracked = state.dirty || state.integrated?.length
    ? await mergePackViews(session, prior, local, prior, check, options.device) : previous;
  const view = await combinePacks(listing, tracked, base.id, listing.tips, load, session, check, options.device, state.integrated);
  if (!writable) {
    if (!view.count && anchor.hasRecords) return { kind: 'empty', pending: true };
    const next = applyPackView({ ...anchor, pack: { ...state, known: graph.versions, integrated: tipIds } }, view);
    await options.commit(next, applyPackFiles(files, view));
    return settled(next, 'read-only', true);
  }
  const guard = await packGuard(session, prior, view, anchor.hasRecords || files.everHadRecords === true);
  check();
  if (guard.blocked) return { kind: 'empty', pending: true };
  if (guard.stamp && !await options.authorize(guard.stamp))
    return { kind: 'confirm-deletion', pending: true, before: guard.before, after: guard.after, removed: guard.removed, stamp: guard.stamp };

  const head = wrap.info.keyEpoch < files.keyEpoch
    ? new Uint8Array(await derive<number[]>('sync:publish-wrap', [session.key, session.wrap, wrap.head, files.head])) : undefined;
  check();
  const identity = { id: newPackVersionId(), vaultId: files.vaultId };
  const ciphertext = await sealPackContent(material, identity, view);
  const version = await preparePackVersion({ ...identity, packageEncoding: listing.root.packageEncoding,
    parents: tipIds, keyEpoch: files.keyEpoch, createdAt: Date.now(), head }, ciphertext);
  check();
  const ready = applyPackView({ ...anchor, pack: { ...state, known: graph.versions, dirty: false, outbox: { version, ciphertext } } }, view);
  const nextFiles = applyPackFiles(files, view);
  await options.commit(ready, nextFiles);
  check();
  await transport.publish(material, version, ciphertext);
  const verified = await transport.list(material, files.vaultId, [...graph.versions, version]);
  check();
  const done = confirmedPack(ready, verified, version, view, version.head ?? wrap.head);
  await options.commit(done, nextFiles);
  return verified.tips.length === 1 && verified.tips[0]!.id === version.id ? settled(done, 'synced') : { kind: 'deferred', pending: true };
}

function settled(anchor: RemoteAnchor, kind: 'synced' | 'unchanged' | 'read-only', pending = false): SyncResult {
  const count = (anchor.conflictCount ?? 0) + (anchor.pack?.ruleConflicts ?? 0);
  if (count) return { kind: 'conflicts', count, pending: true };
  return { kind, pending: pending || !!anchor.draftCount };
}
