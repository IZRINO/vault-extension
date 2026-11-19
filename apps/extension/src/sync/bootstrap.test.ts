import { beforeAll, describe, expect, it, vi } from 'vitest';
import { readFile } from 'node:fs/promises';
import initCore, * as core from '../../../../crates/vault-core/pkg/vault_core.js';
import initSync, * as wasm from '../../../../crates/vault-sync/pkg/vault_sync.js';
import type { RemoteAnchor, SessionState, VaultFiles } from '../vault-storage';
import { createRemoteVault, endpointFingerprint, packSyncFrames, readRemoteVault } from './bootstrap';
import { nextJournalVersion, type JournalClock } from './journal-device';
import { runDavSync } from './run';
import { prepareRestore, restoreHistoryLocally } from './history';
import { WebDavClient, webDavConfig } from './webdav';

function decoded(head: wasm.RemoteHead) {
  try {
    return { localHead: Array.from(head.local_head), wrap: Array.from(head.session_wrap), vaultId: head.vault_id,
      keyEpoch: head.key_epoch, snapshotId: head.snapshot_id, snapshotEpoch: head.snapshot_epoch, root: Array.from(head.root),
      history: Array.from({ length: 5 }, (_, i) => head.history_id(i)).filter((value): value is string => !!value) };
  } finally { head.free(); }
}
function replayed(replay: wasm.Replayed) {
  try { return { head: Array.from(replay.head), snap: Array.from(replay.snap), hlc: replay.hlc, count: replay.count,
    included: replay.included ? replay.included.split('\n') : [], conflicts: Array.from(replay.conflicts), conflictCount: replay.conflict_count,
    receipts: Array.from(replay.receipts), compacted: replay.compacted ? replay.compacted.split('\n') : [] }; }
  finally { replay.free(); }
}
vi.mock('../bridge', () => ({ derive: async (op: string, args: unknown[]) => {
  switch (op) {
    case 'sync:authenticate-head': return decoded(wasm.wasm_sync_authenticate_head(...args as Parameters<typeof wasm.wasm_sync_authenticate_head>));
    case 'sync:replay': return replayed(wasm.wasm_sync_replay(...args as Parameters<typeof wasm.wasm_sync_replay>));
    case 'sync:reconcile': return replayed(wasm.wasm_sync_reconcile(...args as Parameters<typeof wasm.wasm_sync_reconcile>));
    case 'sync:make-batch': return Array.from(wasm.wasm_sync_make_batch(...args as Parameters<typeof wasm.wasm_sync_make_batch>));
    case 'sync:device-change': return replayed(wasm.wasm_sync_device_change(...args as Parameters<typeof wasm.wasm_sync_device_change>));
    case 'sync:restore-content': return replayed(wasm.wasm_sync_restore_content(...args as Parameters<typeof wasm.wasm_sync_restore_content>));
    case 'sync:compact': {
      const out = wasm.wasm_sync_compact(...args as Parameters<typeof wasm.wasm_sync_compact>);
      try { return { head: Array.from(out.head), snap: Array.from(out.snap), root: Array.from(out.root) }; }
      finally { out.free(); }
    }
    case 'sync:publish-wrap': return Array.from(wasm.wasm_sync_publish_wrap(...args as Parameters<typeof wasm.wasm_sync_publish_wrap>));
    case 'sync:rebase-wrap': return Array.from(wasm.wasm_sync_rebase_wrap(...args as Parameters<typeof wasm.wasm_sync_rebase_wrap>));
    case 'sync:same-wrap': return wasm.wasm_sync_same_wrap(...args as Parameters<typeof wasm.wasm_sync_same_wrap>);
    case 'sync:verify-snapshot': return wasm.wasm_sync_verify_snapshot(...args as Parameters<typeof wasm.wasm_sync_verify_snapshot>);
    case 'sync:write-guard': {
      const out = wasm.wasm_sync_write_guard(...args as Parameters<typeof wasm.wasm_sync_write_guard>);
      try { return { stamp: out.stamp, before: out.before, after: out.after, removed: out.removed, blocked: out.blocked }; }
      finally { out.free(); }
    }
    default: throw new Error(`Unrecognized sync operation ${op}`);
  }
} }));

const config = webDavConfig({ provider: 'custom', base: 'https://dav.example/dav/', folder: 'vault',
  username: 'synthetic-user', password: 'fixture-password' });
const snapshot = 'snap_000000000000aa_abc01234_00000000000001';
const bytes = (value: number) => new Uint8Array([value]);

function server(honor = true, acceptStaleMethod?: 'PUT' | 'DELETE') {
  const folders = new Set(['/dav/scratch/']);
  const objects = new Map<string, { bytes: Uint8Array<ArrayBuffer>; tag: string }>();
  const requests: { method: string; path: string; headers: Headers }[] = [];
  const issuedTags = new Set<string>();
  let generation = 0;
  const row = (name: string, collection: boolean) => {
    const obj = objects.get(name);
    return `<D:response><D:href>${name}</D:href><D:propstat><D:prop><D:resourcetype>${collection ? '<D:collection/>' : ''}</D:resourcetype>` +
      `${obj ? `<D:getetag>${obj.tag}</D:getetag><D:getcontentlength>${obj.bytes.length}</D:getcontentlength>` : ''}` +
      '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
  };
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname;
    const headers = new Headers(init?.headers);
    const method = init?.method ?? 'GET';
    requests.push({ method, path, headers });
    const found = objects.get(path);
    if (method === 'PROPFIND') {
      if (!folders.has(path)) return new Response(null, { status: 404 });
      const entries = [...folders].filter(name => name !== path && name.startsWith(path) &&
        !name.slice(path.length, -1).includes('/')).map(name => row(name, true));
      entries.push(...[...objects.keys()].filter(name => name.startsWith(path) &&
        !name.slice(path.length).includes('/')).map(name => row(name, false)));
      return new Response(`<D:multistatus xmlns:D="DAV:">${row(path, true)}${entries.join('')}</D:multistatus>`, { status: 207 });
    }
    if (method === 'MKCOL') {
      if (folders.has(path)) return new Response(null, { status: 405 });
      folders.add(path);
      return new Response(null, { status: 201 });
    }
    if (method === 'GET') {
      if (!found) return new Response(null, { status: 404 });
      if (found.tag === headers.get('If-None-Match')) return new Response(null, { status: 304 });
      return new Response(found.bytes, { headers: { ETag: found.tag } });
    }
    const match = headers.get('If-Match');
    if (honor && (match && match !== found?.tag && !(method === acceptStaleMethod && issuedTags.has(match)) ||
        headers.get('If-None-Match') === '*' && found)) return new Response(null, { status: 412 });
    if (method === 'DELETE') { objects.delete(path); return new Response(null, { status: 204 }); }
    if (method === 'PUT' && init?.body instanceof Uint8Array) {
      const tag = `"v${++generation}"`;
      issuedTags.add(tag);
      objects.set(path, { bytes: new Uint8Array(init.body), tag });
      return new Response(null, { status: 201 });
    }
    throw new Error('Unexpected mock operation');
  };
  return { fetcher, objects, folders, requests };
}

describe('first WebDAV vault', () => {
  it('only creates objects below the selected child after conditional write proof, not in the account root', async () => {
    const dav = server();
    const create = () => Promise.resolve({ snapshotId: snapshot, head: bytes(11), snap: bytes(22) });
    const result = await createRemoteVault(config, 'scratch', {}, create, dav.fetcher);
    expect(result.head.bytes).toEqual(bytes(11));
    expect([...dav.objects.keys()].sort()).toEqual(['/dav/vault/head.bin', `/dav/vault/${snapshot}.bin`].sort());
    expect(dav.folders.has('/dav/vault/wal/')).toBe(true);
    const firstNewObject = dav.requests.findIndex(row => row.path.startsWith('/dav/vault/') && row.method !== 'PROPFIND');
    expect(dav.requests.slice(0, firstNewObject).some(row => row.path.startsWith('/dav/scratch/verify_') && row.method === 'DELETE')).toBe(true);
    expect(dav.requests.filter(row => row.method === 'PUT' && row.path.endsWith('/head.bin'))[0]?.headers.get('If-None-Match')).toBe('*');
    await expect(createRemoteVault(config, 'scratch', {}, create, dav.fetcher)).rejects.toThrow('已有');
    expect(dav.objects.get('/dav/vault/head.bin')?.bytes).toEqual(bytes(11));
  });

  it('does not create a collection on servers that return ETags but ignore stale conditions', async () => {
    const dav = server(false);
    await expect(createRemoteVault(config, 'scratch', {}, async () => ({
      snapshotId: snapshot, head: bytes(1), snap: bytes(2),
    }), dav.fetcher)).rejects.toThrow('条件写');
    expect(dav.requests.filter(row => row.path.startsWith('/dav/vault/') && row.method !== 'PROPFIND')).toEqual([]);
    expect(dav.folders.has('/dav/vault/')).toBe(false);
  });

  it.each(['PUT', 'DELETE'] as const)('requires the scratch server to reject an actually stale ETag for %s', async method => {
    const dav = server(true, method);
    await expect(createRemoteVault(config, 'scratch', {}, async () => ({
      snapshotId: snapshot, head: bytes(1), snap: bytes(2),
    }), dav.fetcher)).rejects.toThrow('条件写');
    expect(dav.requests.filter(row => row.path.startsWith('/dav/vault/') && row.method !== 'PROPFIND')).toEqual([]);
    expect(dav.folders.has('/dav/vault/')).toBe(false);
  });

  it('refuses to claim a partially initialized collection', async () => {
    const dav = server();
    dav.folders.add('/dav/vault/');
    dav.folders.add('/dav/vault/wal/');
    await expect(createRemoteVault(config, 'scratch', {}, async () => {
      throw new Error('must not construct vault');
    }, dav.fetcher)).rejects.toThrow('已有');
    expect(dav.requests.map(row => row.method)).toEqual(['PROPFIND']);
  });

  it('allows only one of two in-flight heads to claim the same empty directory', async () => {
    const dav = server();
    dav.folders.add('/dav/vault/');
    dav.folders.add('/dav/other-scratch/');
    const reached = Promise.withResolvers<void>();
    let offers = 0;
    const request: typeof fetch = async (input, init) => {
      if (String(input).endsWith('/vault/head.bin') && init?.method === 'PUT') {
        if (++offers === 2) reached.resolve();
        await reached.promise;
      }
      return dav.fetcher(input, init);
    };
    const concurrent = await Promise.allSettled([1, 2].map((n, index) => createRemoteVault(config, index ? 'other-scratch' : 'scratch', {},
      async () => ({ snapshotId: snapshot.slice(0, -1) + n, head: bytes(n), snap: bytes(n) }), request)));
    expect(concurrent.filter(output => output.status === 'fulfilled')).toHaveLength(1);
    expect(dav.requests.filter(row => row.method === 'PUT' && row.path.endsWith('/head.bin'))).toHaveLength(2);
    expect(dav.objects.size).toBe(2);
    const accepted = concurrent.find(result => result.status === 'fulfilled');
    expect(dav.objects.get('/dav/vault/head.bin')?.bytes).toEqual(accepted?.value.head.bytes);
  });
});

const master = 'test-only-original-master';
const newKey = () => crypto.getRandomValues(new Uint8Array(32));
const session = (key: Uint8Array, wrap: Uint8Array): SessionState => ({ key, wrap, unlockedAtMs: 1, lastActivityMs: 1 });
const files = (head: Uint8Array, snap: Uint8Array, vaultId: string, keyEpoch: number): VaultFiles =>
  ({ head, snap, vaultId, keyEpoch, updatedAtMs: 1, changesSinceBackup: 0 });

async function setup() {
  const dav = server();
  const key = newKey();
  const created = core.wasm_create_new_vault(master, 32768, 2, 1, key, 1000);
  const primary = session(key, created.session_wrap_bytes);
  const version = nextJournalVersion(undefined, 1000);
  const output = wasm.wasm_sync_create_genesis(key, primary.wrap, created.head_bytes, created.snap_bytes, version.id);
  const genesis = await createRemoteVault(config, 'scratch', {}, async () => ({
    snapshotId: `snap_${version.id}`, head: new Uint8Array(output.head), snap: new Uint8Array(output.snap),
  }), dav.fetcher);
  const recovery = created.recovery_code;
  output.free(); created.free();
  const endpoint = await endpointFingerprint(config.url);
  const open = async (method: 'master' | 'recovery' = 'recovery', secret = method === 'master' ? master : recovery) => {
    const key = newKey();
    const results = await readRemoteVault(new WebDavClient(config, {}, dav.fetcher),
      object => Promise.resolve(decoded(wasm.wasm_sync_unlock_head(object.bytes, key, secret, method === 'recovery'))),
      (head, snap, wal, history) => Promise.resolve(replayed(wasm.wasm_sync_replay(key, new Uint8Array(head.wrap),
        new Uint8Array(head.localHead), snap, packSyncFrames(wal), packSyncFrames(history)))));
    const { authenticated, head, snap, result, objects } = results;
    const anchor: RemoteAnchor = { vaultId: authenticated.vaultId, endpoint, head: head.bytes, snap: snap.bytes, etag: head.etag,
      objects, appliedHead: new Uint8Array(result.head), appliedSnap: new Uint8Array(result.snap), hasRecords: result.count > 0,
      checkedAt: Date.now() };
    return {
      files: files(new Uint8Array(result.head), new Uint8Array(result.snap), authenticated.vaultId, authenticated.keyEpoch),
      session: session(key, new Uint8Array(authenticated.wrap)),
      anchor,
      pending: false, clock: undefined as JournalClock | undefined,
    };
  };
  return { dav, genesis, recovery, open };
}

type Side = Awaited<ReturnType<Awaited<ReturnType<typeof setup>>['open']>>;
type Edit = { id?: string; title: string; note?: string; data: { kind: 'login'; password: string; passwordHistory?: { password: string }[] } };
function put(local: Side, item: Edit) {
  const engine = new core.WasmVaultEngine();
  try {
    engine.restore_from_session(local.session.key, local.session.wrap, local.files.head, local.files.snap);
    const edit = engine.upsert_item_json(JSON.stringify(item), Date.now(), 'fixture');
    try { local.files = { ...local.files, head: edit.head_bytes, snap: edit.snap_bytes, changesSinceBackup: local.files.changesSinceBackup + 1 }; }
    finally { edit.free(); }
    local.pending = true;
  } finally { engine.free(); }
}
const add = (local: Side, title: string) => put(local, { title, data: { kind: 'login', password: 'fixture secret' } });
function records(local: Side) {
  const engine = new core.WasmVaultEngine();
  try {
    engine.restore_from_session(local.session.key, local.session.wrap, local.files.head, local.files.snap);
    return (JSON.parse(engine.list_summaries_json()) as { id: string }[]).map(item => JSON.parse(engine.get_item_json(item.id, true)) as Edit);
  } finally { engine.free(); }
}
const titles = (local: Side) => records(local).map(item => item.title);
const sync = (local: Side, request: typeof fetch, extras: { write?: boolean; idle?: boolean; signal?: AbortSignal; force?: boolean } = {}) =>
  runDavSync({ ...config, writeVerified: extras.write ?? true }, {
    ...local, forceHead: !!extras.force, compactWhenIdle: !!extras.idle, context: { signal: extras.signal }, authorize: async () => false,
    commit: async (anchor, files, consume, clock) => {
      local.anchor = structuredClone(anchor); local.files = structuredClone(files);
      if (clock) local.clock = structuredClone(clock);
      if (consume) local.pending = false;
    },
  }, request);

describe('WebDAV sync with the real Wasm codec', () => {
  beforeAll(async () => {
    await initCore({ module_or_path: await readFile(new URL('../../../../crates/vault-core/pkg/vault_core_bg.wasm', import.meta.url)) });
    await initSync({ module_or_path: await readFile(new URL('../../../../crates/vault-sync/pkg/vault_sync_bg.wasm', import.meta.url)) });
  });

  it('resumes a committed upload after lock and lets a second install verify it without authorizing writes', async () => {
    const { dav, open } = await setup();
    const a = await open('master');
    const b = await open();
    await expect(open('master', 'wrong-file-only-password')).rejects.toBeDefined();
    add(a, 'First offline edit');
    add(a, 'Second offline edit');
    const lock = new AbortController();
    const walPuts = () => dav.requests.filter(r => r.method === 'PUT' && r.path.startsWith('/dav/vault/wal/'));
    const loseResponse: typeof fetch = async (input, init) => {
      const result = await dav.fetcher(input, init);
      if (init?.method === 'PUT' && new URL(String(input)).pathname.includes('/wal/')) lock.abort();
      return result;
    };
    await expect(sync(a, loseResponse, { signal: lock.signal })).rejects.toThrow('已锁定');
    expect(walPuts()).toHaveLength(1);
    expect(dav.requests.at(-1)?.method).toBe('PUT');
    expect(a.anchor.outbox?.id).toBeTruthy();
    expect(a.pending).toBe(true);
    await expect(sync(b, dav.fetcher, { write: false })).resolves.toMatchObject({ kind: 'synced', pending: false });
    expect(titles(b)).toEqual(expect.arrayContaining(['First offline edit', 'Second offline edit']));
    const recoveredAfterUpload = await open();
    expect(recoveredAfterUpload.files.vaultId).toBe(a.files.vaultId);
    expect(titles(recoveredAfterUpload).sort()).toEqual(titles(b).sort());
    const restarted = structuredClone(a);
    await expect(sync(restarted, dav.fetcher)).resolves.toMatchObject({ kind: 'synced', pending: false });
    expect(restarted.anchor.outbox).toBeUndefined();
    expect(walPuts()).toHaveLength(1);
    const last = dav.requests.length;
    await sync(b, dav.fetcher, { write: false });
    expect(dav.requests.slice(last).map(row => row.method)).toEqual(['PROPFIND']);
  });

  it('stores a conflicted credential encrypted, publishes unrelated edits and converges after resolution', async () => {
    const { dav, open } = await setup();
    const a = await open('master');
    add(a, 'Entry with conflict');
    await sync(a, dav.fetcher);
    const b = await open();
    const change = (side: Side, password: string) => {
      const item = records(side).find(item => item.title === 'Entry with conflict')!;
      put(side, { ...item, data: { ...item.data, password } });
    };
    change(a, 'new-on-A');
    change(b, 'new-on-B');
    add(b, 'Unrelated edit on B');
    await sync(a, dav.fetcher);
    await expect(sync(b, dav.fetcher)).resolves.toMatchObject({ kind: 'conflicts', pending: false, count: 1 });
    await sync(a, dav.fetcher);
    expect(titles(a)).toContain('Unrelated edit on B');
    expect(Array.from(b.anchor.conflicts!)).not.toEqual([]);
    expect(new TextDecoder().decode(b.anchor.conflicts)).not.toContain('new-on-B');
    const restarted = structuredClone(b);
    const { key, wrap } = restarted.session;
    const encrypted = restarted.anchor.conflicts!;
    const review = wasm.wasm_sync_conflicts(key, wrap, encrypted, false);
    expect(review).not.toContain('new-on-A');
    expect(review).not.toContain('new-on-B');
    const [{ id }] = JSON.parse(review);
    const resolved = replayed(wasm.wasm_sync_resolve(key, wrap, restarted.files.head, restarted.files.snap, encrypted,
      JSON.stringify([{ id, mode: 'fields', fields: { 'data.password': 'ours' } }]), Date.now()));
    restarted.anchor.conflicts = new Uint8Array(resolved.conflicts);
    restarted.anchor.conflictCount = resolved.conflictCount;
    restarted.files = { ...restarted.files, head: new Uint8Array(resolved.head), snap: new Uint8Array(resolved.snap) };
    restarted.pending = true;
    await sync(restarted, dav.fetcher);
    await sync(a, dav.fetcher);
    const result = records(a).find(item => item.id === id)!;
    expect(result.data.password).toBe('new-on-B');
    expect(result.data.passwordHistory?.filter(entry => entry.password === 'new-on-A')).toHaveLength(1);
  });

  it('compacts repeatedly, keeps five snapshots and refuses a replayed head', async () => {
    const { dav, open } = await setup();
    const a = await open('master');
    const original = structuredClone(dav.objects.get('/dav/vault/head.bin')!);
    for (let index = 0; index < 8; index++) {
      add(a, `Credential ${index}`);
      await sync(a, dav.fetcher);
      await sync(a, dav.fetcher, { idle: true });
      await sync(a, dav.fetcher);
    }
    const final = decoded(wasm.wasm_sync_authenticate_head(a.anchor.head, a.session.key, a.session.wrap));
    expect(final.snapshotEpoch).toBe(9);
    expect(final.history).toHaveLength(5);
    expect([...dav.objects.keys()].filter(key => /\/snap_/.test(key))).toHaveLength(5);
    expect([...dav.objects.keys()].filter(key => /\/wal\//.test(key))).toHaveLength(0);
    dav.objects.set('/dav/vault/head.bin', original);
    await expect(sync(a, dav.fetcher, { force: true })).rejects.toThrow('RollbackDetected');
    expect(titles(a)).toHaveLength(8);
  });

  it.each(['staged', 'published'] as const)('restarts compaction after a %s snapshot with no cleanup while read-only', async stopAt => {
    const { dav, open } = await setup();
    const editor = await open('master');
    add(editor, 'Retained credential');
    await sync(editor, dav.fetcher);
    const lock = new AbortController();
    const request: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      const pathname = new URL(String(input)).pathname;
      if (init?.method === 'PUT' && (stopAt === 'staged' ? pathname.includes('/snap_') : pathname.endsWith('/head.bin'))) lock.abort();
      return response;
    };
    await expect(sync(editor, request, { idle: true, signal: lock.signal })).rejects.toThrow('已锁定');
    const abandoned = `/dav/vault/snap_${editor.anchor.pendingCompaction?.id}.bin`;
    expect(dav.objects.has(abandoned)).toBe(true);
    const originalObjects = [...dav.objects.keys()].sort();
    const restarted = structuredClone(editor);
    const firstRead = dav.requests.length;
    await sync(restarted, dav.fetcher, { write: false, force: true, idle: true });
    expect(dav.requests.slice(firstRead).every(({ method }) => ['GET', 'PROPFIND'].includes(method))).toBe(true);
    expect([...dav.objects.keys()].sort()).toEqual(originalObjects);
    expect(restarted.anchor.pendingCompaction).toBeTruthy();
    await sync(restarted, dav.fetcher, { idle: true });
    expect(restarted.anchor.pendingCompaction).toBeUndefined();
    expect(dav.objects.has(abandoned)).toBe(stopAt === 'published');
    expect([...dav.objects.keys()].filter(name => name.includes('/wal/'))).toHaveLength(0);
    expect(titles(await open())).toEqual(['Retained credential']);
  });

  it('preserves a WAL arriving while two competing compactors hold the old ETag', async () => {
    const { dav, open } = await setup();
    const a = await open('master');
    add(a, 'Before compaction');
    await sync(a, dav.fetcher);
    const [b, c] = await Promise.all([open(), open()]);
    add(c, 'Arrived during compaction');
    const reached = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    let offers = 0, preconditionFailures = 0;
    const race: typeof fetch = async (input, init) => {
      if (init?.method === 'PUT' && String(input).endsWith('/vault/head.bin')) {
        if (++offers === 2) reached.resolve();
        await release.promise;
        const response = await dav.fetcher(input, init);
        if (response.status === 412) preconditionFailures++;
        return response;
      }
      return dav.fetcher(input, init);
    };
    const contestants = Promise.all([sync(a, race, { idle: true }), sync(b, race, { idle: true })]);
    try {
      await Promise.race([reached.promise, contestants.then(() => { throw new Error('Both compactors did not stage an update'); })]);
      await sync(c, dav.fetcher);
    } finally { release.resolve(); }
    await contestants;
    expect(preconditionFailures).toBe(1);
    expect([...dav.objects.keys()].filter(name => name.includes('/wal/'))).toHaveLength(1);
    for (const side of [a, b, c]) {
      await sync(side, dav.fetcher, { force: true });
      expect(titles(side).sort()).toEqual(['Arrived during compaction', 'Before compaction']);
    }
  });

  it('previews and restores old credentials locally without publishing them, even if ETags reappear', async () => {
    const { dav, open } = await setup();
    const a = await open('master');
    for (const title of ['Present in history', 'Added after history']) {
      add(a, title);
      await sync(a, dav.fetcher);
      await sync(a, dav.fetcher, { idle: true });
      await sync(a, dav.fetcher);
    }
    const client = new WebDavClient(config, {}, dav.fetcher);
    const head = decoded(wasm.wasm_sync_authenticate_head(a.anchor.head, a.session.key, a.session.wrap));
    const old = head.history[1]!;
    const start = dav.requests.length;
    const prepared = await prepareRestore(client, a.anchor, a.session, a.files, old);
    expect(prepared.preview).toMatchObject({ before: 2, after: 1, removed: 1, readOnly: true });
    const save = vi.fn(async (anchor: RemoteAnchor, files: VaultFiles) => {
      a.anchor = structuredClone(anchor);
      a.files = structuredClone(files);
      a.pending = true;
    });
    await expect(restoreHistoryLocally(client, a.anchor, a.files, prepared, 'changed-stamp', () => {}, save)).rejects.toThrow('重新预览');
    expect(save).not.toHaveBeenCalled();
    await restoreHistoryLocally(client, a.anchor, a.files, prepared, prepared.preview.stamp, () => {}, save);
    expect(titles(a)).toEqual(['Present in history']);
    const restarted = structuredClone(a);
    await expect(sync(restarted, dav.fetcher, { write: true, force: true, idle: true }))
      .resolves.toMatchObject({ kind: 'read-only', pending: true });
    expect(titles(restarted)).toEqual(['Present in history']);
    expect(dav.requests.slice(start).every(row => ['GET', 'PROPFIND'].includes(row.method))).toBe(true);
    expect(titles(await open())).toHaveLength(2);
  });

  it('publishes an authenticated new master wrap without replacing the snapshot and does not consume offline edits', async () => {
    const { dav, open, recovery } = await setup();
    const a = await open('master');
    const b = await open();
    add(b, 'B editing offline');
    const before = [...dav.objects].find(([path]) => /\/snap_/.test(path))![1].bytes;
    const newMaster = 'test-new-master-never-networked';
    const changed = core.wasm_change_master_password(a.files.head, master, newMaster, a.session.key, Date.now());
    a.anchor.rotationFrom = a.files.keyEpoch;
    a.files = { ...a.files, head: changed.head_bytes, keyEpoch: Number(changed.key_epoch) };
    a.session.wrap = changed.session_wrap_bytes;
    changed.free();
    await sync(a, dav.fetcher);
    expect([...dav.objects].find(([path]) => /\/snap_/.test(path))![1].bytes).toEqual(before);
    await expect(open('master')).rejects.toBeDefined();
    await expect(open('master', newMaster)).resolves.toMatchObject({ files: { keyEpoch: a.files.keyEpoch } });
    await expect(open('recovery', recovery)).resolves.toMatchObject({ files: { keyEpoch: a.files.keyEpoch } });
    await expect(sync(b, dav.fetcher, { force: true })).resolves.toMatchObject({ kind: 'key-update', pending: true, epoch: a.files.keyEpoch });
    expect(b.anchor.observedHead).toBeTruthy();
    expect(titles(b)).toEqual(['B editing offline']);
    expect(b.pending).toBe(true);
  });
});
