import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import initCore, * as core from '../../../../crates/vault-core/pkg/vault_core.js';
import initSync, * as wasm from '../../../../crates/vault-sync/pkg/vault_sync.js';
import type { RemoteAnchor, SessionState, VaultFiles } from '../vault-storage';
import { createRemoteVault, endpointFingerprint, packSyncFrames, readRemoteVault } from './bootstrap';
import { nextJournalVersion, type JournalClock } from './journal-device';
import { runDavSync } from './run';
import { prepareRestore, restoreHistory, restoreHistoryLocally } from './history';
import { reserveAppend } from './capacity';
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
    draftCount: replay.draft_count,
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
  const output = wasm.wasm_sync_create_genesis(key, primary.wrap, created.head_bytes, created.snap_bytes, version.id, version.state.deviceId);
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
      checkedAt: Date.now(), conflicts: new Uint8Array(result.conflicts), conflictCount: result.conflictCount };
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
type Edit = { id?: string; title: string; note?: string; requireReprompt?: boolean; data: { kind: 'login'; password: string; passwordHistory?: { password: string }[];
  username?: string; uris?: { uri: string }[] } };
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
const fixtureId = (n: number) => `${n.toString(16).padStart(14, '0')}_09abcd11_${n.toString(16).padStart(14, '0')}`;
const fixtureNote = (length: number) => createHash('shake256', { outputLength: length }).update('synthetic note').digest('base64');
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

  it('keeps the directory readable when two devices sync with one WAL slot remaining', async () => {
    const { dav, open } = await setup();
    const [a, b] = await Promise.all([open(), open()]);
    const fixture = structuredClone(a);
    add(fixture, 'Earlier edit');
    const writer = crypto.randomUUID();
    for (let i = 0; i < 749; i++) {
      const id = fixtureId(2000 + i);
      const bytes = wasm.wasm_sync_make_batch(a.session.key, a.session.wrap, a.files.head, a.files.snap,
        a.files.head, a.files.snap, fixture.files.head, fixture.files.snap, id, writer);
      dav.objects.set(`/dav/vault/wal/${id}.bin`, { bytes: new Uint8Array(bytes), tag: `"seed-${i}"` });
    }
    add(a, 'Offline edit A');
    add(b, 'Offline edit B');
    const reached = Promise.withResolvers<void>();
    let observed = 0;
    const simultaneous: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'PROPFIND' && String(input).endsWith('/vault/wal/') && observed < 2) {
        if (++observed === 2) reached.resolve();
        await reached.promise;
      }
      return response;
    };
    await Promise.all([sync(a, simultaneous), sync(b, simultaneous)]);
    expect([...dav.objects.keys()].filter(path => path.startsWith('/dav/vault/wal/')).length).toBeLessThanOrEqual(750);
    const joined = await open();
    expect(titles(joined)).toContain('Earlier edit');
    const restarted = [structuredClone(a), structuredClone(b)];
    for (const side of restarted) {
      for (let retry = 0; retry < 2 && side.pending; retry++) await sync(side, dav.fetcher);
      expect(side.pending).toBe(false);
    }
    await Promise.all(restarted.map(side => sync(side, dav.fetcher)));
    const expected = ['Earlier edit', 'Offline edit A', 'Offline edit B'];
    for (const side of [...restarted, await open()]) expect(titles(side).sort()).toEqual(expected);
  });

  it('does not grant the same last WAL slots to three concurrent devices', async () => {
    const { dav, open } = await setup();
    const devices = await Promise.all([open(), open(), open()]);
    const base = devices[0]!, fixture = structuredClone(base), writer = crypto.randomUUID();
    add(fixture, 'Existing');
    for (let i = 0; i < 748; i++) {
      const id = fixtureId(2000 + i);
      const bytes = wasm.wasm_sync_make_batch(base.session.key, base.session.wrap, base.files.head, base.files.snap,
        base.files.head, base.files.snap, fixture.files.head, fixture.files.snap, id, writer);
      dav.objects.set(`/dav/vault/wal/${id}.bin`, { bytes: new Uint8Array(bytes), tag: `"seed-${i}"` });
    }
    const checked = Promise.withResolvers<void>();
    let observers = 0, largest = 0;
    await Promise.all(devices.map((device, index) => {
      add(device, `Offline ${index}`);
      let listings = 0;
      const together: typeof fetch = async (url, init) => {
        const result = await dav.fetcher(url, init);
        if (init?.method === 'PROPFIND' && String(url).endsWith('/vault/wal/') && ++listings === 2) {
          if (++observers === devices.length) checked.resolve();
          await checked.promise;
        }
        if (init?.method === 'PUT' && String(url).includes('/vault/wal/')) {
          largest = Math.max(largest, [...dav.objects.keys()].filter(path => path.includes('/vault/wal/')).length);
        }
        return result;
      };
      return sync(device, together);
    }));
    expect(largest).toBeLessThanOrEqual(750);
    expect(titles(await open())).toContain('Existing');
    const restarted = devices.map(device => structuredClone(device));
    for (const device of restarted) {
      for (let retry = 0; retry < 4 && device.pending; retry++) await sync(device, dav.fetcher);
      expect(device.pending).toBe(false);
    }
    expect(titles(await open()).sort()).toEqual(['Existing', 'Offline 0', 'Offline 1', 'Offline 2']);
  });

  it('counts distinct in-flight ancestor bytes once and never grants a future unreadable history', async () => {
    const dav = server(), client = new WebDavClient(config, {}, dav.fetcher);
    const permit = (id: number, base: number, size: number) => reserveAppend(client, [], { id: fixtureId(id), bytes: bytes(id) },
      `snap_${fixtureId(base)}`, size, [], async () => true);
    const mib = 1024 * 1024;
    expect(await permit(10, 1, 5 * mib)).toBe('granted');
    expect(await permit(11, 1, 5 * mib)).toBe('granted');
    expect(await permit(12, 2, 3 * mib)).toBe('granted');
    expect(await permit(13, 3, 1)).toBe('snapshot');
    expect(await permit(14, 4, 8 * mib + 1)).toBe('snapshot');
  });

  it('keeps a byte-sized margin for a legacy WAL arriving after two new devices check the directory', async () => {
    const { dav, open } = await setup();
    const [a, b, legacy] = await Promise.all([open(), open(), open()]);
    const note = fixtureNote(2 * 1024 * 1024 + 65536);
    for (const [device, title] of [[a, 'New A'], [b, 'New B'], [legacy, 'Legacy']] as const) {
      put(device, { title, note, data: { kind: 'login', password: 'fixture secret' } });
    }
    const version = nextJournalVersion(undefined, Date.now()), base = legacy.anchor;
    const delta = new Uint8Array(wasm.wasm_sync_make_batch(legacy.session.key, legacy.session.wrap, base.appliedHead, base.appliedSnap,
      base.appliedHead, base.appliedSnap, legacy.files.head, legacy.files.snap, version.id, version.state.deviceId));
    expect(delta.length * 3).toBeGreaterThan(8 * 1024 * 1024);
    expect(delta.length).toBeLessThan(4 * 1024 * 1024);
    const checked = Promise.withResolvers<void>();
    let readers = 0, peak = 0;
    const observe: typeof fetch = async (url, init) => {
      const response = await dav.fetcher(url, init);
      if (init?.method === 'PUT' && String(url).includes('/vault/wal/')) {
        const size = [...dav.objects].reduce((total, [name, object]) => total + (name.includes('/vault/wal/') ? object.bytes.length : 0), 0);
        peak = Math.max(peak, size);
      }
      return response;
    };
    await Promise.all([a, b].map(device => {
      let listings = 0;
      return sync(device, async (url, init) => {
        const response = await observe(url, init);
        if (init?.method === 'PROPFIND' && String(url).endsWith('/vault/wal/') && ++listings === 2) {
          if (++readers === 2) {
            await new WebDavClient(config, {}, observe).put(`wal/${version.id}.bin`, delta, { absent: true });
            checked.resolve();
          }
          await checked.promise;
        }
        return response;
      });
    }));
    expect(peak).toBeLessThanOrEqual(8 * 1024 * 1024);
    expect(titles(await open())).toContain('Legacy');
    for (const device of [a, b]) {
      for (let retry = 0; retry < 4 && device.pending; retry++) await sync(device, observe);
      expect(device.pending).toBe(false);
    }
    expect(peak).toBeLessThanOrEqual(8 * 1024 * 1024);
    expect(titles(await open()).sort()).toEqual(['Legacy', 'New A', 'New B']);
  });

  it('joins from the current snapshot without downloading unrelated history over 8 MiB', async () => {
    const { dav, open } = await setup();
    const seed = await open();
    const { key, wrap } = seed.session;
    let wire = seed.anchor.head;
    const large = fixtureNote(4 * 1024 * 1024 + 65536);
    put(seed, { title: 'Existing login', note: large, data: { kind: 'login', password: 'fixture secret' } });
    const historical: string[] = [];
    const time = Date.now() + 60_000;
    for (let index = 0; index < 3; index++) {
      if (index === 2) put(seed, { ...records(seed)[0]!, note: '' });
      const id = fixtureId(time + index);
      const next = wasm.wasm_sync_compact(key, wrap, wire, seed.files.head, seed.files.snap, id);
      const path = `/dav/vault/snap_${id}.bin`;
      try {
        wire = next.head;
        const snap = new Uint8Array(next.snap);
        seed.files = { ...seed.files, head: new Uint8Array(decoded(wasm.wasm_sync_authenticate_head(wire, key, wrap)).localHead), snap };
        dav.objects.set(path, { bytes: snap, tag: `"history-${index}"` });
        if (index < 2) historical.push(path);
      } finally { next.free(); }
    }
    dav.objects.set('/dav/vault/head.bin', { bytes: new Uint8Array(wire), tag: '"head-with-history"' });
    expect(historical.reduce((total, path) => total + dav.objects.get(path)!.bytes.length, 0)).toBeGreaterThan(8 * 1024 * 1024);
    const editor = await open();
    add(editor, 'Increment for the current snapshot');
    await sync(editor, dav.fetcher);
    const before = dav.requests.length;
    const joined = await open();
    expect(titles(joined).sort()).toEqual(['Existing login', 'Increment for the current snapshot']);
    expect(dav.requests.slice(before).filter(row => row.method === 'GET').some(row => historical.includes(row.path))).toBe(false);
  });

  it('verifies a required older ancestor and stops if it is missing, damaged or over budget', async () => {
    const { dav, open } = await setup();
    const [base, editor] = await Promise.all([open(), open()]);
    add(editor, 'Edit based on older snapshot');
    await sync(editor, dav.fetcher);
    const { key, wrap } = base.session;
    const ancestor = decoded(wasm.wasm_sync_authenticate_head(base.anchor.head, key, wrap));
    const id = fixtureId(Date.now() + 60_000);
    // A compactor read before the edit was published; the edit still depends on the prior snapshot.
    const compacted = wasm.wasm_sync_compact(key, wrap, base.anchor.head, base.files.head, base.files.snap, id);
    try {
      dav.objects.set('/dav/vault/head.bin', { bytes: new Uint8Array(compacted.head), tag: '"head-newer"' });
      dav.objects.set(`/dav/vault/snap_${id}.bin`, { bytes: new Uint8Array(compacted.snap), tag: '"snapshot-newer"' });
    } finally { compacted.free(); }
    const path = `/dav/vault/${ancestor.snapshotId}.bin`;
    const existing = dav.objects.get(path)!;
    const before = dav.requests.length;
    expect(titles(await open())).toEqual(['Edit based on older snapshot']);
    expect(dav.requests.slice(before).some(row => row.path === path && row.method === 'GET')).toBe(true);

    const damaged = new Uint8Array(existing.bytes);
    damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1;
    for (const [replacement, error] of [[undefined, 'SyncAncestorRequired'], [damaged, 'CRYPTO_AUTH_FAILED'],
      [new Uint8Array(8 * 1024 * 1024 + 1), '超过大小限制']] as const) {
      if (replacement) dav.objects.set(path, { bytes: replacement, tag: '"fixture-unusable-ancestor"' });
      else dav.objects.delete(path);
      const start = dav.requests.length;
      await expect(open().catch(reason => String(reason))).resolves.toContain(error);
      expect(dav.requests.slice(start).every(row => row.method === 'GET' || row.method === 'PROPFIND')).toBe(true);
      expect(titles(editor)).toEqual(['Edit based on older snapshot']);
    }
  });

  it('fetches the required ancestor directly even with an unrelated large newer history snapshot', async () => {
    const { dav, open } = await setup();
    const base = await open(), offline = structuredClone(base);
    const { key, wrap } = base.session;
    add(offline, 'Late offline WAL');
    const version = nextJournalVersion(undefined, Date.now());
    const delta = wasm.wasm_sync_make_batch(key, wrap, base.files.head, base.files.snap, base.files.head,
      base.files.snap, offline.files.head, offline.files.snap, version.id, version.state.deviceId);
    const first = decoded(wasm.wasm_sync_authenticate_head(base.anchor.head, key, wrap)).snapshotId;
    put(base, { title: 'Other edit', note: fixtureNote(8 * 1024 * 1024 + 65536),
      data: { kind: 'login', password: 'fixture secret' } });
    let wire = base.anchor.head;
    const paths: string[] = [];
    for (let i = 0; i < 2; i++) {
      if (i) put(base, { ...records(base)[0]!, note: '' });
      const id = fixtureId(Date.now() + 60_000 + i);
      const next = wasm.wasm_sync_compact(key, wrap, wire, base.files.head, base.files.snap, id);
      try {
        wire = next.head;
        base.files = { ...base.files, head: new Uint8Array(decoded(wasm.wasm_sync_authenticate_head(wire, key, wrap)).localHead), snap: new Uint8Array(next.snap) };
        const path = `/dav/vault/snap_${id}.bin`;
        paths.push(path);
        dav.objects.set(path, { bytes: new Uint8Array(next.snap), tag: `"history-${i}"` });
      } finally { next.free(); }
    }
    expect(dav.objects.get(paths[0]!)!.bytes.length).toBeGreaterThan(8 * 1024 * 1024);
    dav.objects.set('/dav/vault/head.bin', { bytes: new Uint8Array(wire), tag: '"new-head"' });
    dav.objects.set(`/dav/vault/wal/${version.id}.bin`, { bytes: new Uint8Array(delta), tag: '"late-wal"' });
    const before = dav.requests.length;
    expect(titles(await open()).sort()).toEqual(['Late offline WAL', 'Other edit']);
    const reads = dav.requests.slice(before).filter(row => row.method === 'GET').map(row => row.path);
    expect(reads).toContain(`/dav/vault/${first}.bin`);
    expect(reads).not.toContain(paths[0]);
  });

  it('keeps offline edits pending across an interrupted compaction near the 8 MiB WAL budget', async () => {
    const { dav, open } = await setup();
    const editor = await open();
    const fixture = structuredClone(editor);
    put(fixture, { title: 'Earlier large note', note: fixtureNote(3 * 1024 * 1024 - 65536),
      data: { kind: 'login', password: 'fixture secret' } });
    const writer = crypto.randomUUID();
    let total = 0;
    for (const i of [1, 2]) {
      const id = fixtureId(2000 + i);
      const bytes = wasm.wasm_sync_make_batch(editor.session.key, editor.session.wrap, editor.files.head, editor.files.snap,
        editor.files.head, editor.files.snap, fixture.files.head, fixture.files.snap, id, writer);
      total += bytes.length;
      dav.objects.set(`/dav/vault/wal/${id}.bin`, { bytes: new Uint8Array(bytes), tag: `"large-seed-${i}"` });
    }
    expect(total).toBeGreaterThan(8 * 1024 * 1024 - 256 * 1024);
    expect(total).toBeLessThanOrEqual(8 * 1024 * 1024);
    put(editor, { title: 'Pending offline note', note: fixtureNote(256 * 1024),
      data: { kind: 'login', password: 'fixture secret' } });
    const lock = new AbortController();
    const interrupt: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'PUT' && String(input).endsWith('/vault/head.bin')) lock.abort();
      return response;
    };
    const before = dav.requests.length;
    await expect(sync(editor, interrupt, { signal: lock.signal })).rejects.toThrow('已锁定');
    expect(dav.requests.slice(before).some(row => row.method === 'PUT' && row.path.startsWith('/dav/vault/wal/'))).toBe(false);
    expect(editor.pending).toBe(true);
    expect(editor.anchor.pendingCompaction).toBeTruthy();
    expect(titles(await open())).toEqual(['Earlier large note']);
    const restarted = structuredClone(editor);
    const noWrite = dav.requests.length;
    await expect(sync(restarted, dav.fetcher, { write: false })).resolves.toMatchObject({ kind: 'read-only', pending: true });
    expect(dav.requests.slice(noWrite).every(row => row.method === 'GET' || row.method === 'PROPFIND')).toBe(true);
    for (let retry = 0; retry < 2 && restarted.pending; retry++) await sync(restarted, dav.fetcher);
    expect(restarted.pending).toBe(false);
    expect(titles(await open()).sort()).toEqual(['Earlier large note', 'Pending offline note']);
  });

  it('publishes a readable first offline batch larger than half the WAL directory budget', async () => {
    const { dav, open } = await setup();
    const editor = await open();
    put(editor, { title: 'Large first offline batch', note: fixtureNote(3 * 1024 * 1024 + 65536),
      data: { kind: 'login', password: 'fixture secret' } });
    const { key, wrap } = editor.session;
    const before = editor.anchor;
    const delta = wasm.wasm_sync_make_batch(key, wrap, before.appliedHead, before.appliedSnap,
      before.appliedHead, before.appliedSnap, editor.files.head, editor.files.snap, fixtureId(Date.now()), crypto.randomUUID());
    expect(delta.length).toBeGreaterThan(4 * 1024 * 1024);
    expect(delta.length).toBeLessThan(8 * 1024 * 1024);
    for (let retry = 0; retry < 2 && editor.pending; retry++) await sync(editor, dav.fetcher);
    expect(editor.pending).toBe(false);
    expect(records(await open())).toEqual(records(editor));
  });

  it('leaves a single WAL over the 8 MiB read budget on the local device', async () => {
    const { dav, open } = await setup();
    const editor = await open();
    const beforeFiles = editor.files;
    put(editor, { title: 'Too large to append', note: fixtureNote(8 * 1024 * 1024 + 65536),
      data: { kind: 'login', password: 'fixture secret' } });
    const sample = wasm.wasm_sync_make_batch(editor.session.key, editor.session.wrap, beforeFiles.head, beforeFiles.snap,
      beforeFiles.head, beforeFiles.snap, editor.files.head, editor.files.snap, fixtureId(Date.now()), crypto.randomUUID());
    expect(sample.length).toBeGreaterThan(8 * 1024 * 1024);
    const synced = dav.requests.length;
    await expect(sync(editor, dav.fetcher)).resolves.toEqual({ kind: 'deferred', pending: true });
    expect(dav.requests.slice(synced).every(row => row.method === 'GET' || row.method === 'PROPFIND')).toBe(true);
    expect(editor.pending).toBe(true);
    const restarted = structuredClone(editor);
    expect(titles(restarted)).toEqual(['Too large to append']);
    expect(titles(await open())).toEqual([]);
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

  it('upgrades a legacy unconfirmed outbox without sending a second copy of its in-flight PUT', async () => {
    const { dav, open } = await setup();
    const editor = await open();
    add(editor, 'Written before upgrade');
    const version = nextJournalVersion(undefined, Date.now());
    const { key, wrap } = editor.session, base = editor.anchor;
    const delta = new Uint8Array(wasm.wasm_sync_make_batch(key, wrap, base.appliedHead, base.appliedSnap,
      base.appliedHead, base.appliedSnap, editor.files.head, editor.files.snap, version.id, version.state.deviceId));
    editor.anchor.outbox = { id: version.id, bytes: delta, priorIds: [], source: structuredClone(editor.files) };
    editor.clock = version.state;
    const path = `wal/${version.id}.bin`, offered = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    // The older client knows only immutable WAL objects, not the new capacity register.
    const delayed = new WebDavClient(config, {}, async (url, init) => {
      offered.resolve();
      await release.promise;
      return dav.fetcher(url, init);
    }).put(path, delta, { absent: true });
    await offered.promise;
    const restarted = structuredClone(editor), start = dav.requests.length;
    try {
      for (let retry = 0; retry < 3 && restarted.pending; retry++) await sync(restarted, dav.fetcher);
      expect(restarted.pending).toBe(false);
      expect(titles(await open())).toEqual(['Written before upgrade']);
      expect(dav.requests.slice(start).filter(row => row.path.endsWith(path) && row.method === 'PUT')).toHaveLength(0);
    } finally { release.resolve(); await delayed; }
    await sync(restarted, dav.fetcher, { force: true });
    expect(titles(await open())).toEqual(['Written before upgrade']);
    expect(titles(restarted)).toEqual(['Written before upgrade']);
  });

  it('resolves an unconfirmed grant after further local and remote edits without pinning old history', async () => {
    const { dav, open } = await setup();
    const [editor, peer] = await Promise.all([open(), open()]);
    const first = decoded(wasm.wasm_sync_authenticate_head(editor.anchor.head, editor.session.key, editor.session.wrap)).snapshotId;
    add(editor, 'Before disconnect');
    const lock = new AbortController();
    const interrupt: typeof fetch = async (url, init) => {
      const response = await dav.fetcher(url, init);
      if (init?.method === 'PUT' && String(url).endsWith('/wal-budget.bin')) lock.abort();
      return response;
    };
    await expect(sync(editor, interrupt, { signal: lock.signal })).rejects.toThrow('已锁定');
    expect(editor.pending).toBe(true);
    expect(titles(await open())).toEqual([]);
    const restarted = structuredClone(editor);
    add(restarted, 'Also saved offline');
    add(peer, 'From another device');
    await sync(peer, dav.fetcher);
    for (let retry = 0; retry < 4 && restarted.pending; retry++) await sync(restarted, dav.fetcher);
    expect(restarted.pending).toBe(false);
    expect(titles(await open()).sort()).toEqual(['Also saved offline', 'Before disconnect', 'From another device']);
    for (let i = 0; i < 6; i++) {
      add(peer, `Later ${i}`);
      await sync(peer, dav.fetcher);
      await sync(peer, dav.fetcher, { idle: true });
    }
    const info = decoded(wasm.wasm_sync_authenticate_head(peer.anchor.head, peer.session.key, peer.session.wrap));
    expect(info.history).not.toContain(first);
    expect(titles(await open())).toHaveLength(9);
  });

  it('lets peers recover an admitted edit when its device never returns after reserving capacity', async () => {
    const { dav, open } = await setup();
    const [gone, active] = await Promise.all([open(), open()]);
    const genesis = decoded(wasm.wasm_sync_authenticate_head(gone.anchor.head, gone.session.key, gone.session.wrap)).snapshotId;
    add(gone, 'Still recoverable without this device');
    const stopped = new AbortController();
    await expect(sync(gone, async (url, init) => {
      const result = await dav.fetcher(url, init);
      if (init?.method === 'PUT' && String(url).endsWith('/wal-budget.bin')) stopped.abort();
      return result;
    }, { signal: stopped.signal })).rejects.toThrow('已锁定');
    for (let i = 0; i < 7; i++) {
      add(active, `Continued ${i}`);
      await sync(active, dav.fetcher);
      await sync(active, dav.fetcher, { idle: true });
    }
    expect(titles(await open())).toContain('Still recoverable without this device');
    const info = decoded(wasm.wasm_sync_authenticate_head(active.anchor.head, active.session.key, active.session.wrap));
    expect(info.history).not.toContain(genesis);
    expect(titles(await open())).toHaveLength(8);
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
    const stamp = wasm.wasm_sync_conflict_stamp(restarted.session.key, restarted.session.wrap, encrypted);
    await expect(sync(restarted, dav.fetcher, { force: true })).resolves.toMatchObject({ kind: 'conflicts', count: 1 });
    expect(wasm.wasm_sync_conflict_stamp(restarted.session.key, restarted.session.wrap, restarted.anchor.conflicts!)).toBe(stamp);
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

  it('syncs unrelated edits with a third draft, then reopens the draft after the earlier conflict is settled', async () => {
    const { dav, open } = await setup();
    const a = await open();
    add(a, 'Shared login');
    await sync(a, dav.fetcher);
    const b = await open(), c = await open();
    const change = (side: Side, password: string) => {
      const item = records(side).find(item => item.title === 'Shared login')!;
      put(side, { ...item, data: { ...item.data, password } });
    };
    change(a, 'version on A');
    change(b, 'version on B');
    change(c, 'version on C');
    add(c, 'Unrelated from C');

    const ready = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let offered = 0;
    const parallel: typeof fetch = async (url, init) => {
      if (init?.method === 'PUT' && new URL(String(url)).pathname.startsWith('/dav/vault/wal/')) {
        if (++offered === 2) ready.resolve();
        await release.promise;
      }
      return dav.fetcher(url, init);
    };
    const concurrent = Promise.all([sync(a, parallel), sync(b, parallel)]);
    await Promise.race([ready.promise, concurrent]);
    release.resolve();
    await concurrent;
    const review = (side: Side, revealed = false) => JSON.parse(wasm.wasm_sync_conflicts(
      side.session.key, side.session.wrap, side.anchor.conflicts ?? new Uint8Array(), revealed));
    const resolve = (side: Side, id: string) => {
      const out = replayed(wasm.wasm_sync_resolve(side.session.key, side.session.wrap, side.files.head, side.files.snap,
        side.anchor.conflicts!, JSON.stringify([{ id, mode: 'ours' }]), Date.now()));
      side.files = { ...side.files, head: new Uint8Array(out.head), snap: new Uint8Array(out.snap) };
      side.anchor = { ...side.anchor, conflicts: new Uint8Array(out.conflicts), conflictCount: out.conflictCount,
        pendingResolutions: new Uint8Array(out.receipts) };
      side.pending = true;
    };

    await expect(sync(c, dav.fetcher)).resolves.toMatchObject({ kind: 'conflicts', count: 1 });
    const restarted = structuredClone(c);
    expect(restarted.anchor.draftCount).toBe(1);
    expect(new TextDecoder().decode(restarted.anchor.conflicts)).not.toContain('version on C');
    const original = await open();
    expect(titles(original)).toContain('Unrelated from C');
    expect(review(original)).toHaveLength(1);
    resolve(original, review(original)[0].id);
    await sync(original, dav.fetcher, { force: true });
    const beforeReadOnly = dav.requests.length;
    await expect(sync(restarted, dav.fetcher, { write: false, force: true })).resolves.toMatchObject({ kind: 'read-only', pending: true });
    expect(dav.requests.slice(beforeReadOnly).every(row => row.method === 'GET' || row.method === 'PROPFIND')).toBe(true);
    expect(restarted.anchor.draftCount).toBe(1);
    await expect(sync(restarted, dav.fetcher, { write: false })).resolves.toMatchObject({ kind: 'read-only', pending: true });
    await sync(restarted, dav.fetcher, { force: true });
    expect(review(await open())).toHaveLength(0);
    const next = review(restarted, true);
    expect(next).toHaveLength(1);
    expect(next[0].ours.values['data.password']).toBe('version on C');
    resolve(restarted, next[0].id);
    await sync(restarted, dav.fetcher);
    const final = records(await open()).find(item => item.title === 'Shared login')!;
    expect(final.data.password).toBe('version on C');
    expect(final.data.passwordHistory?.map(row => row.password)).toEqual(expect.arrayContaining(['version on A', 'version on B']));
  });

  it('reviews every same-account draft in turn without blocking a different credential', async () => {
    const { dav, open } = await setup();
    const a = await open(), b = await open();
    const login = (side: Side, title: string) => put(side, { title, data: { kind: 'login', username: 'fixture',
      uris: [{ uri: 'https://login.example.net' }], password: `${title}-password` } });
    login(a, 'Already on the server');
    login(b, 'First offline login');
    login(b, 'Second offline login');
    add(b, 'Different credential');
    await sync(a, dav.fetcher);
    await expect(sync(b, dav.fetcher)).resolves.toMatchObject({ kind: 'conflicts', count: 1 });
    expect(titles(await open())).toEqual(expect.arrayContaining(['Already on the server', 'Different credential']));
    const pending = structuredClone(b);
    const { key, wrap } = pending.session;
    const review = () => JSON.parse(wasm.wasm_sync_conflicts(key, wrap, pending.anchor.conflicts!, true));
    const [first] = review();
    expect(first.fields).toEqual(['$duplicate']);
    const resolved = replayed(wasm.wasm_sync_resolve(key, wrap, pending.files.head, pending.files.snap, pending.anchor.conflicts!,
      JSON.stringify([{ id: first.id, mode: 'theirs' }]), Date.now()));
    pending.files = { ...pending.files, head: new Uint8Array(resolved.head), snap: new Uint8Array(resolved.snap) };
    pending.anchor = { ...pending.anchor, conflicts: new Uint8Array(resolved.conflicts), conflictCount: resolved.conflictCount };
    pending.pending = true;
    await expect(sync(pending, dav.fetcher)).resolves.toMatchObject({ kind: 'conflicts', count: 1 });
    const [second] = review();
    expect(second.fields).toEqual(['$duplicate']);
    expect(second.ours.title).not.toBe(first.ours.title);
    expect(titles(await open())).not.toContain(second.ours.title);
  });

  it.each(['ours', 'theirs', 'both'] as const)('presents all remote matches before resolving an offline login group (%s)', async mode => {
    const { dav, open } = await setup();
    const a = await open(), b = await open();
    const login = (side: Side, title: string) => put(side, { title, data: { kind: 'login', username: 'fixture',
      uris: [{ uri: 'https://login.example.net' }], password: `${title}-password` } });
    login(a, 'Server version 1');
    put(a, { title: 'Server version 2', requireReprompt: true, data: { kind: 'login', username: 'fixture',
      uris: [{ uri: 'https://login.example.net' }], password: 'Server version 2-password' } });
    login(b, 'Offline version');
    add(b, 'Unrelated group fixture');
    await sync(a, dav.fetcher);
    await expect(sync(b, dav.fetcher)).resolves.toMatchObject({ kind: 'conflicts', count: 1 });
    expect(titles(await open())).toContain('Unrelated group fixture');
    const { key, wrap } = b.session;
    const [review] = JSON.parse(wasm.wasm_sync_conflicts(key, wrap, b.anchor.conflicts!, false));
    expect([review.theirs.title, ...review.otherMatches.map((row: { title: string }) => row.title)].sort())
      .toEqual(['Server version 1', 'Server version 2']);
    expect(review.protected).toBe(true);
    expect(JSON.stringify(review)).not.toContain('Server version 2-password');
    expect(titles(await open())).not.toContain('Offline version');
    const output = replayed(wasm.wasm_sync_resolve(key, wrap, b.files.head, b.files.snap, b.anchor.conflicts!,
      JSON.stringify([{ id: review.id, mode }]), Date.now()));
    b.files = { ...b.files, head: new Uint8Array(output.head), snap: new Uint8Array(output.snap) };
    b.anchor = { ...b.anchor, conflicts: new Uint8Array(output.conflicts), conflictCount: output.conflictCount };
    b.pending = true;
    await sync(b, dav.fetcher);
    const final = records(await open());
    expect(final).toHaveLength(mode === 'ours' ? 2 : mode === 'theirs' ? 3 : 4);
    expect(final.every(row => row.title === 'Unrelated group fixture' || row.requireReprompt)).toBe(true);
    if (mode !== 'theirs') expect(final.find(row => row.title === 'Offline version')!.data.passwordHistory?.map(row => row.password))
      .toEqual(expect.arrayContaining(['Server version 1-password', 'Server version 2-password']));
    if (mode !== 'ours') expect(final.filter(row => row.title.startsWith('Server version')).every(row =>
      row.data.passwordHistory?.some(entry => entry.password === 'Offline version-password'))).toBe(true);
  });

  it('keeping both names the originating device even after compaction and protects both histories', async () => {
    const { dav, open } = await setup();
    const a = await open();
    a.clock = nextJournalVersion(undefined, Date.now()).state;
    const device = replayed(wasm.wasm_sync_device_change(a.session.key, a.session.wrap, a.files.head, a.files.snap,
      JSON.stringify({ action: 'track', id: a.clock.deviceId, tag: a.clock.tag, name: 'Remote Laptop',
        time: Date.now(), system: 'Fixture OS', browser: 'Edge', version: '0.0.0' })));
    a.files = { ...a.files, head: new Uint8Array(device.head), snap: new Uint8Array(device.snap) };
    add(a, 'Split fixture');
    await sync(a, dav.fetcher);
    const b = await open();
    const item = records(a).find(row => row.title === 'Split fixture')!;
    put(a, { ...item, data: { ...item.data, password: 'remote fixture' } });
    put(b, { ...item, requireReprompt: true, data: { ...item.data, password: 'protected local fixture' } });
    await sync(a, dav.fetcher);
    await sync(a, dav.fetcher, { idle: true });
    expect([...dav.objects.keys()].every(name => !name.startsWith('/dav/vault/wal/'))).toBe(true);
    const compacted = await open();
    expect(JSON.parse(wasm.wasm_sync_devices(compacted.session.key, compacted.session.wrap, compacted.files.head, compacted.files.snap)))
      .toMatchObject([{ name: 'Remote Laptop', lastEditCount: 1 }]);
    await expect(sync(b, dav.fetcher)).resolves.toMatchObject({ kind: 'conflicts', count: 1 });
    const { key, wrap } = b.session;
    const [review] = JSON.parse(wasm.wasm_sync_conflicts(key, wrap, b.anchor.conflicts!, false));
    expect(review.theirs.source).toBe('Remote Laptop');
    const result = replayed(wasm.wasm_sync_resolve(key, wrap, b.files.head, b.files.snap, b.anchor.conflicts!,
      JSON.stringify([{ id: review.id, mode: 'both' }]), Date.now()));
    b.files = { ...b.files, head: new Uint8Array(result.head), snap: new Uint8Array(result.snap) };
    b.anchor = { ...b.anchor, conflicts: new Uint8Array(result.conflicts), conflictCount: result.conflictCount };
    b.pending = true;
    await sync(b, dav.fetcher);
    const actual = records(await open());
    expect(actual).toHaveLength(2);
    const retained = actual.find(row => row.id === item.id)!;
    const copy = actual.find(row => row.id !== item.id)!;
    expect(retained).toMatchObject({ title: 'Split fixture', requireReprompt: true,
      data: { password: 'protected local fixture', passwordHistory: expect.arrayContaining([expect.objectContaining({ password: 'remote fixture' })]) } });
    expect(copy).toMatchObject({ title: `Split fixture（${review.theirs.source}）`, requireReprompt: true,
      data: { password: 'remote fixture', passwordHistory: expect.arrayContaining([expect.objectContaining({ password: 'protected local fixture' })]) } });
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

  it('keeps the authenticated ancestor of an admitted in-flight WAL across repeated compactions', async () => {
    const { dav, open } = await setup();
    const [late, active] = await Promise.all([open(), open()]);
    add(late, 'Admitted before compaction');
    const offered = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    const upload = sync(late, async (url, init) => {
      if (init?.method === 'PUT' && String(url).includes('/vault/wal/')) {
        offered.resolve();
        await release.promise;
      }
      return dav.fetcher(url, init);
    });
    await Promise.race([offered.promise, upload.then(() => { throw new Error('WAL was not offered'); })]);
    try {
      for (let i = 0; i < 6; i++) {
        add(active, `Other edit ${i}`);
        await sync(active, dav.fetcher);
        await sync(active, dav.fetcher, { idle: true });
      }
    } finally { release.resolve(); await upload; }
    expect(titles(await open()).sort()).toEqual(['Admitted before compaction', ...Array.from({ length: 6 }, (_, i) => `Other edit ${i}`)]);
    await sync(active, dav.fetcher, { idle: true, force: true });
    expect([...dav.objects.keys()].filter(path => path.includes('/wal/'))).toHaveLength(0);
    expect(titles(await open())).toHaveLength(7);
  });

  it('does not let a manual history restore evict the ancestor needed by an admitted WAL', async () => {
    const { dav, open } = await setup();
    const active = await open();
    add(active, 'Present before restore');
    await sync(active, dav.fetcher);
    await sync(active, dav.fetcher, { idle: true });
    const late = await open();
    add(late, 'Irrevocable in-flight edit');
    const lock = new AbortController();
    await expect(sync(late, async (url, init) => {
      const response = await dav.fetcher(url, init);
      if (init?.method === 'PUT' && String(url).endsWith('/wal-budget.bin')) lock.abort();
      return response;
    }, { signal: lock.signal })).rejects.toThrow('已锁定');
    for (let i = 0; i < 4; i++) {
      add(active, `History ${i}`);
      await sync(active, dav.fetcher);
      await sync(active, dav.fetcher, { idle: true });
    }
    await sync(active, dav.fetcher, { force: true });
    const info = decoded(wasm.wasm_sync_authenticate_head(active.anchor.head, active.session.key, active.session.wrap));
    const client = new WebDavClient({ ...config, writeVerified: true }, {}, dav.fetcher);
    const before = dav.requests.length, reserve = vi.fn(), save = vi.fn();
    const prepared = await prepareRestore(client, active.anchor, active.session, active.files, info.history[1]!);
    await expect(restoreHistory(client, active.anchor, active.session, active.files, prepared, active.clock,
      prepared.preview.stamp, () => {}, reserve, save)).rejects.toThrow('先同步');
    expect(reserve).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
    expect(dav.requests.slice(before).every(row => row.method === 'GET' || row.method === 'PROPFIND')).toBe(true);
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
