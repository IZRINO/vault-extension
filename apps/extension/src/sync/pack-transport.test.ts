import { describe, expect, it } from 'vitest';
import { createHmac, hkdfSync } from 'node:crypto';
import { PackIntegrityError, PackTransport, preparePackVersion } from './pack-transport';
import { webDavConfig } from './webdav';

const vaultId = '12121212-1212-4121-8121-121212121212';
const material = new Uint8Array(32).fill(7);
const cfg = webDavConfig({ provider: 'custom', base: 'https://dav.example/dav/', folder: 'vault',
  username: 'fixture', password: 'fixture' });
const genesisId = 'a'.repeat(32);
const payload = new Uint8Array([0xff, 0x00, 0x8b, 0x42]);
const genesisVersion = () => preparePackVersion({ id: genesisId, vaultId, parents: [],
  createdAt: 10, keyEpoch: 1, head: Uint8Array.of(8, 0, 23) }, payload);

function server() {
  const folders = new Set(['/dav/scratch/']);
  const files = new Map<string, { bytes: Uint8Array<ArrayBuffer>; etag: string }>();
  const requests: { method: string; path: string }[] = [];
  let generation = 0;
  const row = (href: string, collection = false) => {
    const file = files.get(href);
    return `<D:response><D:href>${href}</D:href><D:propstat><D:prop><D:resourcetype>${collection ? '<D:collection/>' : ''}</D:resourcetype>` +
      `${file ? `<D:getetag>${file.etag}</D:getetag><D:getcontentlength>${file.bytes.length}</D:getcontentlength>` : ''}` +
      '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
  };
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname, method = init?.method ?? 'GET';
    requests.push({ method, path });
    const file = files.get(path), headers = new Headers(init?.headers);
    switch (method) {
      case 'PROPFIND': {
        if (!folders.has(path)) return new Response(null, { status: 404 });
        const immediate = (name: string) => name !== path && name.startsWith(path) && !name.slice(path.length).replace(/\/$/, '').includes('/');
        const rows = [...folders].filter(immediate).map(name => row(name, true)).concat([...files.keys()].filter(immediate).map(name => row(name)));
        return new Response(`<D:multistatus xmlns:D="DAV:">${row(path, true)}${rows.join('')}</D:multistatus>`, { status: 207 });
      }
      case 'MKCOL':
        if (folders.has(path)) return new Response(null, { status: 405 });
        if (!folders.has(new URL('..', new URL(path, cfg.url)).pathname) && path !== '/dav/vault/') return new Response(null, { status: 409 });
        folders.add(path);
        return new Response(null, { status: 201 });
      case 'GET':
        if (!file) return new Response(null, { status: 404 });
        if (headers.get('If-None-Match') === file.etag) return new Response(null, { status: 304 });
        return new Response(file.bytes, { headers: { ETag: file.etag, 'Content-Length': String(file.bytes.length) } });
      case 'PUT':
        if (!folders.has(path.slice(0, path.lastIndexOf('/') + 1))) return new Response(null, { status: 409 });
        if ((headers.get('If-None-Match') === '*' && file) || (headers.has('If-Match') && headers.get('If-Match') !== file?.etag))
          return new Response(null, { status: 412 });
        if (!(init?.body instanceof Uint8Array)) throw new Error('Expected bytes');
        files.set(path, { bytes: new Uint8Array(init.body), etag: `"write-${++generation}"` });
        return new Response(null, { status: 201 });
      case 'DELETE':
        if (headers.get('If-Match') !== file?.etag) return new Response(null, { status: 412 });
        files.delete(path);
        return new Response(null, { status: 204 });
      default:
        throw new Error(`Unexpected request ${method} ${path}`);
    }
  };
  return { fetcher, files, folders, requests };
}

describe('WebDAV encrypted packs', () => {
  it('commits genesis only after complete package readback, and reads only metadata on an idle check', async () => {
    const dav = server();
    const genesis = await genesisVersion();
    const writer = new PackTransport(cfg, {}, dav.fetcher);
    await writer.create(material, genesis, payload, 'scratch');
    const packagePath = `/dav/vault/packages/p_${genesisId}.bin`;
    const packageRead = dav.requests.findIndex(row => row.path === packagePath && row.method === 'GET');
    const rootWrite = dav.requests.findIndex(row => row.path === '/dav/vault/pack-root.txt' && row.method === 'PUT');
    expect(packageRead).toBeGreaterThan(-1);
    expect(rootWrite).toBeGreaterThan(packageRead);
    expect([...dav.files.keys()].some(path => path.startsWith('/dav/scratch/'))).toBe(false);
    const start = dav.requests.length;
    const reader = new PackTransport(cfg, {}, dav.fetcher);
    const listing = await reader.list(material, vaultId);
    expect(listing.root.id).toBe(genesisId);
    expect(listing.tips.map(version => version.id)).toEqual([genesisId]);
    expect(dav.requests.slice(start).every(row => !row.path.includes('/packages/'))).toBe(true);
    expect(reader.stats).toMatchObject({ metadataBytes: expect.any(Number), packageDownloadBytes: 0, packageUploadBytes: 0 });
    expect(reader.stats.metadataBytes).toBeGreaterThan(0);
    await expect(reader.download(listing.root)).resolves.toEqual(payload);
    expect(reader.stats.packageDownloadBytes).toBe(4);
  });

  it('keeps the last commit visible during interrupted publication and retries an ambiguous commit once', async () => {
    const dav = server(), genesis = await genesisVersion();
    await new PackTransport(cfg, {}, dav.fetcher).create(material, genesis, payload, 'scratch');
    const uploaded = Uint8Array.of(88, 17, 0), id = 'b'.repeat(32);
    const version = await preparePackVersion({ id, vaultId, parents: [genesis.id], createdAt: 20, keyEpoch: 1 }, uploaded);
    const packageName = `/dav/vault/packages/p_${id}.bin`;
    const recordName = `/dav/vault/versions/v_${id}.txt`;
    let outage: 'before-record' | 'after-record' | undefined = 'before-record';
    const request: typeof fetch = async (target, init) => {
      const pathname = new URL(String(target)).pathname;
      if (outage === 'before-record' && init?.method === 'PUT' && pathname === recordName) throw new TypeError('Disconnected');
      const result = await dav.fetcher(target, init);
      if (outage === 'after-record' && init?.method === 'PUT' && pathname === recordName) throw new TypeError('Lost reply');
      return result;
    };
    const writer = new PackTransport({ ...cfg, writeVerified: true }, {}, request);
    const reader = new PackTransport(cfg, {}, dav.fetcher);
    await expect(writer.publish(material, version, uploaded)).rejects.toThrow(/无法连接/);
    expect(dav.files.has(packageName)).toBe(true);
    expect((await reader.list(material, vaultId)).tips.map(item => item.id)).toEqual([genesis.id]);
    outage = 'after-record';
    await expect(writer.publish(material, version, uploaded)).rejects.toThrow(/无法连接/);
    expect((await reader.list(material, vaultId)).tips.map(item => item.id)).toEqual([id]);
    outage = undefined;
    const before = dav.requests.length;
    await writer.publish(material, version, uploaded);
    expect(dav.requests.slice(before).every(row => row.method !== 'PUT' && row.path !== packageName)).toBe(true);
    expect([...dav.files.keys()].filter(path => path === recordName)).toHaveLength(1);
    await expect(reader.download(version)).resolves.toEqual(uploaded);
  });

  it('finds wrapping material for the newest epoch without a package and rejects a forged version record', async () => {
    const dav = server(), genesis = await genesisVersion();
    const writer = new PackTransport(cfg, {}, dav.fetcher);
    await writer.create(material, genesis, payload, 'scratch');
    const update = await preparePackVersion({ id: 'b'.repeat(32), vaultId, parents: [genesis.id],
      keyEpoch: 2, createdAt: 20, head: Uint8Array.of(3, 7) }, payload);
    await writer.publish(material, update, payload);
    const reader = new PackTransport(cfg, {}, dav.fetcher);
    const candidates = await reader.joinCandidates();
    expect(candidates).toEqual([update]);
    expect(reader.stats.packageDownloadBytes).toBe(0);
    await expect(reader.list(material, vaultId)).resolves.toMatchObject({ tips: [update] });
    const path = `/dav/vault/versions/v_${update.id}.txt`;
    const record = dav.files.get(path)!;
    // The operator can edit this metadata, but cannot produce a new record authentication tag.
    const body = new TextDecoder().decode(record.bytes);
    dav.files.set(path, { bytes: new TextEncoder().encode(body.replace(',20,2,', ',21,2,')), etag: '"forged"' });
    await expect(reader.list(material, vaultId)).rejects.toThrow(/无法认证/);
    expect(reader.stats.packageDownloadBytes).toBe(0);
  });

  it('keeps the active directory read-only when the actual final pack does not round-trip in scratch', async () => {
    const dav = server(), genesis = await genesisVersion();
    await new PackTransport(cfg, {}, dav.fetcher).create(material, genesis, payload, 'scratch');
    const request: typeof fetch = async (input, init) => {
      const path = new URL(String(input)).pathname;
      const response = await dav.fetcher(input, init);
      if (path.startsWith('/dav/scratch/') && path.endsWith('.bin') && init?.method === 'GET' &&
          response.ok && response.headers.get('Content-Length') === String(payload.length))
        return new Response(null, { headers: response.headers });
      return response;
    };
    const reader = new PackTransport(cfg, {}, request);
    const start = dav.requests.length;
    await expect(reader.verifyWrites(material, genesis, payload, 'scratch')).rejects.toThrow(/4 字节.*0 字节/);
    const update = await preparePackVersion({ id: 'b'.repeat(32), vaultId, parents: [genesis.id],
      keyEpoch: 1, createdAt: 20 }, payload);
    await expect(reader.publish(material, update, payload)).rejects.toThrow(/仍只读/);
    expect(dav.requests.slice(start).filter(row => row.path.startsWith('/dav/vault/') && ['MKCOL', 'PUT', 'DELETE'].includes(row.method))).toEqual([]);
    await expect(reader.list(material, vaultId)).resolves.toMatchObject({ tips: [genesis] });
  });

  it('requires the proof endpoint to list both sibling records alongside the last committed version', async () => {
    const dav = server(), genesis = await genesisVersion();
    const request: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'PROPFIND' && new URL(String(input)).pathname === '/dav/scratch/') {
        const records = [...dav.files.keys()].filter(path => path.startsWith('/dav/scratch/') && path.endsWith('.txt'));
        if (records.length >= 3) {
          const rows = (await response.text()).split('</D:response>');
          return new Response(rows.filter(row => !row.includes(`<D:href>${records[2]}</D:href>`)).join('</D:response>'), { status: 207 });
        }
      }
      return response;
    };
    await expect(new PackTransport(cfg, {}, request).create(material, genesis, payload, 'scratch'))
      .rejects.toThrow(/独立版本记录/);
    expect(dav.requests.filter(row => row.path.startsWith('/dav/vault/') && row.method !== 'PROPFIND')).toEqual([]);
    expect(dav.files.size).toBe(0);
  });

  it('uses only the root and one directory query at idle when known records have stable strong versions', async () => {
    const dav = server(), genesis = await genesisVersion();
    const writer = new PackTransport(cfg, {}, dav.fetcher);
    await writer.create(material, genesis, payload, 'scratch');
    const update = await preparePackVersion({ id: 'b'.repeat(32), vaultId, parents: [genesis.id],
      keyEpoch: 1, createdAt: 20 }, payload);
    await writer.publish(material, update, payload);
    const authenticated = await new PackTransport(cfg, {}, dav.fetcher).list(material, vaultId);
    const saved = structuredClone(authenticated.versions);
    const start = dav.requests.length;
    const reader = new PackTransport(cfg, {}, dav.fetcher);
    const current = await reader.list(material, vaultId, saved);
    expect(current.tips.map(item => item.id)).toEqual([update.id]);
    expect(dav.requests.slice(start)).toEqual([
      { method: 'GET', path: '/dav/vault/pack-root.txt' },
      { method: 'PROPFIND', path: '/dav/vault/versions/' },
    ]);
    expect(reader.stats.packageDownloadBytes).toBe(0);
  });

  it('checks the signed length against decoded ciphertext when HTTP encoding adds wire overhead', async () => {
    const dav = server(), genesis = await genesisVersion();
    await new PackTransport(cfg, {}, dav.fetcher).create(material, genesis, payload, 'scratch');
    const request: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'GET' && new URL(String(input)).pathname.endsWith('.bin') && response.ok) {
        // Browser fetch exposes decoded bytes but preserves the compressed wire length in the headers.
        response.headers.set('Content-Encoding', 'gzip');
        response.headers.set('Content-Length', '24');
      }
      return response;
    };
    const reader = new PackTransport(cfg, {}, request);
    const listing = await reader.list(material, vaultId);
    await expect(reader.download(listing.root)).resolves.toEqual(payload);
  });

  it('reports integrity failure for wrong staged ciphertext and permits retry on an HTTP 503', async () => {
    const dav = server(), genesis = await genesisVersion();
    await new PackTransport(cfg, {}, dav.fetcher).create(material, genesis, payload, 'scratch');
    const id = 'b'.repeat(32);
    const update = await preparePackVersion({ id, vaultId, parents: [genesis.id], keyEpoch: 1, createdAt: 20 }, payload);
    let readBack: 'corrupt' | 'unavailable' | 'normal' = 'corrupt';
    const request: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'GET' && new URL(String(input)).pathname.endsWith(`/p_${id}.bin`) && response.ok) {
        if (readBack === 'corrupt') return new Response(Uint8Array.of(0, 8, 18, 28), { headers: response.headers });
        if (readBack === 'unavailable') return new Response(null, { status: 503 });
      }
      return response;
    };
    const writer = new PackTransport({ ...cfg, writeVerified: true }, {}, request);
    await expect(writer.publish(material, update, payload)).rejects.toBeInstanceOf(PackIntegrityError);
    expect(dav.files.has(`/dav/vault/versions/v_${id}.txt`)).toBe(false);
    readBack = 'unavailable';
    await expect(writer.publish(material, update, payload)).rejects.not.toBeInstanceOf(PackIntegrityError);
    expect(dav.files.has(`/dav/vault/versions/v_${id}.txt`)).toBe(false);
    readBack = 'normal';
    await expect(writer.publish(material, update, payload)).resolves.toMatchObject(update);
  });

  it('checks again for an occupied target after the independent proof', async () => {
    const dav = server(), genesis = await genesisVersion();
    const legacyPath = '/dav/vault/head.bin';
    const request: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'GET' && new URL(String(input)).pathname.startsWith('/dav/scratch/') &&
        new URL(String(input)).pathname.endsWith('.bin') && response.status === 404) {
        dav.folders.add('/dav/vault/');
        dav.files.set(legacyPath, { bytes: Uint8Array.of(42), etag: '"legacy"' });
      }
      return response;
    };
    const writer = new PackTransport(cfg, {}, request);
    await expect(writer.create(material, genesis, payload, 'scratch')).rejects.toThrow(/已有文件/);
    expect(dav.requests.filter(row => row.path.startsWith('/dav/vault/') && row.method !== 'PROPFIND')).toEqual([]);
    expect([...dav.files.keys()]).toEqual([legacyPath]);
  });

  it('uses one root claim when two vaults create in the same directory simultaneously', async () => {
    const dav = server(), genesis = await genesisVersion();
    dav.folders.add('/dav/second-scratch/');
    const other = await preparePackVersion({ id: 'b'.repeat(32), vaultId: '34343434-3434-4343-8343-343434343434',
      parents: [], keyEpoch: 1, createdAt: 20, head: Uint8Array.of(1, 2) }, Uint8Array.of(88));
    const barrier = Promise.withResolvers<void>();
    let claims = 0;
    const request: typeof fetch = async (input, init) => {
      if (init?.method === 'PUT' && new URL(String(input)).pathname === '/dav/vault/pack-root.txt') {
        if (++claims === 2) barrier.resolve();
        await barrier.promise;
      }
      return dav.fetcher(input, init);
    };
    const first = new PackTransport(cfg, {}, request), second = new PackTransport(cfg, {}, request);
    const outcomes = await Promise.allSettled([
      first.create(material, genesis, payload, 'scratch'),
      second.create(material, other, Uint8Array.of(88), 'second-scratch'),
    ]);
    expect(outcomes.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.find(result => result.status === 'rejected')).toMatchObject({ reason: expect.any(Error) });
    const winner = outcomes[0]!.status === 'fulfilled' ? genesis : other;
    const reader = new PackTransport(cfg, {}, dav.fetcher);
    expect((await reader.list(material, winner.vaultId)).root.id).toBe(winner.id);
    expect(dav.files.has(`/dav/vault/packages/p_${genesis.id}.bin`)).toBe(true);
    expect(dav.files.has(`/dav/vault/packages/p_${other.id}.bin`)).toBe(true);
  });

  it('confirms an already committed root on the same attempt after its PUT response is lost', async () => {
    const dav = server(), genesis = await genesisVersion();
    const request: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'PUT' && new URL(String(input)).pathname === '/dav/vault/pack-root.txt' && response.ok)
        throw new TypeError('Connection ended before the reply');
      return response;
    };
    const transport = new PackTransport(cfg, {}, request);
    await expect(transport.create(material, genesis, payload, 'scratch')).resolves.toBeDefined();
    expect(dav.requests.filter(row => row.path === '/dav/vault/pack-root.txt' && row.method === 'PUT')).toHaveLength(1);
  });

  it('enumerates both simultaneous descendants and refuses a listing that omits an observed branch', async () => {
    const dav = server(), genesis = await genesisVersion();
    await new PackTransport(cfg, {}, dav.fetcher).create(material, genesis, payload, 'scratch');
    const ids = ['b'.repeat(32), 'c'.repeat(32)];
    const barrier = Promise.withResolvers<void>();
    let commits = 0;
    const request: typeof fetch = async (input, init) => {
      if (init?.method === 'PUT' && new URL(String(input)).pathname.startsWith('/dav/vault/versions/')) {
        if (++commits === 2) barrier.resolve();
        await barrier.promise;
      }
      return dav.fetcher(input, init);
    };
    await Promise.all(ids.map(async (id, at) => {
      const data = Uint8Array.of(11 + at);
      const version = await preparePackVersion({ id, vaultId, parents: [genesis.id], createdAt: 20, keyEpoch: 1 }, data);
      await new PackTransport({ ...cfg, writeVerified: true }, {}, request).publish(material, version, data);
    }));
    const reader = new PackTransport(cfg, {}, dav.fetcher);
    const known = structuredClone((await reader.list(material, vaultId)).versions);
    expect(known.filter(version => version.parents.length).map(version => version.id).sort()).toEqual(ids);
    dav.files.delete(`/dav/vault/versions/v_${ids[1]}.txt`);
    await expect(new PackTransport(cfg, {}, dav.fetcher).list(material, vaultId, known)).rejects.toThrow(/缺少已验证的版本/);
  });

  it('rechecks a previously authenticated record when the listing supplies no strong ETag', async () => {
    const dav = server(), genesis = await genesisVersion();
    const writer = new PackTransport(cfg, {}, dav.fetcher);
    await writer.create(material, genesis, payload, 'scratch');
    const id = 'b'.repeat(32);
    const version = await preparePackVersion({ id, vaultId, parents: [genesis.id], createdAt: 20, keyEpoch: 1 }, payload);
    await writer.publish(material, version, payload);
    const known = (await new PackTransport(cfg, {}, dav.fetcher).list(material, vaultId)).versions;
    const path = `/dav/vault/versions/v_${id}.txt`;
    const original = dav.files.get(path)!;
    dav.files.set(path, { ...original, bytes: Uint8Array.of(23) });
    const request: typeof fetch = async (input, init) => {
      const response = await dav.fetcher(input, init);
      if (init?.method === 'PROPFIND' && new URL(String(input)).pathname.endsWith('/versions/')) {
        const listing = (await response.text()).replace(/<D:getetag>[^<]+<\/D:getetag>/g, '');
        return new Response(listing, { status: 207 });
      }
      return response;
    };
    const reader = new PackTransport(cfg, {}, request);
    await expect(reader.list(material, vaultId, known)).rejects.toThrow(/版本记录无效/);
    expect(dav.requests.at(-1)).toEqual({ method: 'GET', path });
  });

  it('rejects an oversized version history before starting individual version downloads', async () => {
    const dav = server(), genesis = await genesisVersion();
    await new PackTransport(cfg, {}, dav.fetcher).create(material, genesis, payload, 'scratch');
    for (let at = 0; at < 2048; at++) {
      const id = at.toString(16).padStart(32, '0');
      dav.files.set(`/dav/vault/versions/v_${id}.txt`, { bytes: Uint8Array.of(0), etag: '"unread"' });
    }
    const reader = new PackTransport(cfg, {}, dav.fetcher), start = dav.requests.length;
    await expect(reader.list(material, vaultId)).rejects.toThrow(/超过自动检查上限/);
    expect(dav.requests.slice(start).filter(row => row.path.includes('/versions/v_'))).toEqual([]);
  });

  it('refuses to stage an additional package when the reading capacity is reserved for pending concurrent commits', async () => {
    const dav = server(), genesis = await genesisVersion();
    await new PackTransport(cfg, {}, dav.fetcher).create(material, genesis, payload, 'scratch');
    const key = Buffer.from(hkdfSync('sha256', material, vaultId, 'vault:webdav-pack:version-record:v1', 32));
    let previous = genesis.id;
    for (let at = 1; at < 1984; at++) {
      const id = at.toString(16).padStart(32, '0');
      const record = [1, id, vaultId, [previous], genesis.sha256, payload.length, 11 + at, 1, null];
      const mac = createHmac('sha256', key).update(JSON.stringify(record)).digest('base64');
      const bytes = new TextEncoder().encode(JSON.stringify([record, mac]));
      dav.files.set(`/dav/vault/versions/v_${id}.txt`, { bytes, etag: `"fixture-${at}"` });
      previous = id;
    }
    key.fill(0);
    const transport = new PackTransport({ ...cfg, writeVerified: true }, {}, dav.fetcher);
    const listing = await transport.list(material, vaultId);
    expect(listing.versions).toHaveLength(1984);
    const next = await preparePackVersion({ id: 'c'.repeat(32), vaultId, parents: [previous], keyEpoch: 1, createdAt: 2500 }, payload);
    const start = dav.requests.length;
    await expect(transport.publish(material, next, payload)).rejects.toThrow(/超过自动检查上限/);
    expect(dav.requests.slice(start).filter(row => row.method === 'PUT')).toEqual([]);
  });
});
