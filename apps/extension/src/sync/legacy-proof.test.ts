import { expect, it, vi } from 'vitest';
import { probeWebDav, proveLegacyWritesInVault, WebDavClient, type WebDavConfig } from './webdav';

const url = 'https://dav.example/dav/vault/';
const config: WebDavConfig = { url, username: 'fixture', password: 'fixture password' };
const nonce = '11111111-1111-4111-8111-111111111111';
const otherProbe = `verify_${nonce.replaceAll('-', '')}.bin`;
const otherPackProbe = `pack_${otherProbe}`;
const snap = 'snap_11111111111111_11111111_11111111111111.bin';

function legacyServer() {
  const objects = new Map<string, { bytes: Uint8Array<ArrayBuffer>; etag: string; stale?: string }>(
    ['head.bin', snap, otherProbe].map(name => [name, { bytes: Uint8Array.of(9, 8, 7), etag: `"${name}"` }]),
  );
  const calls: { name: string; method: string; match: string | null; absent: string | null }[] = [];
  let etag = 0;
  const fetcher: typeof fetch = async (input, init) => {
    const href = String(input);
    if (!href.startsWith(url)) throw new Error('Request escaped vault directory');
    const name = href.slice(url.length), method = init?.method ?? 'GET';
    const headers = new Headers(init?.headers), match = headers.get('If-Match'), absent = headers.get('If-None-Match');
    calls.push({ name, method, match, absent });
    const object = objects.get(name);
    if (method === 'GET') {
      if (!object) return new Response(null, { status: 404 });
      return new Response(object.bytes, { headers: { ETag: object.etag } });
    }
    if (method === 'PUT') {
      if (absent === '*' && object || match !== null && match !== object?.etag) return new Response(null, { status: 412 });
      objects.set(name, { bytes: new Uint8Array(init?.body as Uint8Array<ArrayBuffer>), etag: `"probe-${++etag}"`, stale: object?.etag });
      return new Response(null, { status: object ? 204 : 201 });
    }
    if (method === 'DELETE') {
      if (object && match !== object.etag) return new Response(null, { status: 412 });
      objects.delete(name);
      return new Response(null, { status: object ? 204 : 404 });
    }
    throw new Error('Unexpected request');
  };
  return { objects, calls, fetcher };
}

it('verifies legacy conditions in the authenticated directory and cleans up only its own file', async () => {
  const server = legacyServer();
  const original = [...server.objects];
  await expect(proveLegacyWritesInVault(config, {}, server.fetcher)).resolves.toBe(true);
  expect([...server.objects]).toEqual(original);
  const [name] = [...new Set(server.calls.map(call => call.name))];
  expect(name).toMatch(/^verify_[0-9a-f]{32}\.bin$/);
  expect(original.some(([file]) => file === name)).toBe(false);
  expect(server.calls.every(call => call.name === name)).toBe(true);
  expect(server.calls[0]).toMatchObject({ method: 'GET' });
  expect(server.calls.filter(call => call.method === 'PUT').map(call => call.absent)).toEqual(['*', '*', null, null, null]);
  const deletes = server.calls.filter(call => call.method === 'DELETE').map(call => call.match);
  expect(deletes).toEqual([expect.stringMatching(/^"never-/), '"probe-1"', '"probe-2"']);
  expect(server.calls.at(-1)).toMatchObject({ method: 'GET' });
});

it('does not mutate a probe left by another operation even when given the same name', async () => {
  const server = legacyServer();
  const uuid = vi.spyOn(crypto, 'randomUUID').mockReturnValue(nonce);
  try {
    await expect(proveLegacyWritesInVault(config, {}, server.fetcher)).rejects.toThrow(/同名测试文件已存在/);
  } finally { uuid.mockRestore(); }
  expect(server.calls).toEqual([{ name: otherProbe, method: 'GET', match: null, absent: null }]);
});

it('refuses a server that deletes using a stale ETag', async () => {
  const server = legacyServer();
  const fetcher: typeof fetch = async (input, init) => {
    const name = String(input).slice(url.length), object = server.objects.get(name);
    if (init?.method === 'DELETE' && object?.stale && object.stale === new Headers(init.headers).get('If-Match')) {
      server.objects.delete(name);
      return new Response(null, { status: 204 });
    }
    return server.fetcher(input, init);
  };
  const original = [...server.objects];
  await expect(proveLegacyWritesInVault(config, {}, fetcher)).rejects.toThrow(/过期版本标签删除/);
  expect([...server.objects]).toEqual(original);
});

it('stops without deleting when readback no longer proves file ownership', async () => {
  const server = legacyServer();
  const bytes = new Uint8Array(32).fill(0xa5);
  let replacement: string | undefined;
  const fetcher: typeof fetch = async (input, init) => {
    const name = String(input).slice(url.length);
    if (init?.method === 'GET' && !replacement && server.objects.has(name)) {
      replacement = name;
      server.objects.set(name, { bytes, etag: '"another-client"' });
    }
    return server.fetcher(input, init);
  };
  await expect(proveLegacyWritesInVault(config, {}, fetcher)).rejects.toThrow(/内容.*不符/);
  expect(server.calls.some(call => call.method === 'DELETE')).toBe(false);
  expect(server.objects.get(replacement!)).toEqual({ bytes, etag: '"another-client"' });
});

it('does not mistake exact reserved probe files for pack layout entries or ignore unrelated files', async () => {
  const row = (path: string, collection = false) =>
    `<d:response><d:href>${url}${path}</d:href><d:propstat><d:prop><d:resourcetype>${collection ? '<d:collection/>' : ''}</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
  const list = (...rows: string[]) => async () => new Response(`<d:multistatus xmlns:d="DAV:">${rows.join('')}</d:multistatus>`, { status: 207 });
  const pack = [row('', true), row('pack-root.txt'), row('versions/', true), row('packages/', true)];
  await expect(probeWebDav(config, {}, list(...pack, row(otherPackProbe))))
    .resolves.toMatchObject({ kind: 'existing', format: 'pack', writeAllowed: false });
  const legacy = [row('', true), row('head.bin'), row(snap), row('wal/', true)];
  await expect(probeWebDav(config, {}, list(...legacy, row(otherProbe)))).resolves.toMatchObject({ kind: 'existing' });
  await expect(probeWebDav(config, {}, list(row('', true), row(otherProbe)))).resolves.toMatchObject({ kind: 'incomplete' });
  await expect(probeWebDav(config, {}, list(...pack, row('pack_verify_notes.txt')))).resolves.toMatchObject({ kind: 'incomplete' });
  await expect(probeWebDav(config, {}, list(...pack, row(`${otherPackProbe}/`, true)))).resolves.toMatchObject({ kind: 'incomplete' });
});

it('accepts reserved pack paths only with the extension for each subdirectory', async () => {
  const fetcher = vi.fn(async () => new Response(null, { status: 404 }));
  const client = new WebDavClient(config, {}, fetcher);
  const text = otherPackProbe.replace('.bin', '.txt');
  await expect(client.get(`versions/${text}`, 32)).resolves.toBeUndefined();
  await expect(client.get(`packages/${otherPackProbe}`, 32)).resolves.toBeUndefined();
  await expect(client.get(`versions/${otherPackProbe}`, 32)).rejects.toThrow();
  await expect(client.get(`packages/${text}`, 32)).rejects.toThrow();
  await expect(client.get(`versions/nested/${text}`, 32)).rejects.toThrow();
  await expect(client.get(`packages/${otherProbe}`, 32)).rejects.toThrow();
  expect(fetcher).toHaveBeenCalledTimes(2);
});
