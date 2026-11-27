import { describe, expect, it, vi } from 'vitest';
import { probeWebDav, webDavConfig, WebDavClient, WebDavStop, type WebDavInput } from './webdav';

const input: WebDavInput = { provider: 'koofr', base: '', folder: 'Vault test', username: 'test@example.com', password: 'Fixture app password' };
const endpoint = 'https://app.koofr.net/dav/Koofr/Vault%20test/';
const row = (href: string, collection = false, status = 200) =>
  `<D:response><D:href>${href}</D:href><D:propstat><D:prop><D:resourcetype>${collection ? '<D:collection/>' : ''}</D:resourcetype><D:getetag>"tag"</D:getetag></D:prop><D:status>HTTP/1.1 ${status} Fixture</D:status></D:propstat></D:response>`;
const root = row('/dav/Koofr/Vault%20test/', true);
const xml = (...rows: string[]) => `<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">${rows.join('')}</D:multistatus>`;
const response = (...rows: string[]) => new Response(xml(...rows), { status: 207, headers: { Date: new Date(1_000_045_000).toUTCString() } });

describe('WebDAV file download', () => {
  it('reports the expected and received byte counts when a successful GET delivers an empty body', async () => {
    const request = async () => new Response(null, { status: 200, headers: { 'Content-Length': '32' } });
    const client = new WebDavClient(webDavConfig(input), {}, request);
    await expect(client.get('head.bin', 64)).rejects.toThrow(/32 字节.*0 字节/);
  });
  it('reports how many bytes arrived when the browser signals a truncated transfer', async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(Uint8Array.of(1, 2, 3)); },
      pull(controller) { controller.error(new TypeError('network error')); },
    });
    const client = new WebDavClient(webDavConfig(input), {}, async () =>
      new Response(body, { headers: { 'Content-Length': '32' } }));
    await expect(client.get('head.bin', 64)).rejects.toThrow(/32 字节.*3 字节/);
  });
  it('accepts a decoded response whose wire length differs from its file size', async () => {
    const file = Uint8Array.of(4, 8, 15);
    const client = new WebDavClient(webDavConfig(input), {}, async () => new Response(file, { headers: {
      'Content-Encoding': 'gzip', 'Content-Length': '23', ETag: '"compressed"',
    } }));
    await expect(client.get('head.bin', 64)).resolves.toEqual({ bytes: file, etag: '"compressed"' });
  });
  it('identifies a Koofr short download with its support request ID', async () => {
    const requestId = '0a1bcdef-1234-4321-8899-0123456789ab';
    const request = async () => new Response(null, { headers: { 'Content-Length': '32', 'X-Request-ID': requestId } });
    const client = new WebDavClient(webDavConfig(input), {}, request);
    await expect(client.get('head.bin', 64)).rejects.toThrow(
      new RegExp(`32 字节.*0 字节.*Koofr.*文件类型.*${requestId}`),
    );
  });
  it.each([
    ['https://other.example/dav/', 'x-private-diagnostic'],
    ['https://app.koofr.net.example/dav/Koofr/', 'x-private-diagnostic'],
    ['https://app.koofr.net/dav/Koofr/', 'x-private-diagnostic'],
  ])('keeps arbitrary response header text out of the short-read error for %s', async (url, identifier) => {
    const request = async () => new Response(null, { headers: { 'Content-Length': '32', 'X-Request-ID': identifier } });
    const client = new WebDavClient({ url, username: 'test', password: 'fixture' }, {}, request);
    const failure = await client.get('head.bin', 64).then(() => '', (error: Error) => error.message);
    expect(failure).toContain('实际收到 0 字节');
    expect(failure).not.toContain(identifier);
    expect(failure.includes('Koofr')).toBe(url.startsWith('https://app.koofr.net/'));
  });
});

describe('read-only WebDAV connection', () => {
  it('uses the exact provider collection and never tests write access with a mutation', async () => {
    const request = vi.fn(async () => response(root));
    const result = await probeWebDav(webDavConfig(input), {}, request, () => 1_000_000_000);
    expect(result).toEqual({ kind: 'empty', offsetSeconds: 45, writeAllowed: false });
    expect(request).toHaveBeenCalledExactlyOnceWith(endpoint, expect.objectContaining({
      method: 'PROPFIND', redirect: 'error', credentials: 'omit', referrerPolicy: 'no-referrer',
      headers: expect.objectContaining({ Depth: '1', Authorization: expect.stringMatching(/^Basic /) }),
    }));
  });
  it('distinguishes an existing vault, incomplete vault, unavailable target and unproven data', async () => {
    const config = webDavConfig(input);
    const head = row(endpoint + 'head.bin'), snap = row(endpoint + 'snap_abc.bin'), wal = row(endpoint + 'wal/', true);
    await expect(probeWebDav(config, {}, async () => response(root, head, snap, wal))).resolves.toMatchObject({ kind: 'existing', writeAllowed: false });
    await expect(probeWebDav(config, {}, async () => response(root, snap))).resolves.toMatchObject({ kind: 'incomplete' });
    await expect(probeWebDav(config, {}, async () => response(root, row(endpoint + 'other.txt')))).resolves.toMatchObject({ kind: 'incomplete' });
    await expect(probeWebDav(config, {}, async () => new Response(null, { status: 404 }))).resolves.toMatchObject({ kind: 'missing' });
    await expect(probeWebDav(config, {}, async () => response(root, row(endpoint + 'denied', false, 403)))).rejects.toMatchObject({ status: 403 });
    await expect(probeWebDav(config, {}, async () => response(root, row('https://other.example/foreign')))).rejects.toThrow('目录');
    await expect(probeWebDav(config, {}, async () => response(row('/DAV/Koofr/', true)))).rejects.toThrow('目录');
    await expect(probeWebDav(config, {}, async () => new Response('<!DOCTYPE x><x/>', { status: 207 }))).rejects.toThrow('目录');
  });
  it.each([401, 403, 429])('stops immediately on HTTP %s and does not issue a second request', async status => {
    const request = vi.fn(async () => new Response(null, { status }));
    const stop = vi.fn();
    await expect(probeWebDav(webDavConfig(input), { stop }, request)).rejects.toBeInstanceOf(WebDavStop);
    expect(stop).toHaveBeenCalledExactlyOnceWith(status);
    expect(request).toHaveBeenCalledTimes(1);
  });
  it('requires HTTPS, with explicitly confirmed loopback-only HTTP for debugging', () => {
    const custom = { ...input, provider: 'custom' as const };
    for (const base of ['http://localhost:8787/DAV/', 'http://192.168.0.1/dav/', 'https://username@example.com/dav', 'https://example.com/dav/?account=1', 'https://example.com/a/%2f/']) {
      expect(() => webDavConfig({ ...custom, base })).toThrow();
    }
    expect(() => webDavConfig({ ...custom, base: 'http://192.168.0.1/', confirmHttp: true })).toThrow();
    expect(webDavConfig({ ...custom, base: 'http://127.0.0.1:8081/DaV', confirmHttp: true }).url).toBe('http://127.0.0.1:8081/DaV/Vault%20test/');
    expect(() => webDavConfig({ ...input, folder: '..' })).toThrow();
    expect(() => webDavConfig({ ...input, username: 'wrong:login' })).toThrow();
  });
  it('uses only a bounded HTTPS Date sample and lets lock cancel an in-flight test', async () => {
    const conf = webDavConfig(input);
    const fetchDate = (date: string | null) => async () => new Response(xml(root), { status: 207, headers: date ? { Date: date } : {} });
    const now = () => 1_000_000_000;
    await expect(probeWebDav(conf, {}, fetchDate(new Date(now() + 14000).toUTCString()), now)).resolves.toMatchObject({ offsetSeconds: null });
    await expect(probeWebDav(conf, {}, fetchDate(new Date(now() + 15000).toUTCString()), now)).resolves.toMatchObject({ offsetSeconds: 15 });
    await expect(probeWebDav(conf, {}, fetchDate('not a timestamp'), now)).resolves.toMatchObject({ offsetSeconds: null });
    await expect(probeWebDav(conf, {}, fetchDate(null), now)).resolves.toMatchObject({ offsetSeconds: null });
    const lock = new AbortController();
    const guard = vi.fn();
    await expect(probeWebDav(conf, { signal: lock.signal, check: guard }, async () => {
      lock.abort(); return response(root);
    })).rejects.toThrow('已锁定');
  });
  it('refreshes the clock sample on a regular pack version poll and expires an invalid sample', async () => {
    const now = () => 1_000_000_000;
    const folder = row(endpoint + 'versions/', true);
    const requests = vi.fn().mockResolvedValueOnce(response(folder)).mockResolvedValueOnce(new Response(xml(folder), { status: 207 }));
    const observeClock = vi.fn();
    const client = new WebDavClient(webDavConfig(input), { observeClock }, requests, now);
    await client.list('versions/');
    await client.list('versions/');
    expect(observeClock.mock.calls).toEqual([[45, now()], [null, now()]]);
    expect(requests.mock.calls.map(([url]) => url)).toEqual([endpoint + 'versions/', endpoint + 'versions/']);
  });
});
