import { describe, expect, it, vi } from 'vitest';
import { WebDavClient, WebDavContentError, WebDavHttpError, WebDavStop, type WebDavConfig } from './webdav';

const config: WebDavConfig = { url: 'https://storage.example.test/dav/My%20Vault/', username: 'test', password: 'test' };
const record = `versions/v_${'2'.repeat(32)}.txt`;
const data = Uint8Array.of(3, 1, 4);

type File = { bytes: Uint8Array<ArrayBuffer>; tag: string };
type Call = { method: string; path: string; headers: Headers };
function davServer(intercept?: (call: Call, files: Map<string, File>) => Response | undefined) {
  const files = new Map<string, File>();
  const calls: Call[] = [];
  const request: typeof fetch = async (url, init) => {
    const href = String(url);
    expect(href.startsWith(config.url)).toBe(true);
    const path = href.slice(config.url.length);
    const headers = new Headers(init?.headers), method = init!.method!;
    const call = { method, path, headers };
    calls.push(call);
    const override = intercept?.(call, files);
    if (override) return override;
    const file = files.get(path);
    if (method === 'HEAD') {
      expect(init!.body).toBeUndefined();
      return file ? new Response(null, { headers: { ETag: file.tag, 'Content-Length': String(file.bytes.length) } })
        : new Response(null, { status: 404 });
    }
    if (method === 'GET') return file ? new Response(file.bytes, { headers: { ETag: file.tag } }) : new Response(null, { status: 404 });
    if (method === 'PUT') {
      if (file && headers.get('If-None-Match') === '*') return new Response(null, { status: 412 });
      files.set(path, { bytes: new Uint8Array(init!.body as Uint8Array), tag: '"uploaded"' });
      return new Response(null, { status: file ? 204 : 201 });
    }
    if (method === 'MOVE') {
      const destination = headers.get('Destination')!;
      expect(destination.startsWith(config.url)).toBe(true);
      const target = destination.slice(config.url.length);
      if (!file || headers.get('If-Match') !== file.tag || (files.has(target) && headers.get('Overwrite') === 'F'))
        return new Response(null, { status: 412 });
      files.set(target, file);
      files.delete(path);
      return new Response(null, { status: 201 });
    }
    throw Error(`Unexpected method ${method}`);
  };
  return { files, calls, request };
}

describe('immutable whole-pack creation by WebDAV MOVE', () => {
  it('stages and reads back bytes in the same directory, then moves once without replacement and verifies the result', async () => {
    const { files, calls, request } = davServer();
    const client = new WebDavClient(config, {}, request);
    await expect(client.createByMove(record, data)).resolves.toBe(true);
    const upload = calls.find(c => c.method === 'PUT')!;
    const move = calls.find(c => c.method === 'MOVE')!;
    expect(upload.path).toMatch(/^versions\/pack_verify_[0-9a-f]{32}\.txt$/);
    expect(upload.headers.get('If-None-Match')).toBe('*');
    expect(move.path).toBe(upload.path);
    expect([move.headers.get('Destination'), move.headers.get('Overwrite'), move.headers.get('If-Match')])
      .toEqual([config.url + record, 'F', '"uploaded"']);
    expect(calls.map(c => [c.method, c.path])).toEqual([
      ['HEAD', upload.path], ['PUT', upload.path], ['GET', upload.path], ['MOVE', upload.path],
      ['HEAD', upload.path], ['GET', record],
    ]);
    expect([...files.keys()]).toEqual([record]);
    expect(files.get(record)!.bytes).toEqual(data);
  });

  it('returns a collision when another device already has a file and leaves both the winner and staging file intact', async () => {
    const { files, calls, request } = davServer();
    const winner = { bytes: Uint8Array.of(9, 8, 7, 6, 5), tag: '"first-device"' };
    files.set(record, winner);
    const retained: [string, string][] = [];
    await expect(new WebDavClient(config, {}, request).createByMove(record, data,
      (name, etag) => { retained.push([name, etag]); })).resolves.toBe(false);
    expect(files.get(record)).toEqual(winner);
    const staged = calls.find(c => c.method === 'PUT')!.path;
    expect(retained).toEqual([[staged, '"uploaded"']]);
    expect(files.get(staged)?.bytes).toEqual(data);
    expect(calls.slice(-2).map(c => [c.method, c.path])).toEqual([['GET', staged], ['HEAD', record]]);
    expect(calls.some(c => c.method === 'DELETE')).toBe(false);
  });

  it.each(['source disappeared', 'source tag changed', 'source bytes changed', 'missing destination'])(
    'rejects a 412 that does not prove a destination collision: %s', async cause => {
      const { files, request } = davServer(({ method, path }, remote) => {
        if (method !== 'MOVE') return;
        if (cause === 'source disappeared') remote.delete(path);
        if (cause === 'source tag changed') remote.get(path)!.tag = '"another-device"';
        if (cause === 'source bytes changed') remote.get(path)!.bytes = Uint8Array.of(9);
        return new Response(null, { status: 412 });
      });
      if (cause !== 'missing destination') files.set(record, { bytes: Uint8Array.of(8), tag: '"first"' });
      const retained: string[] = [];
      await expect(new WebDavClient(config, {}, request).createByMove(record, data,
        name => { retained.push(name); })).rejects.toBeInstanceOf(WebDavContentError);
      expect(retained).toEqual([]);
    },
  );

  it.each([200, 202, 204, 207])('rejects an ambiguous successful MOVE response (%i) as a failed guarantee', async status => {
    const { calls, request } = davServer(({ method }) => method === 'MOVE' ? new Response(null, { status }) : undefined);
    await expect(new WebDavClient(config, {}, request).createByMove(record, data)).rejects.toBeInstanceOf(WebDavContentError);
    expect(calls.at(-1)?.method).toBe('MOVE');
  });

  it.each([405, 501, 503])('preserves HTTP status %i when the service declines a MOVE', async status => {
    const { calls, request } = davServer(({ method }) => method === 'MOVE' ? new Response(null, { status }) : undefined);
    const failure = await new WebDavClient(config, {}, request).createByMove(record, data).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(WebDavHttpError);
    expect(failure).toMatchObject({ status });
    expect(calls.at(-1)?.method).toBe('MOVE');
  });

  it.each([401, 403, 429])('propagates the shared stop on HTTP %i and sends no cleanup or further requests', async status => {
    const { calls, request } = davServer(({ method }) => method === 'MOVE' ? new Response(null, { status }) : undefined);
    const stops: number[] = [];
    const client = new WebDavClient(config, { stop: s => { stops.push(s); } }, request);
    await expect(client.createByMove(record, data)).rejects.toBeInstanceOf(WebDavStop);
    expect(stops).toEqual([status]);
    expect(calls.at(-1)?.method).toBe('MOVE');
  });

  it.each([200, 204])('stops when the staging PUT reports replacement (%i) after a 404', async status => {
    const { calls, request } = davServer(({ method, path }, remote) => {
      if (method !== 'PUT') return;
      remote.set(path, { bytes: data, tag: '"other-device"' });
      return new Response(null, { status });
    });
    await expect(new WebDavClient(config, {}, request).createByMove(record, data)).rejects.toBeInstanceOf(WebDavContentError);
    expect(calls.map(c => c.method)).toEqual(['HEAD', 'PUT']);
  });

  it.each(['strong tag missing', 'different bytes'])('stops before MOVE if the staged object has %s', async fault => {
    const { request, calls } = davServer(({ method, path }, remote) => {
      const entry = remote.get(path);
      if (method === 'GET' && entry)
        return new Response(fault === 'different bytes' ? Uint8Array.of(8) : entry.bytes,
          { headers: { ETag: fault === 'different bytes' ? entry.tag : 'W/"bad"' } });
    });
    await expect(new WebDavClient(config, {}, request).createByMove(record, data)).rejects.toBeInstanceOf(WebDavContentError);
    expect(calls.map(c => c.method)).toEqual(['HEAD', 'PUT', 'GET']);
  });

  it.each(['source retained', 'destination missing', 'destination damaged'])('rejects 201 followed by %s', async fault => {
    const { request, calls } = davServer(({ method, path }, remote) => {
      if (method !== 'MOVE') return;
      const source = remote.get(path)!;
      if (fault !== 'destination missing') remote.set(record,
        fault === 'destination damaged' ? { ...source, bytes: Uint8Array.of(42) } : source);
      if (fault !== 'source retained') remote.delete(path);
      return new Response(null, { status: 201 });
    });
    await expect(new WebDavClient(config, {}, request).createByMove(record, data)).rejects.toBeInstanceOf(WebDavContentError);
    expect(calls.some(c => c.method === 'DELETE' || (c.method === 'PUT' && c.path === record))).toBe(false);
  });

  it.each(['source', 'destination'])('rejects a partial HTTP response as a failed MOVE integrity check on the %s', async stage => {
    let moved = false;
    const { request } = davServer(({ method, path }) => {
      if (method === 'MOVE') moved = true;
      if (moved && (stage === 'source' ? method === 'HEAD' && path !== record : method === 'GET' && path === record))
        return new Response(method === 'HEAD' ? null : Uint8Array.of(1), { status: 206 });
    });
    await expect(new WebDavClient(config, {}, request).createByMove(record, data)).rejects.toBeInstanceOf(WebDavContentError);
  });

  it('only stages root, record and package destinations or their exact reserved proof names in the same directory', async () => {
    const id = 'b'.repeat(32);
    for (const [target, source] of [
      ['pack-root.txt', /^pack_verify_[0-9a-f]{32}\.txt$/],
      [`packages/p_${id}.json`, /^packages\/pack_verify_[0-9a-f]{32}\.json$/],
      [`packages/p_${id}.bin`, /^packages\/pack_verify_[0-9a-f]{32}\.bin$/],
      [`pack_verify_${id}.txt`, /^pack_verify_[0-9a-f]{32}\.txt$/],
      [`versions/pack_verify_${id}.txt`, /^versions\/pack_verify_[0-9a-f]{32}\.txt$/],
      [`packages/pack_verify_${id}.json`, /^packages\/pack_verify_[0-9a-f]{32}\.json$/],
    ] as const) {
      const { request, calls } = davServer();
      await expect(new WebDavClient(config, {}, request).createByMove(target, data)).resolves.toBe(true);
      const put = calls.find(c => c.method === 'PUT')!;
      expect(put.path).toMatch(source);
      expect(put.path).not.toBe(target);
    }
    const { request, calls } = davServer();
    const client = new WebDavClient(config, {}, request);
    for (const name of ['head.bin', `wal/${'a'.repeat(14)}_12345678_${'b'.repeat(14)}.bin`, 'versions/', `packages/v_${id}.txt`,
      `versions/pack_verify_${id}.json`, `versions/../v_${id}.txt`, `${record}\n`, `https://other.example.test/${record}`])
      await expect(client.createByMove(name, data)).rejects.toBeInstanceOf(WebDavContentError);
    expect(calls).toHaveLength(0);
  });

  it('stops before PUT if the random source already exists and refuses a source identical to the proof target', async () => {
    const uuid = 'bbbbb000-aaaa-4ccc-8111-111111111111';
    const source = `versions/pack_verify_${uuid.replaceAll('-', '')}.txt`;
    const uuidMock = vi.spyOn(crypto, 'randomUUID').mockReturnValue(uuid);
    try {
      const { request, calls, files } = davServer();
      const occupied = { bytes: Uint8Array.of(9), tag: '"old"' };
      files.set(source, occupied);
      const client = new WebDavClient(config, {}, request);
      await expect(client.createByMove(record, data)).rejects.toBeInstanceOf(WebDavContentError);
      await expect(client.createByMove(source, data)).rejects.toBeInstanceOf(WebDavContentError);
      expect(calls.map(c => [c.method, c.path])).toEqual([['HEAD', source]]);
      expect(files.get(source)).toEqual(occupied);
    } finally { uuidMock.mockRestore(); }
  });

  it('honors lock between the staging upload and MOVE', async () => {
    const locked = new AbortController();
    const { request, calls } = davServer(({ method }) => {
      if (method === 'PUT') locked.abort();
      return undefined;
    });
    const client = new WebDavClient(config, { signal: locked.signal }, request);
    await expect(client.createByMove(record, data)).rejects.toThrow('已锁定');
    expect(calls.map(c => c.method)).toEqual(['HEAD', 'PUT']);
  });
});
