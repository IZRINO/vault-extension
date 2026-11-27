const { createServer } = require('node:http');
const { once } = require('node:events');

async function webdavFixture() {
  const objects = new Map();
  const folders = new Set(['/dav/', '/dav/scratch/']);
  const requests = [];
  const transfers = [];
  let generation = 0;
  const state = { failWal: false, rejectNextHeadWrite: false, password: 'fixture-app-password', stopNextProbe: undefined,
    packCommitFailure: undefined, beforePackCommit: undefined, beforePackList: undefined, failRootPut: false, rootAttempts: [] };
  const row = (path, folder, obj = objects.get(path)) => `<D:response><D:href>${path}</D:href><D:propstat>` +
    `<D:prop><D:resourcetype>${folder ? '<D:collection/>' : ''}</D:resourcetype>` +
    (obj ? `<D:getetag>${obj.tag}</D:getetag><D:getcontentlength>${obj.bytes.length}</D:getcontentlength>` : '') +
    '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const path = url.pathname;
    if (!/^\/dav\/[a-zA-Z0-9_./-]*$/.test(path) || url.search) { res.writeHead(404).end(); return; }
    requests.push({ method: req.method, path, ifMatch: req.headers['if-match'] });
    const transfer = { method: req.method, path, uploadBytes: 0, downloadBytes: 0 };
    transfers.push(transfer);
    const auth = 'Basic ' + Buffer.from('fixture-user:' + state.password).toString('base64');
    if (req.headers.authorization !== auth) { res.writeHead(401).end(); return; }
    if (req.method === 'PROPFIND') {
      for await (const chunk of req) transfer.uploadBytes += chunk.length;
      if (state.stopNextProbe) {
        const status = state.stopNextProbe;
        state.stopNextProbe = undefined;
        res.writeHead(status).end();
        return;
      }
      if (req.headers.depth !== '1' || !folders.has(path)) { res.writeHead(404).end(); return; }
      if (path.endsWith('/versions/')) await state.beforePackList?.();
      const child = key => key.startsWith(path) && key !== path && !key.slice(path.length).replace(/\/$/, '').includes('/');
      const rows = [row(path, true), ...[...folders].filter(child).map(key => row(key, true)),
        ...[...objects.keys()].filter(child).map(key => row(key, false))];
      const response = `<D:multistatus xmlns:D="DAV:">${rows.join('')}</D:multistatus>`;
      transfer.downloadBytes = Buffer.byteLength(response);
      res.writeHead(207, { 'Content-Type': 'application/xml; charset=utf-8' }).end(response);
    } else if (req.method === 'MKCOL') {
      if (folders.has(path)) { res.writeHead(405).end(); return; }
      const parent = path.slice(0, path.lastIndexOf('/', path.length - 2) + 1);
      if (!folders.has(parent)) { res.writeHead(409).end(); return; }
      folders.add(path); res.writeHead(201).end();
    } else if (req.method === 'GET') {
      const existing = objects.get(path);
      if (!existing) res.writeHead(404).end();
      else if (req.headers['if-none-match'] === existing.tag) res.writeHead(304).end();
      else {
        transfer.downloadBytes = existing.bytes.length;
        res.writeHead(200, { ETag: existing.tag, 'Content-Length': existing.bytes.length }).end(existing.bytes);
      }
    } else if (req.method === 'PUT' || req.method === 'DELETE') {
      if (req.method === 'PUT' && state.failWal && path.includes('/wal/')) { req.resume(); res.writeHead(503).end(); return; }
      const bytes = [];
      for await (const chunk of req) bytes.push(chunk);
      const body = Buffer.concat(bytes);
      transfer.uploadBytes = body.length;
      const packCommit = req.method === 'PUT' && /\/versions\/v_[a-f0-9]{32}\.txt$/.test(path);
      if (req.method === 'PUT' && path.endsWith('/pack-root.txt')) {
        state.rootAttempts.push(body);
        if (state.failRootPut) { state.failRootPut = false; res.writeHead(503).end(); return; }
      }
      if (packCommit) {
        if (state.packCommitFailure === 'before') { res.destroy(); return; }
        await state.beforePackCommit?.(path);
      }
      const match = req.headers['if-match'];
      const absent = req.headers['if-none-match'] === '*';
      const existing = objects.get(path); // Compare and commit against the state after the request body arrives.
      if ((match && match !== existing?.tag) || (absent && existing)) { res.writeHead(412).end(); return; }
      if (!match && (!absent || req.method === 'DELETE')) { res.writeHead(400).end(); return; }
      if (state.rejectNextHeadWrite && req.method === 'PUT' && match && path === '/dav/vault/head.bin') {
        state.rejectNextHeadWrite = false;
        res.writeHead(412).end();
        return;
      }
      if (req.method === 'DELETE') { objects.delete(path); res.writeHead(204).end(); return; }
      objects.set(path, { bytes: body, tag: `"fixture-${++generation}"` });
      if (packCommit && state.packCommitFailure === 'after') {
        state.packCommitFailure = undefined;
        res.destroy();
        return;
      }
      res.writeHead(201).end();
    } else { req.resume(); res.writeHead(405).end(); }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    state, requests, transfers, objects, folders,
    config: { provider: 'custom', base: `http://127.0.0.1:${server.address().port}/dav/`, folder: 'vault',
      username: 'fixture-user', password: state.password, confirmHttp: true },
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

module.exports = { webdavFixture };
