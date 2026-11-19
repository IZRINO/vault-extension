const { createServer } = require('node:http');
const { once } = require('node:events');

async function webdavFixture() {
  const objects = new Map();
  const folders = new Set(['/dav/', '/dav/scratch/']);
  const requests = [];
  let generation = 0;
  const state = { failWal: false, rejectNextHeadWrite: false };
  const row = (path, folder, obj = objects.get(path)) => `<D:response><D:href>${path}</D:href><D:propstat>` +
    `<D:prop><D:resourcetype>${folder ? '<D:collection/>' : ''}</D:resourcetype>` +
    (obj ? `<D:getetag>${obj.tag}</D:getetag><D:getcontentlength>${obj.bytes.length}</D:getcontentlength>` : '') +
    '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const path = url.pathname;
    if (!/^\/dav\/[a-zA-Z0-9_./-]*$/.test(path) || url.search) { res.writeHead(404).end(); return; }
    const auth = 'Basic ' + Buffer.from('fixture-user:fixture-app-password').toString('base64');
    if (req.headers.authorization !== auth) { res.writeHead(401).end(); return; }
    requests.push({ method: req.method, path, ifMatch: req.headers['if-match'] });
    if (req.method === 'PROPFIND') {
      req.resume();
      if (req.headers.depth !== '1' || !folders.has(path)) { res.writeHead(404).end(); return; }
      const child = key => key.startsWith(path) && key !== path && !key.slice(path.length).replace(/\/$/, '').includes('/');
      const rows = [row(path, true), ...[...folders].filter(child).map(key => row(key, true)),
        ...[...objects.keys()].filter(child).map(key => row(key, false))];
      res.writeHead(207, { 'Content-Type': 'application/xml; charset=utf-8' })
        .end(`<D:multistatus xmlns:D="DAV:">${rows.join('')}</D:multistatus>`);
    } else if (req.method === 'MKCOL') {
      if (folders.has(path)) { res.writeHead(405).end(); return; }
      folders.add(path); res.writeHead(201).end();
    } else if (req.method === 'GET') {
      const existing = objects.get(path);
      if (!existing) res.writeHead(404).end();
      else if (req.headers['if-none-match'] === existing.tag) res.writeHead(304).end();
      else res.writeHead(200, { ETag: existing.tag }).end(existing.bytes);
    } else if (req.method === 'PUT' || req.method === 'DELETE') {
      if (req.method === 'PUT' && state.failWal && path.includes('/wal/')) { req.resume(); res.writeHead(503).end(); return; }
      const bytes = [];
      for await (const chunk of req) bytes.push(chunk);
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
      objects.set(path, { bytes: Buffer.concat(bytes), tag: `"fixture-${++generation}"` });
      res.writeHead(201).end();
    } else { req.resume(); res.writeHead(405).end(); }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    state, requests, objects,
    config: { provider: 'custom', base: `http://127.0.0.1:${server.address().port}/dav/`, folder: 'vault',
      username: 'fixture-user', password: 'fixture-app-password', confirmHttp: true },
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

module.exports = { webdavFixture };
