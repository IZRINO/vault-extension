const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const { createHash, createPublicKey, randomBytes, verify } = require('node:crypto');
const { createServer } = require('node:http');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { waitForBuiltInFilters } = require('./browser-fixtures.cjs');
const { webdavFixture } = require('./webdav-fixture.cjs');

const extension = path.resolve(process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const browsers = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const master = 'Local-Passkey-E2E-Fixture#2026';
const sourceMaster = 'Independent-Source-E2E-Fixture#2026';
const filePassword = 'Local-Pack-E2E-Fixture#2026';
const hash = data => createHash('sha256').update(data).digest();
const decode = data => Buffer.from(data, 'base64url');

function readCbor(bytes) {
  let offset = 0;
  function take(size) {
    assert(offset + size <= bytes.length, 'Truncated attestation CBOR');
    const value = bytes.subarray(offset, offset + size);
    offset += size;
    return value;
  }
  function value() {
    const tag = take(1)[0];
    let length = tag & 31;
    if (length === 24) length = take(1)[0];
    else if (length === 25) length = take(2).readUInt16BE();
    else assert(length <= 23, 'Unsupported CBOR length in the local verifier');
    switch (tag >> 5) {
      case 0: return length;
      case 1: return -1 - length;
      case 2: return take(length);
      case 3: return take(length).toString('utf8');
      case 5: {
        const fields = new Map();
        while (length--) {
          const key = value();
          assert(!fields.has(key), 'Duplicate CBOR map key');
          fields.set(key, value());
        }
        return fields;
      }
      default: assert.fail(`Unexpected CBOR type: ${tag >> 5}`);
    }
  }
  const result = value();
  assert.equal(offset, bytes.length);
  return result;
}

async function fixture() {
  const html = () => {
    const challenge = randomBytes(32).toString('base64url');
    return `<!doctype html>
      <html><title>Local WebAuthn verifier</title><body>
      <label>Account <input type="text" autocomplete="username webauthn"></label>
      <button id="start">Start ceremony</button>
      <output></output>
      <script>
      window.challenge = '${challenge}';
      const from64 = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
      window.settings = { kind: 'assert', conditional: false, uv: 'discouraged' };
      window.start = async () => {
        window.outcome = undefined;
        const { kind, alg, conditional, uv, rp = 'localhost', allow, abort } = settings;
        const challenge = from64(window.challenge);
        try {
          const result = kind === 'register'
            ? await navigator.credentials.create({ signal: abort?.signal, publicKey: {
                rp: { id: rp, name: 'Local verifier' }, user: { id: new Uint8Array([21, 22, alg + 10]), name: 'local fixture ' + alg, displayName: 'Fixture' },
                challenge, pubKeyCredParams: [{ type: 'public-key', alg }],
                authenticatorSelection: { userVerification: uv, residentKey: 'required' }, attestation: 'none', extensions: { credProps: true }
              } })
            : await navigator.credentials.get({ mediation: conditional ? 'conditional' : 'optional', signal: abort?.signal, publicKey: {
                rpId: rp, challenge, userVerification: uv, allowCredentials: allow ? [{ type: 'public-key', id: from64(allow) }] : []
              } });
          window.outcome = { value: result.toJSON(), shape: result instanceof PublicKeyCredential && result.rawId instanceof ArrayBuffer &&
            result.response.clientDataJSON instanceof ArrayBuffer &&
            (kind === 'register' ? result.response instanceof AuthenticatorAttestationResponse && result.response.getPublicKey() instanceof ArrayBuffer :
              result.response instanceof AuthenticatorAssertionResponse && result.response.signature instanceof ArrayBuffer) };
        } catch (error) { window.outcome = { error: error.name }; }
        document.querySelector('output').textContent = window.outcome.error || 'Verified by test runner';
      };
      document.querySelector('#start').onclick = start;
      </script></body></html>`;
  };
  let served = 0;
  const reply = (req, res) => {
    if (req.url === '/favicon.ico') { res.writeHead(204).end(); return; }
    ++served;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(html());
  };
  const listen = (server, host, port) => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const ipv4 = createServer(reply), ipv6 = createServer(reply);
  const done = () => Promise.all([ipv4, ipv6].filter(server => server.listening)
    .map(server => new Promise(resolve => server.close(resolve))));
  await listen(ipv4, '127.0.0.1', 0);
  const { port } = ipv4.address();
  // Browsers can resolve the same localhost RP to either loopback family.
  try { await listen(ipv6, '::1', port); }
  catch (error) {
    if (!['EADDRNOTAVAIL', 'EAFNOSUPPORT'].includes(error.code)) { await done(); throw error; }
  }
  const origin = `http://localhost:${port}`;
  return { async page(local) {
    const page = await local.context.newPage();
    await page.bringToFront();
    const before = served;
    const response = await page.goto(origin, { waitUntil: 'domcontentloaded' }).catch(error => {
      throw new Error(`Local WebAuthn verifier did not load (HTTP requests served: ${served - before})`, { cause: error });
    });
    assert.equal(response?.status(), 200, 'The loopback verifier must serve the ceremony page');
    return page;
  }, done };
}

async function open(name, localMaster = master) {
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-passkeys-'));
  let context;
  const close = async () => {
    await context?.close();
    assert(path.dirname(profile) === path.resolve(os.tmpdir()) && path.basename(profile).startsWith('vault-passkeys-'));
    await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
  };
  try {
    context = await chromium.launchPersistentContext(profile, {
      executablePath: process.env.VAULT_BROWSER_PATH || browsers[name],
      headless: process.env.VAULT_HEADED == null ? name !== 'helium' : process.env.VAULT_HEADED !== '1',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension],
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
    await waitForBuiltInFilters(context, name);
    const root = `chrome-extension://${new URL(worker.url()).host}`;
    const view = await context.newPage();
    await view.goto(`${root}/sidepanel.html`);
    const send = message => view.evaluate(async message => {
      const response = await chrome.runtime.sendMessage({ target: 'vault', ...message });
      if (!response?.ok) throw new Error(response?.error ?? 'No response from background');
      return response.value;
    }, message);
    const kit = localMaster && await send({ type: 'create', masterPassword: localMaster, calibrate: false });
    return { context, close, send, root, view, kit, password: localMaster ?? master };
  } catch (error) {
    await close();
    throw error;
  }
}

const auth = (response, kind, origin, challenge, flags) => {
  assert.equal(response.shape, true, 'The page should receive WebAuthn prototypes and buffers');
  const { value } = response;
  const json = decode(value.response.clientDataJSON);
  const client = JSON.parse(json);
  assert.deepEqual(client, { challenge, crossOrigin: false, origin, type: kind });
  const data = decode(value.response.authenticatorData);
  assert.deepEqual(data.subarray(0, 32), hash('localhost'));
  assert.equal(data[32], flags);
  return { value, data, json };
};
const result = async page => {
  await page.waitForFunction(() => !!window.outcome);
  return page.evaluate(() => window.outcome);
};
const set = async (page, settings) => page.evaluate(value => { window.settings = value; window.outcome = undefined; }, settings);
const panel = (local, page) => local.context.pages().find(value => value.url().startsWith(`${local.root}/passkey-prompt.html#`) && value !== page);
async function nextPanel(local) {
  await expect.poll(() => !!panel(local), { timeout: 15000 }).toBe(true);
  return panel(local);
}
async function register(local, page, alg, increment = false) {
  await set(page, { kind: 'register', alg, uv: 'required' });
  await page.getByText('Start ceremony').click();
  const prompt = await nextPanel(local);
  await expect(prompt.getByRole('heading', { name: '保存通行密钥' })).toBeVisible();
  await expect(prompt.getByRole('button', { name: '保存', exact: true })).toBeDisabled();
  if (increment) await prompt.getByRole('checkbox', { name: /递增签名计数/ }).check();
  await prompt.getByLabel('主密码', { exact: true }).fill(local.password);
  await prompt.getByRole('button', { name: '保存', exact: true }).click();
  const reg = auth(await result(page), 'webauthn.create', new URL(page.url()).origin, await page.evaluate(() => window.challenge), 0x4d);
  const id = decode(reg.value.id);
  assert.deepEqual(reg.data.subarray(37, 53), Buffer.alloc(16));
  assert.equal(reg.data.readUInt16BE(53), id.length);
  assert.deepEqual(reg.data.subarray(55, 55 + id.length), id);
  const attestation = readCbor(decode(reg.value.response.attestationObject));
  assert.equal(attestation.get('fmt'), 'none');
  assert.equal(attestation.get('attStmt').size, 0);
  assert.deepEqual(attestation.get('authData'), reg.data);
  const cose = readCbor(attestation.get('authData').subarray(55 + id.length));
  assert.equal(cose.get(3), alg);
  assert.equal(cose.get(-2).length, 32);
  assert.deepEqual([cose.get(1), cose.get(-1)], alg === -7 ? [2, 1] : [1, 6]);
  const x = cose.get(-2).toString('base64url');
  const jwk = alg === -7 ? { kty: 'EC', crv: 'P-256', x, y: cose.get(-3).toString('base64url') } : { kty: 'OKP', crv: 'Ed25519', x };
  const publicKey = createPublicKey({ format: 'jwk', key: jwk });
  assert.deepEqual(publicKey.export({ format: 'der', type: 'spki' }), decode(reg.value.response.publicKey));
  assert.deepEqual(reg.value.clientExtensionResults, { credProps: { rk: true } });
  assert.equal(publicKey.asymmetricKeyType, alg === -7 ? 'ec' : 'ed25519');
  return { alg, id: reg.value.id, publicKey };
}

async function sign(local, page, expected, conditional, flags, count = 0) {
  const before = await local.send({ type: 'status' });
  await page.bringToFront();
  await set(page, { kind: 'assert', conditional, uv: flags & 4 ? 'required' : 'discouraged', allow: expected.id });
  if (conditional) {
    await page.evaluate(() => { void window.start(); });
    assert.equal(await page.evaluate(() => PublicKeyCredential.isConditionalMediationAvailable()), true);
    await page.getByLabel('Account').click();
    const iframe = () => page.frames().find(frame => frame.url().endsWith('.inline'));
    await expect.poll(() => !!iframe(), { timeout: 12000 }).toBe(true);
    assert.equal(await page.evaluate(() => document.querySelectorAll('iframe[src*="passkey"]').length), 0);
    await iframe().getByRole('button', { name: /local fixture/ }).click();
  } else await page.getByText('Start ceremony').click();
  const prompt = await nextPanel(local);
  if (!conditional) await prompt.getByRole('radio').first().check();
  if (flags & 4) await prompt.getByLabel('主密码', { exact: true }).fill(local.password);
  await prompt.getByRole('button', { name: '确认登录' }).click();
  const assertion = auth(await result(page), 'webauthn.get', new URL(page.url()).origin, await page.evaluate(() => window.challenge), flags);
  assert.equal(assertion.value.id, expected.id);
  assert.equal(assertion.data.readUInt32BE(33), count);
  assert.equal(verify(expected.alg === -7 ? 'sha256' : null, Buffer.concat([assertion.data, hash(assertion.json)]), expected.publicKey,
    decode(assertion.value.response.signature)), true);
  assert.equal((await local.send({ type: 'status' })).changesSinceBackup, before.changesSinceBackup + (count > 0 ? 1 : 0));
}

async function verifyCanceledCeremonies(local, page, credential, timeout = false) {
  const before = (await local.send({ type: 'status' })).changesSinceBackup;
  const settings = { kind: 'assert', allow: credential.id, uv: 'required' };
  await page.bringToFront();
  await set(page, settings);
  await page.evaluate(() => { window.settings.abort = new AbortController(); });
  await page.getByText('Start ceremony').click();
  const aborted = await nextPanel(local);
  await page.evaluate(() => window.settings.abort.abort());
  assert.equal((await result(page)).error, 'AbortError');
  await expect.poll(() => aborted.isClosed()).toBe(true);
  await page.bringToFront();
  await set(page, settings);
  await page.getByText('Start ceremony').click();
  const stale = await nextPanel(local);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await expect.poll(() => stale.isClosed()).toBe(true);
  assert.equal(await page.evaluate(() => window.outcome), undefined);
  if (timeout) {
    await page.bringToFront();
    await set(page, settings);
    await page.getByText('Start ceremony').click();
    const expiring = await nextPanel(local);
    await page.waitForFunction(() => !!window.outcome, undefined, { timeout: 67_000 });
    assert.equal((await result(page)).error, 'NotAllowedError');
    await expect.poll(() => expiring.isClosed()).toBe(true);
  }
  assert.equal((await local.send({ type: 'status' })).changesSinceBackup, before);
}

async function verifyNativeFallback(local, page) {
  const cdp = await local.context.newCDPSession(page);
  try {
    await cdp.send('WebAuthn.enable');
    const device = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    } });
    const before = (await local.send({ type: 'list' })).length;
    await page.bringToFront();
    await set(page, { kind: 'register', alg: -7, uv: 'required' });
    await page.getByText('Start ceremony').click();
    const prompt = await nextPanel(local);
    await prompt.getByRole('button', { name: '改用系统 / USB 密钥' }).click()
      .catch(error => { if (!prompt.isClosed()) throw error; });
    const registered = await result(page);
    assert.equal(registered.shape, true);
    const getCredentials = () => cdp.send('WebAuthn.getCredentials', device);
    const nativeCredentials = (await getCredentials()).credentials;
    assert.equal(nativeCredentials.length, 1);
    const nextCount = nativeCredentials[0].signCount + 1;
    const origin = new URL(page.url()).origin;
    const flag = passkeyDisabled => local.send({ type: 'set-autofill-site', origin,
      flags: { inlineDisabled: false, saveDisabled: false, passkeyDisabled } });
    await flag(true);
    await page.bringToFront();
    await set(page, { kind: 'assert', uv: 'required', allow: registered.value.id });
    await page.getByText('Start ceremony').click();
    const asserted = await result(page);
    assert.equal(asserted.value.id, registered.value.id);
    assert.equal(decode(asserted.value.response.authenticatorData).readUInt32BE(33), nextCount);
    assert.equal((await getCredentials()).credentials[0].signCount, nextCount);
    assert(!panel(local), 'Per-site disable must not open a Vault Passkey prompt');
    assert.equal((await local.send({ type: 'list' })).length, before);
    await flag(false);
    await cdp.send('WebAuthn.removeVirtualAuthenticator', device);
  } finally { await cdp.detach(); }
}

async function encryptedLocalCopy(local, key) {
  return local.view.evaluate(async key => {
    const read = event => new Promise((resolve, reject) => {
      event.onsuccess = () => resolve(event.result);
      event.onerror = () => reject(event.error);
    });
    const db = await read(indexedDB.open('vault-extension'));
    try {
      const value = await read(db.transaction('vault').objectStore('vault').get(key));
      if (!value) return null;
      const fingerprint = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))];
      return { vaultId: value.vaultId, head: await fingerprint(value.head), snap: await fingerprint(value.snap) };
    } finally { db.close(); }
  }, key);
}

async function mergeIndependentVault(local, first, dav) {
  const source = await encryptedLocalCopy(local, 'active');
  assert.notEqual(source.vaultId, first.kit.vaultId);
  const originalTitles = (await local.send({ type: 'list' })).map(row => row.title).sort();
  const proof = { method: 'master', secret: sourceMaster };
  const request = { type: 'webdav-merge', input: dav.config, method: 'recovery', secret: first.kit.recoveryCode, proof };
  const requestIndex = dav.requests.length;
  await assert.rejects(local.send({ ...request, secret: local.kit.recoveryCode }));
  await assert.rejects(local.send({ ...request, proof: { method: 'master', secret: master } }));
  const summary = await local.send(request);
  assert.deepEqual([summary.sourceCount, summary.targetCount, summary.mergedCount, summary.conflicts], [3, 2, 3, 0]);
  assert.deepEqual(await encryptedLocalCopy(local, 'active'), source);
  await assert.rejects(local.send({ ...request, stamp: summary.stamp }), /最新的 .vaultpack/);
  const copied = await local.send({ type: 'export', password: filePassword, proof });
  await local.send({ type: 'backup-saved', receipt: copied.receipt });
  await assert.rejects(local.send({ ...request, stamp: 'stale-preview' }), /重新预览/);
  assert.deepEqual(await encryptedLocalCopy(local, 'active'), source);
  assert.equal(await encryptedLocalCopy(local, `merged-source:${source.vaultId}`), null);
  const status = await local.send({ ...request, stamp: summary.stamp });
  assert.equal(status.vaultId, first.kit.vaultId);
  assert.deepEqual(await encryptedLocalCopy(local, `merged-source:${source.vaultId}`), source);
  await local.send({ type: 'lock' });
  await assert.rejects(local.send({ type: 'unlock', password: sourceMaster }));
  await local.send({ type: 'unlock', password: master });
  assert.deepEqual((await local.send({ type: 'list' })).map(row => row.title).sort(), originalTitles);
  assert((await local.send({ type: 'webdav-status' })).linked);
  assert(dav.requests.slice(requestIndex).every(({ method }) => ['GET', 'PROPFIND'].includes(method)));
}

async function verifyConflictReview(first, second) {
  await first.send({ type: 'unlock', password: master });
  await second.send({ type: 'webdav-enable-write', scratchFolder: 'scratch', masterPassword: master });
  const title = 'Conflict review fixture';
  const update = (local, item) => local.send({ type: 'upsert', itemJson: JSON.stringify(item) });
  await update(first, { id: '', title, data: { kind: 'login', username: 'fixture', password: 'fixture-base', uris: [] },
    note: '', tags: [], customFields: [], pinned: false, requireReprompt: false, trashed: false });
  await first.send({ type: 'webdav-sync' });
  await second.send({ type: 'webdav-sync' });
  const { id } = (await second.send({ type: 'list' })).find(row => row.title === title);
  for (const [local, password] of [[first, 'fixture-A'], [second, 'fixture-B']]) {
    const item = await local.send({ type: 'get-edit', id });
    await update(local, { ...item, data: { ...item.data, password } });
  }
  await first.send({ type: 'webdav-sync' });
  const result = await second.send({ type: 'webdav-sync' });
  assert.equal(result.count, 1);
  const original = await second.send({ type: 'webdav-conflicts' });
  assert.equal(original.rows[0].theirs.source, 'Fixture Edge device');
  await second.view.reload();
  const opened = second.context.waitForEvent('page');
  await second.view.getByRole('button', { name: '处理 1 项同步冲突' }).click();
  const review = await opened;
  await review.waitForURL('**/sidepanel.html?view=conflicts');
  await review.getByRole('button', { name: '全部保留双份' }).click();
  await review.getByRole('button', { name: '预览 1 项裁决' }).click();
  const password = review.getByLabel('当前主密码', { exact: true });
  const confirm = review.getByRole('button', { name: '确认裁决' });
  await password.fill('fixture-wrong-master');
  await confirm.click();
  await expect(review.getByRole('alert')).toContainText('主密码验证失败');
  assert.equal((await second.send({ type: 'webdav-conflicts' })).rows.length, 1);
  assert.equal((await second.send({ type: 'webdav-sync' })).count, 1);
  assert.equal((await second.send({ type: 'webdav-conflicts' })).stamp, original.stamp, 'Replaying the same conflict preserves the review stamp');
  await password.fill(master);
  await confirm.click();
  await expect(review.getByRole('button', { name: '新建', exact: true })).toBeVisible();
  await expect(review.getByText(`${title}（Fixture Edge device）`, { exact: true })).toBeVisible();
  await second.send({ type: 'webdav-sync' });
  await first.send({ type: 'webdav-sync' });
  const copies = (await first.send({ type: 'list' })).filter(row => row.title.startsWith(title));
  assert.equal(copies.length, 2);
  const values = await Promise.all(copies.map(row => first.send({ type: 'get', id: row.id })));
  assert.deepEqual(values.map(item => item.data.password).sort(), ['fixture-A', 'fixture-B']);
  await review.close();
}

async function run() {
  const site = await fixture();
  const dav = await webdavFixture();
  const locals = [];
  try {
    const first = await open('edge');
    locals.push(first);
    const proof = { method: 'master', secret: master };
    assert.equal((await first.send({ type: 'webdav-test', input: dav.config })).kind, 'missing');
    await first.send({ type: 'webdav-create', input: dav.config, scratchFolder: 'scratch', masterPassword: master,
      deviceName: 'Fixture Edge device' });
    const devices = await first.send({ type: 'webdav-devices' });
    assert.equal(devices.rows.find(row => row.id === devices.active).name, 'Fixture Edge device');
    dav.state.failWal = true;
    const page = await site.page(first);
    const keys = [];
    for (const alg of [-7, -8]) keys.push(await register(first, page, alg));
    await sign(first, page, keys[0], false, 0x09);
    await assert.rejects(first.send({ type: 'webdav-sync' }), /503/);
    await sign(first, page, keys[1], true, 0x0d);
    assert.equal([...dav.objects.keys()].filter(key => key.includes('/wal/')).length, 0);
    await set(page, { kind: 'assert', uv: 'required', allow: keys[0].id });
    await page.getByText('Start ceremony').click();
    const wrong = await nextPanel(first);
    await wrong.getByRole('radio').first().check();
    await wrong.getByLabel('主密码', { exact: true }).fill('wrong-test-password');
    await wrong.getByRole('button', { name: '确认登录' }).click();
    await expect(wrong.getByRole('alert')).toBeVisible();
    assert.equal(await page.evaluate(() => window.outcome), undefined);
    await wrong.bringToFront();
    await wrong.getByLabel('主密码', { exact: true }).focus();
    await wrong.keyboard.press('Escape').catch(error => { if (!wrong.isClosed()) throw error; });
    assert.equal((await result(page)).error, 'NotAllowedError');
    await set(page, { kind: 'assert', uv: 'required', allow: keys[0].id });
    await page.getByText('Start ceremony').click();
    await nextPanel(first);
    await first.send({ type: 'lock' });
    assert.equal((await result(page)).error, 'NotAllowedError');
    await first.send({ type: 'unlock', password: master });
    await verifyCanceledCeremonies(first, page, keys[0], true);
    dav.state.failWal = false;
    assert.equal((await first.send({ type: 'webdav-sync' })).pending, false);
    await sign(first, page, keys[0], false, 0x19);
    await verifyNativeFallback(first, page);
    const pack = await first.send({ type: 'export', password: filePassword, proof });
    await first.send({ type: 'lock' });
    const second = await open('helium', null);
    locals.push(second);
    const beforeJoin = dav.requests.length;
    await assert.rejects(second.send({ type: 'webdav-join', input: dav.config, method: 'master', secret: filePassword }));
    assert.equal((await second.send({ type: 'status' })).configured, false);
    await second.send({ type: 'webdav-join', input: dav.config, method: 'recovery', secret: first.kit.recoveryCode });
    const other = await site.page(second);
    await sign(second, other, keys[0], true, 0x19);
    await sign(second, other, keys[1], false, 0x1d);
    await verifyCanceledCeremonies(second, other, keys[0]);
    await verifyNativeFallback(second, other);
    assert.ok(dav.requests.slice(beforeJoin).every(({ method }) => ['GET', 'PROPFIND'].includes(method)));

    const restored = await open('helium', sourceMaster);
    locals.push(restored);
    const importMessage = { bytes: pack.bytes, password: filePassword, proof: { method: 'master', secret: sourceMaster } };
    const preview = await restored.send({ type: 'preview-vaultpack', ...importMessage });
    assert.deepEqual([preview.added, preview.updated, preview.skipped], [2, 0, 0]);
    await assert.rejects(restored.send({ type: 'import', ...importMessage, stamp: 'stale-preview' }), /重新预览/);
    assert.equal((await restored.send({ type: 'list' })).length, 0);
    assert.equal(await restored.send({ type: 'import', ...importMessage, stamp: preview.stamp }), 2);
    const backupPage = await site.page(restored);
    await sign(restored, backupPage, keys[0], true, 0x19);
    await sign(restored, backupPage, keys[1], false, 0x1d);
    await restored.send({ type: 'upsert', itemJson: JSON.stringify({ id: '', title: 'Independent source item',
      data: { kind: 'login', username: 'local-fixture', password: 'Synthetic-Item#2026', uris: [] },
      note: '', tags: [], customFields: [], pinned: false, trashed: false, requireReprompt: false }) });
    await mergeIndependentVault(restored, first, dav);
    const incremental = [];
    for (const alg of [-7, -8]) incremental.push(await register(second, other, alg, true));
    for (const key of incremental) await sign(second, other, key, false, 0x09, 1);
    await second.send({ type: 'lock' });
    await second.send({ type: 'unlock', password: master });
    for (const key of incremental) await sign(second, other, key, false, 0x09, 2);
    await verifyConflictReview(first, second);
    console.log(JSON.stringify({ edge: 'ES256/Ed25519 registration, assertion, UV, conditional, lock cancellation',
      helium: ['WebDAV sign-in using both original keys', 'authenticated .vaultpack restored both original keys'],
      failedUploadBS0: true, verifiedRecoveryBS1: true, defaultCountNoWrite: true, incrementalCountPersisted: true,
      independentMergeKeptSourceAndTargetIdentity: true, nativeFallbackOnceWithVirtualAuthenticator: true,
      abortAndNavigationCanceledOnBothBrowsers: true, promptTimeoutCanceledOnEdge: true, conflictReviewTabAndKeepBoth: true }));
  } finally {
    await Promise.all(locals.reverse().map(local => local.close()));
    await site.done();
    await dav.close();
  }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
