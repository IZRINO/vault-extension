const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises'), http = require('node:http'), path = require('node:path'), os = require('node:os');
const { createHmac, createCipheriv, createDecipheriv, createHash, pbkdf2Sync, argon2Sync, randomBytes, timingSafeEqual } = require('node:crypto');
const QR = require('qrcode');
const { waitForBuiltInFilters } = require('./browser-fixtures.cjs');
const root = path.resolve(__dirname, '..'), output = path.join(root, 'test-results');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const firstColor = process.env.VAULT_QR_FIRST || 'light';
const browsers = { edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', helium: 'C:/Program Files/imput/Helium/Application/chrome.exe' };
const master = 'Migration-Fixture-Master#2026', filePassword = 'Portable-File-Fixture#2026';
const otp = 'otpauth://totp/QR-Fixture%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=QR-Fixture';
const source = { encrypted: false, folders: [{ id: 'folder-a', name: 'Fixture work' }], items: [
  { id: 'login-a', type: 1, name: 'Migrated Login', notes: 'Keep this note', folderId: 'folder-a', reprompt: 1, favorite: true,
    login: { username: 'fixture-alice', password: 'Migration-Login-Secret#2026', totp: 'JBSWY3DPEHPK3PXP',
      uris: [{ uri: 'https://example.com/login', match: 1 }], fido2Credentials: [{ credentialId: 'preserved-fixture', keyValue: 'fixture-not-a-real-key' }] },
    fields: [{ name: 'custom hidden', value: 'Custom-Fixture-Secret', type: 1 }] },
  { id: 'note-a', type: 2, name: 'Migrated Note', notes: 'Private fixture note', secureNote: { type: 0 } },
  { id: 'card-a', type: 3, name: 'Migrated Card', card: { cardholderName: 'Test User', number: '4111111111111111', brand: 'Visa', expMonth: '11', expYear: '2030', code: '123' } },
  { id: 'identity-a', type: 4, name: 'Migrated Identity', identity: { firstName: 'Ada', lastName: 'Lovelace', passportNumber: 'Fixture-Passport', ssn: 'Fixture-SSN', address1: 'One', address2: 'Two', city: 'Test City', country: 'GB' } },
] };
function portable(json, kdfType = 0) {
  const salt = randomBytes(16).toString('base64');
  const material = kdfType === 0 ? pbkdf2Sync(filePassword, salt, 10000, 32, 'sha256')
    : argon2Sync('argon2id', { message: Buffer.from(filePassword), nonce: createHash('sha256').update(salt).digest(),
      parallelism: 1, tagLength: 32, memory: 16 * 1024, passes: 2 });
  // HKDF expand only, without extract.
  const expand = info => createHmac('sha256', material).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
  const encKey = expand('enc'), macKey = expand('mac');
  const encrypt = value => {
    const iv = randomBytes(16), cipher = createCipheriv('aes-256-cbc', encKey, iv);
    const ciphertext = Buffer.concat([cipher.update(value), cipher.final()]);
    const mac = createHmac('sha256', macKey).update(iv).update(ciphertext).digest();
    return '2.' + [iv, ciphertext, mac].map(value => value.toString('base64')).join('|');
  };
  const result = { encrypted: true, passwordProtected: true, salt, kdfType, kdfIterations: kdfType === 0 ? 10000 : 2,
    ...(kdfType === 1 ? { kdfMemory: 16, kdfParallelism: 1 } : {}),
    encKeyValidation_DO_NOT_EDIT: encrypt('fixture validation'), data: encrypt(JSON.stringify(json)) };
  material.fill(0); encKey.fill(0); macKey.fill(0);
  return result;
}
function openPortable(doc) {
  const material = pbkdf2Sync(filePassword, doc.salt, doc.kdfIterations, 32, 'sha256');
  const enc = createHmac('sha256', material).update(Buffer.from('enc\x01')).digest();
  const mac = createHmac('sha256', material).update(Buffer.from('mac\x01')).digest();
  const [iv, ciphertext, tag] = doc.data.slice(2).split('|').map(value => Buffer.from(value, 'base64'));
  assert(timingSafeEqual(createHmac('sha256', mac).update(iv).update(ciphertext).digest(), tag));
  const decipher = createDecipheriv('aes-256-cbc', enc, iv);
  const result = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString());
  material.fill(0); enc.fill(0); mac.fill(0);
  return result;
}
async function proof(page) {
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('主密码', { exact: true }).fill(master);
  await dialog.getByRole('button', { name: '验证', exact: true }).click();
}
async function run(name, server) {
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-migration-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, { executablePath: browsers[name], headless: process.env.VAULT_HEADED == null ? name !== 'helium' : process.env.VAULT_HEADED !== '1',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension, '--enable-unsafe-extension-debugging'],
      viewport: name === 'edge' ? { width: 400, height: 600 } : { width: 330, height: 760 } });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    await waitForBuiltInFilters(context, name);
    const id = new URL(worker.url()).host, page = await context.newPage(), errors = [], requests = [];
    context.on('weberror', error => errors.push(error.error().message));
    context.on('request', request => { if (request.url().endsWith('.wasm')) requests.push(request.url()); });
    context.on('response', response => { if (response.status() >= 400 && response.url().startsWith(`chrome-extension://${id}`)) errors.push(`${response.status()} ${response.url()}`); });
    await page.goto(`chrome-extension://${id}/${name === 'edge' ? 'popup' : 'sidepanel'}.html`);
    const reply = message => page.evaluate(message => chrome.runtime.sendMessage({ target: 'vault', ...message }), message);
    const send = async message => { const result = await reply(message); if (!result.ok) throw new Error(result.error); return result.value; };
    await send({ type: 'create', masterPassword: master });
    assert(!requests.some(url => /vault_importers|vault_qr/.test(url)), 'Unlock must not load migration or QR WASM');
    await page.reload(); await page.getByRole('button', { name: '设置', exact: true }).click();
    await page.getByRole('button', { name: /^Bitwarden 密码库迁移/ }).click();
    const bytes = [...Buffer.from(JSON.stringify(portable(source)))];
    const argonBytes = [...Buffer.from(JSON.stringify(portable(source, 1)))];
    assert.equal((await send({ type: 'preview-migration', format: 'bitwarden', bytes: argonBytes, password: filePassword })).ready, 4);
    const tampered = portable(source); tampered.data = tampered.data.slice(0, -4) + 'AAAA';
    assert.equal((await reply({ type: 'preview-migration', format: 'bitwarden', bytes: [...Buffer.from(JSON.stringify(tampered))], password: filePassword })).ok, false);
    assert.equal((await reply({ type: 'preview-migration', format: 'bitwarden', bytes, password: 'Wrong-fixture-password' })).ok, false);
    await page.getByLabel('Bitwarden JSON 文件', { exact: true }).setInputFiles({ name: 'portable.json', mimeType: 'application/json', buffer: Buffer.from(bytes) });
    await page.getByLabel('文件密码（加密 JSON 才需填写）', { exact: true }).fill(filePassword);
    await page.getByRole('button', { name: '预览迁移内容', exact: true }).click();
    await expect(page.getByRole('heading', { name: '可导入 4 条凭证', exact: true })).toBeVisible();
    assert.equal((await send({ type: 'list' })).length, 0);
    assert(!(await page.locator('body').innerText()).includes('Migration-Login-Secret'));
    await page.screenshot({ path: path.join(output, `migration-${name}-preview.png`) });
    await page.getByRole('button', { name: '确认导入 4 条', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
    assert.equal((await send({ type: 'list' })).length, 0);
    await page.getByRole('button', { name: '确认导入 4 条', exact: true }).click(); await proof(page);
    await expect(page.getByText('已导入 4 条凭证。', { exact: true })).toBeVisible();
    const summaries = await send({ type: 'list' }); assert.equal(summaries.length, 4);
    const login = await send({ type: 'get', id: summaries.find(item => item.title === 'Migrated Login').id, proof: { method: 'master', secret: master } });
    assert.equal(login.data.password, source.items[0].login.password); assert(login.requireReprompt);
    assert.equal(login.tags[0], 'Fixture work');
    assert.equal((await send({ type: 'preview-migration', format: 'bitwarden', bytes, password: filePassword })).ready, 0);
    assert.equal((await reply({ type: 'export-migration', format: 'bitwarden', proof: { method: 'pin', secret: '123456' }, confirmPlaintext: true })).ok, false);
    await page.getByRole('button', { name: '导出凭证', exact: true }).click();
    await page.getByLabel('导出文件密码', { exact: true }).fill(filePassword); await page.getByLabel('再次输入文件密码', { exact: true }).fill(filePassword);
    await page.getByRole('button', { name: '导出 Bitwarden JSON', exact: true }).click();
    const downloadEvent = page.waitForEvent('download'); await proof(page);
    const download = await downloadEvent;
    const exported = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
    assert(exported.encrypted && exported.passwordProtected);
    assert(!JSON.stringify(exported).includes('Migration-Login-Secret'));
    assert.equal(openPortable(exported).items.find(item => item.type === 1).login.password, source.items[0].login.password);
    const exportBytes = [...Buffer.from(JSON.stringify(exported))];
    const decoded = await send({ type: 'preview-migration', format: 'bitwarden', bytes: exportBytes, password: filePassword });
    assert.equal(decoded.ready, 0);
    const plain = await send({ type: 'export-migration', format: 'bitwarden', proof: { method: 'master', secret: master }, confirmPlaintext: true });
    const rows = JSON.parse(plain.text).items;
    assert.equal(rows.find(row => row.type === 1).login.fido2Credentials[0].credentialId, 'preserved-fixture');
    assert.equal(rows.find(row => row.type === 4).identity.address2, 'Two');
    await page.getByRole('button', { name: '返回设置', exact: true }).click();
    await page.getByRole('button', { name: /^CSV 字段映射与导出/ }).click();
    const csv = Buffer.from('称呼,站点,账号,口令,备注\r\nMapped fixture,https://mapped.example,alice," p,""q","two\r\nlines"\r\n');
    await page.getByLabel('CSV 文件', { exact: true }).setInputFiles({ name: 'mapping.csv', mimeType: 'text/csv', buffer: csv });
    await page.getByRole('button', { name: '读取列名', exact: true }).click();
    const previewButton = page.getByRole('button', { name: '预览迁移内容', exact: true });
    await expect(previewButton).toBeDisabled();
    const titleSelect = page.getByLabel('名称', { exact: true });
    await titleSelect.focus();
    await titleSelect.press('ArrowDown');
    await expect(titleSelect).toHaveValue('0');
    await page.locator('[draggable="true"]').filter({ hasText: /^2\. 站点$/ })
      .dragTo(page.getByLabel('网站（必选）', { exact: true }));
    await expect(page.getByLabel('网站（必选）', { exact: true })).toHaveValue('1');
    await page.getByLabel('备注', { exact: true }).selectOption('1');
    await expect(page.getByText('同一个源列不能用于多个字段。')).toBeVisible();
    await expect(previewButton).toBeDisabled();
    await page.getByLabel('备注', { exact: true }).selectOption('4');
    await previewButton.click();
    await expect(page.getByRole('heading', { name: '可导入 1 条凭证' })).toBeVisible();
    await page.getByLabel('备注', { exact: true }).selectOption('');
    await expect(page.getByRole('button', { name: '确认导入 1 条', exact: true })).toHaveCount(0);
    await page.getByLabel('备注', { exact: true }).selectOption('4');
    await previewButton.click();
    await expect(page.getByRole('heading', { name: '可导入 1 条凭证' })).toBeVisible();
    const mapping = { title: 0, url: 1, username: 2, password: 3, note: 4 };
    const preview = await send({ type: 'preview-migration', format: 'csv', bytes: [...csv], mapping });
    const changed = await reply({ type: 'import-migration', format: 'csv', bytes: [...csv], mapping: { ...mapping, note: 0 }, stamp: preview.stamp, proof: { method: 'master', secret: master } });
    assert(!changed.ok && changed.error.includes('重新预览'));
    await page.getByRole('button', { name: '确认导入 1 条', exact: true }).click(); await proof(page);
    await expect(page.getByText('已导入 1 条凭证。', { exact: true })).toBeVisible();
    const mapped = (await send({ type: 'list' })).find(row => row.title === 'Mapped fixture');
    assert.equal((await send({ type: 'get', id: mapped.id })).data.password, ' p,"q');
    assert.equal((await send({ type: 'get', id: mapped.id })).note, 'two\r\nlines');
    const exportedCsv = await send({ type: 'export-migration', format: 'csv', proof: { method: 'master', secret: master }, confirmPlaintext: true });
    assert.equal(exportedCsv.count, 2); assert.equal(exportedCsv.skipped, 3); assert(exportedCsv.text.includes('" p,""q"'));
    await page.screenshot({ path: path.join(output, `migration-${name}-csv.png`) });

    const website = await context.newPage();
    await website.bringToFront();
    await website.setViewportSize({ width: 1000, height: 800 });
    const base = `http://127.0.0.1:${server.address().port}`;
    const firstPath = firstColor === 'dark' ? '/qr-dark' : '/qr';
    const nextPath = firstColor === 'dark' ? '/qr' : '/qr-dark';
    await website.goto(base + firstPath);
    await expect(website.getByRole('img')).toBeVisible();
    const tab = (await page.evaluate(() => chrome.tabs.query({}))).find(tab => tab.url?.includes('/qr'));
    await page.evaluate(tabId => chrome.tabs.update(tabId, { active: true }), tab.id);
    const browserCdp = await context.browser().newBrowserCDPSession();
    const { targetInfos } = await browserCdp.send('Target.getTargets', { filter: [{ type: 'tab', exclude: false }] });
    const tabTarget = targetInfos.find(target => target.url === website.url());
    assert(tabTarget, 'Browser tab target must exist for the real extension action');
    await browserCdp.send('Extensions.triggerAction', { id, targetId: tabTarget.targetId });
    await browserCdp.detach();
    const scanStarted = performance.now();
    const first = await send({ type: 'scan-otp' });
    const scanned = first.values;
    const qrEndToEndMs = Math.round(performance.now() - scanStarted);
    assert.equal(scanned.length, 1); assert(scanned[0].includes('JBSWY3DPEHPK3PXP'));
    await website.screenshot({ path: path.join(output, `migration-${name}-qr.png`) });
    await website.goto(base + nextPath);
    await website.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await new Promise(resolve => setTimeout(resolve, 650));
    const nextStarted = performance.now();
    const following = await send({ type: 'scan-otp' }); assert.deepEqual(following.values, scanned);
    const qrFollowupMs = Math.round(performance.now() - nextStarted);
    await website.goto(base + '/empty');
    await website.getByText('No QR here', { exact: true }).waitFor();
    await website.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const empty = await reply({ type: 'scan-otp' }); assert(!empty.ok && empty.error.includes('没有找到'), JSON.stringify(empty));
    await website.goto(`http://localhost:${server.address().port}/qr`);
    const notGranted = await reply({ type: 'scan-otp' });
    assert(!notGranted.ok && notGranted.error.includes('尚未授权'), JSON.stringify(notGranted));
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ browser: name, portableJson: true, argon2AndPbkdf2Reference: true, tamperRejected: true, confirmationAndReprompt: true,
      fourTypesAndPreservedFields: true, csvMappingAndExport: true, screenshotQr: true, invertedQr: true, qrFirstColor: firstColor,
      qrEndToEndMs, qrFollowupMs, qrFirstTimings: first.timings, qrFollowupTimings: following.timings,
      noActiveTabRejected: true, canvasOverrideIgnored: true, errors }));
  } finally {
    await context?.close();
    assert(path.dirname(profile) === path.resolve(os.tmpdir()) && path.basename(profile).startsWith('vault-migration-'));
    await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
}
(async () => {
  assert(['light', 'dark'].includes(firstColor), 'VAULT_QR_FIRST must be light or dark');
  await fs.mkdir(output, { recursive: true });
  const [background, kdf, content, qrWorker, migrationWorker, syncWorker, passkeyWorker] = await Promise.all(
    ['background.js', 'kdf-worker.js', 'content-scripts/autofill.js', 'qr-worker.js', 'migration-worker.js', 'sync-worker.js', 'passkey-worker.js']
      .map(file => fs.readFile(path.join(extension, file), 'utf8')));
  for (const bundle of [background, kdf, content]) {
    assert(!/vault_(?:importers|qr|sync|passkeys)_bg/.test(bundle), 'Main, KDF and autofill bundles must exclude optional WASM');
  }
  assert(qrWorker.includes('wasm_scan_otp'), 'Missing optional QR scanner');
  assert(migrationWorker.includes('wasm_portable_import'), 'Missing optional portable import engine');
  assert(syncWorker.includes('wasm_sync_replay'), 'Missing optional sync engine');
  assert(passkeyWorker.includes('wasm_passkey_candidates'), 'Missing optional Passkey engine');
  const image = await QR.toDataURL(otp, { width: 420, margin: 4 });
  const darkImage = await QR.toDataURL(otp, { width: 420, margin: 4, color: { dark: '#ffffff', light: '#111111' } });
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html;charset=utf-8');
    res.end(`<html><body><h1>Local screenshot QR fixture</h1>${req.url?.startsWith('/qr') ? `<img alt="Fixture OTP QR" src="${req.url === '/qr-dark' ? darkImage : image}">` : '<p>No QR here</p>'}
      <script>HTMLCanvasElement.prototype.getContext=()=>{throw new Error('Page canvas is intentionally blocked')};window.OffscreenCanvas=undefined;</script></body></html>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { for (const name of process.argv.slice(2).length ? process.argv.slice(2) : ['edge', 'helium']) await run(name, server); }
  finally { server.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
