const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises'), http = require('node:http'), path = require('node:path'), os = require('node:os');
const { createHmac, createCipheriv, createDecipheriv, createHash, pbkdf2Sync, argon2Sync, randomBytes, timingSafeEqual } = require('node:crypto');
const QR = require('qrcode');
const { waitForBuiltInFilters } = require('./browser-fixtures.cjs');
const root = path.resolve(__dirname, '..'), output = path.resolve(root, process.env.VAULT_MIGRATION_RESULTS || 'test-results');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const firstColor = process.env.VAULT_QR_FIRST || 'light';
const nativeQr = process.env.VAULT_QR_NATIVE === '1';
const browsers = { edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', helium: 'C:/Program Files/imput/Helium/Application/chrome.exe' };
const master = 'Migration-Fixture-Master#2026', filePassword = 'Portable-File-Fixture#2026';
const otp = 'otpauth://totp/QR-Fixture%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=QR-Fixture';
const sshKey = { privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\r\nsynthetic-ssh-fixture\r\n-----END OPENSSH PRIVATE KEY-----\r\n',
  publicKey: 'ssh-ed25519 synthetic-public-key fixture@example.test', keyFingerprint: 'SHA256:synthetic-fingerprint' };
const source = { encrypted: false, folders: [{ id: 'folder-a', name: 'Fixture work' }], items: [
  { id: 'login-a', type: 1, name: 'Migrated Login', notes: 'Keep this note', folderId: 'folder-a', reprompt: 1, favorite: true,
    login: { username: 'fixture-alice', password: 'Migration-Login-Secret#2026', totp: 'JBSWY3DPEHPK3PXP',
      uris: [{ uri: 'https://example.com/login', match: 1 }], fido2Credentials: [{ credentialId: 'preserved-fixture', keyValue: 'fixture-not-a-real-key' }] },
    fields: [{ name: 'custom hidden', value: 'Custom-Fixture-Secret', type: 1 }] },
  { id: 'note-a', type: 2, name: 'Migrated Note', notes: 'Private fixture note', secureNote: { type: 0 } },
  { id: 'card-a', type: 3, name: 'Migrated Card', card: { cardholderName: 'Test User', number: '4111111111111111', brand: 'Visa', expMonth: '11', expYear: '2030', code: '123' } },
  { id: 'identity-a', type: 4, name: 'Migrated Identity', identity: { firstName: 'Ada', lastName: 'Lovelace', passportNumber: 'Fixture-Passport', ssn: 'Fixture-SSN', address1: 'One', address2: 'Two', city: 'Test City', country: 'GB' } },
  { id: 'ssh-a', type: 5, name: 'Migrated SSH key', folderId: 'folder-a', reprompt: 1, favorite: true, sshKey },
] };
const sourceCount = source.items.length;
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
async function verifyGoogleImages(page, send, reply) {
  const seed = Buffer.from('12345678901234567890');
  const field = (tag, body) => Buffer.concat([Buffer.from([tag << 3 | 2, body.length]), body]);
  const part = (index, kind, batch = 24, secret = seed) => {
    const payload = Buffer.concat([field(1, secret), field(2, Buffer.from(`Batch fixture:google-${index}`)),
      field(3, Buffer.from('Batch fixture')), Buffer.from([0x20, 1, 0x28, 1, 0x30, kind, 0x38, 7])]);
    const encoded = Buffer.concat([field(1, payload), Buffer.from([0x10, 1, 0x18, 2, 0x20, index, 0x28, batch])]);
    return 'otpauth-migration://offline?data=' + encodeURIComponent(encoded.toString('base64'));
  };
  const [first, second, unrelated, damaged] = await Promise.all([
    part(0, 2), part(1, 1), part(0, 2, 25), 'otpauth-migration://offline?data=AA%3D%3D',
  ].map(value => QR.toDataURL(value, { width: 420 })));
  const preview = images => ({ type: 'preview-auth-backup', format: 'google', images });
  const ids = async () => (await send({ type: 'list' })).map(row => row.id).sort();
  const original = await ids();
  const missing = await send(preview([second]));
  assert.equal(missing.missingParts, 1);
  const incomplete = await reply({ ...preview([second]), type: 'import-auth-backup', stamp: missing.stamp, proof: { method: 'master', secret: master } });
  assert(!incomplete.ok && incomplete.error.includes('缺少 1 张'));
  const mixed = await reply(preview([second, unrelated]));
  assert(!mixed.ok && mixed.error.includes('不同批次'));
  assert.equal((await reply(preview([first, damaged]))).ok, false, 'A malformed protobuf must not be treated as a valid fragment');
  assert.equal((await reply(preview(['data:image/png;base64,' + 'A'.repeat(6 * 1024 * 1024)]))).ok, false);
  assert.deepEqual(await ids(), original);

  const images = [second, first, second];
  const complete = await send(preview(images));
  assert.equal(complete.ready, 2); assert.equal(complete.missingParts, 0); assert.equal(complete.repeatedParts, 1);
  assert.deepEqual(complete.sample, ['google-0', 'google-1'].map(account => ({ title: 'Batch fixture', kind: 'login', account })));
  await page.reload();
  await page.getByRole('button', { name: '设置', exact: true }).click();
  await page.getByRole('button', { name: /^导入其他验证器/ }).click();
  const input = page.getByLabel('迁移二维码图片', { exact: true });
  const previewButton = page.getByRole('button', { name: '预览迁移内容', exact: true });
  const links = page.getByLabel('或粘贴迁移 URI（每行一个）', { exact: true });
  await links.fill([part(0, 2), part(1, 1, 24, Buffer.alloc(0))].join('\n'));
  await previewButton.click();
  await expect(page.getByRole('heading', { name: '二维码批次损坏', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '确认导入', exact: true })).toBeDisabled();
  assert.deepEqual(await ids(), original);
  await input.setInputFiles(images.map((data, index) => ({
    name: `batch-synthetic-${index}.png`, mimeType: 'image/png', buffer: Buffer.from(data.split(',')[1], 'base64'),
  })));
  await expect(previewButton).toBeEnabled();
  await input.setInputFiles([]);
  await expect(previewButton).toBeDisabled();
  await page.getByRole('group', { name: '拖入迁移二维码', exact: true }).evaluate((target, images) => {
    const files = new DataTransfer();
    images.forEach((encoded, index) => {
      const bytes = Uint8Array.from(atob(encoded.split(',')[1]), char => char.charCodeAt(0));
      files.items.add(new File([bytes], `dropped-synthetic-${index}.png`, { type: 'image/png' }));
    });
    target.dispatchEvent(new DragEvent('drop', { dataTransfer: files, bubbles: true, cancelable: true }));
  }, images);
  await expect(page.getByText('已选择 3 张图片。', { exact: true })).toBeVisible();
  await previewButton.click();
  await expect(page.getByRole('heading', { name: '可导入 2 个验证码', exact: true })).toBeVisible();
  await expect(page.getByText('忽略重复图片 1 张。', { exact: false })).toBeVisible();
  const confirm = page.getByRole('button', { name: '确认导入', exact: true });
  await confirm.click();
  await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
  await expect(confirm).toBeEnabled();
  assert.deepEqual(await ids(), original);
  await confirm.click(); await proof(page);
  await expect(page.getByText('已导入 2 个验证码。', { exact: true })).toBeVisible();

  const imported = (await ids()).filter(id => !original.includes(id));
  const rows = await Promise.all(imported.map(id => send({ type: 'get', id })));
  assert.equal(rows.length, 2);
  assert(rows.every(row => !Object.hasOwn(row.data, 'totpUri')));
  const totp = rows.find(row => row.data.username === 'google-0');
  const hotp = rows.find(row => row.data.username === 'google-1');
  const timed = await send({ type: 'read-otp', id: totp.id, handle: totp.otp.handle });
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(timed.validTo / 30 - 1));
  const hmac = createHmac('sha1', seed).update(counter).digest();
  assert.equal(timed.value, String((hmac.readUInt32BE(hmac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0'));
  assert.deepEqual(await send({ type: 'next-hotp', id: hotp.id }), { kind: 'hotp', value: '162583', counter: '7' });
  assert.deepEqual(await send({ type: 'next-hotp', id: hotp.id }), { kind: 'hotp', value: '399871', counter: '8' });
}
async function verifyEncrypted2fas(send, reply) {
  const file = process.env.VAULT_2FAS_FIXTURE_PATH;
  if (!file) return 'skipped';
  // Public synthetic Aegis importer fixture; see docs/agents/authenticator-backup-fixtures.md.
  const bytes = await fs.readFile(file);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), '0e769224ea2778f9b2d6467d9185efdcba2e4914541c3d3f36b687018bf789c9');
  const ids = async () => (await send({ type: 'list' })).map(row => row.id).sort();
  const original = await ids();
  const input = { format: '2fas', bytes: [...bytes], password: 'test' };
  const preview = await send({ ...input, type: 'preview-auth-backup' });
  assert.equal(preview.ready, 5);
  assert(preview.sample.every(row => !Object.hasOwn(row, 'data')));
  const confirm = { ...input, type: 'import-auth-backup', stamp: preview.stamp, proof: { method: 'master', secret: master } };
  assert.equal((await reply({ ...confirm, password: 'incorrect' })).ok, false);
  assert.deepEqual(await ids(), original, 'Preview and failed authentication must not modify the vault');
  await send(confirm);
  const added = (await ids()).filter(id => !original.includes(id));
  assert.equal(added.length, 5);
  const rows = await Promise.all(added.map(id => send({ type: 'get', id })));
  assert(rows.every(row => row.otp && !Object.hasOwn(row.data, 'totpUri')));
  const codes = [];
  for (const row of rows.filter(row => row.otp.kind === 'hotp')) codes.push(await send({ type: 'next-hotp', id: row.id }));
  // Independently derived from the upstream file using Node AES-GCM and HMAC.
  assert.deepEqual(codes.sort((a, b) => Number(a.counter) - Number(b.counter)), [
    { kind: 'hotp', counter: '1', value: '253717' },
    { kind: 'hotp', counter: '50', value: '4444976' },
    { kind: 'hotp', counter: '10300', value: '24622277' },
  ]);
  assert.equal((await send({ ...input, type: 'preview-auth-backup' })).ready, 0);
  return true;
}
async function nativePopupQr(cdp, id, existingTargets) {
  let target;
  await expect.poll(async () => {
    const { targetInfos } = await cdp.send('Target.getTargets', { filter: [{ type: 'page' }] });
    target = targetInfos.find(entry => entry.url === `chrome-extension://${id}/popup.html` && !existingTargets.has(entry.targetId));
    return Boolean(target);
  }, { message: 'Find the real toolbar Popup, not the extension setup tab' }).toBe(true);
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: target.targetId, flatten: false });
  const pending = new Map();
  let sequence = 0;
  const receive = event => {
    if (event.sessionId === sessionId) {
      const message = JSON.parse(event.message);
      pending.get(message.id)?.(message);
    }
  };
  cdp.on('Target.receivedMessageFromTarget', receive);
  async function evaluate(fn, ...args) {
    const id = ++sequence;
    let timer;
    try {
      const response = new Promise((resolve, reject) => {
        pending.set(id, resolve);
        timer = setTimeout(() => reject(new Error('Native QR Popup did not respond')), 4500);
      });
      const [, message] = await Promise.all([
        cdp.send('Target.sendMessageToTarget', { sessionId, message: JSON.stringify({
          id, method: 'Runtime.evaluate', params: { expression: `(${fn})(...${JSON.stringify(args)})`, returnByValue: true },
        }) }),
        response,
      ]);
      if (message.error || message.result.exceptionDetails) throw new Error('Cannot read native QR Popup');
      return message.result.result.value;
    } finally {
      clearTimeout(timer);
      pending.delete(id);
    }
  }
  async function click(selector, label) {
    await expect.poll(() => evaluate((selector, label) => {
      const node = [...document.querySelectorAll(selector)].find(item => item.textContent.trim() === label && !item.disabled);
      if (!node || !node.getClientRects().length) return false;
      node.focus();
      node.click();
      return true;
    }, selector, label), { message: `Click the native Popup control ${label}` }).toBe(true);
  }
  async function scan() {
    await click('button', '扫描当前网页二维码');
    let metrics;
    await expect.poll(async () => {
      metrics = await evaluate(() => {
        const mark = name => performance.getEntriesByName(`vault:qr-${name}`, 'mark').at(-1);
        const result = [...document.querySelectorAll('fieldset button')].find(node => node.textContent.trim() === 'QR-Fixture:alice');
        if (!mark('presented') || !result || result.disabled) return null;
        const rect = result.getBoundingClientRect();
        if (!rect.width || !rect.height || !result.contains(document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2))) return null;
        const start = mark('start').startTime;
        return { replyMs: mark('preview').startTime - start, domMs: mark('dom').startTime - start,
          presentedMs: mark('presented').startTime - start, timings: mark('preview').detail };
      });
      return Boolean(metrics);
    }, { message: 'Wait for a presented and clickable QR choice in the Popup viewport' }).toBe(true);
    return metrics;
  }
  try {
    await click('button', '新建');
    await click('[role=menuitem]', '登录');
    await click('summary', '两步验证码（可选）');
    const first = await scan();
    await click('button', '取消选择');
    // captureVisibleTab is rate limited. The second timing excludes the cooldown.
    await new Promise(resolve => setTimeout(resolve, 650));
    return { first, hot: await scan() };
  } finally {
    cdp.off('Target.receivedMessageFromTarget', receive);
    await cdp.send('Target.detachFromTarget', { sessionId }).catch(() => undefined);
    await cdp.send('Target.closeTarget', { targetId: target.targetId }).catch(() => undefined);
  }
}
async function run(name, server) {
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-migration-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, { executablePath: browsers[name], headless: !nativeQr && (process.env.VAULT_HEADED == null ? name !== 'helium' : process.env.VAULT_HEADED !== '1'),
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
    const argonPreview = await send({ type: 'preview-migration', format: 'bitwarden', bytes: argonBytes, password: filePassword });
    assert.equal(argonPreview.ready, sourceCount);
    assert.equal(argonPreview.unsupported, 0);
    assert(!JSON.stringify(argonPreview).includes('synthetic-ssh-fixture'));
    const tampered = portable(source); tampered.data = tampered.data.slice(0, -4) + 'AAAA';
    assert.equal((await reply({ type: 'preview-migration', format: 'bitwarden', bytes: [...Buffer.from(JSON.stringify(tampered))], password: filePassword })).ok, false);
    assert.equal((await reply({ type: 'preview-migration', format: 'bitwarden', bytes, password: 'Wrong-fixture-password' })).ok, false);
    await page.getByLabel('Bitwarden JSON 文件', { exact: true }).setInputFiles({ name: 'portable.json', mimeType: 'application/json', buffer: Buffer.from(bytes) });
    await page.getByLabel('文件密码（加密 JSON 才需填写）', { exact: true }).fill(filePassword);
    await page.getByRole('button', { name: '预览迁移内容', exact: true }).click();
    await expect(page.getByRole('heading', { name: `可导入 ${sourceCount} 条凭证`, exact: true })).toBeVisible();
    assert.equal((await send({ type: 'list' })).length, 0);
    const previewText = await page.locator('body').innerText();
    assert(!previewText.includes('Migration-Login-Secret') && !previewText.includes('synthetic-ssh-fixture'));
    await page.screenshot({ path: path.join(output, `migration-${name}-preview.png`) });
    const confirmImport = page.getByRole('button', { name: `确认导入 ${sourceCount} 条`, exact: true });
    await confirmImport.click();
    await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
    assert.equal((await send({ type: 'list' })).length, 0);
    await confirmImport.click(); await proof(page);
    await expect(page.getByText(`已导入 ${sourceCount} 条凭证。`, { exact: true })).toBeVisible();
    const summaries = await send({ type: 'list' }); assert.equal(summaries.length, sourceCount);
    const login = await send({ type: 'get', id: summaries.find(item => item.title === 'Migrated Login').id, proof: { method: 'master', secret: master } });
    assert.equal(login.data.password, source.items[0].login.password); assert(login.requireReprompt);
    assert.equal(login.tags[0], 'Fixture work');
    const ssh = summaries.find(item => item.title === 'Migrated SSH key');
    assert(ssh?.devSubtype === 'ssh_key' && ssh.requireReprompt && ssh.pinned);
    assert(!JSON.stringify(ssh).includes('synthetic-ssh-fixture'));
    assert.equal((await reply({ type: 'get', id: ssh.id })).ok, false);
    const sshDetail = await send({ type: 'get', id: ssh.id, proof: { method: 'master', secret: master } });
    assert.equal(sshDetail.data.privateKey, sshKey.privateKey);
    assert.equal(sshDetail.data.publicKey, sshKey.publicKey);
    assert.deepEqual(sshDetail.tags, ['Fixture work']);
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
    const decrypted = openPortable(exported).items;
    assert.equal(decrypted.find(item => item.type === 1).login.password, source.items[0].login.password);
    assert.deepEqual(decrypted.find(item => item.type === 5).sshKey, sshKey);
    const exportBytes = [...Buffer.from(JSON.stringify(exported))];
    const decoded = await send({ type: 'preview-migration', format: 'bitwarden', bytes: exportBytes, password: filePassword });
    assert.deepEqual([decoded.ready, decoded.skipped, decoded.invalid, decoded.unsupported], [0, sourceCount, 0, 0]);
    const plain = await send({ type: 'export-migration', format: 'bitwarden', proof: { method: 'master', secret: master }, confirmPlaintext: true });
    const rows = JSON.parse(plain.text).items;
    assert.equal(rows.find(row => row.type === 1).login.fido2Credentials[0].credentialId, 'preserved-fixture');
    assert.equal(rows.find(row => row.type === 4).identity.address2, 'Two');
    const sshRow = rows.find(row => row.type === 5);
    assert.deepEqual(sshRow.sshKey, sshKey);
    assert(!JSON.stringify(sshRow.fields).includes('synthetic-ssh-fixture'));
    await page.getByRole('button', { name: '启用已保留的通行密钥', exact: true }).click();
    await expect(page.getByLabel('Bitwarden JSON 文件', { exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: '检查已有凭证', exact: true }).click();
    await expect(page.getByRole('heading', { name: '可更新 0 条凭证', exact: true })).toBeVisible();
    await expect(page.getByText('有 1 个通行密钥缺少可用私钥或使用了不支持的算法。', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '确认更新 0 条', exact: true })).toBeDisabled();
    assert.deepEqual(await send({ type: 'list' }), summaries);
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
    assert.equal(exportedCsv.count, 2);
    assert.equal(exportedCsv.skipped, source.items.filter(item => item.type !== 1).length);
    assert(exportedCsv.text.includes('" p,""q"'));
    await page.screenshot({ path: path.join(output, `migration-${name}-csv.png`) });

    const beforeScan = await send({ type: 'list' });
    const website = await context.newPage();
    await page.getByRole('button', { name: '密码库', exact: true }).click();
    await page.getByRole('button', { name: '新建', exact: true }).click();
    await page.getByRole('menuitem', { name: '登录', exact: true }).click();
    await page.getByText('两步验证码（可选）', { exact: true }).click();
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
    const pagesBefore = nativeQr ? (await browserCdp.send('Target.getTargets', { filter: [{ type: 'page' }] })).targetInfos : [];
    await browserCdp.send('Extensions.triggerAction', { id, targetId: tabTarget.targetId });
    const popup = nativeQr ? await nativePopupQr(browserCdp, id, new Set(pagesBefore.map(entry => entry.targetId))) : undefined;
    await browserCdp.detach();
    const button = page.getByRole('button', { name: '扫描当前网页二维码', exact: true });
    const choice = page.getByRole('button', { name: 'QR-Fixture:alice', exact: true });
    const seed = page.getByLabel('验证码设置密钥', { exact: true });
    const click = locator => locator.evaluate(node => node.click());
    const scan = async () => {
      await click(button);
      await expect(choice).toBeVisible();
      return page.evaluate(() => {
        const last = name => performance.getEntriesByName(`vault:qr-${name}`, 'mark').at(-1);
        const start = last('start'), preview = last('preview'), dom = last('dom');
        return { replyMs: preview.startTime - start.startTime, domMs: dom.startTime - start.startTime, timings: preview.detail };
      });
    };
    const first = await scan();
    await page.evaluate(async sourceId => {
      const own = await chrome.tabs.getCurrent();
      await chrome.tabs.update(own.id, { active: true });
      await chrome.tabs.update(sourceId, { active: true });
    }, tab.id);
    await expect(choice, 'Switching away and back must invalidate the unapplied QR choice').toHaveCount(0);
    await expect(seed).toHaveValue('');
    // Keep the next scan inside the capture cooldown so cancellation is deterministic.
    await click(button);
    const cancelScan = page.getByRole('button', { name: '取消扫描', exact: true });
    await click(cancelScan);
    await expect(choice).toHaveCount(0);
    await expect(button).toBeEnabled();
    await website.screenshot({ path: path.join(output, `migration-${name}-qr.png`) });
    await website.goto(base + nextPath);
    await website.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await new Promise(resolve => setTimeout(resolve, 650));
    const following = await scan();
    await click(page.getByRole('button', { name: '取消选择', exact: true }));
    await expect(seed).toHaveValue('');
    await scan();
    await click(choice);
    await expect(seed).toHaveValue(/otpauth:\/\/totp\/.*JBSWY3DPEHPK3PXP/);
    assert.deepEqual(await send({ type: 'list' }), beforeScan, 'Scanning and choosing must not mutate the vault');
    await website.goto(base + '/empty');
    await website.getByText('No QR here', { exact: true }).waitFor();
    await website.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await click(button);
    await expect(page.getByRole('alert').filter({ hasText: '没有找到验证码二维码' })).toBeVisible();
    await expect(choice).toHaveCount(0);
    await website.goto(`http://localhost:${server.address().port}/qr`);
    await click(button);
    await expect(page.getByRole('alert').filter({ hasText: '截图尚未授权' })).toBeVisible();
    await expect(choice).toHaveCount(0);
    await website.close();
    await page.bringToFront();
    await verifyGoogleImages(page, send, reply);
    const encrypted2fasFixture = await verifyEncrypted2fas(send, reply);
    assert.deepEqual(errors, []);
    const result = { browser: name, version: context.browser().version(), portableJson: true, argon2AndPbkdf2Reference: true, tamperRejected: true, confirmationAndReprompt: true,
      retainedPasskeyPreview: true, googleMultiImageDrop: true,
      preservedFieldsAndSshRoundTrip: true, csvMappingAndExport: true, screenshotQr: true, invertedQr: true, qrFirstColor: firstColor,
      first, following, popup, switchedTabInvalidated: true, canceledScanAndChoice: true, noSaveUntilConfirmed: true,
      noActiveTabRejected: true, canvasOverrideIgnored: true, googleBatchImages: true, encrypted2fasFixture, errors };
    console.log(JSON.stringify(result));
    return result;
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
  try {
    const results = [];
    for (const name of process.argv.slice(2).length ? process.argv.slice(2) : ['edge', 'helium']) results.push(await run(name, server));
    if (nativeQr) {
      await fs.writeFile(path.join(output, `qr-native-${firstColor}.json`), JSON.stringify({
        extension: path.relative(root, extension), results,
      }, null, 2) + '\n', 'utf8');
      assert(results.every(result => result.browser !== 'helium' || result.popup.first.presentedMs < 200),
        'First native Helium Popup QR presentation must be under 200 ms');
    }
  }
  finally { server.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
