const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const candidates = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
async function run(name) {
  const executablePath = process.env.VAULT_BROWSER_PATH || candidates[name];
  await fs.access(executablePath);
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-smoke-' + name + '-'));
  const context = await chromium.launchPersistentContext(profile, { executablePath, headless: process.env.VAULT_HEADED !== '1',
    args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension], viewport: { width: 900, height: 850 } });
  const errors = [];
  const result = { browser: name, version: context.browser().version(), extension: path.relative(root, extension) };
  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
    const id = new URL(worker.url()).host;
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.goto('chrome-extension://' + id + '/sidepanel.html');
    await page.getByRole('button', { name: '暂不配置，创建本地密码库', exact: true }).click();
    await page.getByLabel('主密码', { exact: true }).fill('Browser-Test-Master#2026');
    await page.getByLabel('再次输入主密码').fill('Browser-Test-Master#2026');
    await page.getByRole('button', { name: '创建本地密码库', exact: true }).click();
    await page.getByRole('button', { name: '下载应急恢复包' }).waitFor();
    const recoveryCode = await page.locator('.recovery-code').innerText();
    const downloadEvent = page.waitForEvent('download');
    await page.getByRole('button', { name: '下载应急恢复包' }).click();
    assert.equal((await downloadEvent).suggestedFilename(), 'Vault-Emergency-Kit.txt');
    await page.getByRole('button', { name: '我已保存，进入密码库' }).click();
    await page.getByRole('button', { name: '添加登录项' }).click();
    await page.getByLabel('名称', { exact: true }).fill('Browser-Secret_9981');
    await page.getByLabel('用户名', { exact: true }).fill('test-user');
    await page.getByLabel('密码', { exact: true }).fill('Never-Persist-Plaintext#9981');
    await page.getByRole('button', { name: '添加网站', exact: true }).click();
    await page.getByLabel('网站 1', { exact: true }).fill('https://example-bank.com');
    await page.getByRole('button', { name: '保存凭证', exact: true }).click();
    await page.getByText('凭证已保存。').waitFor();
    const send = message => page.evaluate(async message => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
      if (!reply.ok) throw new Error(reply.error);
      return reply.value;
    }, message);
    const readFiles = () => page.evaluate(() => new Promise((resolve, reject) => {
      const open = indexedDB.open('vault-extension');
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const request = db.transaction('vault').objectStore('vault').get('active');
        request.onsuccess = () => { const files = request.result; db.close(); resolve({ head: Array.from(files.head), snap: Array.from(files.snap) }); };
        request.onerror = () => reject(request.error);
      };
    }));
    const persisted = await readFiles();
    const local = await page.evaluate(() => chrome.storage.local.get(null));
    for (const marker of ['Browser-Secret_9981', 'Never-Persist-Plaintext#9981', 'example-bank.com']) {
      assert(!Buffer.from(persisted.head).toString().includes(marker));
      assert(!Buffer.from(persisted.snap).toString().includes(marker));
      assert(!JSON.stringify(local).includes(marker));
    }
    result.encryptedPersistence = true;
    const cdp = await context.newCDPSession(page);
    let versions = [];
    cdp.on('ServiceWorker.workerVersionUpdated', event => { versions = event.versions; });
    await cdp.send('ServiceWorker.enable');
    await expect.poll(() => versions.find(version => version.scriptURL.startsWith('chrome-extension://' + id))).toBeTruthy();
    const version = versions.find(version => version.scriptURL.startsWith('chrome-extension://' + id));
    await cdp.send('ServiceWorker.stopWorker', { versionId: version.versionId });
    const start = performance.now();
    assert((await send({ type: 'status' })).unlocked);
    result.wakeMs = Math.round(performance.now() - start);
    assert.equal((await send({ type: 'list' })).length, 1);
    const proof = { method: 'master', secret: 'Browser-Test-Master#2026' };
    await send({ type: 'create-pin', pin: '734928', proof });
    await send({ type: 'lock' });
    await expect(page.getByRole('button', { name: '解锁', exact: true })).toBeVisible();
    for (let i = 0; i < 4; i++) await assert.rejects(send({ type: 'unlock-pin', pin: '111111' }));
    await page.getByRole('button', { name: '使用 PIN', exact: true }).click();
    await page.getByLabel('本机 PIN', { exact: true }).fill('111111');
    await page.getByRole('button', { name: '解锁', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('快捷解锁已移除');
    await expect(page.getByLabel('主密码', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '使用 PIN', exact: true })).toHaveCount(0);
    await assert.rejects(send({ type: 'unlock-pin', pin: '734928' }));
    const settings = await page.evaluate(async () => (await chrome.storage.local.get('settings')).settings);
    assert(!('pinWrap' in settings));
    await send({ type: 'unlock', password: proof.secret });
    let item = await send({ type: 'get', id: (await send({ type: 'list' }))[0].id });
    item.requireReprompt = true;
    await send({ type: 'upsert', itemJson: JSON.stringify(item) });
    await assert.rejects(send({ type: 'get', id: item.id, repromptVerified: true }));
    assert.equal((await send({ type: 'get', id: item.id, proof })).title, item.title);
    const { bytes: backup } = await send({ type: 'export', password: 'Backup-Password-2026!', proof });
    assert(!Buffer.from(backup).toString().includes('Never-Persist-Plaintext#9981'));
    await send({ type: 'trash', id: item.id, trashed: true });
    await send({ type: 'delete', id: item.id });
    assert.equal((await send({ type: 'list' })).length, 0);
    const backupPreview = await send({ type: 'preview-vaultpack', bytes: backup, password: 'Backup-Password-2026!', proof });
    assert.equal(backupPreview.added, 1);
    assert.equal(await send({ type: 'import', bytes: backup, password: 'Backup-Password-2026!', proof, stamp: backupPreview.stamp }), 1);
    const beforeRotation = await readFiles();
    await send({ type: 'lock' });
    await send({ type: 'recover', recoveryCode, newPassword: 'Recovered-Master#2026' });
    assert.deepEqual((await readFiles()).snap, beforeRotation.snap);
    const newProof = { method: 'master', secret: 'Recovered-Master#2026' };
    assert.equal((await send({ type: 'get', id: item.id, proof: newProof })).data.password, 'Never-Persist-Plaintext#9981');
    await page.reload();
    await page.getByRole('button', { name: '密码库', exact: true }).waitFor();
    await page.getByRole('button', { name: '生成器', exact: true }).click();
    await page.getByLabel('类型', { exact: true }).selectOption('passphrase');
    await page.getByLabel('单词数', { exact: true }).fill('7');
    await page.getByRole('button', { name: '生成', exact: true }).click();
    await expect.poll(async () => (await page.locator('output').innerText()).split('-').length).toBe(7);
    await cdp.send('WebAuthn.enable');
    let authenticator = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
    } });
    await page.getByRole('button', { name: '设置', exact: true }).click();
    await page.getByRole('button', { name: /解锁与自动锁定/ }).click();
    await page.getByRole('button', { name: '设置系统解锁', exact: true }).click();
    await page.getByRole('dialog').getByLabel('主密码', { exact: true }).fill(newProof.secret);
    await page.getByRole('dialog').getByRole('button', { name: '验证', exact: true }).click();
    await expect(page.getByRole('button', { name: '移除系统解锁', exact: true })).toBeVisible();
    assert((await send({ type: 'status' })).prf);
    await send({ type: 'lock' });
    await page.reload();
    await page.getByRole('button', { name: '系统解锁', exact: true }).click();
    await expect(page.getByRole('button', { name: '密码库', exact: true })).toBeVisible();
    await send({ type: 'remove-prf' });
    await page.reload();
    await cdp.send('WebAuthn.removeVirtualAuthenticator', authenticator);
    authenticator = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: false,
    } });
    await page.getByRole('button', { name: '设置', exact: true }).click();
    await page.getByRole('button', { name: /解锁与自动锁定/ }).click();
    await page.getByRole('button', { name: '设置系统解锁', exact: true }).click();
    await page.getByRole('dialog').getByLabel('主密码', { exact: true }).fill(newProof.secret);
    await page.getByRole('dialog').getByRole('button', { name: '验证', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('PIN');
    assert.equal((await send({ type: 'status' })).prf, undefined);
    await cdp.send('WebAuthn.removeVirtualAuthenticator', authenticator);
    result.virtualPrfAndFallback = true;
    await send({ type: 'copy-sensitive', value: 'Clipboard-Secret-9981' });
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'Clipboard-Secret-9981');
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), { timeout: 45000, intervals: [1000] }).toBe('');
    await send({ type: 'copy-sensitive', value: 'Clipboard-Secret-9981' });
    await page.evaluate(() => navigator.clipboard.writeText('ordinary-copy-must-survive'));
    await expect.poll(() => page.evaluate(async () => (await chrome.storage.session.get('clipboard')).clipboard), { timeout: 45000, intervals: [1000] }).toBeUndefined();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'ordinary-copy-must-survive');
    result.clipboardCleanupAndPreservation = true;
    assert.equal((await page.evaluate(() => chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] }))).length, 0);
    const popup = await context.newPage();
    popup.on('pageerror', error => errors.push(error.message));
    await popup.setViewportSize({ width: 400, height: 600 });
    await popup.goto('chrome-extension://' + id + '/popup.html');
    await popup.getByRole('button', { name: '密码库', exact: true }).waitFor();
    assert(await popup.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await fs.mkdir(path.join(root, 'test-results'), { recursive: true });
    await popup.screenshot({ path: path.join(root, 'test-results/' + name + '-popup.png') });
    await page.setViewportSize({ width: 330, height: 760 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({ path: path.join(root, 'test-results/' + name + '-sidepanel.png'), fullPage: true });
    await page.evaluate(() => chrome.storage.session.set({ active: { key: Array(32).fill(0), wrap: [], lastActivityMs: Date.now() - 3600000, unlockedAtMs: Date.now() - 3600000 } }));
    const running = versions.find(entry => entry.scriptURL.startsWith('chrome-extension://' + id) && entry.runningStatus === 'running');
    if (running) await cdp.send('ServiceWorker.stopWorker', { versionId: running.versionId });
    assert.equal((await send({ type: 'status' })).unlocked, false);
    assert.deepEqual(errors, []);
    result.consoleErrors = errors;
    result.passed = true;
    console.log(JSON.stringify(result));
    return result;
  } finally {
    await context.close();
    const resolved = path.resolve(profile);
    if (path.dirname(resolved) !== path.resolve(os.tmpdir()) || !path.basename(resolved).startsWith('vault-smoke-' + name + '-')) {
      throw new Error('Refusing to remove a profile outside the test temporary directory');
    }
    await fs.rm(resolved, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
  }
}
(async () => {
  const results = [];
  for (const name of process.argv.slice(2).length ? process.argv.slice(2) : ['edge', 'helium']) results.push(await run(name));
  await fs.writeFile(path.join(root, 'test-results/browser-smoke.json'), JSON.stringify(results, null, 2));
})().catch(error => { console.error(error); process.exitCode = 1; });
