const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const { createHmac } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { waitForBuiltInFilters } = require('./browser-fixtures.cjs');

const root = path.resolve(__dirname, '..');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const browsers = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const password = 'Phase-Two-Local-Test#2026';
const csvPassword = 'Sample-Csv-Secret#2026';
const setupKey = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // RFC 6238 test fixture, never a real account.
const output = path.join(root, 'test-results');
function fixtureCode(ms, steam = false) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(ms / 30000)));
  const hash = createHmac('sha1', Buffer.from('12345678901234567890')).update(counter).digest();
  let value = hash.readUInt32BE(hash[19] & 15) & 0x7fffffff;
  if (!steam) return String(value % 1000000).padStart(6, '0');
  const alphabet = '23456789BCDFGHJKMNPQRTVWXY';
  return Array.from({ length: 5 }, () => {
    const char = alphabet[value % alphabet.length]; value = Math.floor(value / alphabet.length); return char;
  }).join('');
}

async function verify(name) {
  const executablePath = process.env.VAULT_BROWSER_PATH || browsers[name];
  assert(executablePath, 'Unknown browser: ' + name);
  await fs.access(executablePath);
  const temp = path.resolve(os.tmpdir());
  const profile = await fs.mkdtemp(path.join(temp, 'vault-phase-2-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      executablePath, headless: process.env.VAULT_HEADED == null ? name !== 'helium' : process.env.VAULT_HEADED !== '1',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension],
      viewport: name === 'edge' ? { width: 400, height: 600 } : { width: 330, height: 760 },
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
    await waitForBuiltInFilters(context, name);
    const id = new URL(worker.url()).host;
    const view = name === 'edge' ? 'popup' : 'sidepanel';
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    context.on('requestfailed', request => {
      if (request.url().startsWith(`chrome-extension://${id}/`)) errors.push(request.url() + ': ' + request.failure()?.errorText);
    });
    context.on('response', response => {
      if (response.status() >= 400 && response.url().startsWith(`chrome-extension://${id}/`)) errors.push(response.url() + ': ' + response.status());
    });
    const wasmRequests = [];
    context.on('request', request => { if (request.url().includes('.wasm')) wasmRequests.push(request.url()); });
    await page.addInitScript(() => {
      const fetchResource = globalThis.fetch.bind(globalThis);
      globalThis.vaultOtpLoaded = false;
      globalThis.fetch = (input, ...args) => {
        if (/\/vault_otp_bg-.*\.wasm$/.test(String(input))) globalThis.vaultOtpLoaded = true;
        return fetchResource(input, ...args);
      };
      // Observe the UI's copy intent without changing the real system clipboard.
      for (const runtime of new Set([globalThis.chrome?.runtime, globalThis.browser?.runtime])) {
        if (!runtime) continue;
        const sendMessage = runtime.sendMessage.bind(runtime);
        runtime.sendMessage = (...args) => {
          const message = args[0];
          if (message?.target === 'vault' && message.type === 'copy-sensitive') {
            globalThis.vaultCopiedCode = message.value;
            return Promise.resolve({ ok: true });
          }
          return sendMessage(...args);
        };
      }
    });
    await page.goto(`chrome-extension://${id}/${view}.html`);
    const otpLoaded = () => page.evaluate(() => globalThis.vaultOtpLoaded);
    const setClock = async ms => {
      await worker.evaluate(fixed => { Date.now = () => fixed; }, ms);
      await page.clock.setFixedTime(new Date(ms));
    };
    const send = message => page.evaluate(async message => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
      if (!reply.ok) throw new Error(reply.error);
      return reply.value;
    }, message);
    await send({ type: 'create', masterPassword: password, calibrate: false });
    assert(!wasmRequests.some(url => url.includes('vault_importers')), 'Unlock must not load the optional importer');
    await send({ type: 'upsert', itemJson: JSON.stringify({
      title: 'Existing login', data: { kind: 'login', username: 'old', password: 'Existing-Test-Secret', uris: [{ uri: 'https://existing.example' }] },
    }) });
    await page.reload();
    await page.getByRole('button', { name: '设置', exact: true }).click();
    await page.getByRole('button', { name: /^导入浏览器密码/ }).click();
    assert.equal(await otpLoaded(), false);
    await page.getByLabel('浏览器密码文件').setInputFiles({
      name: 'browser-export.csv', mimeType: 'text/csv', buffer: Buffer.from([
        'Title,URL,Username,Password,Notes,OTPAuth',
        `Mail import,https://new.example,guest,${csvPassword},"Work, account",`,
        'Duplicate,https://new.example/page,guest,Second-Test-Secret,,',
        'Existing,https://EXISTING.example:443,old,Do-Not-Replace,,',
        'Bad address,ftp://invalid.example,guest,Invalid-Test-Secret,,',
      ].join('\r\n')),
    });
    await page.getByRole('button', { name: '预览导入', exact: true }).click();
    await expect(page.getByRole('heading', { name: '可添加 1 条登录凭证' })).toBeVisible();
    await expect(page.getByText(/跳过 2 条，无法读取 1 条/)).toBeVisible();
    assert((await send({ type: 'list' })).length === 1);
    assert(!(await page.locator('body').innerText()).includes(csvPassword));
    await fs.mkdir(output, { recursive: true });
    await screenshot(page, name, 'csv-preview');
    await page.getByRole('button', { name: '确认导入 1 条' }).click();
    await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
    assert((await send({ type: 'list' })).length === 1);
    await page.getByRole('button', { name: '确认导入 1 条' }).click();
    await enterProof(page);
    await expect(page.getByText('已导入 1 条登录凭证。')).toBeVisible();

    await page.getByRole('button', { name: '密码库', exact: true }).click();
    await page.getByText('Mail import', { exact: true }).click();
    await page.getByRole('button', { name: '编辑', exact: true }).click();
    await page.getByText('两步验证码（可选）', { exact: true }).click();
    const setup = page.getByLabel('验证码设置密钥', { exact: true });
    await setup.fill('123456');
    await page.getByRole('button', { name: '保存凭证', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('设置密钥无效');
    await setup.fill(setupKey);
    await page.getByRole('switch', { name: '查看或修改前再次验证' }).check();
    await page.getByRole('button', { name: '保存凭证', exact: true }).click();
    await expect(page.getByText('凭证已保存。')).toBeVisible();
    await page.getByText('Mail import', { exact: true }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.locator('output[aria-label="当前验证码"]')).toHaveCount(0);
    assert.equal(await otpLoaded(), false);
    const fixtureTime = Math.floor(Date.now() / 30000) * 30000 + 59000;
    await setClock(fixtureTime);
    await enterProof(page);
    const code = page.locator('output[aria-label="当前验证码"] .cells');
    await expect(code).toHaveText(fixtureCode(fixtureTime));
    assert.equal(await otpLoaded(), false, 'The panel does not load OTP WASM or receive a setup key');
    await expect(page.getByText('1 秒后刷新')).toBeVisible();
    await setClock(fixtureTime + 1000);
    await expect(code).toHaveText(fixtureCode(fixtureTime + 1000));
    await screenshot(page, name, 'totp');
    await page.getByRole('button', { name: '复制验证码', exact: true }).click();
    await expect.poll(() => page.evaluate(() => globalThis.vaultCopiedCode)).toBe(fixtureCode(fixtureTime + 1000));
    await verifyEnte(page, send, name, () => setClock(fixtureTime + 30000), fixtureTime + 30000);
    await page.getByRole('button', { name: '锁定密码库', exact: true }).click();
    await expect(page.getByRole('heading', { name: '解锁密码库' })).toBeVisible();
    await expect(code).toHaveCount(0);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ browser: name, csvPreviewAndImport: true, otpNeverLoadedInPanel: true,
      totpRotationCopyAndReprompt: true, entePreviewMergeAndExport: true, steamAndHotp: true, errors }));
  } finally {
    try { await context?.close(); }
    finally {
      const resolved = path.resolve(profile);
      assert(path.dirname(resolved) === temp && path.basename(resolved).startsWith('vault-phase-2-'));
      await fs.rm(resolved, { recursive: true, maxRetries: 3, retryDelay: 200 });
    }
  }
}

async function verifyEnte(page, send, name, setSteamTime, steamTime) {
  const proof = { method: 'master', secret: password };
  await send({ type: 'upsert', itemJson: JSON.stringify({
    title: 'GitHub login', data: { kind: 'login', username: 'tester', password: 'Keep-Original-GitHub-Password', uris: [{ uri: 'https://github.com/login' }] },
    requireReprompt: true, note: 'Original note', tags: ['existing'],
  }) });
  const before = await send({ type: 'list' });
  const github = before.find(item => item.title === 'GitHub login');
  const uri = (kind, label, issuer, extra = '') =>
    `otpauth://${kind}/${label}?secret=${setupKey}&issuer=${issuer}${extra}`;
  const githubUri = uri('totp', 'GitHub%3Atester', 'GitHub', '&codeDisplay=' + encodeURIComponent(JSON.stringify({
    pinned: true, tags: ['work'], note: 'Imported note', iconID: 'custom-icon', position: 7,
  })));
  const content = [
    githubUri,
    uri('totp', 'Acme%3Auser#123', 'Acmeperiod=60', '&algorithm=Algorithm.sha256'),
    uri('steam', 'Steam%3Atester', 'Steam', '&digits=5'),
    uri('hotp', 'Counter%3Atester', 'Counter', '&counter=0'),
    uri('totp', 'Archived%3Aold', 'Archived', '&codeDisplay=' + encodeURIComponent(JSON.stringify({ trashed: true, note: 'Archived note', tags: ['archive'] }))),
    githubUri,
    'invalid-record',
  ].join('\n');
  await page.getByRole('button', { name: '设置', exact: true }).click();
  await page.getByRole('button', { name: /^Ente Auth 验证器迁移/ }).click();
  await page.getByLabel('Ente Auth 文本文件').setInputFiles({ name: 'ente-auth-export.txt', mimeType: 'text/plain', buffer: Buffer.from(content) });
  await page.getByRole('button', { name: '预览验证码', exact: true }).click();
  await expect(page.getByRole('heading', { name: '可导入 5 个验证码' })).toBeVisible();
  await expect(page.getByText(/重复跳过 1 个，无法读取 1 个/)).toBeVisible();
  await expect(page.getByText(/1 个会保留在回收站/)).toBeVisible();
  assert(!(await page.locator('body').innerText()).includes(setupKey), 'Preview must not reveal the seed');
  assert.equal((await send({ type: 'list' })).length, before.length);
  const merge = page.getByRole('checkbox', { name: 'GitHub login · tester' });
  await expect(merge).not.toBeChecked();
  await merge.check();
  await screenshot(page, name, 'ente-preview');
  await page.getByRole('button', { name: '确认导入 5 个', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
  assert.equal((await send({ type: 'list' })).length, before.length);
  await page.getByRole('button', { name: '确认导入 5 个', exact: true }).click();
  await enterProof(page);
  await expect(page.getByText('已导入 5 个验证码。')).toBeVisible();
  const merged = await send({ type: 'get', id: github.id, proof });
  assert.equal(merged.data.password, 'Keep-Original-GitHub-Password');
  assert.equal(merged.requireReprompt, true);
  assert.equal(merged.note, 'Original note\n\nImported note');
  assert.deepEqual(merged.tags, ['existing', 'work']);
  const all = await send({ type: 'list' });
  assert.equal(all.length, before.length + 4);
  assert(all.find(item => item.title === 'Archived').trashed);
  const audit = await send({ type: 'audit' });
  for (const title of ['Acme', 'Steam', 'Counter']) {
    assert(!audit.weakItems.some(item => item.title === title), 'A standalone OTP is not a weak password');
  }

  await page.getByRole('button', { name: '密码库', exact: true }).click();
  await page.getByText('Counter', { exact: true }).click();
  await expect(page.locator('output[aria-label="当前验证码"]')).toHaveCount(0);
  await page.getByRole('button', { name: '生成验证码', exact: true }).click();
  await expect(page.locator('output[aria-label="当前验证码"] .cells')).toHaveText('755224');
  await page.getByRole('button', { name: '生成下一个验证码', exact: true }).click();
  await expect(page.locator('output[aria-label="当前验证码"] .cells')).toHaveText('287082');
  const counterId = all.find(item => item.title === 'Counter').id;
  assert(await page.evaluate(async () => new Promise((resolve, reject) => {
    const open = indexedDB.open('vault-extension');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction(['vault', 'journal', 'pendingWal']);
      const current = tx.objectStore('vault').get('active');
      const pending = tx.objectStore('pendingWal').openCursor(null, 'prev');
      const clock = tx.objectStore('journal').getAll();
      tx.oncomplete = () => {
        const bytes = pending.result?.value?.bytes;
        const valid = bytes instanceof Uint8Array && new TextDecoder().decode(bytes.subarray(0, 4)) === 'VLTE' && bytes[6] === 3 &&
          pending.result.value.vaultId === current.result.vaultId && clock.result.length === 1 &&
          pending.result.key.endsWith(clock.result[0].sequence.toString(16).padStart(14, '0'));
        db.close(); resolve(valid);
      };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  })), 'HOTP counter and its encrypted pending change must commit together');
  const changes = (await send({ type: 'status' })).changesSinceBackup;
  await page.getByRole('button', { name: '复制验证码', exact: true }).click();
  await expect.poll(() => page.evaluate(() => globalThis.vaultCopiedCode)).toBe('287082');
  assert.equal((await send({ type: 'status' })).changesSinceBackup, changes);
  await screenshot(page, name, 'hotp');
  await page.getByRole('button', { name: '编辑', exact: true }).click();
  await page.getByLabel('备注', { exact: true }).fill('Edited after generating');
  await page.getByRole('button', { name: '保存凭证', exact: true }).click();
  await expect(page.getByText('凭证已保存。')).toBeVisible();
  assert(!(await send({ type: 'get', id: counterId })).data.totpUri);
  assert((await send({ type: 'get-edit', id: counterId })).data.totpUri.includes('counter=2'));

  await page.getByText('Steam', { exact: true }).click();
  await expect(page.getByText('两步验证码', { exact: true })).toHaveCount(2);
  await expect(page.getByText('密码', { exact: true })).toHaveCount(0);
  await expect(page.getByText('在线泄露检查', { exact: true })).toHaveCount(0);
  await setSteamTime();
  await expect(page.locator('output[aria-label="当前验证码"] .cells')).toHaveText(fixtureCode(steamTime, true));
  await expect(page.locator('output[aria-label="下一期验证码"]')).toBeVisible();
  await screenshot(page, name, 'steam-next-code');

  await send({ type: 'create-pin', pin: '734928', proof });
  await page.getByRole('button', { name: '设置', exact: true }).click();
  await page.getByRole('button', { name: /^Ente Auth 验证器迁移/ }).click();
  await page.getByRole('button', { name: '导出验证码', exact: true }).click();
  const exportButton = page.getByRole('button', { name: '导出 Ente Auth 文本', exact: true });
  await expect(exportButton).toBeDisabled();
  await page.getByRole('checkbox', { name: /我理解文件未加密/ }).check();
  await exportButton.click();
  await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
  await exportButton.click();
  await page.getByRole('dialog').getByRole('button', { name: '验证主密码并导出', exact: true }).click();
  await expect(page.getByRole('dialog').getByLabel('主密码', { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog').getByLabel('验证方式')).toHaveCount(0);
  const downloaded = page.waitForEvent('download');
  await enterProof(page);
  const download = await downloaded;
  assert.match(download.suggestedFilename(), /^Vault-Ente-Auth-.*\.txt$/);
  const stream = await download.createReadStream();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  const exported = Buffer.concat(chunks).toString('utf8');
  assert(exported.includes('counter=2'));
  assert(!exported.includes('Keep-Original-GitHub-Password'), 'OTP export must not include login passwords');
  const entries = exported.trim().split('\n').map(line => new URL(line));
  assert.equal(entries.length, 6);
  const exportedGithub = entries.find(entry => entry.searchParams.get('issuer') === 'GitHub');
  const display = JSON.parse(exportedGithub.searchParams.get('codeDisplay'));
  assert.equal(display.iconID, 'custom-icon');
  assert.equal(display.note, 'Original note\n\nImported note');
  assert.deepEqual(display.tags, ['existing', 'work']);
  assert(JSON.parse(entries.find(entry => entry.searchParams.get('issuer') === 'Archived').searchParams.get('codeDisplay')).trashed);
  await expect(page.getByText(/已请求下载验证码文本/)).toBeVisible();
  await screenshot(page, name, 'ente-export');
}

async function enterProof(page) {
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('主密码', { exact: true }).fill(password);
  await dialog.getByRole('button', { name: '验证', exact: true }).click();
}

async function screenshot(page, name, stage) {
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.screenshot({ path: path.join(output, `phase-2-${name}-${stage}.png`), animations: 'disabled' });
}

(async () => {
  const readBundle = entry => fs.readFile(path.join(extension, entry), 'utf8');
  const [background, kdf, csv, otp] = await Promise.all(['background.js', 'kdf-worker.js', 'csv-worker.js', 'otp-worker.js'].map(readBundle));
  const optionalExports = /wasm_parse_browser_csv|wasm_validate_totp|wasm_totp_at/;
  assert.doesNotMatch(background, optionalExports);
  assert.doesNotMatch(kdf, optionalExports);
  assert.match(csv, /wasm_parse_browser_csv/);
  assert.match(otp, /wasm_validate_totp/);
  for (const name of process.argv.length > 2 ? process.argv.slice(2) : Object.keys(browsers)) await verify(name);
})().catch(error => { console.error(error); process.exitCode = 1; });
