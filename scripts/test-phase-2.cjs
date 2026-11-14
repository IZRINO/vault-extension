const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

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

async function verify(name) {
  const executablePath = process.env.VAULT_BROWSER_PATH || browsers[name];
  assert(executablePath, 'Unknown browser: ' + name);
  await fs.access(executablePath);
  const temp = path.resolve(os.tmpdir());
  const profile = await fs.mkdtemp(path.join(temp, 'vault-phase-2-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      executablePath, headless: process.env.VAULT_HEADED !== '1',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension],
      viewport: name === 'edge' ? { width: 400, height: 600 } : { width: 330, height: 760 },
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
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
    const send = message => page.evaluate(async message => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
      if (!reply.ok) throw new Error(reply.error);
      return reply.value;
    }, message);
    await send({ type: 'create', masterPassword: password, calibrate: false });
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
    await page.clock.setFixedTime(new Date(59_000));
    await enterProof(page);
    const code = page.locator('output[aria-label="当前验证码"] .cells');
    await expect(code).toHaveText('287082');
    assert.equal(await otpLoaded(), true);
    await expect(page.getByText('1 秒后刷新')).toBeVisible();
    await page.clock.setFixedTime(new Date(60_000));
    await expect(code).toHaveText('359152');
    await screenshot(page, name, 'totp');
    await page.getByRole('button', { name: '复制验证码', exact: true }).click();
    await expect.poll(() => page.evaluate(() => globalThis.vaultCopiedCode)).toBe('359152');
    await page.getByRole('button', { name: '锁定密码库', exact: true }).click();
    await expect(page.getByRole('heading', { name: '解锁密码库' })).toBeVisible();
    await expect(code).toHaveCount(0);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ browser: name, csvPreviewAndImport: true, otpLoadedAfterProof: true, totpRotationCopyAndReprompt: true, errors }));
  } finally {
    try { await context?.close(); }
    finally {
      const resolved = path.resolve(profile);
      assert(path.dirname(resolved) === temp && path.basename(resolved).startsWith('vault-phase-2-'));
      await fs.rm(resolved, { recursive: true, maxRetries: 3, retryDelay: 200 });
    }
  }
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
