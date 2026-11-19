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
const sourcePassword = 'Safety-Test-Source#2026';
const restorePassword = 'Safety-Test-Restore#2026';
const backupPassword = 'Safety-Test-Backup#2026';
const proof = secret => ({ method: 'master', secret });
const output = path.join(root, 'test-results');

async function run(name) {
  const executablePath = process.env.VAULT_BROWSER_PATH || browsers[name];
  assert(executablePath, 'Unknown browser: ' + name);
  await fs.access(executablePath);
  const tempRoot = path.resolve(os.tmpdir());
  const directory = await fs.mkdtemp(path.join(tempRoot, 'vault-data-safety-'));
  const errors = [];
  async function withVault(profile, acceptDownloads, view, action) {
    const context = await chromium.launchPersistentContext(path.join(directory, profile), {
      executablePath, acceptDownloads, headless: process.env.VAULT_HEADED !== '1',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension],
      viewport: view === 'popup' ? { width: 400, height: 600 } : { width: 330, height: 760 },
    });
    try {
      const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
      const id = new URL(worker.url()).host;
      const page = await context.newPage();
      page.on('pageerror', error => errors.push(error.message));
      page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
      page.on('requestfailed', request => {
        if (request.url().startsWith('chrome-extension://')) errors.push(request.url() + ': ' + request.failure()?.errorText);
      });
      page.on('response', response => {
        if (response.status() >= 400 && response.url().startsWith('chrome-extension://')) errors.push(response.url() + ': ' + response.status());
      });
      await page.goto(`chrome-extension://${id}/${view}.html`);
      const send = message => page.evaluate(async message => {
        const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
        if (!reply.ok) throw new Error(reply.error);
        return reply.value;
      }, message);
      await action({ page, send });
    } finally {
      await context.close();
    }
  }
  const backupPath = path.join(directory, 'restorable.vaultpack');
  const screenshot = async (page, stage) => {
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({ path: path.join(output, `data-safety-${name}-${stage}.png`), animations: 'disabled' });
  };
  const add = (send, title) => send({ type: 'upsert', itemJson: JSON.stringify({
    title, data: { kind: 'login', username: 'sample', password: 'Previous-Test-Password#2026' },
  }) });
  const countChanges = async send => (await send({ type: 'status' })).changesSinceBackup;

  try {
    await fs.mkdir(output, { recursive: true });
    let exportedItem;
    let beforeBackup;
    // Deny browser downloads in the first run to exercise a real browser-side cancellation.
    await withVault('source', false, 'popup', async ({ page, send }) => {
      await send({ type: 'create', masterPassword: sourcePassword, calibrate: false });
      for (const title of ['Keep my login', 'Visible trash', 'Hidden trash']) await add(send, title);
      const items = await send({ type: 'list' });
      const keptId = items.find(item => item.title === 'Keep my login').id;
      for (const item of items.filter(item => item.id !== keptId)) await send({ type: 'trash', id: item.id, trashed: true });
      const get = () => send({ type: 'get', id: keptId, proof: proof(sourcePassword) });
      const keep = await get();
      keep.requireReprompt = true;
      keep.data.password = 'Current-Test-Password#2026';
      keep.customFields = [{ name: 'Sample', value: 'Hidden test content', hidden: true }];
      await send({ type: 'upsert', itemJson: JSON.stringify(keep) });
      for (let index = 0; index < 2; index++) {
        const item = await get();
        await send({ type: 'upsert', itemJson: JSON.stringify({ ...item, note: 'Backup test note ' + index }), proof: proof(sourcePassword) });
      }
      exportedItem = await get();
      await page.reload();
      await page.getByRole('button', { name: '回收站', exact: true }).click();
      await page.getByRole('searchbox').fill('Visible trash');
      await expect(page.getByText('回收站共 2 条凭证。当前搜索显示 1 条。')).toBeVisible();
      const clear = page.getByRole('button', { name: '清空回收站', exact: true });
      const dialog = page.getByRole('dialog');
      await clear.click();
      await expect(dialog).toContainText('全部 2 条凭证');
      await expect(dialog).toContainText('未出现在当前搜索结果里的条目');
      await screenshot(page, 'trash-confirmation');
      await dialog.getByRole('button', { name: '取消' }).click();
      assert.equal((await send({ type: 'list' })).filter(item => item.trashed).length, 2);
      await clear.click();
      await dialog.getByRole('button', { name: '清空回收站', exact: true }).click();
      await expect(page.getByText('回收站已清空。')).toBeVisible();
      assert.deepEqual((await send({ type: 'list' })).map(item => item.id), [keptId]);

      beforeBackup = await countChanges(send);
      assert(beforeBackup >= 10);
      await openBackup(page);
      const canceled = await requestDownload(page);
      assert(await canceled.failure(), 'the first download must fail or be canceled');
      assert.equal(await countChanges(send), beforeBackup);
      await screenshot(page, 'backup-confirmation');
      await page.getByRole('button', { name: '未保存', exact: true }).click();
      await expect(page.getByRole('button', { name: '文件已保存', exact: true })).toHaveCount(0);
      assert.equal(await countChanges(send), beforeBackup);
    });

    await withVault('source', true, 'sidepanel', async ({ page, send }) => {
      await send({ type: 'unlock', password: sourcePassword });
      await page.reload();
      assert.equal(await countChanges(send), beforeBackup);
      await openBackup(page);
      await (await requestDownload(page)).saveAs(backupPath);
      assert((await fs.stat(backupPath)).size > 0);
      await add(send, 'Saved after exporting');
      assert.equal(await countChanges(send), beforeBackup + 1);
      await page.getByRole('button', { name: '文件已保存', exact: true }).click();
      await expect(page.getByText('已记录这次备份。')).toBeVisible();
      assert.equal(await countChanges(send), 1);
    });

    await withVault('new-profile', true, 'sidepanel', async ({ page, send }) => {
      assert.equal((await send({ type: 'status' })).configured, false);
      await send({ type: 'create', masterPassword: restorePassword, calibrate: false });
      await page.reload();
      await openBackup(page);
      await page.getByRole('button', { name: '导入备份', exact: true }).click();
      await page.getByLabel('导入加密备份').setInputFiles(backupPath);
      const previewBackup = async password => {
        await page.getByLabel('备份密码', { exact: true }).fill(password);
        await page.getByRole('button', { name: '验证并预览', exact: true }).click();
        await enterProof(page, restorePassword);
      };
      await previewBackup('Wrong-Test-Password#2026');
      await expect(page.getByRole('alert')).toContainText('无法读取此备份');
      assert.deepEqual(await send({ type: 'list' }), []);
      await previewBackup(backupPassword);
      await expect(page.getByRole('button', { name: '确认合入', exact: true })).toBeEnabled();
      assert.deepEqual(await send({ type: 'list' }), []);
      await page.getByRole('button', { name: '取消', exact: true }).click();
      assert.deepEqual(await send({ type: 'list' }), []);
      await previewBackup(backupPassword);
      await page.getByRole('button', { name: '确认合入', exact: true }).click();
      await enterProof(page, restorePassword);
      await expect(page.getByText('已合并 1 条凭证。')).toBeVisible();
      const [item] = await send({ type: 'list' });
      assert(item.requireReprompt);
      assert.equal(item.id, exportedItem.id);
      await assert.rejects(send({ type: 'get', id: item.id }), /再次验证/);
      const restored = await send({ type: 'get', id: item.id, proof: proof(restorePassword) });
      assert.deepEqual(restored.data, exportedItem.data);
      assert.equal(restored.data.passwordHistory.length, 1);
      assert.deepEqual(restored.customFields, exportedItem.customFields);
      assert.equal(restored.note, exportedItem.note);
      await screenshot(page, 'fresh-restore');
    });
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ browser: name, trashScope: true, canceledDownloadKeptReminder: true, savedBackupKeptLaterEdits: true, restoredInFreshProfile: true, pageErrors: errors }));
  } finally {
    const resolved = path.resolve(directory);
    assert(path.dirname(resolved) === tempRoot && path.basename(resolved).startsWith('vault-data-safety-'));
    await fs.rm(resolved, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
}

async function openBackup(page) {
  await page.getByRole('button', { name: '设置', exact: true }).click();
  await page.getByRole('button', { name: /^备份与恢复/ }).click();
}
async function enterProof(page, password) {
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('主密码', { exact: true }).fill(password);
  await dialog.getByRole('button', { name: '验证', exact: true }).click();
}
async function requestDownload(page) {
  await page.getByLabel('备份密码', { exact: true }).fill(backupPassword);
  await page.getByLabel('再次输入备份密码', { exact: true }).fill(backupPassword);
  await page.getByRole('button', { name: '导出 .vaultpack', exact: true }).click();
  const download = page.waitForEvent('download');
  await enterProof(page, sourcePassword);
  await expect(page.getByRole('button', { name: '文件已保存', exact: true })).toBeVisible();
  return download;
}

(async () => {
  for (const name of process.argv.length > 2 ? process.argv.slice(2) : Object.keys(browsers)) await run(name);
})().catch(error => { console.error(error); process.exitCode = 1; });
