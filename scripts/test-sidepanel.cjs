const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { extensionBuildHash, waitForBuiltInFilters, waitForSetupTab } = require('./browser-fixtures.cjs');

const root = path.resolve(__dirname, '..');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const executables = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const master = 'Native-Sidepanel-Fixture#2026';
const title = 'Sidepanel test login';
const password = 'Fixture-Credential#2026';

// Chromium exposes the native sidebar as a DevTools target outside Playwright's tab list.
async function attachPanel(cdp, targetId) {
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: false });
  const pending = new Map();
  const errors = [];
  let sequence = 0;
  function onMessage(event) {
    if (event.sessionId !== sessionId) return;
    const message = JSON.parse(event.message);
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
    if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') errors.push('Console error in side panel');
    const request = pending.get(message.id);
    if (!request) return;
    if (message.error) request.reject(new Error(message.error.message));
    else request.resolve(message.result);
  }
  cdp.on('Target.receivedMessageFromTarget', onMessage);
  async function send(method, params = {}) {
    const id = ++sequence;
    let timer;
    const response = new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      timer = setTimeout(() => reject(new Error(`Native side panel timed out in ${method}`)), 5000);
    });
    try {
      const [, result] = await Promise.all([
        cdp.send('Target.sendMessageToTarget', { sessionId, message: JSON.stringify({ id, method, params }) }),
        response,
      ]);
      return result;
    } finally {
      pending.delete(id);
      clearTimeout(timer);
    }
  }
  async function evaluate(fn, ...args) {
    const expression = `(${fn.toString()})(...${JSON.stringify(args)})`;
    const { result, exceptionDetails } = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
    return result.value;
  }
  async function click(selector, name) {
    let point;
    await expect.poll(async () => {
      point = await evaluate((selector, name) => {
        const controls = [...document.querySelectorAll(selector)];
        const label = node => node.getAttribute('aria-label') ?? node.labels?.[0]?.textContent ?? node.textContent;
        const node = controls.find(control => !control.disabled && control.getClientRects().length > 0 &&
          (name === null || label(control)?.trim() === name));
        if (!node) return null;
        node.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' });
        const rect = node.getBoundingClientRect();
        const x = rect.x + rect.width / 2;
        const y = rect.y + rect.height / 2;
        return node.contains(document.elementFromPoint(x, y)) ? { x, y } : null;
      }, selector, name ?? null);
      return !!point;
    }, { message: `Find available side panel control: ${name ?? selector}` }).toBe(true);
    const mouse = { ...point, button: 'left', clickCount: 1 };
    await send('Input.dispatchMouseEvent', { type: 'mousePressed', ...mouse });
    await send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...mouse });
  }
  async function fill(selector, name, value) {
    await click(selector, name);
    await evaluate(() => { document.activeElement.select(); });
    await send('Input.insertText', { text: value });
  }
  await send('Runtime.enable');
  return {
    click, fill, evaluate, errors,
    async detach() {
      cdp.off('Target.receivedMessageFromTarget', onMessage);
      await cdp.send('Target.detachFromTarget', { sessionId }).catch(() => undefined);
    },
  };
}

async function exerciseClipboard(panel, editedTitle, copyAfterVerification, stopBackground) {
  const ordinary = 'Vault side panel clipboard test complete';
  const multiline = password + '\r\nSecond fixture line';
  // An imported login may contain CRLF, which a single-line password input cannot enter.
  await panel.evaluate(async (title, syntheticPassword, masterPassword) => {
    const send = async message => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
      if (!reply?.ok) throw new Error('Could not prepare the protected multiline fixture');
      return reply.value;
    };
    const summary = (await send({ type: 'list' })).find(item => item.title === title);
    const proof = { method: 'master', secret: masterPassword };
    const item = await send({ type: 'get-edit', id: summary.id, proof });
    item.data.password = syntheticPassword;
    await send({ type: 'upsert', itemJson: JSON.stringify(item), proof });
  }, editedTitle, multiline, master);

  // Compare in the extension document. Unexpected clipboard data never enters the report or assertion output.
  const content = () => panel.evaluate(async (secret, replacement) => {
    const current = await navigator.clipboard.readText();
    if (current === secret) return 'fixture';
    if (current === replacement) return 'replacement';
    return current === '' ? 'empty' : 'other';
  }, multiline, ordinary);
  const pending = () => panel.evaluate(async () => Boolean((await chrome.storage.session.get('clipboard')).clipboard));

  async function copy() {
    await copyAfterVerification();
    await expect.poll(content, { timeout: 15000, intervals: [100] }).toBe('fixture');
    return performance.now();
  }
  const first = await copy();
  await stopBackground();
  await expect.poll(content, { timeout: 45000, intervals: [250] }).toBe('empty');
  const clearMs = Math.round(performance.now() - first);
  assert(clearMs >= 28000, `Clipboard cleared too early (${clearMs} ms after observing the copy)`);
  await expect.poll(pending).toBe(false);

  const second = await copy();
  await expect.poll(pending).toBe(true);
  await delay(Math.max(0, second + 10000 - performance.now()));
  await panel.evaluate(async (secret, replacement) => {
    const current = await navigator.clipboard.readText();
    if (current !== secret) throw new Error('Clipboard changed before the replacement check');
    await navigator.clipboard.writeText(replacement);
  }, multiline, ordinary);
  const replacedAtMs = Math.round(performance.now() - second);
  await expect.poll(pending, { timeout: 45000, intervals: [250] }).toBe(false);
  const preservationCheckMs = Math.round(performance.now() - second);
  assert(preservationCheckMs >= 28000, 'The replacement check must span the cleanup deadline');
  assert.equal(await content(), 'replacement', 'The ordinary text must survive the expiry of the earlier copy');
  return { clearMs, replacedAtMs, preservationCheckMs, workerStoppedAfterCopy: true, multiline: true, ordinaryTextPreserved: true };
}

async function exercise(panel, stopBackground) {
  const text = selector => panel.evaluate(selector => document.querySelector(selector)?.textContent ?? '', selector);
  const count = selector => panel.evaluate(selector => document.querySelectorAll(selector).length, selector);
  const button = (label, scope = '') => panel.click(scope + 'button', label);
  const verify = async secret => {
    await panel.fill('dialog input', '主密码', secret);
    await button('验证', 'dialog ');
  };

  await button('添加登录项');
  await panel.fill('input', '名称', title);
  await panel.fill('input', '用户名', 'synthetic-user');
  await panel.fill('input', '密码', password);
  await panel.click('[role="switch"]', '查看或修改前再次验证');
  await button('保存凭证');
  await expect.poll(() => text('.row-title')).toContain(title);

  await panel.fill('input', '搜索凭证', 'unmatched sidepanel filter');
  await expect.poll(() => count('.row-main')).toBe(0);
  await panel.fill('input', '搜索凭证', title);
  await expect.poll(() => text('.row-title')).toContain(title);
  await panel.click('.row-main');
  await expect.poll(() => text('dialog h2')).toBe('再次验证身份');
  await button('取消', 'dialog ');
  assert.equal(await count('.identity'), 0);
  await panel.click('.row-main');
  await verify('Wrong-Sidepanel-Fixture#2026');
  await expect.poll(() => text('[role="alert"]')).toContain('验证失败');
  assert.equal(await count('.identity'), 0);
  await panel.click('.row-main');
  await verify(master);
  await expect.poll(() => text('.identity h2')).toBe(title);

  await button('编辑');
  await verify(master);
  const edited = title + ' edited';
  await panel.fill('input', '名称', edited);
  await button('保存凭证');
  await verify(master);
  await expect.poll(() => text('.row-title')).toContain(edited);

  await button('复制“' + edited + '”的密码');
  await expect.poll(() => text('dialog h2')).toBe('再次验证身份');
  await button('取消', 'dialog ');
  assert.equal(await panel.evaluate(async () => Boolean((await chrome.storage.session.get('clipboard')).clipboard)), false);

  const clipboard = stopBackground ? await exerciseClipboard(panel, edited, async () => {
    await button('复制“' + edited + '”的密码');
    await expect.poll(() => text('dialog h2')).toBe('再次验证身份');
    await verify(master);
    await expect.poll(() => text('.toast'), { timeout: 15000 }).toContain('已复制');
  }, stopBackground) : undefined;

  await button('设置');
  assert.equal(await panel.evaluate(() => chrome.permissions.contains({ permissions: ['privacy'] })), false);
  // Stub the browser API in this test document. A managed Chromium preference may
  // resolve set() even though its effective value does not change.
  await panel.evaluate(() => {
    const api = globalThis.browser?.runtime?.id ? globalThis.browser : chrome;
    const fixture = { allow: false, granted: false, value: true, control: 'not_controllable', setCalls: 0 };
    globalThis.nativeSavingFixture = fixture;
    const revokeListeners = new Set();
    Object.defineProperties(api.permissions, {
      contains: { value: async () => fixture.granted },
      request: { value: async () => { fixture.granted = fixture.allow; return fixture.granted; } },
      remove: { value: async () => {
        fixture.granted = false;
        for (const notify of revokeListeners) notify({ permissions: ['privacy'] });
        return true;
      } },
      onRemoved: { value: { addListener: listener => revokeListeners.add(listener), removeListener: listener => revokeListeners.delete(listener) } },
    });
    Object.defineProperty(api, 'privacy', {
      value: { services: { passwordSavingEnabled: {
        get: async () => ({ value: fixture.value, levelOfControl: fixture.control }),
        set: async ({ value }) => {
          fixture.setCalls++;
          if (fixture.control === 'controllable_by_this_extension') {
            fixture.control = 'controlled_by_this_extension';
            fixture.value = value;
          }
        },
        clear: async () => {
          if (fixture.control === 'controlled_by_this_extension') {
            fixture.control = 'controllable_by_this_extension';
            fixture.value = true;
          }
        },
      } } },
    });
  });
  await panel.click('.nav-row', '浏览器设置管理浏览器原生的保存密码提示');
  await expect.poll(() => text('main h1')).toBe('浏览器设置');
  await button('关闭原生保存提示');
  await expect.poll(() => text('.toast')).toContain('未授权');
  await panel.evaluate(() => { globalThis.nativeSavingFixture.allow = true; });
  await button('关闭原生保存提示');
  await expect.poll(() => text('main [role="status"]')).toContain('策略');
  assert.equal(await panel.evaluate(() => globalThis.nativeSavingFixture.setCalls), 0);
  await button('撤回浏览器设置权限');
  assert.equal(await panel.evaluate(() => globalThis.nativeSavingFixture.granted), false);
  await panel.evaluate(() => { globalThis.nativeSavingFixture.control = 'controllable_by_this_extension'; });
  await button('关闭原生保存提示');
  await expect.poll(() => text('.toast')).toContain('已关闭');
  assert.equal(await panel.evaluate(() => globalThis.nativeSavingFixture.value), false);
  await button('恢复浏览器设置并撤回权限');
  await expect.poll(() => text('.toast')).toContain('已撤回');
  assert.deepEqual(await panel.evaluate(() => {
    const { value, granted } = globalThis.nativeSavingFixture;
    return { value, granted };
  }), { value: true, granted: false });
  await button('锁定密码库');
  await expect.poll(() => text('.lamp')).toBe('已锁定');
  return clipboard;
}

async function run(name, artifact, useClipboard) {
  const executablePath = process.env.VAULT_BROWSER_PATH ?? executables[name];
  assert(executablePath, `Unknown browser ${name}`);
  await fs.access(executablePath);
  const temp = path.resolve(os.tmpdir());
  const profile = await fs.mkdtemp(path.join(temp, 'vault-sidepanel-'));
  let context;
  let panel;
  try {
    context = await chromium.launchPersistentContext(profile, {
      executablePath, headless: false, viewport: null,
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension],
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
    await waitForBuiltInFilters(context, name);
    assert.notEqual(await worker.evaluate(() => chrome.idle.queryState(60)), 'locked',
      'Unlock the Windows desktop before running the native side panel test.');
    const origin = 'chrome-extension://' + new URL(worker.url()).host;
    const panelUrl = origin + '/sidepanel.html';
    await (await waitForSetupTab(context, worker.url())).close();
    // The launcher closes itself after opening the native panel.
    const monitor = useClipboard ? await context.newCDPSession(await context.newPage()) : undefined;
    const popup = await context.newPage();
    await popup.goto(origin + '/popup.html');
    await popup.evaluate(async masterPassword => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault', type: 'create', masterPassword });
      if (!reply?.ok) throw new Error(reply?.error ?? 'Vault did not reply');
    }, master);
    await popup.reload();
    await popup.getByRole('button', { name: '打开浏览器侧栏', exact: true }).click();

    await expect.poll(async () => {
      const contexts = await worker.evaluate(documentUrl => chrome.runtime.getContexts({
        contextTypes: ['SIDE_PANEL'], documentUrls: [documentUrl],
      }), panelUrl);
      return contexts.length;
    }).toBe(1);
    assert(!context.pages().some(page => page.url() === panelUrl));
    const cdp = await context.browser().newBrowserCDPSession();
    let panelTarget;
    await expect.poll(async () => {
      const { targetInfos } = await cdp.send('Target.getTargets', { filter: [{ type: 'page' }] });
      panelTarget = targetInfos.find(target => target.url === panelUrl);
      return !!panelTarget;
    }).toBe(true);
    panel = await attachPanel(cdp, panelTarget.targetId);
    const platformAuthenticatorAvailable = await panel.evaluate(async () =>
      !!window.PublicKeyCredential && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
    const clipboard = await exercise(panel, monitor ? async () => {
      try {
        let version;
        monitor.on('ServiceWorker.workerVersionUpdated', ({ versions }) => {
          version = versions.find(entry => entry.scriptURL === worker.url()) ?? version;
        });
        await monitor.send('ServiceWorker.enable');
        await expect.poll(() => version?.runningStatus).toBe('running');
        await monitor.send('ServiceWorker.stopWorker', { versionId: version.versionId });
        await expect.poll(() => version?.runningStatus).toBe('stopped');
      } finally { await monitor.detach(); }
    } : undefined);
    assert.deepEqual(panel.errors, []);
    const result = {
      browser: name, version: context.browser().version(), extension: path.relative(root, extension), buildSha256: artifact,
      contextType: 'SIDE_PANEL', createSearchEdit: true, reprompt: true, cancelCopy: true,
      platformAuthenticatorAvailable, protectedCopyClipboard: clipboard,
      privacyOptional: true, privacyPolicyAndRevocationSimulated: true,
      manualVaultLock: true, consoleErrors: panel.errors,
    };
    console.log(JSON.stringify(result));
    return result;
  } catch (error) {
    if (panel) {
      const state = await panel.evaluate(() => ({
        focused: document.hasFocus(),
        header: document.querySelector('.view h1')?.textContent,
        dialog: document.querySelector('dialog[open] h2')?.textContent,
        alert: document.querySelector('[role="alert"]')?.textContent,
        titleFieldPresent: [...document.querySelectorAll('input')].some(input => input.labels?.[0]?.textContent?.trim() === '名称'),
      })).catch(() => ({ unavailable: true }));
      console.error(JSON.stringify({ browser: name, panelState: state, panelErrors: panel.errors }));
    }
    throw error;
  } finally {
    await panel?.detach();
    await context?.close();
    assert(path.dirname(path.resolve(profile)) === temp && path.basename(profile).startsWith('vault-sidepanel-'));
    await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
}

(async () => {
  const args = process.argv.slice(2);
  const useClipboard = args.includes('--clipboard');
  const names = args.filter(arg => arg !== '--clipboard');
  for (const name of names) assert(Object.hasOwn(executables, name), `Unknown browser ${name}`);
  const artifact = await extensionBuildHash(extension);
  const results = [];
  for (const name of names.length ? names : ['edge', 'helium']) results.push(await run(name, artifact, useClipboard));
  assert.equal(await extensionBuildHash(extension), artifact, 'The extension changed during side panel verification');
  const output = path.resolve(root, process.env.VAULT_TEST_OUTPUT || 'test-results');
  await fs.mkdir(output, { recursive: true });
  const filename = useClipboard ? 'sidepanel-clipboard.json' : 'sidepanel.json';
  await fs.writeFile(path.join(output, filename), JSON.stringify(results, null, 2) + '\n');
})().catch(error => { console.error(error); process.exitCode = 1; });
