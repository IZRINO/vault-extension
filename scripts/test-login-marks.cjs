const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { evaluateNativePopup, extensionBuildHash, waitForBuiltInFilters } = require('./browser-fixtures.cjs');

const root = path.resolve(__dirname, '..');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const output = path.resolve(root, process.env.VAULT_TEST_OUTPUT || 'test-results');
const browsers = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const master = 'Synthetic-Marking-Master#217';
const username = 'fixture-operator';
const password = 'Synthetic-Website-Password#880';
const markHost = '[data-vault-mark-picker]';
const fillHost = '[data-vault-ui]';

async function fixture() {
  const server = http.createServer((request, response) => {
    const { pathname, searchParams } = new URL(request.url, 'http://localhost');
    const scenario = searchParams.get('scenario');
    const pass = `<input id="new-pin" name="new-pin" type="password" autocomplete="new-password"${scenario === 'hidden' ? ' hidden' : ''}>`;
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    if (pathname === '/steps') {
      response.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>同址分步登录</title>
        <style>body{margin:32px;font:16px system-ui}form{margin:16px 0}input{padding:6px}</style>
        <form id="shared"><label>第一步<input id="step-one" autocomplete="off"></label></form>
        <button id="next" type="button">下一步</button>
        <template id="second"><label>第二步<input id="step-two" type="password" autocomplete="new-password"></label></template>
        <form id="other"><label>另一张表单<input id="other-badge" autocomplete="off"></label></form>
        <script>document.querySelector('#next').onclick = () => document.querySelector('#shared')
          .replaceChildren(document.querySelector('#second').content.cloneNode(true));</script></html>`);
      return;
    }
    response.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>登录框标记测试</title>
      <style>body{margin:32px;max-width:540px;color:#222;background:#fff;font:16px system-ui}
      label{display:grid;gap:3px;margin-block:10px}input{box-sizing:border-box;width:285px;padding:5px 8px;font:inherit}
      input[hidden]{display:none}</style><h1>合成登录表单</h1><form id="gate">
      <label>通行编号<input id="badge" name="badge" autocomplete="off"${scenario === 'hidden-user' ? ' hidden' : ''}></label>
      <label>暂存口令${pass}</label>
      ${scenario === 'duplicate' ? `<label>另一个口令${pass}</label>` : ''}
      <label>当班记录<input id="stamp" name="stamp" maxlength="8" autocomplete="off"></label>
      <hr><label>未标记用户名<input id="spare-user" autocomplete="username"></label>
      <label>未标记密码<input id="spare-pass" type="password" autocomplete="current-password"></label>
      </form></html>`);
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}

async function withCurrentSite(context, page, id, action) {
  await page.bringToFront();
  const cdp = await context.browser().newBrowserCDPSession();
  let popup;
  const list = async type => (await cdp.send('Target.getTargets', { filter: [{ type, exclude: false }] })).targetInfos;
  try {
    const tab = (await list('tab')).find(target => target.url === page.url());
    assert(tab, 'The fixture must be the active toolbar tab');
    const prior = new Set((await list('page')).map(target => target.targetId));
    await cdp.send('Extensions.triggerAction', { id, targetId: tab.targetId });
    await expect.poll(async () => {
      popup = (await list('page')).find(target => target.url === `chrome-extension://${id}/popup.html` && !prior.has(target.targetId));
      return !!popup;
    }, { timeout: 8000 }).toBe(true);
    const evaluate = (fn, ...args) => evaluateNativePopup(cdp, popup.targetId, `(${fn})(...${JSON.stringify(args)})`);
    const host = new URL(page.url()).host;
    await expect.poll(() => evaluate(host => {
      const summary = [...document.querySelectorAll('summary')].find(node => node.textContent === `当前网站 · ${host}`);
      if (!summary) return false;
      if (!summary.parentElement.open) summary.click();
      return true;
    }, host), { timeout: 8000 }).toBe(true);
    await action(evaluate);
  } finally {
    if (popup) await cdp.send('Target.closeTarget', { targetId: popup.targetId }).catch(() => undefined);
    await cdp.detach();
  }
}

function popupButton(evaluate, text, activate = false) {
  return expect.poll(() => evaluate((text, activate) => {
    const button = [...document.querySelectorAll('details[open] button')].find(node => node.textContent === text);
    if (!button || button.disabled) return false;
    if (activate) button.click();
    return true;
  }, text, activate), { timeout: 8000 }).toBe(true);
}

async function pickerButton(page, cdp, label, click = true) {
  await expect(page.locator(markHost)).toBeVisible();
  const get = async () => {
    const { nodes } = await cdp.send('Accessibility.getFullAXTree');
    return nodes.find(node => !node.ignored && node.role?.value === 'button' && node.name?.value === label);
  };
  await expect.poll(async () => Boolean(await get()), { timeout: 5000, message: `Picker control: ${label}` }).toBe(true);
  const node = await get();
  if (click) {
    assert(!node.properties?.some(prop => prop.name === 'disabled' && prop.value.value));
    const { quads } = await cdp.send('DOM.getContentQuads', { backendNodeId: node.backendDOMNodeId });
    assert(quads[0], 'The actual picker button must be visible in the viewport');
    const [x1, y1, , , x3, y3] = quads[0];
    await page.mouse.click((x1 + x3) / 2, (y1 + y3) / 2);
  }
}

async function openMenu(page, field) {
  await page.locator(field).click();
  const icon = page.locator(fillHost);
  await expect(icon).toBeVisible();
  const box = await icon.boundingBox();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  await expect.poll(() => page.frames().filter(frame => frame.url().endsWith('/inline-menu.html')).length).toBe(1);
  const menu = page.frames().find(frame => frame.url().endsWith('/inline-menu.html'));
  await expect(menu.getByRole('heading')).toBeVisible();
  const clipboard = menu.getByRole('checkbox', { name: '填充后复制时间验证码，30 秒后清理', exact: true });
  if (await clipboard.count()) await clipboard.uncheck();
  const confirmation = menu.getByRole('checkbox', { name: '我确认网站来源，允许本次操作' });
  if (await confirmation.count()) await confirmation.check();
  return menu;
}

async function noMenu(page, field) {
  const offer = page.waitForEvent('framenavigated', {
    predicate: frame => frame.url().endsWith('/inline-menu.html'), timeout: 900,
  }).then(() => true, error => { if (error.name !== 'TimeoutError') throw error; return false; });
  await page.locator(field).first().click();
  await expect(page.locator(fillHost)).toHaveCount(0);
  await page.keyboard.press('Alt+Shift+L');
  assert.equal(await offer, false, 'An unmarked or unavailable login target must not open the fill menu');
  for (const actual of await page.locator('form input').evaluateAll(fields => fields.map(field => field.value))) assert.equal(actual, '');
}

async function run(name, primary, secondary, buildHash) {
  assert(Object.hasOwn(browsers, name), `Unsupported test browser: ${name}`);
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-login-marks-'));
  let context, page;
  const errors = [], stage = value => console.log(`${name}: ${value}`);
  try {
    const executablePath = process.env.VAULT_BROWSER_PATH || browsers[name];
    await fs.access(executablePath);
    context = await chromium.launchPersistentContext(profile, {
      executablePath, headless: process.env.VAULT_HEADED == null ? name !== 'helium' : process.env.VAULT_HEADED !== '1',
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--enable-unsafe-extension-debugging', '--no-proxy-server'],
      viewport: { width: 850, height: 720 },
    });
    context.on('weberror', error => errors.push(error.error().message));
    context.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    context.on('requestfailed', request => {
      const error = request.failure()?.errorText;
      if (error !== 'net::ERR_ABORTED') errors.push(`${request.url()}: ${error}`);
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 15000 });
    await waitForBuiltInFilters(context, name);
    const id = new URL(worker.url()).host;
    const vault = await context.newPage();
    await vault.goto(`chrome-extension://${id}/popup.html`);
    const send = message => vault.evaluate(async message => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
      if (!reply.ok) throw new Error(reply.error);
      return reply.value;
    }, message);
    await send({ type: 'create', masterPassword: master });
    for (const [title, guarded] of [['Fixture primary', false], ['Fixture protected', true]]) {
      await send({ type: 'upsert', itemJson: JSON.stringify({ title, requireReprompt: guarded, data: {
        kind: 'login', username, password, uris: [{ uri: primary.origin }], totpUri: 'JBSWY3DPEHPK3PXP',
      } }) });
    }
    page = await context.newPage();
    await page.goto(`${primary.origin}/gate`);
    const cdp = await context.newCDPSession(page);
    const clickPicker = (label, click) => pickerButton(page, cdp, label, click);
    const popup = fn => withCurrentSite(context, page, id, fn);
    const openPicker = async (label = '标记登录框') => {
      await popup(async evaluate => {
        await popupButton(evaluate, label, true);
        await expect(page.locator(markHost)).toBeVisible();
      });
      assert(await page.locator(markHost).evaluate(node => node.shadowRoot === null));
      await page.bringToFront();
    };
    stage('cancel');
    await noMenu(page, '#new-pin');
    await openPicker();
    await page.locator('#badge').click();
    await clickPicker('用户名 · 已选', false);
    await clickPicker('取消');
    await expect(page.locator(markHost)).toHaveCount(0);
    await page.reload();
    await noMenu(page, '#badge');

    stage('save all three roles');
    await openPicker();
    await page.locator('#badge').click();
    await clickPicker('密码');
    await page.locator('#new-pin').click();
    await clickPicker('两步验证码');
    await page.locator('#stamp').click();
    await clickPicker('两步验证码 · 已选', false);
    await page.screenshot({ path: path.join(output, `login-marks-${name}-picker.png`) });
    await clickPicker('保存标记');
    await expect(page.locator(markHost)).toHaveCount(0);

    stage('reload, explicit fill and verification');
    await send({ type: 'lock' });
    await send({ type: 'unlock', password: master });
    await page.reload();
    await popup(evaluate => popupButton(evaluate, '重新标记登录框'));
    await page.bringToFront();
    for (const field of ['#badge', '#new-pin', '#stamp']) await expect(page.locator(field)).toHaveValue('');
    const menu = await openMenu(page, '#new-pin');
    await menu.getByRole('button', { name: /Fixture protected/ }).click();
    await expect(menu.getByLabel('主密码', { exact: true })).toBeVisible();
    await expect(page.locator('#new-pin')).toHaveValue('');
    await menu.getByLabel('主密码', { exact: true }).fill(master);
    await menu.getByRole('button', { name: '验证并填充', exact: true }).click();
    await expect(page.locator('#badge')).toHaveValue(username);
    await expect(page.locator('#new-pin')).toHaveValue(password);
    for (const field of ['#stamp', '#spare-pass', '#spare-user']) await expect(page.locator(field)).toHaveValue('');

    const otp = await openMenu(page, '#stamp');
    await otp.getByRole('button', { name: /Fixture primary/ }).click();
    await expect(page.locator('#stamp')).toHaveValue(/^\d{6}$/);

    stage('ambiguous/hidden and site scope');
    for (const scenario of ['duplicate', 'hidden']) {
      await page.goto(`${primary.origin}/gate?scenario=${scenario}`);
      // The valid username should offer filling on its first focus, even while settings load.
      const present = await openMenu(page, '#badge');
      await present.getByRole('button', { name: '关闭填充菜单', exact: true }).click();
      if (scenario === 'duplicate') await noMenu(page, '#new-pin');
      await noMenu(page, '#spare-pass');
    }
    await page.goto(`${primary.origin}/gate?scenario=hidden-user`);
    const partial = await openMenu(page, '#new-pin');
    await partial.getByRole('button', { name: /Fixture primary/ }).click();
    await expect(page.locator('#new-pin')).toHaveValue(password);
    for (const selector of ['#badge', '#spare-user', '#spare-pass']) await expect(page.locator(selector)).toHaveValue('');
    await expect.poll(async () => (await cdp.send('Accessibility.getFullAXTree')).nodes.some(
      node => !node.ignored && node.name?.value?.includes('已跳过这些框。请重新标记。'))).toBe(true);
    for (const url of [`${primary.origin}/other-gate`, `${secondary.origin}/gate`]) {
      await page.goto(url);
      await popup(evaluate => popupButton(evaluate, '标记登录框'));
      await page.bringToFront();
      await noMenu(page, '#new-pin');
    }
    stage('two forms and two login steps at the same URL');
    await page.goto(`${primary.origin}/steps`);
    const saveField = async (field, role, additional) => {
      await openPicker(additional ? '标记其他表单或步骤' : '标记登录框');
      if (role !== '用户名') await clickPicker(role);
      await page.locator(field).click();
      await clickPicker(`${role} · 已选`, false);
      await clickPicker('保存标记');
      await expect(page.locator(markHost)).toHaveCount(0);
    };
    await saveField('#step-one', '用户名', false);
    await saveField('#other-badge', '用户名', true);
    await page.locator('#next').click();
    await saveField('#step-two', '密码', true);
    await page.reload();
    const fillPrimary = async field => {
      const menu = await openMenu(page, field);
      await menu.getByRole('button', { name: /Fixture primary/ }).click();
    };
    await fillPrimary('#step-one');
    await expect(page.locator('#step-one')).toHaveValue(username);
    await expect(page.locator('#step-two')).toHaveCount(0);
    await expect(page.locator('#other-badge')).toHaveValue('');
    await page.locator('#next').click();
    await fillPrimary('#step-two');
    await expect(page.locator('#step-two')).toHaveValue(password);
    await expect(page.locator('#other-badge')).toHaveValue('');
    await fillPrimary('#other-badge');
    await expect(page.locator('#other-badge')).toHaveValue(username);
    assert.deepEqual(errors, []);
    const report = { browser: name, buildHash, cancelledWithoutSaving: true, persistedAfterUnlockAndReload: true,
      selectedRoles: ['username', 'password', 'otp'], noAutofillBeforeUse: true, protectedFill: true,
      unmarkedFieldsUntouched: true, firstFocusAfterNavigation: true, ambiguityRejected: true, hiddenFallbackRejected: true,
      routeAndPortIsolated: true, partialFillWarned: true, separateFormsAndSteps: true, errors };
    await fs.writeFile(path.join(output, `login-marks-${name}.json`), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report));
  } catch (error) {
    if (page && !page.isClosed()) await page.screenshot({ path: path.join(output, `login-marks-${name}-failure.png`) }).catch(() => undefined);
    throw error;
  } finally {
    await context?.close();
    assert(path.dirname(profile) === path.resolve(os.tmpdir()) && path.basename(profile).startsWith('vault-login-marks-'));
    await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
}

(async () => {
  const buildHash = await extensionBuildHash(extension);
  const primary = await fixture();
  let secondary;
  try {
    secondary = await fixture();
    await fs.mkdir(output, { recursive: true });
    const requested = process.argv.slice(2);
    for (const name of requested.length ? requested : Object.keys(browsers)) await run(name, primary, secondary, buildHash);
  } finally {
    primary.server.close();
    secondary?.server.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
