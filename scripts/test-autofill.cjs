const { chromium, expect } = require('@playwright/test');
const { buildSync } = require('esbuild');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { evaluateNativePopup, waitForBuiltInFilters } = require('./browser-fixtures.cjs');
const { observeOtpMessages } = require('./test-phase-2.cjs');

const root = path.resolve(__dirname, '..');
const extension = path.resolve(root, process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const output = path.resolve(root, process.env.VAULT_TEST_OUTPUT || 'test-results');
const browsers = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const master = 'Autofill-Fixture-Master#2026';
const secret = 'Autofill-Fixture-Password#719';
const jsx = `
  import React, {useState} from 'react';
  import {createRoot} from 'react-dom/client';
  function App() {
    const [username, user] = useState(''), [password, pass] = useState(''), [step, next] = useState(0), [result, done] = useState('');
    const multi = location.pathname === '/multi';
    return <form onSubmit={event => {event.preventDefault(); done(username + ':' + password);}}>
      <h1>Local test login</h1>
      {(!multi || !step) && <label>Account<input name="username" autoComplete="username" value={username} onChange={event => user(event.target.value)} /></label>}
      {multi && !step ? <button type="button" onClick={() => next(1)}>Next</button> :
        <><label>Password<input name="password" type="password" autoComplete="current-password" value={password} onChange={event => pass(event.target.value)} /></label><button>Log in</button></>}
      <output id="result">{result}</output>
      <label>Department<input name="department" defaultValue="" /></label>
      <input className="honey" style={{display:'none'}} type="password" autoComplete="current-password" />
      <input className="honey" style={{opacity:0}} type="password" autoComplete="current-password" />
      <input className="honey" style={{position:'absolute',left:'-9999px'}} type="password" autoComplete="current-password" />
    </form>;
  }
  createRoot(document.getElementById('app')).render(<App />);
`;
const bundle = buildSync({ stdin: { contents: jsx, loader: 'jsx', resolveDir: path.join(root, 'apps/extension') },
  bundle: true, write: false, format: 'iife', define: { 'process.env.NODE_ENV': '"production"' } }).outputFiles[0].text;
function html(body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Vault local autofill fixture</title><style>
    body{font:16px system-ui;padding:40px;max-width:600px}label{display:grid;gap:6px;margin:14px 0}input{font:inherit;padding:10px;width:260px}
    button{font:inherit;padding:10px;margin:8px 0}.otp{width:24px}iframe{width:560px;height:540px;border:1px solid #ccc}
    </style></head><body>${body}</body></html>`;
}
async function disableSubdomainFromPopup(context, id, origin, wildcard, read) {
  const cdp = await context.browser().newBrowserCDPSession();
  const list = async type => (await cdp.send('Target.getTargets', { filter: [{ type, exclude: false }] })).targetInfos;
  let popup;
  try {
    const tab = (await list('tab')).find(target => target.url === `${origin}/plain`);
    assert(tab, 'The test form must be the current toolbar tab');
    const prior = new Set((await list('page')).map(target => target.targetId));
    await cdp.send('Extensions.triggerAction', { id, targetId: tab.targetId });
    await expect.poll(async () => {
      popup = (await list('page')).find(target => target.url === `chrome-extension://${id}/popup.html` && !prior.has(target.targetId));
      return !!popup;
    }).toBe(true);
    const evaluate = (fn, ...args) => evaluateNativePopup(cdp, popup.targetId, `(${fn})(...${JSON.stringify(args)})`);
    await expect.poll(() => evaluate((targetOrigin, rule) => {
      const summary = [...document.querySelectorAll('summary')].find(node => node.textContent.includes(new URL(targetOrigin).host));
      if (!summary) return false;
      if (!summary.parentElement.open) summary.click();
      const select = summary.parentElement.querySelector('select');
      if (!select || ![...select.options].some(option => option.value === rule)) return false;
      select.value = rule;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    }, origin, wildcard)).toBe(true);
    for (const [label, flag] of [
      ['显示填充图标', 'inlineDisabled'], ['提示保存新密码', 'saveDisabled'], ['允许接管通行密钥', 'passkeyDisabled'],
    ]) {
      await expect.poll(() => evaluate((name, rule) => {
        const select = document.querySelector('details[open] select');
        const input = [...document.querySelectorAll('label')].find(label => label.textContent === name)?.control;
        if (select?.value !== rule || !input || input.disabled) return false;
        if (input.checked) input.click();
        return true;
      }, label, wildcard)).toBe(true);
      await expect.poll(async () => (await read(wildcard))[flag]).toBe(true);
    }
  } finally {
    if (popup) await cdp.send('Target.closeTarget', { targetId: popup.targetId }).catch(() => undefined);
    await cdp.detach();
  }
}

async function server() {
  const instance = http.createServer((request, response) => {
    if (process.env.VAULT_NAV_DEBUG === '1') console.log('fixture request:', request.headers.host, request.url);
    const url = new URL(request.url, 'http://localhost');
    response.setHeader('Content-Type', url.pathname === '/react.js' ? 'text/javascript' : 'text/html;charset=utf-8');
    if (url.pathname === '/react.js') return response.end(bundle);
    if (url.pathname === '/frame') return response.end(html(`<h1>Unrelated top-level site</h1><iframe src="http://login.target.localhost:${instance.address().port}/controlled"></iframe>`));
    if (url.pathname === '/otp') return response.end(html(`<h1>Six-cell OTP</h1><form>${Array.from({ length: 6 }, (_, i) =>
      `<input class="otp" aria-label="Digit ${i + 1}" inputmode="numeric" type="tel" maxlength="1" ${i === 0 ? 'autocomplete="one-time-code"' : ''}>`).join('')}</form>
      <script>document.addEventListener('input',()=>{window.otpReady=[...document.querySelectorAll('.otp')].every(field=>field.value.length===1)})</script>`));
    if (url.pathname === '/otp-single') return response.end(html('<form><label>One-time code<input autocomplete="one-time-code"></label></form>'));
    if (url.pathname === '/plain') return response.end(html('<form action="/success" method="post"><label>Account<input name="username" autocomplete="username"></label><label>Password<input name="password" type="password" autocomplete="current-password"></label><button>Log in</button></form>'));
    if (url.pathname === '/success') return response.end(html('<h1>Login complete</h1>'));
    if (url.pathname === '/shadow') return response.end(html(`<h1>Open shadow form</h1><div id="shadow"></div><script>
      const root=document.querySelector('#shadow').attachShadow({mode:'open'});root.innerHTML='<form><label>Account<input autocomplete="username"></label><label>Password<input type="password" autocomplete="current-password"></label></form>';</script>`));
    if (url.pathname === '/card') return response.end(html(`<h1>Checkout fixture</h1><form>
      <label>Cardholder<input autocomplete="cc-name"></label><label>Card number<input autocomplete="cc-number"></label>
      <label>Expiry month<input autocomplete="cc-exp-month"></label><label>Expiry year<input autocomplete="cc-exp-year"></label>
      <label>CVV<input autocomplete="cc-csc"></label></form>`));
    if (url.pathname === '/identity') return response.end(html(`<h1>Address fixture</h1><form>
      <label>Full name<input autocomplete="name"></label><label>Contact email<input autocomplete="email"></label>
      <label>City<input autocomplete="address-level2"></label><label>Postcode<input autocomplete="postal-code"></label>
      <label>Country<select autocomplete="country"><option value="">Choose</option><option value="GB">United Kingdom</option></select></label></form>`));
    return response.end(html('<div id="app"></div><script src="/react.js"></script>'));
  });
  await new Promise(resolve => instance.listen(0, '127.0.0.1', resolve));
  return instance;
}
async function menu(page) {
  await expect.poll(() => page.frames().filter(frame => frame.url().endsWith('/inline-menu.html')).length).toBe(1);
  const frame = page.frames().find(frame => frame.url().endsWith('/inline-menu.html'));
  await expect(frame.getByRole('heading')).toBeVisible();
  const clipboard = frame.getByRole('checkbox', { name: '填充后复制时间验证码，30 秒后清理', exact: true });
  if (await clipboard.count()) await clipboard.uncheck(); // Do not change the user's system clipboard in this fixture.
  return frame;
}
async function open(page, field) {
  await field.click();
  const icon = page.locator('[data-vault-ui]');
  await expect(icon).toBeVisible();
  const box = await icon.boundingBox();
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  return menu(page);
}
async function confirm(frame) {
  const checkbox = frame.getByRole('checkbox', { name: '我确认网站来源，允许本次操作' });
  if (await checkbox.count()) await checkbox.check();
}
async function run(name, primary, secondary) {
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-autofill-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      executablePath: process.env.VAULT_BROWSER_PATH || browsers[name], headless: process.env.VAULT_HEADED == null ? name !== 'helium' : process.env.VAULT_HEADED !== '1',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension,
        '--host-resolver-rules=MAP *.test 127.0.0.1', '--no-proxy-server', '--enable-unsafe-extension-debugging'], viewport: { width: 1000, height: 800 },
    });
    const errors = [];
    context.on('weberror', error => errors.push(error.error().message));
    context.on('page', page => {
      page.on('console', entry => { if (entry.type() === 'error') errors.push(entry.text()); });
      page.on('requestfailed', request => {
        if (request.failure()?.errorText !== 'net::ERR_ABORTED') errors.push(`${request.url()}: ${request.failure()?.errorText}`);
      });
    });
    if (process.env.VAULT_NAV_DEBUG === '1') {
      context.on('response', response => console.log('browser response:', response.status(), response.url()));
    }
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
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
    const origin = `http://login.target.localhost:${primary.address().port}`;
    const local = `http://127.0.0.1:${primary.address().port}`;
    const add = (title, url, protectedItem = false, totpUri = 'JBSWY3DPEHPK3PXP') => send({ type: 'upsert', itemJson: JSON.stringify({
      title, data: { kind: 'login', username: 'fixture-user', password: secret,
        uris: [{ uri: url }], totpUri }, requireReprompt: protectedItem,
      customFields: [{ name: 'department', value: 'Fixture department', hidden: true }],
    }) });
    await add('Fixture login', origin);
    await add('Protected login', origin, true);
    await add('Local port login', local);
    const page = await context.newPage();
    await page.bringToFront();
    if (process.env.VAULT_NAV_DEBUG === '1') console.log('before navigation tabs:', await vault.evaluate(() => chrome.tabs.query({})));
    await page.goto(origin + '/controlled');
    await expect(page.getByLabel('Password', { exact: true })).toBeVisible();
    assert.equal(await page.getByLabel('Password', { exact: true }).inputValue(), '');
    await page.getByLabel('Password', { exact: true }).dispatchEvent('click');
    assert(!page.frames().some(frame => frame.url().endsWith('/inline-menu.html')), 'Synthetic events must not open a menu');
    let frame = await open(page, page.getByLabel('Password', { exact: true }));
    assert(await page.evaluate(() => document.querySelector('[data-vault-ui]').shadowRoot === null));
    assert(!(await page.locator('body').innerText()).includes('Fixture login'));
    await expect(frame.getByRole('button', { name: /Fixture login/ })).toBeDisabled();
    await confirm(frame);
    await frame.getByRole('button', { name: /Fixture login/ }).click();
    await expect(page.getByLabel('Password', { exact: true })).toHaveValue(secret);
    await expect(page.getByLabel('Account', { exact: true })).toHaveValue('fixture-user');
    await expect(page.getByLabel('Department', { exact: true })).toHaveValue('Fixture department');
    assert.deepEqual(await page.locator('.honey').evaluateAll(fields => fields.map(field => field.value)), ['', '', '']);
    await page.getByRole('button', { name: 'Log in', exact: true }).click();
    await expect(page.locator('#result')).toHaveText('fixture-user:' + secret);
    // Discard the optional save prompt before the next fixture.
    await page.goto(origin + '/multi');
    frame = await open(page, page.getByLabel('Account', { exact: true }));
    await confirm(frame); await frame.getByRole('button', { name: /Fixture login/ }).click();
    await page.getByRole('button', { name: 'Next', exact: true }).click();
    frame = await open(page, page.getByLabel('Password', { exact: true }));
    await confirm(frame); await frame.getByRole('button', { name: /Fixture login/ }).click();
    await expect(page.getByLabel('Password', { exact: true })).toHaveValue(secret);
    await page.goto(origin + '/shadow');
    frame = await open(page, page.locator('#shadow input[type=password]'));
    await confirm(frame); await frame.getByRole('button', { name: /Fixture login/ }).click();
    await expect(page.locator('#shadow input[type=password]')).toHaveValue(secret);

    await page.goto(`http://evil.localhost:${primary.address().port}/frame`);
    const child = page.frames().find(frame => frame.url().includes('/controlled'));
    await child.getByLabel('Password', { exact: true }).click();
    const box = await child.getByLabel('Password', { exact: true }).boundingBox();
    await page.mouse.click(box.x + box.width - 17, box.y + box.height / 2);
    frame = await menu(page);
    await expect(frame.getByRole('alert').filter({ hasText: /evil\.localhost/ })).toBeVisible();
    await expect(frame.getByRole('button', { name: /Fixture login/ })).toBeDisabled();
    await page.screenshot({ path: path.join(output, `autofill-${name}-cross-frame.png`) });
    await confirm(frame); await frame.getByRole('button', { name: /Fixture login/ }).click();
    await expect(child.getByLabel('Password', { exact: true })).toHaveValue(secret);

    await page.goto(`http://127.0.0.1:${secondary.address().port}/controlled`);
    frame = await open(page, page.getByLabel('Password', { exact: true }));
    await expect(frame.getByText('没有匹配的凭证。', { exact: false })).toBeVisible();
    assert.equal(await page.getByLabel('Password', { exact: true }).inputValue(), '');

    await add('Counter field fixture', origin, false, 'otpauth://hotp/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0');
    await add('Steam field fixture', origin, false, 'otpauth://steam/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=5');
    const panel = await context.newPage();
    await panel.goto(`chrome-extension://${id}/sidepanel.html`);
    await page.bringToFront();
    const otpPages = [vault, panel];
    const endTotp = await observeOtpMessages(otpPages);
    await page.goto(origin + '/otp');
    frame = await open(page, page.getByLabel('Digit 1', { exact: true }));
    await confirm(frame); await frame.getByRole('button', { name: /Fixture login/ }).click();
    await expect.poll(() => page.evaluate(() => window.otpReady)).toBe(true);
    assert.match((await page.locator('.otp').evaluateAll(fields => fields.map(field => field.value).join(''))), /^\d{6}$/);
    const ordinaryPageOtpMessages = { totp: await endTotp() };
    await page.screenshot({ path: path.join(output, `autofill-${name}-otp.png`) });
    for (const [kind, title] of [['hotp', 'Counter field fixture'], ['steam', 'Steam field fixture']]) {
      const end = await observeOtpMessages(otpPages);
      await page.goto(origin + '/otp-single');
      const input = page.getByLabel('One-time code');
      frame = await open(page, input);
      await confirm(frame);
      await frame.getByRole('button', { name: new RegExp(title) }).click();
      await expect.poll(() => input.evaluate((field, kind) => kind === 'hotp'
        ? field.value === '755224' : /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/.test(field.value), kind)).toBe(true);
      ordinaryPageOtpMessages[kind] = await end();
    }
    await panel.close();

    await page.goto(origin + '/controlled');
    frame = await open(page, page.getByLabel('Password', { exact: true }));
    await confirm(frame); await frame.getByRole('button', { name: /Protected login/ }).click();
    await frame.getByLabel('主密码', { exact: true }).fill(master);
    await frame.getByRole('button', { name: '验证并填充', exact: true }).click();
    await expect(page.getByLabel('Password', { exact: true })).toHaveValue(secret);

    const before = (await send({ type: 'list' })).length;
    await page.goto(local + '/plain');
    await page.getByLabel('Account', { exact: true }).fill('new-fixture-account');
    await page.getByLabel('Password', { exact: true }).fill('New-Captured-Fixture#2026');
    await page.getByRole('button', { name: 'Log in', exact: true }).click();
    await page.waitForURL('**/success');
    frame = await menu(page);
    await expect(frame.getByRole('heading', { name: '保存新凭证', exact: true })).toBeVisible();
    assert.equal((await send({ type: 'list' })).length, before, 'Capture must never save silently');
    await confirm(frame);
    await frame.getByRole('button', { name: '保存凭证', exact: true }).click();
    await expect.poll(async () => (await send({ type: 'list' })).length).toBe(before + 1);
    const created = (await send({ type: 'list' })).find(item => item.subtitle === 'new-fixture-account');
    assert.equal((await send({ type: 'get', id: created.id })).data.password, 'New-Captured-Fixture#2026');
    await page.goto(local + '/plain');
    await page.getByLabel('Account', { exact: true }).fill('new-fixture-account');
    await page.getByLabel('Password', { exact: true }).fill('Changed-Captured-Fixture#2026');
    await page.getByRole('button', { name: 'Log in', exact: true }).click(); await page.waitForURL('**/success');
    frame = await menu(page);
    await expect(frame.getByRole('heading', { name: '更新网站密码', exact: true })).toBeVisible();
    await confirm(frame); await frame.getByRole('button', { name: '确认更新密码', exact: true }).click();
    await expect.poll(async () => (await send({ type: 'get', id: created.id })).data.password).toBe('Changed-Captured-Fixture#2026');
    assert.equal((await send({ type: 'get', id: created.id })).data.passwordHistory[0].password, 'New-Captured-Fixture#2026');

    const captureLogin = async (username, password) => {
      await page.goto(local + '/plain');
      await page.getByLabel('Account', { exact: true }).fill(username);
      await page.getByLabel('Password', { exact: true }).fill(password);
      await page.getByRole('button', { name: 'Log in', exact: true }).click();
      await page.waitForURL('**/success');
      return menu(page);
    };
    const addLocal = (title, username, extra = {}) => send({ type: 'upsert', itemJson: JSON.stringify({
      ...extra, title, data: { kind: 'login', username, password: secret, uris: [{ uri: local }], ...extra.data },
    }) });
    for (let i = 0; i < 30; i++) await addLocal('Pinned capture fixture ' + i, 'pinned-' + i, { pinned: true });
    const checkout = await send({ type: 'list' });
    const primaryProof = { method: 'master', secret: master };
    for (const kind of ['totp', 'hotp']) {
      const setup = `otpauth://${kind}/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ${kind === 'hotp' ? '&counter=2' : ''}`;
      const username = `${kind}-outside-menu`;
      const metadata = [{ name: 'Vault 迁移来源', value: 'Imported fixture', hidden: true }, { name: 'Extra', value: 'Preserved', hidden: false }];
      await addLocal(username, username, { data: { totpUri: setup }, requireReprompt: true, customFields: metadata });
      const { id: loginId } = (await send({ type: 'list' })).find(item => item.title === username);
      const changed = `Changed fixture password for ${kind}`;
      frame = await captureLogin(username, changed);
      await expect(frame.getByRole('heading', { name: '更新网站密码', exact: true })).toBeVisible();
      assert(!JSON.stringify(await frame.locator('body').innerText()).includes('GEZDGNBV'));
      await confirm(frame);
      await frame.getByLabel('主密码', { exact: true }).fill('Wrong fixture master password');
      await frame.getByRole('button', { name: '确认更新密码', exact: true }).click();
      await expect(frame.getByRole('alert').filter({ hasText: '主密码验证失败' })).toBeVisible();
      assert.equal((await send({ type: 'get-edit', id: loginId, proof: primaryProof })).data.password, secret);
      await frame.getByLabel('主密码', { exact: true }).fill(master);
      await frame.getByRole('button', { name: '确认更新密码', exact: true }).click();
      await expect.poll(async () => (await send({ type: 'get', id: loginId, proof: primaryProof })).data.password).toBe(changed);
      const read = await send({ type: 'get', id: loginId, proof: primaryProof });
      assert(!Object.hasOwn(read.data, 'totpUri'));
      assert.deepEqual(read.data.passwordHistory.map(item => item.password), [secret]);
      const saved = await send({ type: 'get-edit', id: loginId, proof: primaryProof });
      assert.equal(saved.data.totpUri, setup);
      assert.deepEqual(saved.customFields, metadata);
      if (kind === 'hotp') {
        assert.equal((await send({ type: 'next-hotp', id: loginId, proof: primaryProof })).counter, '2');
      }
    }
    assert.equal((await send({ type: 'list' })).length, checkout.length + 2);
    await addLocal('Pinned ambiguous', 'totp-outside-menu', { pinned: true });
    frame = await captureLogin('totp-outside-menu', 'Do not save this ambiguous fixture');
    await expect(frame.getByRole('alert').filter({ hasText: '有多条同账号凭证' })).toBeVisible();
    await expect(frame.getByRole('button', { name: '确认更新密码', exact: true })).toHaveCount(0);
    assert.equal((await send({ type: 'list' })).length, checkout.length + 3);

    await page.goto(origin + '/controlled');
    await page.getByLabel('Password', { exact: true }).click();
    await page.keyboard.press('Alt+Shift+L');
    frame = await menu(page);
    await frame.getByRole('button', { name: '关闭填充菜单', exact: true }).click();
    await expect.poll(() => page.frames().filter(frame => frame.url().endsWith('/inline-menu.html')).length).toBe(0);
    const setSite = flags => vault.evaluate(async ({ origin, flags }) => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault-autofill', type: 'site', origin, flags });
      if (!reply.ok) throw new Error(reply.error);
    }, { origin, flags });
    const disabled = { inlineDisabled: true, saveDisabled: true, passkeyDisabled: false };
    await setSite(disabled);
    await page.goto(origin + '/controlled');
    await page.getByLabel('Password', { exact: true }).click();
    await expect(page.locator('[data-vault-ui]')).toHaveCount(0);
    const stored = await vault.evaluate(() => chrome.storage.local.get(null));
    assert(stored.autofillSealed, 'Site preferences must be persisted as an authenticated envelope');
    assert(!JSON.stringify(stored).includes('target.localhost'), 'Site names must never appear on disk in plaintext');
    assert(!Object.hasOwn(stored, 'autofill'));
    await send({ type: 'lock' }); await send({ type: 'unlock', password: master });
    assert.deepEqual((await send({ type: 'autofill-settings' })).sites[origin], disabled);
    await setSite({ inlineDisabled: false, saveDisabled: false, passkeyDisabled: false });
    await page.goto(origin + '/controlled');
    frame = await open(page, page.getByLabel('Password', { exact: true }));
    await frame.getByRole('button', { name: '关闭填充菜单', exact: true }).click();

    const scopeHost = 'login.vault-scope.test';
    const scopePort = primary.address().port;
    const scopedOrigin = `http://${scopeHost}:${scopePort}`;
    const wildcard = `http://*.vault-scope.test:${scopePort}`;
    const scopedRule = (rule, flags) => vault.evaluate(async ({ rule, flags }) => {
      const reply = await chrome.runtime.sendMessage({ target: 'vault-autofill', type: 'site', origin: rule, flags });
      if (!reply.ok) throw new Error(reply.error);
      return reply.value;
    }, { rule, flags });
    await page.goto(scopedOrigin + '/plain');
    await page.getByLabel('Password', { exact: true }).click();
    await expect(page.locator('[data-vault-ui]')).toBeVisible();
    await disableSubdomainFromPopup(context, id, scopedOrigin, wildcard, scopedRule);
    await page.bringToFront();
    assert.deepEqual(await scopedRule(wildcard), {
      inlineDisabled: true, saveDisabled: true, passkeyDisabled: true,
    });
    await expect(page.locator('[data-vault-ui]')).toHaveCount(0);
    await page.getByLabel('Password', { exact: true }).click();
    await page.keyboard.press('Alt+Shift+L');
    frame = await menu(page);
    await frame.getByRole('button', { name: '关闭填充菜单', exact: true }).click();
    await expect(page.locator('[data-vault-ui]')).toHaveCount(0);
    const savePrompt = page.waitForEvent('framenavigated', {
      predicate: frame => frame.url().endsWith('/inline-menu.html'), timeout: 900,
    }).then(() => true, error => { if (error.name !== 'TimeoutError') throw error; return false; });
    await page.getByLabel('Account', { exact: true }).fill('wildcard-synthetic');
    await page.getByLabel('Password', { exact: true }).fill('Wildcard-fixture-password');
    await page.getByRole('button', { name: 'Log in', exact: true }).click();
    await page.waitForURL('**/success');
    assert.equal(await savePrompt, false, 'Submitting on an excluded subdomain must not show a save prompt');
    assert(!(await send({ type: 'list' })).some(item => item.account === 'wildcard-synthetic'));
    const sealed = await vault.evaluate(() => chrome.storage.local.get(['autofill', 'autofillSealed']));
    assert(sealed.autofillSealed && !Object.hasOwn(sealed, 'autofill'));
    assert(!JSON.stringify(sealed).includes('vault-scope.test'));
    await send({ type: 'lock' });
    await send({ type: 'unlock', password: master });
    assert(await scopedRule(wildcard).then(flags => flags.passkeyDisabled));
    for (const host of [`${scopeHost}:${secondary.address().port}`, `vault-scope.test:${scopePort}`]) {
      await page.goto(`http://${host}/plain`);
      await page.getByLabel('Password', { exact: true }).click();
      await expect(page.locator('[data-vault-ui]')).toBeVisible();
    }
    await scopedRule(wildcard, { inlineDisabled: false, saveDisabled: false, passkeyDisabled: false });
    await page.goto(scopedOrigin + '/plain');
    await page.getByLabel('Password', { exact: true }).click();
    await expect(page.locator('[data-vault-ui]')).toBeVisible();

    await send({ type: 'upsert', itemJson: JSON.stringify({ title: 'Fixture checkout card',
      data: { kind: 'payment_card', cardholderName: 'Fixture User', cardNumber: '4111111111111111', expMonth: '11', expYear: '2030', cvv: '123' } }) });
    await page.goto(origin + '/card');
    frame = await open(page, page.getByLabel('Card number', { exact: true }));
    await confirm(frame); await frame.getByRole('button', { name: /Fixture checkout card/ }).click();
    await expect(page.getByLabel('Card number', { exact: true })).toHaveValue('4111111111111111');
    await expect(page.getByLabel('CVV', { exact: true })).toHaveValue('123');
    await expect(page.getByLabel('Expiry year', { exact: true })).toHaveValue('2030');
    await send({ type: 'upsert', itemJson: JSON.stringify({ title: 'Fixture identity',
      data: { kind: 'identity', fullName: 'Ada Fixture', email: 'fixture@example.com', city: 'Fixture City', postalCode: 'TEST1', country: 'GB' } }) });
    await page.goto(origin + '/identity');
    frame = await open(page, page.getByLabel('Contact email', { exact: true }));
    await confirm(frame); await frame.getByRole('button', { name: /Fixture identity/ }).click();
    await expect(page.getByLabel('Full name', { exact: true })).toHaveValue('Ada Fixture');
    await expect(page.getByLabel('Contact email', { exact: true })).toHaveValue('fixture@example.com');
    await expect(page.getByLabel('City', { exact: true })).toHaveValue('Fixture City');
    await expect(page.getByRole('combobox', { name: 'Country', exact: true })).toHaveValue('GB');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ browser: name, controlledReact: true, multiStep: true, honeyPotsEmpty: true,
      closedShadow: true, openShadowForms: true, crossFrameConfirmation: true, portIsolation: true,
      splitOtp: true, ordinaryPageOtpMessages, protectedFill: true, customVisibleField: true, captureAfterNavigation: true, updatePasswordHistory: true,
      protectedPasswordOnlyCaptureBeyondMenuLimit: true, ambiguousCaptureBlocked: true, shortcutAndClose: true,
      encryptedSitePreferences: true, wildcardScopeAndPortIsolation: true, wildcardNativePopup: true,
      paymentAndIdentity: true, errors }));
  } catch (error) {
    for (const [index, page] of (context?.pages() ?? []).entries()) {
      console.error('failure page:', page.url(), 'frames:', page.frames().map(frame => frame.url()));
      console.error(await page.locator('body').innerText().catch(() => 'No body'));
      for (const frame of page.frames().slice(1)) console.error('frame text:', await frame.locator('body').innerText().catch(() => 'No body'));
      console.error(await page.evaluate(() => [...document.querySelectorAll('[data-vault-ui]')].map(node => node.getBoundingClientRect().toJSON())).catch(() => []));
      await page.screenshot({ path: path.join(output, `autofill-${name}-failure-${index}.png`) }).catch(() => undefined);
    }
    throw error;
  } finally {
    await context?.close();
    assert(path.dirname(profile) === path.resolve(os.tmpdir()) && path.basename(profile).startsWith('vault-autofill-'));
    await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
}
(async () => {
  const primary = await server(), secondary = await server();
  try {
    await fs.mkdir(output, { recursive: true });
    for (const name of process.argv.slice(2).length ? process.argv.slice(2) : ['edge', 'helium']) await run(name, primary, secondary);
  } finally { primary.close(); secondary.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
