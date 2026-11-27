const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { extensionBuildHash, waitForBuiltInFilters, waitForSetupTab } = require('./browser-fixtures.cjs');
const { webdavFixture } = require('./webdav-fixture.cjs');
const { verifyPackMergeRecovery } = require('./pack-merge-fixture.cjs');

const extension = path.resolve(process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const browsers = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const master = 'Synthetic-Vault-Pack-Master#2026';
const baseline = 'Pack fixture login';
const hotpTitle = 'Pack fixture HOTP';
const fixturePassword = 'Synthetic-Login#37';
const rule = 'https://*.fixture.example.com';
const flags = { inlineDisabled: true, saveDisabled: false, passkeyDisabled: true };
const domainGroups = [['example.com', 'example.net']];
const root = '/dav/vault/';
const packagePath = /^\/dav\/vault\/packages\/p_[0-9a-f]{32}\.bin$/;
const recordPath = /^\/dav\/vault\/versions\/v_[0-9a-f]{32}\.txt$/;
const proofPath = /^\/dav\/vault\/(?:versions\/|packages\/)?pack_verify_[0-9a-f]{32}\.(bin|txt)$/;
const records = dav => [...dav.objects.keys()].filter(key => recordPath.test(key));

async function openBrowser(name, resources, priorProfile, { install = extension, args = [] } = {}) {
  const profile = priorProfile || await fs.mkdtemp(path.join(os.tmpdir(), 'vault-pack-sync-'));
  if (!priorProfile) resources.profiles.add(profile);
  const context = await chromium.launchPersistentContext(profile, {
    executablePath: browsers[name],
    headless: name !== 'helium' && process.env.VAULT_HEADED !== '1',
    viewport: { width: 400, height: 600 },
    args: [`--disable-extensions-except=${install}`, `--load-extension=${install}`, ...args],
  });
  resources.contexts.add(context);
  const worker = context.serviceWorkers().find(worker => worker.url().endsWith('/background.js')) ||
    await context.waitForEvent('serviceworker', { predicate: worker => worker.url().endsWith('/background.js'), timeout: 20000 });
  await waitForBuiltInFilters(context, name);
  const setup = !priorProfile && await waitForSetupTab(context, worker.url());
  const view = await context.newPage();
  await view.goto(new URL('/sidepanel.html', worker.url()).href);
  if (setup) await setup.close();
  const send = message => view.evaluate(async message => {
    const reply = await chrome.runtime.sendMessage({ target: 'vault', ...message });
    if (!reply?.ok) throw new Error(reply?.error ?? 'Vault did not respond');
    return reply.value;
  }, message);
  return { view, send, profile, version: context.browser().version(), async close() {
    await context.close();
    resources.contexts.delete(context);
  } };
}

const write = (device, title) => device.send({ type: 'upsert', itemJson: JSON.stringify({
  id: '', title, data: { kind: 'login', username: 'synthetic', password: fixturePassword, uris: [{ uri: 'https://login.example.com' }] },
}) });
const items = device => device.send({ type: 'list' });
const titles = async device => (await items(device)).map(row => row.title).sort();
const status = device => device.send({ type: 'webdav-status' });
const activeRules = device => device.send({ type: 'autofill-settings' });
const sync = device => device.send({ type: 'webdav-sync' });
const enable = device => device.send({ type: 'webdav-enable-write', masterPassword: master });
const assertRulesFit = view => expect.poll(() => view.locator('.site-rule-list').evaluateAll(lists =>
  lists.length > 0 && lists.every(list => list.scrollWidth <= list.clientWidth))).toBe(true);
const assertNoManualTestDirectory = view => expect(view.getByRole('textbox', { name: /测试目录/ })).toHaveCount(0);

async function testConnection(view, config) {
  const fields = {
    'WebDAV 根地址': config.base, '同步目录名': config.folder, '网盘账号': config.username, '应用专用密码': config.password,
  };
  await view.getByLabel('服务商').selectOption('custom');
  for (const [label, value] of Object.entries(fields)) await view.getByLabel(label, { exact: true }).fill(value);
  await view.getByRole('checkbox', { name: /允许本机 HTTP 调试/ }).check();
  await view.getByRole('button', { name: '测试连接', exact: true }).click();
}

async function joinFromUi(device, config, method, secret, use) {
  const { view } = device;
  await testConnection(view, config);
  await view.getByLabel('验证已有网盘库').selectOption(method);
  await view.getByLabel(method === 'master' ? '网盘库主密码' : '应急恢复码', { exact: true }).fill(secret);
  await view.getByRole('button', { name: '恢复到本机', exact: true }).click();
  await expect(view.getByRole('heading', { name: '预览网盘库的网站规则' })).toBeVisible({ timeout: 20000 });
  await expect(view.getByText(rule, { exact: true })).toBeVisible();
  await expect(view.getByText(domainGroups[0].join('、'), { exact: true })).toBeVisible();
  await assertRulesFit(view);
  assert.deepEqual(await activeRules(device), { sites: {}, equivalentDomains: [] });
  assert.equal((await status(device)).writeVerified, false);
  await view.getByRole('button', { name: use ? '采用网盘网站规则' : '跳过网站规则', exact: true }).click();
  await expect(view.getByRole('button', { name: '新建', exact: true })).toBeVisible();
  assert.deepEqual(await activeRules(device), use ? { sites: { [rule]: flags }, equivalentDomains: domainGroups }
    : { sites: {}, equivalentDomains: [] });
  assert.equal(await device.send({ type: 'webdav-site-rules' }), null);
}

async function enableFromUi(device, masterPassword = master) {
  const { view } = device;
  await view.getByRole('button', { name: '设置', exact: true }).click();
  await view.getByRole('button', { name: /^网盘连接/ }).click();
  await expect(view.getByText('网盘当前只读。上传本机变更前需验证写入。', { exact: true })).toBeVisible();
  await view.getByRole('button', { name: '验证写入能力', exact: true }).click();
  await expect(view.getByLabel('当前主密码', { exact: true })).toBeVisible();
  await assertNoManualTestDirectory(view);
  await view.getByLabel('当前主密码', { exact: true }).fill(masterPassword);
  await view.getByRole('button', { name: '验证并启用网盘写入', exact: true }).click();
  await expect(view.getByText('网盘当前只读。上传本机变更前需验证写入。', { exact: true })).toHaveCount(0);
  assert.equal((await status(device)).writeVerified, true);
}

async function verifyGenesisRestart(resources) {
  const dav = await webdavFixture();
  let fresh, resumed;
  try {
    fresh = await openBrowser('edge', resources);
    await testConnection(fresh.view, dav.config);
    await expect(fresh.view.getByLabel('新主密码', { exact: true })).toBeVisible();
    await assertNoManualTestDirectory(fresh.view);
    await fresh.view.getByLabel('新主密码', { exact: true }).fill(master);
    await fresh.view.getByLabel('再次输入主密码', { exact: true }).fill(master);
    dav.state.failRootPut = true;
    await fresh.view.getByRole('button', { name: '验证写入并在网盘建库', exact: true }).click();
    await expect(fresh.view.getByRole('alert')).toBeVisible({ timeout: 30000 });
    assert.equal(dav.state.rootAttempts.length, 1);
    assert.equal(dav.objects.has(`${root}pack-root.txt`), false);
    const [attempt] = dav.state.rootAttempts;
    const [[, id, vaultId]] = JSON.parse(attempt.toString('utf8'));
    const cipher = `${root}packages/p_${id}.bin`;
    assert.equal([...dav.objects.keys()].filter(name => packagePath.test(name)).length, 1);
    assert(dav.objects.has(cipher));
    const staged = dav.objects.get(cipher).bytes;
    assert((await fresh.send({ type: 'status' })).configured === false);
    const profile = fresh.profile;
    await fresh.close();
    fresh = undefined;

    resumed = await openBrowser('edge', resources, profile);
    await testConnection(resumed.view, dav.config);
    await expect(resumed.view.getByText('上次创建这个网盘库时中断了。', { exact: true })).toBeVisible();
    await assertNoManualTestDirectory(resumed.view);
    await resumed.view.getByLabel('当前主密码', { exact: true }).fill(master);
    await resumed.view.getByRole('button', { name: '继续创建网盘库', exact: true }).click();
    await expect(resumed.view.getByRole('heading', { name: '保存应急恢复包', exact: true })).toBeVisible({ timeout: 30000 });
    const recoveryCode = await resumed.view.locator('.recovery-code').innerText();
    assert(recoveryCode);
    assert.equal((await resumed.send({ type: 'status' })).vaultId, vaultId);
    assert.deepEqual(dav.state.rootAttempts, [attempt, attempt]);
    assert.deepEqual(dav.objects.get(`${root}pack-root.txt`).bytes, attempt);
    assert.deepEqual(dav.objects.get(cipher).bytes, staged);
    assert.equal([...dav.objects.keys()].filter(name => packagePath.test(name)).length, 1);
    assert.deepEqual(assertPublished(dav, `${root}pack-root.txt`, 0), []);
    assertTargetPaths(dav);
    assertNoPlaintext(dav, recoveryCode);

    await resumed.send({ type: 'lock' });
    const recovered = await resumed.send({ type: 'recover', recoveryCode, newPassword: 'Synthetic-Recovered-Master#2026' });
    assert.equal(recovered.vaultId, vaultId);
    assert.equal(recovered.unlocked, true);
  } finally {
    try { await Promise.all([fresh?.close(), resumed?.close()]); }
    finally { await dav.close(); }
  }
}

function traffic(dav, since) {
  const result = { metadataUploadBytes: 0, metadataDownloadBytes: 0, packUploadBytes: 0, packDownloadBytes: 0,
    proofUploadBytes: 0, proofDownloadBytes: 0 };
  for (const row of dav.transfers.slice(since)) {
    if (!row.path.startsWith(root)) continue;
    if (packagePath.test(row.path)) {
      result.packUploadBytes += row.uploadBytes;
      result.packDownloadBytes += row.downloadBytes;
    } else if (proofPath.test(row.path)) {
      result.proofUploadBytes += row.uploadBytes;
      result.proofDownloadBytes += row.downloadBytes;
    } else {
      result.metadataUploadBytes += row.uploadBytes;
      result.metadataDownloadBytes += row.downloadBytes;
    }
  }
  return result;
}

function assertPublished(dav, name, since) {
  const [[, id, , parents, hash, size]] = JSON.parse(dav.objects.get(name).bytes.toString('utf8'));
  const cipherPath = `${root}packages/p_${id}.bin`;
  const { bytes } = dav.objects.get(cipherPath);
  assert.equal(bytes.length, size);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), hash);
  assert(!bytes.includes(fixturePassword));
  const rows = dav.transfers.slice(since);
  const fileWrite = rows.findIndex(row => row.path === cipherPath && row.method === 'PUT' && row.uploadBytes === size);
  const readback = rows.findIndex(row => row.path === cipherPath && row.method === 'GET' && row.downloadBytes === size);
  const recordWrite = rows.findIndex(row => row.path === name && row.method === 'PUT');
  assert(fileWrite >= 0 && readback > fileWrite && recordWrite > readback, 'Upload and full ciphertext readback precede commit');
  if (name === `${root}pack-root.txt`) {
    const proofWrites = rows.slice(readback + 1, recordWrite).filter(row => proofPath.test(row.path) && row.method === 'PUT');
    const proofDirectories = new Set(proofWrites.map(({ path }) => path.slice(0, path.lastIndexOf('/') + 1)));
    assert.deepEqual([...proofDirectories].sort(), [root, `${root}packages/`, `${root}versions/`],
      'Genesis proves the root, package, and version write paths after readback and before publishing the root');
  }
  return parents;
}

function assertTargetPaths(dav) {
  for (const { method, path } of dav.requests) {
    if (['PUT', 'GET', 'DELETE', 'MKCOL'].includes(method))
      assert(path.startsWith(root), `${method} must stay within the selected sync folder, got ${path}`);
  }
}

function assertNoPlaintext(dav, recoveryCode) {
  const markers = [baseline, fixturePassword, rule, 'example.net', 'example.co.uk', 'fixture-user', 'fixture-app-password',
    dav.config.password, master, recoveryCode, 'GEZDGNBVGY3TQOJQ'];
  assert(dav.objects.size > 0);
  for (const [name, { bytes }] of dav.objects) {
    assert(!proofPath.test(name), `Temporary proof objects must be cleaned: ${name}`);
    assert(markers.every(marker => !bytes.includes(marker)), `Unencrypted fixture fields in ${name}`);
  }
}

async function verifyInterruptedPublish(dav, edge, helium) {
  const prior = records(dav);
  await write(edge, 'Saved before interrupted publish');
  const since = dav.transfers.length;
  dav.state.packCommitFailure = 'before';
  try {
    await assert.rejects(sync(edge));
    assert.deepEqual(records(dav), prior);
    const attempt = traffic(dav, since);
    assert(attempt.packUploadBytes > 0 && attempt.packDownloadBytes === attempt.packUploadBytes);
    await sync(helium);
    assert(!(await titles(helium)).includes('Saved before interrupted publish'));
  } finally { dav.state.packCommitFailure = undefined; }
  const retry = dav.transfers.length;
  assert.equal((await sync(edge)).pending, false);
  const newRecords = records(dav).filter(name => !prior.includes(name));
  assert.equal(newRecords.length, 1);
  assertPublished(dav, newRecords[0], since);
  assert(traffic(dav, retry).packDownloadBytes > 0);
  await sync(helium);
  assert((await titles(helium)).includes('Saved before interrupted publish'));

  await write(edge, 'Commit whose response was lost');
  const beforeLost = records(dav);
  dav.state.packCommitFailure = 'after';
  try { await sync(edge).catch(() => undefined); }
  finally { assert.equal(dav.state.packCommitFailure, undefined, 'Fixture must lose a committed response'); }
  assert.equal(records(dav).length, beforeLost.length + 1);
  assert.equal((await sync(edge)).pending, false);
  assert.equal(records(dav).length, beforeLost.length + 1, 'Retry must discover exactly one published version');
  assert.equal((await sync(helium)).pending, false);
  assert.equal((await titles(helium)).filter(title => title === 'Commit whose response was lost').length, 1);
}

async function publishTogether(dav, edge, helium) {
  const held = new Set();
  const released = Promise.withResolvers();
  let timer;
  dav.state.beforePackCommit = async name => {
    held.add(name);
    if (held.size === 2) released.resolve();
    await released.promise;
  };
  try {
    return await Promise.race([Promise.all([sync(edge), sync(helium)]), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Both active clients must reach publication')), 30_000);
    })]);
  } finally {
    clearTimeout(timer);
    dav.state.beforePackCommit = undefined;
    released.resolve();
  }
}

async function verifyConcurrent(dav, edge, helium) {
  const before = records(dav);
  const since = dav.transfers.length;
  await Promise.all([write(edge, 'Edge offline change'), write(helium, 'Helium offline change')]);
  assert.equal(traffic(dav, since).packUploadBytes, 0, 'Edits save locally before any publication');
  const results = await publishTogether(dav, edge, helium);
  const branches = records(dav).filter(name => !before.includes(name));
  assert.equal(branches.length, 2);
  const parents = branches.map(name => assertPublished(dav, name, since));
  assert.deepEqual(parents[0], parents[1], 'Both independently publish from the same parent');
  const devices = [edge, helium];
  assert(results.some(result => result.kind === 'deferred'), 'At least the last publisher discovers the other branch');
  for (const [index, result] of results.entries()) {
    if (result.kind === 'deferred') assert.equal((await status(devices[index])).pending, true,
      'A published branch must stay pending in settings until the other known branch is merged');
  }

  assert.equal((await sync(edge)).pending, false);
  assert.equal((await sync(helium)).pending, false);
  assert.equal((await status(edge)).pending, false);
  assert.equal((await status(helium)).pending, false);
  const merged = await titles(edge);
  assert.deepEqual(await titles(helium), merged);
  assert(merged.includes('Edge offline change') && merged.includes('Helium offline change'));
}

async function verifyRuleConflicts(dav, edge, helium) {
  const first = [['example.com', 'example.org']];
  const second = [['example.co.uk', 'example.com']];
  const setGroups = (device, groups) => device.send({ type: 'set-equivalent-domains', groups });
  await Promise.all([setGroups(edge, first), setGroups(helium, second)]);
  await publishTogether(dav, edge, helium);
  await sync(edge);
  await sync(helium);
  assert.equal((await status(edge)).siteRuleConflicts, 1);
  assert.equal((await status(helium)).siteRuleConflicts, 1);

  const { view } = edge;
  await view.setViewportSize({ width: 330, height: 600 });
  await view.reload();
  await view.getByRole('button', { name: '设置', exact: true }).click();
  await view.getByRole('button', { name: /^网盘连接/ }).click();
  await view.getByRole('button', { name: '处理 1 项关联域名冲突', exact: true }).click();
  const heading = view.getByRole('heading', { name: '处理关联域名冲突', exact: true });
  await expect(heading).toBeVisible();
  await expect(view.getByText(first[0].join('、'), { exact: true })).toBeVisible();
  await expect(view.getByText(second[0].join('、'), { exact: true })).toBeVisible();
  await assertRulesFit(view);
  const pick = view.locator('details').filter({ hasText: second[0].join('、') });
  await pick.getByRole('button', { name: /采用第[一二]版/ }).click();
  await expect(heading).toHaveCount(0);
  assert.deepEqual((await activeRules(edge)).equivalentDomains, second);
  await sync(edge);
  await sync(helium);
  assert.equal((await status(helium)).siteRuleConflicts ?? 0, 0);
  assert.deepEqual((await activeRules(helium)).equivalentDomains, second);

  await setGroups(edge, domainGroups);
  await sync(edge);
  await sync(helium);
}

async function verifyEditDuringSync(dav, edge, helium) {
  const entered = Promise.withResolvers();
  const response = Promise.withResolvers();
  dav.state.beforePackList = async () => { entered.resolve(); await response.promise; };
  const editing = 'Saved during an in-flight check';
  const check = sync(edge).catch(error => error);
  let timer;
  try {
    await Promise.race([(async () => {
      await entered.promise;
      await write(edge, editing);
      assert((await titles(edge)).includes(editing));
      assert.equal((await status(edge)).pending, true);
    })(), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Local edit must finish while the WebDAV response is withheld')), 12_000);
    })]);
  } finally {
    clearTimeout(timer);
    dav.state.beforePackList = undefined;
    response.resolve();
    await check;
  }
  assert.equal((await status(edge)).pending, true, 'The earlier check must not acknowledge the subsequent edit');
  await sync(helium);
  assert(!(await titles(helium)).includes(editing));
  assert.equal((await sync(edge)).pending, false);
  await sync(helium);
  assert((await titles(helium)).includes(editing));
}

async function verifyLockAndHistory(dav, edge, helium) {
  const beforeLock = records(dav).length;
  const lockedEdit = 'Saved in the queue before lock';
  await write(edge, lockedEdit);
  await edge.send({ type: 'lock' });
  const locked = dav.transfers.length;
  assert.equal((await sync(edge)).kind, 'locked');
  assert.deepEqual(dav.transfers.slice(locked), []);
  assert.equal(records(dav).length, beforeLock);
  assert.equal((await edge.send({ type: 'unlock', password: master })).unlocked, true);
  await expect.poll(() => records(dav).length, { timeout: 15000 }).toBe(beforeLock + 1);
  await sync(helium);
  assert((await titles(helium)).includes(lockedEdit));

  const id = (await items(edge)).find(item => item.title === hotpTitle).id;
  const [older] = await edge.send({ type: 'webdav-history' });
  assert.deepEqual(await edge.send({ type: 'next-hotp', id }), { kind: 'hotp', counter: '0', value: '755224' });
  assert.equal((await sync(edge)).pending, false);
  const history = await edge.send({ type: 'webdav-history' });
  assert.equal(history.length, 5);
  assert(history[0].current && history[0].id !== older.id);
  const preview = await edge.send({ type: 'webdav-history-preview', id: older.id });
  assert(!preview.blocked && !preview.readOnly);
  const beforeRestore = records(dav).length;
  await edge.send({ type: 'webdav-history-restore', id: older.id, stamp: preview.stamp, destination: 'remote',
    proof: { method: 'master', secret: master } });
  assert.equal(records(dav).length, beforeRestore + 1);
  await sync(helium);
  assert.deepEqual(await helium.send({ type: 'next-hotp', id }), { kind: 'hotp', counter: '1', value: '287082' });
  assert.equal((await sync(helium)).pending, false);
  assert.equal((await sync(edge)).pending, false);
  return history.length;
}

async function verifySafety(dav, edge) {
  const expected = await titles(edge);
  const name = records(dav).at(-1);
  const newest = dav.objects.get(name);
  const since = dav.transfers.length;
  try {
    dav.objects.delete(name);
    await edge.send({ type: 'lock' });
    await edge.send({ type: 'unlock', password: master });
    await expect.poll(async () => (await status(edge)).checkFailed, {
      timeout: 15_000, message: 'The unlock check must leave a warning when authenticated history is missing',
    }).toBe(true);
    await edge.view.reload();
    await edge.view.getByRole('button', { name: '设置', exact: true }).click();
    await edge.view.getByRole('button', { name: /^网盘连接/ }).click();
    await expect(edge.view.getByText(/上次同步检查失败/)).toBeVisible();
    await assert.rejects(sync(edge), /缺少|回滚/);
    assert.deepEqual(await titles(edge), expected);
    assert.equal(traffic(dav, since).packUploadBytes, 0);
  } finally { dav.objects.set(name, newest); }
  await sync(edge);
  assert.equal((await status(edge)).checkFailed, false);
  await expect(edge.view.getByText(/上次同步检查失败/)).toHaveCount(0);

  for (const code of [401, 429]) {
    dav.state.stopNextProbe = code;
    await sync(edge).catch(() => undefined);
    assert.equal((await status(edge)).paused, code);
    const stopped = dav.transfers.length;
    assert.equal((await sync(edge)).kind, 'paused');
    assert.deepEqual(dav.transfers.slice(stopped), []);
    if (code === 401) {
      dav.state.password = 'fixture-updated-app-password';
      dav.config.password = dav.state.password;
    }
    await edge.send({ type: 'webdav-test', input: dav.config, remember: true });
    assert.equal((await status(edge)).paused, undefined);
    assert.equal((await status(edge)).writeVerified, false);
    await enable(edge);
  }

  const local = (await items(edge)).filter(item => !item.trashed);
  assert(local.length >= 6);
  const remote = records(dav);
  for (const item of local.slice(1)) await edge.send({ type: 'trash', id: item.id, trashed: true });
  const deletion = await sync(edge);
  assert.equal(deletion.kind, 'confirm-deletion');
  assert.equal(deletion.removed, local.length - 1);
  assert.deepEqual(records(dav), remote);
  await edge.send({ type: 'trash', id: local[0].id, trashed: true });
  assert.equal((await sync(edge)).kind, 'empty');
  assert.deepEqual(records(dav), remote);
  await edge.send({ type: 'lock' });
}

async function run() {
  const resources = { profiles: new Set(), contexts: new Set() };
  const build = await extensionBuildHash(extension);
  const dav = await webdavFixture();
  try {
    await verifyGenesisRestart(resources);
    if (process.argv.includes('--genesis-only')) {
      console.log(JSON.stringify({ build, genesisRestartRetainsIdentity: true }));
      return;
    }
    const edge = await openBrowser('edge', resources);
    const kit = await edge.send({ type: 'create', masterPassword: master, calibrate: false });
    await write(edge, baseline);
    await edge.send({ type: 'upsert', itemJson: JSON.stringify({
      id: '', title: hotpTitle, data: { kind: 'login', username: 'synthetic', password: fixturePassword, uris: [],
        totpUri: 'otpauth://hotp/Pack?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0' },
    }) });
    await edge.send({ type: 'set-autofill-site', origin: rule, flags });
    await edge.send({ type: 'set-equivalent-domains', groups: domainGroups });
    const helium = await openBrowser('helium', resources);
    dav.state.failRootPut = true;
    await assert.rejects(helium.send({ type: 'webdav-create', input: dav.config, masterPassword: master }), /503/);
    assert(!dav.objects.has(`${root}pack-root.txt`));
    assert.equal((await helium.send({ type: 'status' })).configured, false);
    const beginCreate = dav.transfers.length;
    await edge.send({ type: 'webdav-create', input: dav.config, masterPassword: master, deviceName: 'Edge fixture' });
    assert.equal((await status(edge)).format, 'pack');
    assert.equal((await status(edge)).writeVerified, true);
    assert.deepEqual(assertPublished(dav, `${root}pack-root.txt`, beginCreate), []);
    const create = traffic(dav, beginCreate);

    let since = dav.transfers.length;
    assert.deepEqual(await sync(edge), { kind: 'unchanged', pending: false });
    const idle = traffic(dav, since);
    assert(idle.metadataDownloadBytes > 0);
    assert.equal(idle.packUploadBytes, 0);
    assert.equal(idle.packDownloadBytes, 0);
    await edge.send({ type: 'lock' });
    since = dav.transfers.length;
    assert.equal((await sync(edge)).kind, 'locked');
    assert.deepEqual(dav.transfers.slice(since), []);

    since = dav.transfers.length;
    await joinFromUi(helium, dav.config, 'master', master, true);
    const join = traffic(dav, since);
    assert.equal(join.packUploadBytes, 0);
    assert(join.packDownloadBytes > 0);
    const entry = (await items(helium)).find(item => item.title === baseline);
    assert(entry);
    assert.equal((await helium.send({ type: 'get', id: entry.id })).data.password, fixturePassword);
    assert.equal((await helium.send({ type: 'status' })).vaultId, kit.vaultId);
    await enableFromUi(helium);
    assert.equal((await edge.send({ type: 'unlock', password: master })).unlocked, true);
    await verifyInterruptedPublish(dav, edge, helium);
    await verifyConcurrent(dav, edge, helium);
    await verifyRuleConflicts(dav, edge, helium);
    await verifyEditDuringSync(dav, edge, helium);
    const historyVersions = await verifyLockAndHistory(dav, edge, helium);
    const mergeRecovery = await verifyPackMergeRecovery({ edge, helium, openSource: () => openBrowser('edge', resources),
      config: dav.config, master });

    await helium.send({ type: 'lock' });
    await verifySafety(dav, edge);
    const declined = await openBrowser('edge', resources);
    await joinFromUi(declined, dav.config, 'recovery', kit.recoveryCode, false);
    assert.equal((await declined.send({ type: 'status' })).vaultId, kit.vaultId);
    await declined.send({ type: 'lock' });
    await declined.send({ type: 'unlock', password: master });
    assert.deepEqual(await activeRules(declined), { sites: {}, equivalentDomains: [] });
    assert((await titles(declined)).includes('Helium offline change'));
    assertTargetPaths(dav);
    assertNoPlaintext(dav, kit.recoveryCode);
    const report = { build, edge: edge.version, helium: helium.version, create, idle, join, concurrentBranches: true,
      interruptedPublishResumed: true, lostResponseConverged: true, editsDuringNetwork: true,
      rulesAdoptedAndSkipped: true, concurrentRulesResolved: true, historyVersions, lockRetainsPending: true, historyPreservesHotp: true,
      rollbackBlocked: true, authenticationAndThrottlingPaused: true, emptyAndBulkDeletionProtected: true, noPlaintext: true,
      genesisRestartRetainsIdentity: true, canJoinAfterLosingGenesis: true, automaticWriteProofInTarget: true,
      concurrentStatusPreserved: true, failedCheckVisible: true, mergeRecovery };
    await fs.mkdir('test-results', { recursive: true });
    await fs.writeFile(path.join('test-results', 'pack-sync-loopback.json'), JSON.stringify(report, null, 2) + '\n', 'utf8');
    console.log(JSON.stringify(report));
  } finally {
    const cleanup = outcomes => {
      for (const result of outcomes) if (result.status === 'rejected') {
        console.error('Pack sync fixture cleanup failed', result.reason);
        process.exitCode = 1;
      }
    };
    cleanup(await Promise.allSettled([...resources.contexts].map(context => context.close())));
    cleanup(await Promise.allSettled([...resources.profiles].map(async profile => {
      assert.equal(path.dirname(profile), path.resolve(os.tmpdir()));
      assert(path.basename(profile).startsWith('vault-pack-sync-'));
      await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
    })));
    await dav.close();
  }
}

module.exports = { openBrowser, enableFromUi };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
