const { chromium, expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { waitForBuiltInFilters } = require('./browser-fixtures.cjs');
const { webdavFixture } = require('./webdav-fixture.cjs');

const extension = path.resolve(process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const browsers = {
  edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  helium: 'C:/Program Files/imput/Helium/Application/chrome.exe',
};
const originalMaster = 'Lifecycle-Original-Master#2026';
const newMaster = 'Lifecycle-Changed-Master#2026';
const resetMaster = 'Lifecycle-Recovered-Master#2026';
const pin = '735924';
const prf = { credentialId: [...randomBytes(32)], output: [...randomBytes(32)], salt: [...randomBytes(32)] };
const headPath = '/dav/vault/head.bin';
const pendingTitle = 'Helium edit retained across master change';
const edgeAlias = 'Lifecycle original Edge machine';
const masterProof = secret => ({ method: 'master', secret });

async function browserFixture(name, resources, profile) {
  if (!profile) {
    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-sync-lifecycle-'));
    resources.profiles.add(profile);
  }
  const context = await chromium.launchPersistentContext(profile, {
    executablePath: browsers[name], headless: name !== 'helium' && process.env.VAULT_HEADED !== '1',
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  resources.contexts.add(context);
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 20000 });
  await waitForBuiltInFilters(context, name);
  const view = await context.newPage();
  await view.goto(new URL('/sidepanel.html', worker.url()).href);
  const send = message => view.evaluate(async message => {
    const response = await chrome.runtime.sendMessage({ target: 'vault', ...message });
    if (!response?.ok) throw new Error(response?.error ?? 'No response from background');
    return response.value;
  }, message);
  return { view, send, profile, async close() {
    await context.close();
    resources.contexts.delete(context);
  } };
}

const status = local => local.send({ type: 'status' });
const sync = local => local.send({ type: 'webdav-sync' });
const join = (local, dav, secret) => local.send({ type: 'webdav-join', input: dav.config, method: 'master', secret });
const enableWrites = (local, masterPassword) => local.send({ type: 'webdav-enable-write', scratchFolder: 'scratch', masterPassword });
const add = (local, title, note = '') => local.send({ type: 'upsert', itemJson: JSON.stringify({
  id: '', title, note, data: { kind: 'login', username: 'synthetic', password: 'synthetic', uris: [] },
}) });
const titles = async local => (await local.send({ type: 'list' })).map(row => row.title).sort();
const writes = (dav, since) => dav.requests.slice(since).filter(({ method }) => !['GET', 'PROPFIND'].includes(method));
const contents = dav => [...dav.objects].filter(([name]) => name !== headPath)
  .map(([name, object]) => [name, object.tag, object.bytes]);

const rotationState = local => local.view.evaluate(async () => {
  const read = request => new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const db = await read(indexedDB.open('vault-extension'));
  try {
    const transaction = db.transaction(['vault', 'remoteState', 'pendingWal']);
    const active = await read(transaction.objectStore('vault').get('active'));
    const [anchor, pendingCount] = await Promise.all([
      read(transaction.objectStore('remoteState').get(active.vaultId)),
      read(transaction.objectStore('pendingWal').count()),
    ]);
    return { marked: active.remoteKeyUpdate, observed: !!anchor?.observedHead, epoch: anchor?.observedKeyEpoch, pendingCount };
  } finally { db.close(); }
});

async function publishNewWrap(edge, dav, rotation) {
  const priorTag = dav.objects.get(headPath).tag;
  const priorContents = contents(dav);
  const before = dav.requests.length;
  const rotated = await edge.send(rotation);
  assert.equal((await sync(edge)).pending, false);
  assert.notEqual(dav.objects.get(headPath).tag, priorTag);
  assert.deepEqual(writes(dav, before), [{ method: 'PUT', path: headPath, ifMatch: priorTag }]);
  assert.deepEqual(contents(dav), priorContents, 'Password rotation must not rewrite the snapshots or WAL');
  return rotated.keyEpoch;
}

async function verifyRotation(edge, helium, dav, resources, kit) {
  const proof = masterProof(originalMaster);
  await helium.send({ type: 'create-pin', pin, proof });
  await helium.send({ type: 'register-prf', ...prf, proof });
  await helium.send({ type: 'lock' });
  assert.equal((await helium.send({ type: 'unlock-pin', pin })).unlocked, true);
  await helium.send({ type: 'lock' });
  assert.equal((await helium.send({ type: 'unlock-prf', output: prf.output })).unlocked, true);
  const previousEpoch = (await status(helium)).keyEpoch;

  dav.state.failWal = true;
  await add(helium, pendingTitle);
  await assert.rejects(sync(helium), /503/);
  assert(!(await titles(edge)).includes(pendingTitle));
  await helium.send({ type: 'lock' }); // Do not mix Helium's scheduled retries with Edge's head publication.
  const epoch = await publishNewWrap(edge, dav, { type: 'change-password', currentPassword: originalMaster, newPassword: newMaster });
  assert.equal(epoch, previousEpoch + 1);
  await edge.send({ type: 'lock' });
  await helium.send({ type: 'unlock', password: originalMaster });
  const detected = await sync(helium);
  assert(['key-update', 'locked'].includes(detected.kind));
  assert.equal((await status(helium)).remoteKeyUpdate, true);
  assert.equal((await status(helium)).unlocked, false);
  const blocked = dav.requests.length;
  const persisted = await rotationState(helium);
  assert.deepEqual(persisted, { marked: true, observed: true, epoch, pendingCount: 1 });
  await helium.close();
  const resumed = await browserFixture('helium', resources, helium.profile);

  await expect(resumed.view.getByRole('heading', { name: '验证新的主密码' })).toBeVisible();
  await expect(resumed.view.getByText(/需重新设置本机 PIN 和系统解锁/)).toBeVisible();
  assert.equal((await status(resumed)).keyEpoch, previousEpoch);
  await assert.rejects(resumed.send({ type: 'list' }), /先解锁/);
  await assert.rejects(resumed.send({ type: 'unlock-pin', pin }), /新主密码/);
  await assert.rejects(resumed.send({ type: 'unlock-prf', output: prf.output }), /新主密码/);
  await assert.rejects(resumed.send({ type: 'unlock', password: originalMaster }), /新主密码/);
  await resumed.view.getByLabel('主密码', { exact: true }).fill(originalMaster);
  await resumed.view.getByRole('button', { name: '解锁', exact: true }).click();
  await expect(resumed.view.getByRole('alert')).toBeVisible();
  assert.equal((await status(resumed)).unlocked, false);
  assert.equal((await status(resumed)).keyEpoch, previousEpoch);
  assert.deepEqual(await rotationState(resumed), persisted);
  assert.deepEqual(dav.requests.slice(blocked), [], 'Neither locked client may make a WebDAV request');
  dav.state.failWal = false;

  await resumed.view.getByLabel('主密码', { exact: true }).fill(newMaster);
  await resumed.view.getByRole('button', { name: '解锁', exact: true }).click();
  await expect(resumed.view.getByRole('button', { name: '新建', exact: true })).toBeVisible();
  const after = await status(resumed);
  assert.equal(after.vaultId, kit.vaultId);
  assert.equal(after.keyEpoch, epoch);
  assert.equal(after.pinEnabled, false);
  assert.equal(after.prf, undefined);
  assert((await titles(resumed)).includes(pendingTitle));
  assert.equal((await sync(resumed)).pending, false);
  assert.deepEqual(await rotationState(resumed), { marked: false, observed: false, epoch: undefined, pendingCount: 0 });
  await edge.send({ type: 'unlock', password: newMaster });
  assert.equal((await sync(edge)).pending, false);
  assert((await titles(edge)).includes(pendingTitle));

  await resumed.send({ type: 'lock' });
  await assert.rejects(resumed.send({ type: 'unlock-pin', pin }), /PIN 已禁用/);
  await assert.rejects(resumed.send({ type: 'unlock-prf', output: prf.output }), /未设置系统解锁/);
  await resumed.send({ type: 'unlock', password: newMaster });
  const freshPin = '641857';
  const freshPrf = { credentialId: [...randomBytes(32)], output: [...randomBytes(32)], salt: [...randomBytes(32)] };
  await resumed.send({ type: 'create-pin', pin: freshPin, proof: masterProof(newMaster) });
  await resumed.send({ type: 'register-prf', ...freshPrf, proof: masterProof(newMaster) });
  await resumed.send({ type: 'lock' });
  assert.equal((await resumed.send({ type: 'unlock-pin', pin: freshPin })).unlocked, true);
  await resumed.send({ type: 'lock' });
  assert.equal((await resumed.send({ type: 'unlock-prf', output: freshPrf.output })).unlocked, true);
  const originalHead = dav.objects.get(headPath);
  const resetEpoch = await publishNewWrap(edge, dav, { type: 'recover', recoveryCode: kit.recoveryCode, newPassword: resetMaster });
  assert.equal(resetEpoch, epoch + 1);
  await sync(resumed);
  assert.equal((await status(resumed)).remoteKeyUpdate, true);
  await assert.rejects(resumed.send({ type: 'webdav-update-key', password: newMaster }));
  assert.equal((await status(resumed)).unlocked, false);
  const resetStatus = await resumed.send({ type: 'webdav-update-key', password: resetMaster });
  assert.equal(resetStatus.keyEpoch, resetEpoch);
  assert.equal((await sync(resumed)).pending, false);
  const updatedHead = dav.objects.get(headPath);
  const beforeReplay = dav.requests.length;
  const latest = await titles(resumed);
  try {
    dav.objects.set(headPath, originalHead);
    await assert.rejects(sync(resumed), /RollbackDetected/);
    assert.deepEqual(await titles(resumed), latest);
  } finally { dav.objects.set(headPath, updatedHead); }
  assert.deepEqual(writes(dav, beforeReplay), []);
  return resumed;
}

async function verifyDeviceClaim(edge, helium, dav, resources) {
  const readerAlias = 'Lifecycle separate Helium machine';
  const claimedAlias = 'Lifecycle reinstalled Edge machine';
  const deviceList = local => local.send({ type: 'webdav-devices' });
  const change = (local, action, fields) => local.send({
    type: 'webdav-device-change', action, ...fields, proof: masterProof(resetMaster),
  });
  const walNames = () => [...dav.objects.keys()].filter(name => name.startsWith('/dav/vault/wal/'));
  const writerTag = name => {
    const parsed = /^\/dav\/vault\/wal\/[0-9a-f]{14}_([0-9a-f]{8})_[0-9a-f]{14}\.bin$/.exec(name);
    assert(parsed, 'Expected an opaque WAL path');
    return parsed[1];
  };
  const push = async local => {
    const result = await sync(local);
    assert.equal(result.pending, false);
    assert.notEqual(result.kind, 'conflicts');
  };
  const priorNames = new Set(walNames());
  await add(edge, 'Saved by Edge before reinstall');
  await push(edge);
  const [originalWal] = walNames().filter(name => !priorNames.has(name));
  assert(originalWal);
  const originalObject = dav.objects.get(originalWal);
  const initial = await deviceList(edge);
  const original = initial.rows.find(row => row.id === initial.active);
  assert.equal(original?.name, edgeAlias);
  assert(original.lastSeen > 0);
  assert.equal(original.lastEditCount, 1);

  await push(helium);
  assert.equal((await deviceList(helium)).registered, false);
  const registered = await change(helium, 'register', { name: readerAlias });
  assert(registered.active && registered.active !== original.id);
  await push(helium);

  const reinstalled = await browserFixture('edge', resources);
  const beforeJoin = dav.requests.length;
  await join(reinstalled, dav, resetMaster);
  assert.deepEqual(writes(dav, beforeJoin), []);
  const beforeClaim = await deviceList(reinstalled);
  assert.equal(beforeClaim.registered, false);
  assert.equal(beforeClaim.active, undefined);
  assert.deepEqual(beforeClaim.rows.map(row => row.id).sort(), [original.id, registered.active].sort());
  await enableWrites(reinstalled, resetMaster);

  await reinstalled.view.reload();
  await reinstalled.view.getByRole('button', { name: '设置', exact: true }).click();
  await reinstalled.view.getByRole('button', { name: /^网盘连接/ }).click();
  await reinstalled.view.getByRole('button', { name: '管理设备' }).click();
  const originalRow = reinstalled.view.locator('details').filter({ hasText: edgeAlias });
  await originalRow.locator('summary').click();
  await expect(originalRow.getByText(/最近同步：/)).toBeVisible();
  await expect(originalRow.getByText('与本机的系统或浏览器相同')).toBeVisible();
  await originalRow.getByRole('button', { name: '认领', exact: true }).click();
  await reinstalled.view.getByLabel('设备名称', { exact: true }).fill(claimedAlias);
  const beforeProof = dav.requests.length;
  await reinstalled.view.getByLabel('主密码', { exact: true }).fill(newMaster);
  await reinstalled.view.getByRole('button', { name: '认领这台设备' }).click();
  await expect(reinstalled.view.getByRole('alert')).toContainText('主密码验证失败');
  assert.equal((await deviceList(reinstalled)).registered, false);
  assert.deepEqual(writes(dav, beforeProof), []);
  await reinstalled.view.getByLabel('主密码', { exact: true }).fill(resetMaster);
  await reinstalled.view.getByRole('button', { name: '认领这台设备' }).click();
  await expect(reinstalled.view.getByText(`${claimedAlias} · 本机`, { exact: true })).toBeVisible();
  const claimed = await deviceList(reinstalled);
  assert.equal(claimed.active, original.id);
  assert.equal(claimed.registered, true);
  assert.equal(claimed.rows.find(row => row.id === original.id)?.created, original.created);
  await push(reinstalled);

  // Both instances still run after the claim. Their WALs must be distinct and both edits must converge.
  const beforeBoth = new Set(walNames());
  await Promise.all([add(edge, 'Old Edge instance still editing'), add(reinstalled, 'New Edge instance editing')]);
  await push(edge);
  await push(reinstalled);
  const instanceWrites = walNames().filter(name => !beforeBoth.has(name));
  assert.equal(instanceWrites.length, 2);
  assert.equal(new Set(instanceWrites.map(writerTag)).size, 2);
  assert(instanceWrites.some(name => writerTag(name) === writerTag(originalWal)));
  assert.deepEqual(dav.objects.get(originalWal), originalObject);
  await push(edge);
  await push(helium);
  const finalTitles = await titles(reinstalled);
  assert.deepEqual(await titles(edge), finalTitles);
  assert.deepEqual(await titles(helium), finalTitles);
  for (const title of ['Saved by Edge before reinstall', 'Old Edge instance still editing', 'New Edge instance editing']) {
    assert.equal(finalTitles.filter(value => value === title).length, 1);
  }
  assert.equal((await deviceList(helium)).rows.find(row => row.id === original.id)?.name, claimedAlias);

  const heliumRow = reinstalled.view.locator('details').filter({ hasText: readerAlias });
  await heliumRow.locator('summary').click();
  await heliumRow.getByRole('button', { name: '移除', exact: true }).click();
  await expect(reinstalled.view.getByText(/不删除凭证，也不会撤销该设备已持有的密钥/)).toBeVisible();
  await reinstalled.view.getByLabel('主密码', { exact: true }).fill(resetMaster);
  await reinstalled.view.getByRole('button', { name: '移除设备记录' }).click();
  await expect(heliumRow).toHaveCount(0);
  await push(reinstalled);
  await push(helium);
  assert.equal((await deviceList(helium)).registered, false);
  assert.deepEqual(await titles(helium), finalTitles);
  for (const label of [edgeAlias, readerAlias, claimedAlias, original.id, registered.active]) {
    for (const [name, object] of dav.objects) assert(!name.includes(label) && !object.bytes.includes(Buffer.from(label)));
  }
}

async function run() {
  const dav = await webdavFixture();
  const resources = { profiles: new Set(), contexts: new Set() };
  try {
    const edge = await browserFixture('edge', resources);
    const kit = await edge.send({ type: 'create', masterPassword: originalMaster, calibrate: false });
    // Give the ordinary edits ample room below the idle compaction threshold.
    await add(edge, 'Lifecycle baseline', randomBytes(12000).toString('hex'));
    await edge.send({ type: 'webdav-create', input: dav.config, scratchFolder: 'scratch', masterPassword: originalMaster, deviceName: edgeAlias });
    const helium = await browserFixture('helium', resources);
    await join(helium, dav, originalMaster);
    await enableWrites(helium, originalMaster);
    const resumed = await verifyRotation(edge, helium, dav, resources, kit);
    console.log(JSON.stringify({ rebasedAfterRestart: true, offlineEditArrived: true, pinAndPrfReconfigured: true, lockedNoRequests: true,
      passwordChangeAndRecoveryOnlyRewrapped: true, rollbackRejected: true }));
    await verifyDeviceClaim(edge, resumed, dav, resources);
    console.log(JSON.stringify({ sameSystemNotAutoClaimed: true, proofRequired: true, registeredAndClaimed: true,
      activeOldAndNewWalsBothKept: true, noDuplicateEdits: true, deviceRemovalDidNotDeleteItems: true, noCleartextDeviceMarkers: true }));
  } finally {
    const report = outcome => {
      for (const result of outcome) if (result.status === 'rejected') {
        console.error('Sync lifecycle cleanup:', result.reason);
        process.exitCode = 1;
      }
    };
    report(await Promise.allSettled([...resources.contexts].map(context => context.close())));
    report(await Promise.allSettled([...resources.profiles].map(async profile => {
      assert.equal(path.dirname(profile), path.resolve(os.tmpdir()));
      assert(path.basename(profile).startsWith('vault-sync-lifecycle-'));
      await fs.rm(profile, { recursive: true, maxRetries: 3, retryDelay: 200 });
    })));
    await dav.close();
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
