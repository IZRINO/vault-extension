// Run with VAULT_EXTENSION_PATH=<new unpacked ZIP> and VAULT_PACK_020_PATH=<v0.2.0 unpacked ZIP>.
// Chromium maps the Koofr preset to this process's TLS listener. Only synthetic accounts exist here.
const { expect } = require('@playwright/test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash, X509Certificate } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { extensionBuildHash } = require('./browser-fixtures.cjs');
const { openBrowser, enableFromUi } = require('./test-pack-sync.cjs');
const { webdavFixture } = require('./webdav-fixture.cjs');

const baseline = path.resolve(process.env.VAULT_PACK_020_PATH || 'test-results/release-v0.2.0/chrome-mv3');
const candidate = path.resolve(process.env.VAULT_EXTENSION_PATH || 'apps/extension/.output/chrome-mv3');
const oldHash = '122d1c985b1d290bfb336252b8d505577fb9e3d21302a3a65bc8e7d04c562fb1';
const master = 'Synthetic-Move-Fixture#2026';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const timeout = 25000;
const button = (device, name) => device.view.getByRole('button', { name, exact: true });
const field = (device, name) => device.view.getByLabel(name, { exact: true });
const rootFor = folder => `/dav/Koofr/${folder}/`;
const record = /\/versions\/v_[a-f0-9]{32}\.txt$/;
const pack = /\/packages\/p_[a-f0-9]{32}\.json$/;
const final = key => pack.test(key) || record.test(key) || key?.endsWith('/pack-root.txt');
const packFiles = (dav, root) => [...dav.objects.keys()].filter(key => key.startsWith(root) && pack.test(key));
const versions = (dav, root) => [...dav.objects.keys()].filter(key => key.startsWith(root) && record.test(key));

async function loopbackTls(directory) {
  const keyPath = path.join(directory, 'listener-key.pem'), certPath = path.join(directory, 'listener-cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=vault-loopback.test', '-keyout', keyPath, '-out', certPath], { stdio: 'pipe', windowsHide: true });
  const key = await fs.readFile(keyPath), cert = await fs.readFile(certPath);
  const spki = new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' });
  const pin = createHash('sha256').update(spki).digest('base64');
  return { tls: { key, cert }, pin };
}

async function replaceFixtureInstall(directory, source, expected) {
  // A stable installation path preserves the unpacked extension ID. Only replace
  // the copy belonging to this test, including its obsolete chunk filenames.
  const install = path.join(directory, 'extension');
  assert.equal(path.dirname(await fs.realpath(install)), await fs.realpath(directory));
  await fs.rm(install, { recursive: true });
  await fs.cp(source, install, { recursive: true, errorOnExist: true, force: false });
  assert.equal(await extensionBuildHash(install), expected);
}

async function connect(device, dav, folder) {
  await field(device, '服务商').selectOption('koofr');
  await field(device, '同步目录名').fill(folder);
  await field(device, '网盘账号').fill(dav.config.username);
  await field(device, '应用专用密码').fill(dav.config.password);
  await button(device, '测试连接').click();
}

async function create(device, dav, folder) {
  await connect(device, dav, folder);
  await field(device, '新主密码').fill(master);
  await field(device, '再次输入主密码').fill(master);
  await button(device, '验证写入并在网盘建库').click();
}

async function resume(device, dav, folder) {
  await connect(device, dav, folder);
  await expect(device.view.getByText('上次创建这个网盘库时中断了。', { exact: true })).toBeVisible({ timeout });
  await field(device, '当前主密码').fill(master);
  await button(device, '继续创建网盘库').click();
}

async function join(device, dav, folder) {
  await connect(device, dav, folder);
  await field(device, '验证已有网盘库').selectOption('master');
  await field(device, '网盘库主密码').fill(master);
  await button(device, '恢复到本机').click();
  // Even an empty set of website rules can be offered for explicit review.
  await expect.poll(() => device.send({ type: 'status' }).then(status => status.unlocked), { timeout }).toBe(true);
  if ((await device.send({ type: 'webdav-status' })).siteRulesPending) {
    await button(device, '跳过网站规则').click();
  }
  await expect(button(device, '新建')).toBeVisible({ timeout });
  return device.send({ type: 'status' });
}

function assertRefused(dav, root) {
  assert.equal(versions(dav, root).length, 0);
  assert(!dav.objects.has(root + 'pack-root.txt'));
  assert(!dav.transfers.some(row => row.path === root + 'pack-root.txt' && row.method === 'PUT' ||
    row.destination === root + 'pack-root.txt'));
}

async function oldFailure(device, dav, folder, first) {
  if (first) await create(device, dav, folder);
  else await resume(device, dav, folder);
  const message = device.view.getByRole('alert');
  await expect(message).toContainText('网盘允许重复创建已有测试文件', { timeout });
  const root = rootFor(folder);
  assertRefused(dav, root);
  assert(dav.folders.has(root + 'versions/'));
  assert(![...dav.objects.keys()].some(key => key.startsWith(root + 'versions/')), 'The directory shown by the user is empty');
  const candidates = packFiles(dav, root);
  assert.equal(candidates.length, 1);
  const entry = dav.objects.get(candidates[0]);
  assert.doesNotThrow(() => JSON.parse(entry.bytes.toString('utf8')));
  assert.equal((await device.send({ type: 'status' })).configured, false);
  const successful = dav.transfers.filter(row => row.path.startsWith(root) && row.method === 'PUT' &&
    row.ifNoneMatch === '*' && row.status === 201);
  const changed = successful.find((row, i) => successful.slice(0, i).some(other => other.path === row.path));
  assert(changed, 'The fixture actually accepted the second conditional PUT to the same name');
  return { name: candidates[0], sha256: sha(entry.bytes), bytes: entry.bytes.length, message: await message.innerText() };
}

function assertMove(dav, since, destination) {
  const rows = dav.transfers.slice(since);
  assert(rows.some(row => row.method === 'MOVE' && row.destination === destination && row.overwrite === 'F' &&
    row.status === 201), `Expected a successful MOVE Overwrite:F to ${destination}`);
  assert(!rows.some(row => row.method === 'PUT' && row.path === destination), `Unsafe PUT to ${destination}`);
}

async function writeAfterRestart(device, dav, root, title) {
  const beforePacks = packFiles(dav, root);
  const beforeRecords = versions(dav, root);
  assert((await device.send({ type: 'webdav-status' })).writeVerified);
  const since = dav.transfers.length;
  await device.send({ type: 'upsert', itemJson: JSON.stringify({ id: '', title,
    data: { kind: 'login', username: title, password: 'Synthetic-Regressed-Passphrase#', uris: [] } }) });
  const saved = (await device.send({ type: 'list' })).find(item => item.title === title);
  assert(saved?.id);
  await device.send({ type: 'webdav-sync' });
  await expect.poll(() => versions(dav, root).length, { timeout }).toBe(beforeRecords.length + 1);
  const newRecord = versions(dav, root).filter(name => !beforeRecords.includes(name));
  const newPacks = packFiles(dav, root).filter(name => !beforePacks.includes(name));
  assert.equal(newRecord.length, 1);
  assert.equal(newPacks.length, 1);
  assertMove(dav, since, newRecord[0]);
  assertMove(dav, since, newPacks[0]);
  assert(!dav.transfers.slice(since).some(row => row.method === 'PUT' && final(row.path)));
  return saved.id;
}

async function run() {
  assert.equal(await extensionBuildHash(baseline), oldHash, 'Use the official v0.2.0 release for the upgrade');
  const baselineOnly = process.argv.includes('--baseline-only');
  const build = baselineOnly ? oldHash : await extensionBuildHash(candidate);
  const resources = { contexts: new Set(), profiles: new Set() };
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-move-webdav-'));
  const install = path.join(temp, 'extension');
  const { tls, pin } = await loopbackTls(temp);
  const dav = await webdavFixture({ koofrTls: tls });
  dav.state.ignorePutAbsent = true;
  dav.state.move = 'enforce';
  const args = ['--no-proxy-server', '--disable-quic', `--ignore-certificate-errors-spki-list=${pin}`,
    `--host-resolver-rules=MAP app.koofr.net 127.0.0.1:${dav.port}, MAP * ~NOTFOUND, EXCLUDE localhost`];
  const start = (name, profile) => openBrowser(name, resources, profile, { install, args });
  const report = { oldBuild: oldHash, build, loopback: true, cases: {} };
  const folder = 'vault', root = rootFor(folder);
  try {
    await fs.cp(baseline, install, { recursive: true, errorOnExist: true, force: false });
    let edge = await start('edge');
    const profile = edge.profile;
    report.edge = edge.version;
    const staged = await oldFailure(edge, dav, folder, true);
    report.cases.oldRelease = { stagedBytes: staged.bytes, stagedWireSha256: staged.sha256,
      versions: 0, rootPublished: false, message: staged.message };
    console.log(JSON.stringify({ oldRelease: report.cases.oldRelease }));
    await edge.close();
    if (!baselineOnly) await replaceFixtureInstall(temp, candidate, build);
    edge = await start('edge', profile);
    if (baselineOnly) {
      const again = await oldFailure(edge, dav, folder, false);
      assert.deepEqual(again, staged);
      report.cases.oldResumeStillBlocked = true;
    } else {
      const resuming = dav.transfers.length;
      await resume(edge, dav, folder);
      const kit = edge.view.getByRole('heading', { name: '保存应急恢复包', exact: true });
      const failure = edge.view.getByRole('alert');
      await expect(kit.or(failure).first()).toBeVisible({ timeout });
      if (await failure.isVisible()) throw new Error(`Resuming failed: ${await failure.innerText()}`);
      const state = await edge.send({ type: 'status' });
      assert(state.configured && state.unlocked && state.vaultId);
      assert((await edge.send({ type: 'webdav-status' })).writeVerified);
      assert.deepEqual(packFiles(dav, root), [staged.name]);
      assert.equal(sha(dav.objects.get(staged.name).bytes), staged.sha256);
      assert.equal(versions(dav, root).length, 0, 'Genesis is recorded in pack-root, children in versions/');
      const [[, rootId, vaultId]] = JSON.parse(dav.objects.get(root + 'pack-root.txt').bytes.toString('utf8'));
      assert.equal(staged.name, root + `packages/p_${rootId}.json`);
      assert.equal(state.vaultId, vaultId);
      assertMove(dav, resuming, root + 'pack-root.txt');
      report.cases.resumedOriginalPackage = true;
      report.cases.genesisCommittedByMove = true;
      await edge.send({ type: 'lock' });
      await edge.close();
      edge = await start('edge', profile);
      await edge.send({ type: 'unlock', password: master });
      const itemId = await writeAfterRestart(edge, dav, root, 'Edge MOVE fixture');
      report.cases.reopenedWriterUsedMoveForPackageAndVersion = true;
      let helium = await start('helium');
      const peerProfile = helium.profile;
      report.helium = helium.version;
      const joining = dav.transfers.length;
      assert.equal((await join(helium, dav, folder)).vaultId, vaultId);
      assert.equal((await helium.send({ type: 'get', id: itemId })).data.password, 'Synthetic-Regressed-Passphrase#');
      assert(dav.transfers.slice(joining).every(row => ['GET', 'PROPFIND'].includes(row.method)));
      report.cases.otherBrowserJoinedReadOnly = true;
      await enableFromUi(helium, master);
      await helium.send({ type: 'lock' });
      await helium.close();
      helium = await start('helium', peerProfile);
      await helium.send({ type: 'unlock', password: master });
      const peerItem = await writeAfterRestart(helium, dav, root, 'Helium MOVE fixture');
      await edge.send({ type: 'webdav-sync' });
      assert.equal((await edge.send({ type: 'get', id: peerItem })).data.password, 'Synthetic-Regressed-Passphrase#');
      report.cases.verifiedExistingVaultUsesMoveAfterRestart = true;
      await helium.close();
      await edge.close();

      const unsafe = await start('helium');
      dav.state.move = 'ignore';
      const other = 'unsafe';
      await create(unsafe, dav, other);
      await expect(unsafe.view.getByRole('alert')).toBeVisible({ timeout });
      assertRefused(dav, rootFor(other));
      assert.equal((await unsafe.send({ type: 'status' })).configured, false);
      assert(dav.transfers.some(row => row.path.startsWith(rootFor(other)) && row.method === 'MOVE' &&
        row.overwrite === 'F' && row.destinationExisted && row.status === 201), 'The server overwrote a destination and falsely reported creation');
      report.cases.unsafeServerRefused = true;
      await unsafe.close();

      await replaceFixtureInstall(temp, baseline, oldHash);
      const loadingOld = dav.transfers.length;
      const older = await start('edge', profile);
      await older.send({ type: 'unlock', password: master });
      assert.equal((await older.send({ type: 'webdav-status' })).writeVerified, false);
      await older.send({ type: 'upsert', itemJson: JSON.stringify({ id: '', title: 'Offline edit in the older client',
        data: { kind: 'login', username: 'older', password: 'Synthetic-Older#', uris: [] } }) });
      await older.send({ type: 'webdav-sync' });
      assert(dav.transfers.slice(loadingOld).every(row => ['GET', 'PROPFIND'].includes(row.method)));
      report.cases.officialOldClientKeepsMoveOnlyConnectionReadOnly = true;
    }
    report.status = 'passed';
  } catch (error) {
    report.status = 'failed';
    report.error = String(error.message);
    throw error;
  } finally {
    const output = path.resolve(process.env.VAULT_MOVE_REPORT || path.join('test-results',
      `pack-move-${baselineOnly ? 'baseline-' : ''}${build.slice(0, 12)}.json`));
    try {
      await fs.mkdir(path.dirname(output), { recursive: true });
      await fs.writeFile(output, JSON.stringify(report, null, 2) + '\n', 'utf8');
      console.log(JSON.stringify(report), '\nReport:', output);
    } finally {
      try { await Promise.all([...resources.contexts].map(context => context.close())); }
      finally {
        await dav.close();
        for (const profile of resources.profiles) {
          assert.equal(path.dirname(profile), path.resolve(os.tmpdir()));
          assert(path.basename(profile).startsWith('vault-pack-sync-'));
          await fs.rm(profile, { recursive: true, maxRetries: 4, retryDelay: 200 });
        }
        assert.equal(path.dirname(temp), path.resolve(os.tmpdir()));
        assert(path.basename(temp).startsWith('vault-move-webdav-'));
        await fs.rm(temp, { recursive: true, maxRetries: 4, retryDelay: 200 });
      }
    }
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
