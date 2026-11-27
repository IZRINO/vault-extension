const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

const proof = secret => ({ method: 'master', secret });
const filePassword = 'Synthetic-Pack-Migration-File#52';
const sync = device => device.send({ type: 'webdav-sync' });
const list = device => device.send({ type: 'list' });
const conflicts = device => device.send({ type: 'webdav-conflicts' });
async function login(device, title, account, password, id = '') {
  const item = id ? await device.send({ type: 'get-edit', id }) :
    { id: '', data: { kind: 'login', uris: [{ uri: 'https://pack-merge.example.test' }] } };
  item.title = title;
  Object.assign(item.data, { username: account, password });
  return device.send({ type: 'upsert', itemJson: JSON.stringify(item) });
}

async function saveBackup(device, masterPassword) {
  const { bytes, receipt } = await device.send({ type: 'export', password: filePassword, proof: proof(masterPassword) });
  const file = path.join(device.profile, 'merge-fixture.vaultpack');
  await fs.writeFile(file, Uint8Array.from(bytes), { flag: 'wx' });
  await device.send({ type: 'backup-saved', receipt });
  return Array.from(await fs.readFile(file));
}

// Use separate keys for the source of an explicit import and for the linked devices.
async function verifyPackMergeRecovery({ edge, helium, openSource, config, master }) {
  const device = await helium.send({ type: 'webdav-devices' });
  const name = 'Helium merge fixture';
  await helium.send({ type: 'webdav-device-change', action: device.registered ? 'rename' : 'register',
    id: device.active, name, proof: proof(master) });
  await sync(helium);
  await sync(edge);
  await login(edge, 'Field in dispute', 'shared-id', 'Original#52');
  await login(edge, 'Target copy', 'same-account', 'Target-only#52');
  await sync(edge);
  await sync(helium);
  const { id } = (await list(edge)).find(item => item.title === 'Field in dispute');
  await login(edge, 'Field in dispute', 'shared-id', 'Edge-choice#52', id);
  await login(helium, 'Field in dispute', 'shared-id', 'Helium-choice#52', id);
  await sync(edge);
  await sync(helium);
  await sync(edge);
  const existing = (await conflicts(edge)).rows;
  assert.equal(existing.length, 1);
  assert.deepEqual([existing[0].ours.source, existing[0].theirs.source].sort(), ['Edge fixture', name].sort());

  const source = await openSource();
  const sourceMaster = 'Synthetic-Unlinked-Master#52';
  await source.send({ type: 'create', masterPassword: sourceMaster, calibrate: false });
  await login(source, 'Source copy', 'same-account', 'Source-only#52');
  await login(source, 'Imported unrelated entry', 'other-account', 'Unrelated#52');
  await saveBackup(source, sourceMaster);
  const merge = { type: 'webdav-merge', input: config, method: 'master', secret: master, proof: proof(sourceMaster) };
  const preview = await source.send(merge);
  assert.equal(preview.conflicts, 2, 'Import preview must preserve the existing conflict alongside the duplicate');
  await source.send({ ...merge, stamp: preview.stamp });
  const rules = await source.send({ type: 'webdav-site-rules' });
  await source.send({ type: 'webdav-site-rules-choice', use: false, stamp: rules.stamp });
  await source.send({ type: 'webdav-enable-write', masterPassword: master });
  assert.equal((await sync(source)).kind, 'conflicts');
  await sync(edge);
  const restoredId = (await list(edge)).find(item => item.title === 'Imported unrelated entry').id;
  const review = await conflicts(edge);
  assert.equal(review.rows.length, 2);
  assert(review.rows.some(row => row.id === id));
  assert(review.rows.some(row => row.fields.includes('$duplicate')));
  const choices = review.rows.map(row => ({ id: row.id, mode: row.fields.includes('$duplicate') ? 'both' : 'ours' }));
  await edge.send({ type: 'webdav-resolve', stamp: review.stamp, rules: choices, proof: proof(master) });
  await sync(edge);
  await sync(helium);
  assert.equal((await conflicts(helium)).rows.length, 0);
  const resolved = (await helium.send({ type: 'get', id })).data;
  const displaced = resolved.password === 'Edge-choice#52' ? ['Helium-choice#52', name] : ['Edge-choice#52', 'Edge fixture'];
  assert(resolved.passwordHistory.some(entry => entry.password === displaced[0] && entry.sourceDevice === displaced[1]));
  const passwords = [];
  for (const row of await list(helium)) {
    if (/^(Source|Target) copy/.test(row.title))
      passwords.push((await helium.send({ type: 'get', id: row.id })).data.password);
  }
  assert.deepEqual(passwords.sort(), ['Source-only#52', 'Target-only#52']);
  await source.close();

  const bytes = await saveBackup(edge, master);
  await edge.send({ type: 'trash', id: restoredId, trashed: true });
  await edge.send({ type: 'delete', id: restoredId });
  await sync(edge);
  await sync(helium);
  assert(!(await list(helium)).some(item => item.id === restoredId));
  const input = { bytes, password: filePassword, proof: proof(master) };
  const restore = await edge.send({ type: 'preview-vaultpack', ...input });
  assert.equal(restore.added, 1);
  await edge.send({ type: 'import', ...input, stamp: restore.stamp });
  assert.equal((await sync(edge)).pending, false);
  await sync(helium);
  assert.equal((await helium.send({ type: 'get', id: restoredId })).data.password, 'Unrelated#52');
  return { preservedPriorConflict: true, duplicateResolvedOnPeer: true, conflictDeviceNames: true, deletedIdRestoredOnPeer: true };
}

module.exports = { verifyPackMergeRecovery };
