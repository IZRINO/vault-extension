const assert = require('node:assert/strict');
const { createHash, randomBytes } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

async function load(dir, name) {
  const module = await import(pathToFileURL(path.resolve(dir, `${name}.js`)).href);
  const bytes = await fs.readFile(path.resolve(dir, `${name}_bg.wasm`));
  await module.default({ module_or_path: bytes });
  return { module, fingerprint: createHash('sha256').update(bytes).digest('hex') };
}

async function run() {
  const [oldPackage] = process.argv.slice(2);
  assert(oldPackage && process.argv.length === 3, 'Usage: node scripts/test-legacy-vaultpack.cjs <historical vault-core pkg directory>');
  const crates = path.resolve(__dirname, '../crates');
  const [old, current, sync] = await Promise.all([
    load(oldPackage, 'vault_core'),
    load(path.join(crates, 'vault-core/pkg'), 'vault_core'),
    load(path.join(crates, 'vault-sync/pkg'), 'vault_sync'),
  ]);
  assert.notEqual(old.fingerprint, current.fingerprint, 'The source must be a historical WASM build');
  const now = 1700000000000;
  const sourceKey = randomBytes(32), targetKey = randomBytes(32);
  const source = old.module.wasm_create_new_vault('Synthetic-Historical-Master#23', 32768, 2, 4, sourceKey, now);
  const target = current.module.wasm_create_new_vault('Synthetic-Current-Master#23', 32768, 2, 4, targetKey, now);
  const writer = new old.module.WasmVaultEngine(), reader = new current.module.WasmVaultEngine();
  const backupPassword = 'Synthetic-Historical-File#23';
  try {
    writer.restore_from_session(sourceKey, source.session_wrap_bytes, source.head_bytes, source.snap_bytes);
    const item = {
      id: '', title: 'From the phase 2 backup writer', note: 'Synthetic independent backup',
      data: { kind: 'login', username: 'historical-fixture', password: 'Synthetic-Fixture-Only-Password' },
      tags: ['phase-2'], pinned: true, requireReprompt: true, trashed: false, customFields: [],
    };
    const mutation = writer.upsert_item_json(JSON.stringify(item), now + 1, undefined);
    let backup;
    try {
      backup = old.module.wasm_export_vaultpack(sourceKey, source.session_wrap_bytes, mutation.head_bytes, mutation.snap_bytes, backupPassword, now + 2);
    } finally { mutation.free(); }
    assert.notEqual(source.vault_id, target.vault_id);
    const merge = (confirm, secret = backupPassword) => sync.module.wasm_sync_import_pack(
      targetKey, target.session_wrap_bytes, target.head_bytes, target.snap_bytes, backup, secret, now + 3, confirm);
    assert.throws(() => merge(false, 'Invalid fixture password'));
    const preview = merge(false);
    try {
      assert.equal(preview.added, 1);
      assert.equal(preview.head.length + preview.snap.length, 0, 'Preview must not produce changed ciphertext');
    } finally { preview.free(); }
    const imported = merge(true);
    try {
      assert.equal(imported.added, 1);
      const wrap = current.module.wasm_unlock_head_with_password(imported.head, 'Synthetic-Current-Master#23', targetKey);
      reader.restore_from_session(targetKey, wrap, imported.head, imported.snap);
      wrap.fill(0);
      const [row] = JSON.parse(reader.list_summaries_json());
      assert.equal(row.requireReprompt, true);
      assert.throws(() => reader.get_item_json(row.id, false));
      const restored = JSON.parse(reader.get_item_json(row.id, true));
      assert.equal(restored.title, item.title);
      assert.equal(restored.note, item.note);
      assert.equal(restored.pinned, true);
      assert.deepEqual(restored.tags, item.tags);
      assert.equal(restored.data.username, item.data.username);
      assert.equal(restored.data.password, item.data.password);
    } finally { imported.free(); backup.fill(0); }
    console.log(JSON.stringify({ historicalWasm: old.fingerprint, syncWasm: sync.fingerprint, previewReadOnly: true,
      wrongFilePasswordRejected: true, retainedTargetMasterAndProtectedItem: true }));
  } finally {
    writer.lock_and_zeroize();
    reader.lock_and_zeroize();
    writer.free();
    reader.free();
    source.free();
    target.free();
    sourceKey.fill(0);
    targetKey.fill(0);
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
