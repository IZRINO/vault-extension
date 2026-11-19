const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

// Public synthetic KeePass fixtures (not vendored).
const upstream = '26cb076aa5cbbe36e175326dfdaf5a19799c4085';
const fixtures = [
  ['test_db_with_password.kdbx', '0909889e838988f57bea9ed33ecf244c1fb40c6efb2ba2224592659c749b884a', '3.1', 6],
  ['test_db_kdbx4_with_password_argon2id.kdbx', '1b40d7ac45bcba6051cd7380b2eace7de5e55be400b84e76123f6d36bc69fdb8', '4.0', 2],
];
// The higher-cost Stratum samples are intentionally outside the WASM import budget.
const highCost = [
  ['keepass.kdbx3.kdbx', 'd7d193282e7d84f48cf4f535f4567f315d624492e1fbcd2a4a13c447cb0a3aaf'],
  ['keepass.aes256.argon2id.kdbx', 'fb0922654e99e326bcf9d817737432df990e76cbed8e9f564525808471a56109'],
];

async function wasm(crate) {
  const name = crate.replaceAll('-', '_');
  const mod = await import(`../crates/${crate}/pkg/${name}.js`);
  await mod.default({ module_or_path: await fs.readFile(path.join(__dirname, '..', 'crates', crate, 'pkg', `${name}_bg.wasm`)) });
  return mod;
}

async function run() {
  const dir = process.argv[2];
  assert(dir, 'Usage: node scripts/test-kdbx.cjs <folder with fixtures from https://github.com/sseemayer/keepass-rs/tree/' + upstream + '/tests/resources and Stratum.Test/data>');
  const [core, migration, otp] = await Promise.all(['vault-core', 'vault-importers', 'vault-otp'].map(wasm));
  const key = crypto.getRandomValues(new Uint8Array(32));
  const created = core.wasm_create_new_vault('Synthetic-KeePass-Target#2026', 32768, 2, 1, key, 1000);
  const wrap = created.session_wrap_bytes;
  async function checked(name, digest) {
    const input = await fs.readFile(path.join(dir, name));
    assert.equal(createHash('sha256').update(input).digest('hex'), digest);
    return input;
  }
  const restore = (input, inputPassword, commit) => migration.wasm_portable_import('keepass', key, wrap,
    created.head_bytes, created.snap_bytes, input, inputPassword, 5000, commit);
  for (const [name, digest] of highCost) {
    const bytes = await checked(name, digest);
    assert.throws(() => restore(bytes, 'test', true), /派生成本/);
  }
  for (const [name, digest, version, count] of fixtures) {
    const bytes = await checked(name, digest);
    const preview = restore(bytes, 'demopass', false);
    const report = JSON.parse(preview.report);
    assert.equal(preview.snap.length, 0);
    assert.equal(report.ready, count);
    preview.free();
    assert.throws(() => restore(bytes, 'incorrect', true));
    assert.throws(() => restore(bytes.subarray(0, bytes.length - 32), 'demopass', true));
    const recovered = restore(bytes, 'demopass', true);
    const engine = new core.WasmVaultEngine();
    try {
      engine.restore_from_session(key, wrap, recovered.head, recovered.snap);
      const summaries = JSON.parse(engine.list_summaries_json());
      const entries = summaries.map(({ id }) => JSON.parse(engine.get_item_json(id, true)));
      const tokens = entries.map(({ data }) => data.totpUri).filter(Boolean);
      for (const uri of tokens) assert.match(JSON.parse(otp.wasm_otp_at(uri, 59, 0)).value, /^[0-9]{6,10}$/);
      assert.equal(entries.length, recovered.count);
      assert(entries.every(entry => entry.tags.length > 0));
      console.log(JSON.stringify({ version, entries: entries.length, otp: tokens.length, previewNoWrite: true,
        wrongAndTruncatedRejected: true, highKdfRejected: highCost.length }));
    } finally { engine.free(); recovered.free(); }
  }
  created.free();
  key.fill(0);
  wrap.fill(0);
}

run().catch(error => { console.error(error); process.exitCode = 1; });
