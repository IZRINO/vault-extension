const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash, createHmac, generateKeyPairSync, verify } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
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

async function makeKeepassxcFixture(cli, origin = 'https://example.com') {
  await fs.access(cli);
  const filePassword = 'Synthetic-KeePassXC-Test#2026';
  const loginPassword = 'Synthetic login <&>';
  const oldPassword = 'Synthetic old password';
  const otpSeed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const { hostname: host } = new URL(origin);
  // This is valid base64url data, not a UUID despite the spelling.
  const userHandle = '9004055c-1fe5-4ab1-87d3-474b666bf10d';
  const examples = [
    { title: 'Wrapped PEM', idByte: 13, algorithm: 'sha256' },
    { title: 'Single-line PEM', idByte: 17, algorithm: 'sha256', singleLine: true },
    { title: 'StrongBox fields', idByte: 19, algorithm: null, alias: true },
  ].map(example => {
    const { privateKey, publicKey } = example.algorithm ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' }) : generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    return { ...example, publicKey, id: Buffer.alloc(32, example.idByte).toString('base64url'), pem: example.singleLine ? pem.replace(/\r?\n/g, '') : pem };
  });
  const escape = text => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const field = (name, value, protectedValue = false) =>
    `<String><Key>${name}</Key><Value${protectedValue ? ' ProtectInMemory="True"' : ''}>${escape(value)}</Value></String>`;
  const date = '<Times><LastModificationTime>2025-01-02T03:04:05Z</LastModificationTime></Times>';
  const entries = examples.map(({ title, id, pem, alias }, i) => {
    const uuid = Buffer.alloc(16, 1 + i).toString('base64');
    return `<Entry><UUID>${uuid}</UUID>${field('Title', title)}${field('UserName', 'fixture user')}
      ${field('Password', loginPassword, true)}${field('URL', origin)}${field('Notes', 'Synthetic migration note')}
      ${field('otp', `otpauth://totp/Example:fixture?secret=${otpSeed}&issuer=Example`, true)}
      ${field('KPEX_PASSKEY_USERNAME', 'fixture user')}${field('KPEX_PASSKEY_CREDENTIAL_ID', alias ? examples[0].id : id, true)}
      ${alias ? field('KPEX_PASSKEY_GENERATED_USER_ID', id, true) + field('KPXC_PASSKEY_USERNAME', 'StrongBox user') : ''}
      ${field('KPEX_PASSKEY_PRIVATE_KEY_PEM', pem, true)}${field('KPEX_PASSKEY_RELYING_PARTY', host)}
      ${field('KPEX_PASSKEY_USER_HANDLE', userHandle, true)}${field('KPEX_PASSKEY_FLAG_BE', alias ? '' : '1')}${field('KPEX_PASSKEY_FLAG_BS', '1')}
      <History><Entry><UUID>${uuid}</UUID>${date}${field('Password', oldPassword, true)}</Entry></History></Entry>`;
  }).join('\n');
  const temp = path.resolve(os.tmpdir());
  const prefix = 'vault-keepassxc-fixture-';
  const folder = await fs.mkdtemp(path.join(temp, prefix));
  try {
    const xml = path.join(folder, 'synthetic.xml'), database = path.join(folder, 'synthetic.kdbx');
    // A group tag requires KDBX 4.1 in the native writer.
    await fs.writeFile(xml, `<?xml version="1.0" encoding="UTF-8"?>
      <KeePassFile><Meta><DatabaseName>Vault format fixture</DatabaseName></Meta>
      <Root><Group><UUID>AgMEBQYHCAkKCwwNDg8QEQ==</UUID><Name>Native Group</Name><Tags>format-fixture</Tags>
      ${entries}</Group></Root></KeePassFile>`, { encoding: 'utf8', flag: 'wx' });
    const native = spawnSync(path.resolve(cli), ['import', '--set-password', xml, database], {
      input: `${filePassword}\n${filePassword}\n`, encoding: 'utf8', windowsHide: true, timeout: 30000,
    });
    if (native.error) throw native.error;
    assert.equal(native.status, 0, `KeePassXC CLI failed to write the fixture: ${native.stderr}`);
    const bytes = await fs.readFile(database);
    assert.equal(bytes.readUInt32LE(8), 0x00040001, 'The KeePassXC CLI must write KDBX 4.1');
    assert(!bytes.includes(Buffer.from(loginPassword)) && !bytes.includes(Buffer.from('BEGIN PRIVATE KEY')));
    return { bytes, filePassword, loginPassword, oldPassword, otpSeed, host, origin, userHandle,
      examples: examples.map(({ title, id, algorithm, publicKey, alias }) => ({ title, id, algorithm, publicKey, alias })) };
  } finally {
    assert(path.dirname(folder) === temp && path.basename(folder).startsWith(prefix));
    await fs.rm(folder, { recursive: true, maxRetries: 2, retryDelay: 100 });
  }
}

async function verifyKeepassxc(cli) {
  const [core, migration, otp, passkeys] = await Promise.all(['vault-core', 'vault-importers', 'vault-otp', 'vault-passkeys'].map(wasm));
  const { bytes, filePassword, loginPassword, oldPassword, otpSeed, host, origin, userHandle, examples } = await makeKeepassxcFixture(cli);
  const key = crypto.getRandomValues(new Uint8Array(32));
  let target, wrap, committed, engine;
  try {
    target = core.wasm_create_new_vault('Synthetic target', 32768, 2, 1, key, 1000);
    wrap = target.session_wrap_bytes;
    const read = (input, password, write, base = target) => migration.wasm_portable_import('keepass', key, wrap,
      base.head_bytes ?? base.head, base.snap_bytes ?? base.snap, input, password, 2000, write);
    const preview = read(bytes, filePassword, false);
    try {
      const report = JSON.parse(preview.report);
      assert.equal(report.ready, examples.length);
      assert.equal(report.passkeys, examples.length, 'Each original KeePassXC PEM form must produce a usable Passkey');
      assert.equal(report.ignoredPasskeys, 0);
      assert.equal(preview.snap.length, 0);
      assert(!preview.report.includes(otpSeed) && !preview.report.includes(loginPassword));
    } finally { preview.free(); }
    assert.throws(() => read(bytes, 'wrong fixture password', true));
    assert.throws(() => read(bytes.subarray(0, bytes.length - 32), filePassword, true));
    committed = read(bytes, filePassword, true);
    assert.equal(committed.count, examples.length);
    const duplicate = read(bytes, filePassword, true, committed);
    try { assert.equal(duplicate.count, 0); assert.equal(duplicate.snap.length, 0); }
    finally { duplicate.free(); }
    engine = new core.WasmVaultEngine();
    engine.restore_from_session(key, wrap, committed.head, committed.snap);
    const rows = JSON.parse(engine.list_summaries_json()).map(row => JSON.parse(engine.get_item_json(row.id, true)));
    assert.equal(rows.length, examples.length);
    const moving = Buffer.alloc(8);
    moving.writeBigUInt64BE(1n);
    const digest = createHmac('sha1', '12345678901234567890').update(moving).digest();
    const expectedOtp = ((digest.readUInt32BE(digest.at(-1) & 15) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
    for (const example of examples) {
      const row = rows.find(row => row.title === example.title);
      assert(row);
      assert.equal(row.data.username, 'fixture user');
      assert.equal(row.data.password, loginPassword);
      assert(row.data.uris.some(uri => uri.uri === origin));
      assert.equal(row.note, 'Synthetic migration note');
      assert(row.tags.includes('Native Group'));
      assert(row.data.passwordHistory.some(old => old.password === oldPassword));
      assert.equal(JSON.parse(otp.wasm_otp_at(row.data.totpUri, 59, 0)).value, expectedOtp);
      assert(!row.customFields.some(field => field.name.startsWith('KPEX_PASSKEY_') || field.name === 'KPXC_PASSKEY_USERNAME'));
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const challengeText = Buffer.from(challenge).toString('base64url');
      const request = JSON.stringify({ kind: 'assert', origin, rpId: host, challenge: challengeText, credentialIds: [], uv: 'required' });
      const choices = JSON.parse(passkeys.wasm_passkey_candidates(key, wrap, committed.head, committed.snap, request));
      const choice = choices.find(choice => choice.id === example.id && choice.itemId === row.id);
      assert(choice && !choice.suspended, 'The KeePassXC credential must be available for a real assertion');
      assert.equal(choice.account, example.alias ? 'StrongBox user' : 'fixture user');
      const signed = passkeys.wasm_passkey_perform(key, wrap, committed.head, committed.snap, request, JSON.stringify({
        itemId: choice.itemId, credentialId: choice.id, verified: true, increment: false, now: 3000,
      }), new Uint8Array(), new Uint8Array());
      try {
        const reply = JSON.parse(signed.reply);
        const data = Buffer.from(reply.authenticatorData, 'base64url'), client = Buffer.from(reply.clientDataJson, 'base64url');
        assert.equal(reply.id, example.id);
        assert.equal(reply.userHandle, userHandle);
        assert.deepEqual(JSON.parse(client), { challenge: challengeText, crossOrigin: false, origin, type: 'webauthn.get' });
        assert.deepEqual(data.subarray(0, 32), createHash('sha256').update(host).digest());
        assert.equal(data[32], example.alias ? 0x05 : 0x0d, 'Preserve BE; the source BS flag is not target backup evidence');
        assert.equal(data.readUInt32BE(33), 0);
        assert(verify(example.algorithm, Buffer.concat([data, createHash('sha256').update(client).digest()]), example.publicKey,
          Buffer.from(reply.signature, 'base64url')));
      } finally { signed.free(); }
    }
    console.log(JSON.stringify({ generator: 'KeePassXC CLI', version: '4.1', signed: examples.length, history: true,
      otp: true, wrongAndTruncatedRejected: true, previewAndDuplicateNoWrite: true, sourceBackupFlagNotTrusted: true }));
  } finally {
    engine?.free();
    committed?.free();
    target?.free();
    key.fill(0);
    wrap?.fill(0);
  }
}

async function run() {
  if (process.argv[2] === '--keepassxc-cli') {
    assert(process.argv.length === 4, 'Usage: node scripts/test-kdbx.cjs --keepassxc-cli <path>');
    return verifyKeepassxc(process.argv[3]);
  }
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

module.exports = { makeKeepassxcFixture };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
