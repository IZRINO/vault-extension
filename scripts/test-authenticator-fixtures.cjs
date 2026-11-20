const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createDecipheriv, createHash, createHmac, pbkdf2Sync } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

// Public Aegis test vectors, pinned in docs/agents/authenticator-backup-fixtures.md.
const twofas = [
  ['2fas_authenticator_plain.2fas', '3970a71357f6e1720f741c846e9a2dacb5a86706b98cd9d14db3c0e7fb3ec655', 4],
  ['2fas_authenticator_encrypted.2fas', '19ff92e83889356854f253a431ab0fb8dee719599608a1663a4ab4e40a39e895', 4],
  ['2fas_authenticator_plain_v3.2fas', 'fc25168e05ea9382648b0541d3971296a96356de13889065bbe0dc5828adfffa', 6],
  ['2fas_authenticator_encrypted_v3.2fas', '7328d9b5790a2826fb84985907ebbbdc1e0cb0e05ea4cd6cd26ab7c153012299', 6],
  ['2fas_authenticator_plain_v4.2fas', 'b137b30d6d6c76e83ffeebcf8c1ca3a673e3f2826699d1054cbd5fadc1ec4274', 5],
  ['2fas_authenticator_encrypted_v4.2fas', '0e769224ea2778f9b2d6467d9185efdcba2e4914541c3d3f36b687018bf789c9', 5],
];
const others = [
  ['aegis', 'aegis_plain.json', 'ff7645d711dd05aa1724975b0aa6f2b82b1911d709330f479c87dd755d7ffe5c', 0],
  ['aegis', 'aegis_encrypted.json', 'bf10ba479062b280753eb47f35c898cc286f8c921118f6d4e68c6af67d055d99', 0],
  ['aegis', 'aegis_plain_grouped_v2.json', 'e307d8a80e631f09c352a9eeb2efbec6a6929ab96675f3ab95edb796abfde1a4', 3],
  ['andotp', 'andotp_plain.json', '1c20c8223fe0aa2a27e051e6ad91afd32e2fcaa745b4711105ff0230da13b7a7', 0],
  ['stratum', 'stratum_plain.json', 'a04a06323b02b9a95e8b9fa76f8e7113b84d04f965a48d6d367a2339d2329989', 0],
];
const now = 1700000009;
const samplePassword = 'test';
const enteFixtures = new Map([
  ['legacy', '2311f1891dccd69b2cdd2585c4ba2638a77cc3d391442423a6b62ab2292892bf'],
  ['standard', '13e5c98c33e0ac4e95f6f36668c5f2c11b3cb5a8b1bab26b7cec8d3a11e6b97d'],
  ['native', '5262904087b069bae5e7dac2a01e12a16d43b96113c38fefc6221b25c4b5c041'],
]);

async function wasm(crate) {
  const module = crate.replaceAll('-', '_');
  const pkg = path.join(__dirname, '..', 'crates', crate, 'pkg');
  const api = await import(`../crates/${crate}/pkg/${module}.js`);
  await api.default({ module_or_path: await fs.readFile(path.join(pkg, `${module}_bg.wasm`)) });
  return api;
}

function decryptServices(encrypted) {
  const [ciphertext, salt, iv] = encrypted.split(':').map(value => Buffer.from(value, 'base64'));
  const key = pbkdf2Sync(samplePassword, salt, 10_000, 32, 'sha256');
  try {
    const cipher = createDecipheriv('aes-256-gcm', key, iv);
    cipher.setAuthTag(ciphertext.subarray(-16));
    return JSON.parse(Buffer.concat([cipher.update(ciphertext.subarray(0, -16)), cipher.final()]));
  } finally { key.fill(0); }
}

function independentCode(secret, algorithm, steps, digits, steam) {
  const bytes = [];
  let bits = 0, window = 0;
  for (const ch of secret.toUpperCase().replace(/[\s=]/g, '')) {
    const value = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch);
    assert(value >= 0, 'Invalid Base32 in the upstream vector');
    window = (window << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((window >>> bits) & 255);
    }
  }
  const challenge = Buffer.alloc(8);
  challenge.writeBigUInt64BE(BigInt(steps));
  const mac = createHmac(algorithm, Buffer.from(bytes)).update(challenge).digest();
  let code = mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff;
  if (!steam) return String(code % 10 ** digits).padStart(digits, '0');
  const alphabet = '23456789BCDFGHJKMNPQRTVWXY';
  return Array.from({ length: 5 }, () => {
    const ch = alphabet[code % alphabet.length];
    code = Math.floor(code / alphabet.length);
    return ch;
  }).join('');
}

async function raivoArchive() {
  const [imports, otp] = await Promise.all(['vault-importers', 'vault-otp'].map(wasm));
  const temp = path.resolve(os.tmpdir());
  const dir = await fs.mkdtemp(path.join(temp, 'vault-raivo-fixture-'));
  const filePassword = 'Raivo-Synthetic-ZIP-Only#27';
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const json = 'raivo-otp-export.json', html = 'raivo-otp-export.html', filename = 'raivo-otp-export.zip';
  const samples = [
    { issuer: 'Example', account: 'time-fixture', secret, algorithm: 'SHA512', digits: '8', kind: 'totp', timer: '45', pinned: 'true', counter: '0', iconType: '', iconValue: '' },
    { issuer: 'Example', account: 'counter-fixture', secret, algorithm: 'SHA1', digits: '6', kind: 'hotp', timer: '30', pinned: 'false', counter: '13', iconType: '', iconValue: '' },
  ];
  try {
    await fs.writeFile(path.join(dir, json), JSON.stringify(samples), 'utf8');
    await fs.writeFile(path.join(dir, html), '<!doctype html><title>Synthetic fixture</title>', 'utf8');
    const archive = ['a', '-tzip', '-mm=Copy', '-mem=AES256', '-mx=0', `-p${filePassword}`, filename, json, html];
    execFileSync(process.env.VAULT_7ZIP_PATH || '7z', archive, { cwd: dir, windowsHide: true });
    const listing = execFileSync(process.env.VAULT_7ZIP_PATH || '7z', ['l', '-slt', filename], { cwd: dir, windowsHide: true, encoding: 'utf8' });
    const files = listing.split(/\r?\n\r?\n/);
    for (const name of [json, html]) {
      const entry = files.find(file => file.split(/\r?\n/).includes(`Path = ${name}`));
      assert.match(entry ?? '', /^Method = AES-256 Store\r?$/m, `${name} must be encrypted`);
    }
    const bytes = await fs.readFile(path.join(dir, filename));
    const parse = (input, password) => JSON.parse(imports.wasm_parse_authenticator_backup('raivo', input, password));
    const result = parse(bytes, filePassword);
    assert.equal(result.rows.length, 2);
    assert.equal(result.invalid + result.unsupported, 0);
    for (const [i, row] of result.rows.entries()) {
      const source = samples[i];
      const uri = new URL(row.data.totpUri);
      assert.equal(uri.hostname, source.kind);
      assert.equal(uri.searchParams.get('digits'), source.digits);
      assert.equal(uri.searchParams.get('issuer'), source.issuer);
      assert.equal(row.data.username, source.account);
      assert.equal(row.pinned, source.pinned === 'true');
      const steps = source.kind === 'hotp' ? Number(source.counter) : Math.floor(now / Number(source.timer));
      assert.equal(uri.searchParams.get(source.kind === 'hotp' ? 'counter' : 'period'), source.kind === 'hotp' ? source.counter : source.timer);
      const code = JSON.parse(otp.wasm_otp_at(row.data.totpUri, now, 0)).value;
      assert.equal(code, independentCode(secret, source.algorithm.toLowerCase(), steps, Number(source.digits), false));
    }
    assert.throws(() => parse(bytes, 'Wrong test password'));
    assert.throws(() => parse(bytes.subarray(0, -32), filePassword));
    console.log(JSON.stringify({ fixture: 'Raivo format generated with 7-Zip', aes256: true, restored: 2, pinAndOtpVerified: true,
      wrongPasswordAndTruncationRejected: true }));
  } finally {
    assert.equal(path.dirname(path.resolve(dir)), temp);
    assert(path.basename(dir).startsWith('vault-raivo-fixture-'));
    await fs.rm(dir, { recursive: true, maxRetries: 3, retryDelay: 200 });
  }
}

async function enteBackup(variant) {
  const sha256 = enteFixtures.get(variant);
  assert(sha256, 'Unknown Ente Auth fixture');
  const [imports, otp] = await Promise.all(['vault-ente-auth', 'vault-otp'].map(wasm));
  const password = ' Ente-夹具🔐 ';
  const seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const parse = (bytes, proof = password) => JSON.parse(imports.wasm_parse_ente_auth(bytes, '[]', proof));
  const file = `ente-auth-${variant}.json`;
  const bytes = await fs.readFile(path.join(__dirname, '..', 'crates', 'vault-ente-auth', 'tests', 'fixtures', file));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256, file);
  const backup = JSON.parse(bytes);
  const started = performance.now();
  const result = parse(bytes);
  const elapsedMs = Math.round(performance.now() - started);
  assert.equal(result.invalid + result.skipped, 0, file);
  assert.equal(result.rows.length, 3, file);
  const [totp, hotp, steam] = result.rows;
  assert.deepEqual({ issuer: totp.issuer, account: totp.account, pinned: totp.pinned, note: totp.note, tags: totp.tags },
    { issuer: 'GitHub', account: 'tester', pinned: true, note: '加密备份', tags: ['工单', 'work'] });
  assert.equal(hotp.issuer, 'Lab');
  assert.equal(steam.trashed, true);
  for (const [row, kind, algorithm, counter, digits] of [
    [totp, 'totp', 'sha256', Math.floor(now / 60), 8],
    [hotp, 'hotp', 'sha1', 1, 6],
    [steam, 'steam', 'sha1', Math.floor(now / 30), 5],
  ]) {
    const uri = new URL(row.setupKey);
    assert.equal(uri.hostname, kind, file);
    assert.equal(JSON.parse(otp.wasm_otp_at(row.setupKey, now, 0)).value,
      independentCode(seed, algorithm, counter, digits, kind === 'steam'), `${file} ${kind}`);
  }
  if (variant === 'legacy') {
    const changed = doc => parse(Buffer.from(JSON.stringify(doc)));
    const ciphertext = Buffer.from(backup.encryptedData, 'base64');
    ciphertext[ciphertext.length - 1] ^= 1;
    const header = Buffer.from(backup.encryptionNonce, 'base64');
    header[0] ^= 1;
    assert.throws(() => imports.wasm_parse_ente_auth(bytes, '[]'), /请输入 Ente Auth 文件密码/);
    assert.throws(() => parse(bytes, 'wrong'), /文件密码错误/);
    assert.throws(() => changed({ ...backup, encryptedData: ciphertext.toString('base64') }), /已损坏/);
    assert.throws(() => changed({ ...backup, encryptionNonce: header.toString('base64') }), /已损坏/);
    assert.throws(() => changed({ ...backup, encryptionNonce: Buffer.alloc(23).toString('base64') }), /格式无效/);
    assert.throws(() => changed({ ...backup, version: 2 }), /版本不受支持/);
    for (const [memLimit, opsLimit] of [[2 ** 30 + 1024, 1], [2 ** 30, 5], [8193, 1], [8192, 0]]) {
      assert.throws(() => changed({ ...backup, kdfParams: { ...backup.kdfParams, memLimit, opsLimit } }), /密钥派生参数/);
    }
  }
  console.log(JSON.stringify({ fixture: file, sha256, restored: result.rows.length, otpAndDisplayVerified: true,
    memLimit: backup.kdfParams.memLimit, opsLimit: backup.kdfParams.opsLimit, elapsedMs }));
}

async function run() {
  const dir = process.argv[2];
  if (dir === '--ente' && process.argv.length === 4) return enteBackup(process.argv[3]);
  assert(dir && process.argv.length === 3, 'Usage: node scripts/test-authenticator-fixtures.cjs <public fixture directory>|--raivo|--ente');
  if (dir === '--raivo') return raivoArchive();
  if (dir === '--ente') {
    // Match the disposable extension worker: grown linear memory is not reused.
    for (const variant of enteFixtures.keys()) {
      execFileSync(process.execPath, [__filename, '--ente', variant], { stdio: 'inherit', windowsHide: true, timeout: 120000 });
    }
    return;
  }
  const [imports, otp] = await Promise.all(['vault-importers', 'vault-otp'].map(wasm));
  const read = async (name, hash) => {
    const bytes = await fs.readFile(path.join(dir, name));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), hash, name);
    return bytes;
  };
  const parse = (format, bytes, password = '') => JSON.parse(imports.wasm_parse_authenticator_backup(format, bytes, password));
  for (const [name, hash, count] of twofas) {
    const bytes = await read(name, hash);
    const document = JSON.parse(bytes);
    const result = parse('2fas', bytes, document.servicesEncrypted ? samplePassword : '');
    assert.equal(result.rows.length, count, name);
    assert.equal(result.invalid + result.unsupported, 0, name);
    const source = document.servicesEncrypted ? decryptServices(document.servicesEncrypted) : document.services;
    assert.equal(source.length, count, name);
    for (const [i, row] of result.rows.entries()) {
      const { otp: settings, secret } = source[i];
      const kind = settings.tokenType?.toLowerCase() ?? 'totp';
      const algorithm = (settings.algorithm ?? 'SHA1').toUpperCase().replaceAll('-', '');
      const steam = kind === 'steam', digits = steam ? 5 : (settings.digits ?? 6);
      const period = steam ? 30 : (settings.period ?? 30);
      const uri = new URL(row.data.totpUri);
      assert.equal(row.data.username, [settings.account, settings.label].find(text => text?.trim()) ?? '', name);
      assert.equal(uri.hostname, kind, name);
      assert.equal(uri.searchParams.get('algorithm'), algorithm, name);
      assert.equal(Number(uri.searchParams.get('digits')), digits, name);
      const steps = kind === 'hotp' ? (settings.counter ?? 0) : Math.floor(now / period);
      if (kind === 'hotp') assert.equal(uri.searchParams.get('counter'), String(steps), name);
      else assert.equal(Number(uri.searchParams.get('period')), period, name);
      assert.equal(JSON.parse(otp.wasm_otp_at(row.data.totpUri, now, 0)).value,
        independentCode(secret, algorithm, steps, digits, steam), `${name} OTP ${i + 1}`);
    }
    if (document.servicesEncrypted) {
      assert.throws(() => parse('2fas', bytes, 'incorrect'), /认证失败/);
      const [body, salt, iv] = document.servicesEncrypted.split(':');
      const tampered = Buffer.from(body, 'base64');
      tampered[tampered.length - 1] ^= 1;
      const changed = Buffer.from(JSON.stringify({ ...document, servicesEncrypted: [tampered.toString('base64'), salt, iv].join(':') }));
      assert.throws(() => parse('2fas', changed, samplePassword), /认证失败/);
    }
    console.log(JSON.stringify({ fixture: name, recovered: count, accountAndCodesVerified: true }));
  }
  for (const [format, name, hash, groups] of others) {
    const result = parse(format, await read(name, hash), name.includes('encrypted') ? samplePassword : '');
    assert.equal(result.rows.length, 7, name);
    assert.equal(result.invalid + result.unsupported, 0, name);
    assert.equal(result.rows.filter(row => row.tags.length).length, groups, name);
    assert.deepEqual([...new Set(result.rows.map(row => new URL(row.data.totpUri).hostname))].sort(), ['hotp', 'steam', 'totp'], name);
    console.log(JSON.stringify({ fixture: name, recovered: 7, grouped: groups }));
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
