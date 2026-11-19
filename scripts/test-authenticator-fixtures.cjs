const assert = require('node:assert/strict');
const { createDecipheriv, createHash, createHmac, pbkdf2Sync } = require('node:crypto');
const fs = require('node:fs/promises');
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

async function run() {
  const dir = process.argv[2];
  assert(dir && process.argv.length === 3, 'Usage: node scripts/test-authenticator-fixtures.cjs <public fixture directory>');
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
