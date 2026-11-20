import { execFileSync } from 'node:child_process';
import { createCipheriv, createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, pbkdf2Sync, scryptSync, sign, verify, type KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import initCore, { WasmVaultEngine, wasm_create_new_vault, wasm_unlock_head_with_password } from '../../../crates/vault-core/pkg/vault_core.js';
import initImport, { wasm_csv_headers, wasm_parse_authenticator_backup, wasm_parse_bitwarden, wasm_parse_mapped_csv, wasm_portable_export, wasm_portable_import } from '../../../crates/vault-importers/pkg/vault_importers.js';
import initOtp, { wasm_otp_at } from '../../../crates/vault-otp/pkg/vault_otp.js';
import initKeys, { wasm_passkey_candidates, wasm_passkey_perform } from '../../../crates/vault-passkeys/pkg/vault_passkeys.js';
import { zip } from './test-fixtures/zip';

const str = (value: unknown) => JSON.stringify(value);
const bin = (value: unknown) => Buffer.from(str(value));
const b64 = (value: Uint8Array) => Buffer.from(value).toString('base64');
const url64 = (value: Uint8Array) => Buffer.from(value).toString('base64url');
const dec = (value: string) => Buffer.from(value, 'base64url');
const now = 1_700_000_009;
const seed = Buffer.from('12345678901234567890');
const base32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const filePassword = 'Fixture-File-Password#3';

beforeAll(async () => {
  await Promise.all([
    initCore({ module_or_path: await readFile(new URL('../../../crates/vault-core/pkg/vault_core_bg.wasm', import.meta.url)) }),
    initImport({ module_or_path: await readFile(new URL('../../../crates/vault-importers/pkg/vault_importers_bg.wasm', import.meta.url)) }),
    initOtp({ module_or_path: await readFile(new URL('../../../crates/vault-otp/pkg/vault_otp_bg.wasm', import.meta.url)) }),
    initKeys({ module_or_path: await readFile(new URL('../../../crates/vault-passkeys/pkg/vault_passkeys_bg.wasm', import.meta.url)) }),
  ]);
});

function independentCode(hash: string, moving: number, digits: number, secret = seed) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(moving));
  const mac = createHmac(hash, secret).update(counter).digest();
  return String((mac.readUInt32BE(mac.at(-1)! & 15) & 0x7fffffff) % 10 ** digits).padStart(digits, '0');
}
function aesSeal(key: Buffer, nonce: Buffer, body: Buffer) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  return { body: Buffer.concat([cipher.update(body), cipher.final()]), tag: cipher.getAuthTag() };
}
function twofasSeal(n: number, bytes: Buffer, saltLength = 32) {
  const salt = Buffer.alloc(saltLength, 10 + n), nonce = Buffer.alloc(12, 12 + n);
  const encrypted = aesSeal(pbkdf2Sync(filePassword, salt, 10_000, 32, 'sha256'), nonce, bytes);
  return [Buffer.concat([encrypted.body, encrypted.tag]), salt, nonce].map(b64).join(':');
}
function aegisSeal() {
  const n = 1024, r = 8, p = 1, salt = Buffer.alloc(32, 27), keyNonce = Buffer.alloc(12, 28), dbNonce = Buffer.alloc(12, 29);
  const dek = Buffer.alloc(32, 30);
  const key = aesSeal(scryptSync(filePassword, salt, 32, { N: n, r, p }), keyNonce, dek);
  const data = aesSeal(dek, dbNonce, bin({ version: 3, groups: [{ uuid: 'group', name: 'Fixture Group' }], entries: [{
    type: 'hotp', name: 'fixture-user', issuer: 'Example', note: 'Synthetic note', groups: ['group'],
    info: { secret: base32, algo: 'SHA1', counter: 7, digits: 6 },
  }] }));
  const hex = (b: Buffer) => b.toString('hex');
  return { version: 1, db: b64(data.body), header: { params: { nonce: hex(dbNonce), tag: hex(data.tag) },
    slots: [{ type: 1, n, r, p, salt: hex(salt), key: hex(key.body), key_params: { nonce: hex(keyNonce), tag: hex(key.tag) } }] } };
}
function googleUri(index: number, kind: 1 | 2, batchId = 24) {
  const field = (tag: number, body: Buffer) => Buffer.concat([Buffer.from([tag << 3 | 2, body.length]), body]);
  const otp = Buffer.concat([field(1, seed), field(2, Buffer.from(`Example:fixture-${index}`)), field(3, Buffer.from('Example')),
    Buffer.from([0x20, 1, 0x28, 1, 0x30, kind, 0x38, 7])]);
  return 'otpauth-migration://offline?data=' + encodeURIComponent(b64(Buffer.concat([
    field(1, otp), Buffer.from([0x10, 1, 0x18, 2, 0x20, index, 0x28, batchId]),
  ])));
}
const parseAuth = (format: string, bytes: Uint8Array, password = '') => JSON.parse(wasm_parse_authenticator_backup(format, bytes, password));
const codeAt = (row: { data: { totpUri: string } }) => JSON.parse(wasm_otp_at(row.data.totpUri, now, 0)).value;

function vendorCsv(header: string, rows: string[][]) {
  return Buffer.from('\uFEFF' + header + '\r\n' + rows.map(row => row.map(value => `"${value.replaceAll('"', '""')}"`).join(',')).join('\r\n'));
}

it('recognizes Bitwarden personal and organization CSV without weakening reprompt', () => {
  for (const prefix of ['folder,favorite', 'collections']) {
    const start = prefix.includes(',') ? ['Work', '1'] : ['Work,Team accounts'];
    const source = vendorCsv(prefix + ',type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp', [
      [...start, 'login', 'Imported bank', 'Fixture\r\nnote', 'PIN: keep private', '1',
        '"https://bank.example/a,b",https://login.example', 'fixture-account', ' fixture-password ', base32],
      [...start, 'note', 'Offline note', 'Fixture note only', '', '1', '', '', '', ''],
      [...start, 'login', 'Unrecognized reprompt', '', '', '2', 'https://example.net', 'fixture-account', 'fixture-password', ''],
    ]);
    const info = JSON.parse(wasm_csv_headers(source));
    expect(info).toMatchObject({ vendor: 'Bitwarden', headers: [], count: 3, mapping: {} });
    const batch = JSON.parse(wasm_parse_mapped_csv(source, '{}'));
    expect(batch).toMatchObject({ invalid: 1, unsupported: 0, rows: [
      { title: 'Imported bank', requireReprompt: true, pinned: prefix.includes(','), tags: prefix.includes(',') ? ['Work'] : ['Work', 'Team accounts'], note: 'Fixture\r\nnote',
        customFields: [{ hidden: true, value: 'PIN: keep private' }],
        data: { kind: 'login', password: ' fixture-password ', uris: [{ uri: 'https://bank.example/a,b' }, { uri: 'https://login.example' }] } },
      { title: 'Offline note', requireReprompt: true, data: { kind: 'developer', subtype: 'secure_note' } },
    ] });
    expect(codeAt(batch.rows[0])).toBe(independentCode('sha1', Math.floor(now / 30), 6));
  }
});

it('preserves Proton CSV URL restrictions and ignores a malformed structured column', () => {
  const structured = str([
    { url: 'https://example.com', mode: 0 },
    { url: 'https://exact.example.net/session?q=x,y', mode: 1 },
    { url: 'https://never.example.org', mode: 2 },
    { url: 'https://prefix.example.net/login/', mode: 3 },
    { url: 'https://unsupported.example.net', mode: 6 },
  ]);
  const source = vendorCsv('type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault', [
    ['login', 'Proton login', 'https://example.com', structured, 'mail@example.test', 'fixture-account', ' fixture-password ', 'fixture note', base32, '', '', 'Work'],
    ['login', 'Malformed', 'https://fallback.example.com', '{bad', '', 'second-user', 'p', '', '', '', '', 'Work'],
    ['login', 'Empty modes', 'https://fallback.example.com', '', '', 'third-user', 'p', '', '', '', '', 'Work'],
    ['login', 'Unreadable exclusion', '', str([{ url: 'https://example.com', mode: 0 }, { url: '', mode: 2 }]),
      '', 'fourth-user', 'p', '', '', '', '', 'Work'],
    ['login', 'Overlong rules', '', str([...Array.from({ length: 64 }, () => ({ url: 'https://example.com', mode: 0 })),
      { url: 'https://example.com/not-here', mode: 2 }]), '', 'fifth-user', 'p', '', '', '', '', 'Work'],
    ['note', 'Proton note', '', '', '', '', '', 'plain note', '', '', '', ''],
    ['creditCard', 'Proton card', '', '', '', '', '', str({ cardholderName: 'Fixture', number: '4111111111111111', note: 'card note' }), '', '', '', ''],
    ['alias', 'Unavailable alias', '', '', 'alias@example.test', '', '', '', '', '', '', ''],
  ]);
  expect(JSON.parse(wasm_csv_headers(source)).vendor).toBe('Proton Pass');
  const batch = JSON.parse(wasm_parse_mapped_csv(source, '{}'));
  expect(batch).toMatchObject({ invalid: 0, unsupported: 6, rows: [
    { title: 'Proton login', tags: ['Work'], customFields: [{ name: 'Proton Pass 邮箱', value: 'mail@example.test', hidden: true }],
      data: { username: 'fixture-account', password: ' fixture-password ', uris: [
        { uri: 'https://example.com' }, { uri: 'https://exact.example.net/session?q=x,y', matchRule: 'host' },
        { uri: 'https://never.example.org', matchRule: 'never' }, { uri: 'https://prefix.example.net/login/', matchRule: 'starts_with' },
        { uri: 'https://unsupported.example.net', matchRule: 'never' },
      ] } },
    { title: 'Malformed', data: { uris: [] } },
    { title: 'Empty modes', data: { uris: [] } },
    { title: 'Unreadable exclusion', data: { uris: [] } },
    { title: 'Overlong rules', data: { uris: [] } },
    { title: 'Proton note', data: { kind: 'developer', subtype: 'secure_note' } },
    { title: 'Proton card', note: 'card note', data: { kind: 'payment_card', cardNumber: '4111111111111111' } },
  ] });
  expect(codeAt(batch.rows[0])).toBe(independentCode('sha1', Math.floor(now / 30), 6));
});

it('parses variable-width RoboForm CSV without interpreting script or navigation fields as fill targets', () => {
  const source = vendorCsv('Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2', [
    ['Robo Login', 'https://redirect.example.net', 'https://login.example.com/account', "'@user", "''fixture ",
      'Fixture\r\nnote', 'Parent/Child', `TOTP KEY$fixture,${base32}`, 'Unknown Script$fixture'],
    ['Safe Note', '', '', '', '', 'Local fixture note', 'Parent'],
  ]);
  expect(JSON.parse(wasm_csv_headers(source)).vendor).toBe('RoboForm');
  const batch = JSON.parse(wasm_parse_mapped_csv(source, '{}'));
  expect(batch).toMatchObject({ invalid: 0, unsupported: 1, rows: [
    { title: 'Robo Login', note: 'Fixture\r\nnote', tags: ['Parent/Child'], customFields: [], data: {
      username: '@user', password: "'fixture ", uris: [{ uri: 'https://login.example.com/account', matchRule: 'exact' },
        { uri: 'https://redirect.example.net', matchRule: 'never' }],
    } },
    { title: 'Safe Note', data: { kind: 'developer', subtype: 'secure_note' } },
  ] });
  expect(codeAt(batch.rows[0])).toBe(independentCode('sha1', Math.floor(now / 30), 6));
});

it('retains 1Password CSV password-only and archived records without moving them to trash', () => {
  const source = vendorCsv('Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes', [
    ['Offline password', '', '', ' fixture-password ', '', 'true', '', 'Work,Personal', 'fixture note'],
    ['Archived login', 'https://example.test', 'fixture-account', 'p', base32, 'false', 'true', 'Old', 'fixture archived'],
    ['Unknown archive flag', 'https://example.test', '', 'p', '', '', 'unknown', '', ''],
  ]);
  expect(JSON.parse(wasm_csv_headers(source)).vendor).toBe('1Password');
  const batch = JSON.parse(wasm_parse_mapped_csv(source, '{}'));
  expect(batch).toMatchObject({ invalid: 1, rows: [
    { title: 'Offline password', pinned: true, tags: ['Work', 'Personal'], data: { uris: [], password: ' fixture-password ' } },
    { title: 'Archived login', pinned: false, trashed: false, data: { uris: [{ uri: 'https://example.test', matchRule: 'never' }] } },
  ] });
  expect(codeAt(batch.rows[1])).toBe(independentCode('sha1', Math.floor(now / 30), 6));
});

it('preserves NordPass additional URLs encoded as a JSON array inside a CSV cell', () => {
  const header = 'name,url,additional_urls,username,password,note,folder,cardholdername,cardnumber,type';
  const sites = ['https://example.com/', 'HTTPS://login.example.com/a,b', 'https://example.org/?q=x,y'];
  const cell = (value: string) => `"${value.replaceAll('"', '""')}"`;
  const row = (title: string, extra: string) => [title, sites[0]!, extra, 'fixture-user', ' p,"w', 'Line 1\r\nLine 2', 'Fixture', '', '', 'password'].map(cell).join(',');
  const ambiguousList = 'https://one.example.net/, https://two.example.net/';
  const redirect = 'https://login.example.net/continue?next=https://one.example.net/,https://two.example.net/';
  const source = Buffer.from('\uFEFF' + [
    header,
    row('Mixed array', str([...sites.slice(1), 'https://example.net:bad/', 'https://user:pass@example.net/'])),
    row('Malformed array', '["https://example.net"'),
    row('Ambiguous list', ambiguousList),
    row('Redirect with comma and embedded URLs', redirect),
    row('Single URL with comma', sites[2]!),
  ].join('\r\n'));
  const report = JSON.parse(wasm_csv_headers(source));
  expect(report.vendor).toBe('NordPass');
  const parsed = JSON.parse(wasm_parse_mapped_csv(source, str(report.mapping)));
  expect(parsed).toMatchObject({ unsupported: 4, invalid: 0, rows: [
    { note: 'Line 1\r\nLine 2', data: { password: ' p,"w', uris: sites.map(uri => ({ uri })) } },
    { data: { uris: [{ uri: sites[0] }] } },
    { data: { uris: [{ uri: sites[0] }] } },
    { data: { uris: [sites[0], redirect].map(uri => ({ uri })) } },
    { data: { uris: [sites[0], sites[2]].map(uri => ({ uri })) } },
  ] });
  expect(parsed.rows.map((item: { data: { uris: unknown[] } }) => item.data.uris.length)).toEqual([3, 1, 1, 2, 2]);
});

it('restores the legacy Dashlane TOTP URL emitted without a label', () => {
  const invalid = 'otpauth://totp/?secret=BAD&algorithm=SHA1&digits=6&period=30&lock=false';
  const bytes = Buffer.from('username,username2,username3,title,password,note,url,category,otpUrl\r\n' +
    `fixture-user,,,Fixture,example-password,"first\r\nsecond",https://example.com,Work,otpauth://totp/?secret=${base32.toLowerCase()}&algorithm=SHA1&digits=6&period=30&lock=false\r\n` +
    `bad-fixture,,,Bad OTP,example-password,,https://example.net,Work,${invalid}`);
  const report = JSON.parse(wasm_csv_headers(bytes));
  expect(report.vendor).toBe('Dashlane');
  const parsed = JSON.parse(wasm_parse_mapped_csv(bytes, str(report.mapping)));
  expect(parsed).toMatchObject({ ignoredOtp: 1, invalid: 0, rows: [
    { note: 'first\r\nsecond' },
    { data: { totpUri: null }, customFields: [{ hidden: true, value: invalid }] },
  ] });
  expect(codeAt(parsed.rows[0])).toBe(independentCode('sha1', Math.floor(now / 30), 6));
});

describe('authenticator migration with independently generated fixtures', () => {
  it('authenticates Stratum strong backups and preserves tags and HOTP counters', () => {
    const backup = {
      Authenticators: [
        { Type: 2, Username: 'fixture-user', Issuer: 'Example', Secret: base32, Algorithm: 1, Period: 45, Digits: 8 },
        { Type: 1, Username: 'fixture-hotp', Issuer: 'Example', Secret: base32, Algorithm: 0, Counter: 11, Digits: 6 },
      ],
      Categories: [{ Id: 'fixture', Name: 'Fixture Group' }],
      AuthenticatorCategories: [{ CategoryId: 'fixture', AuthenticatorSecret: base32 }],
    };
    const password = 'Stratum 合成文件口令';
    const header = Buffer.from('AUTHENTICATORPRO');
    const salt = Buffer.alloc(16, 5), nonce = Buffer.alloc(12, 7);
    // Node 26 crypto.argon2Sync vector for this synthetic UTF-8 password and salt.
    const key = Buffer.from('5047c1223961e2b83e97f3df8bace2c41a80fdaa02c84f3322ea873800c576f1', 'hex');
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([header, salt, nonce, cipher.update(bin(backup)), cipher.final(), cipher.getAuthTag()]);
    key.fill(0);
    const report = parseAuth('stratum', encrypted, password);
    expect(report).toEqual(parseAuth('stratum', bin(backup)));
    expect(report.rows[0]).toMatchObject({ tags: ['Fixture Group'], data: { username: 'fixture-user' } });
    expect(report.rows.map(codeAt)).toEqual([independentCode('sha256', Math.floor(now / 45), 8), independentCode('sha1', 11, 6)]);
    expect(() => parseAuth('stratum', encrypted)).toThrow(/文件密码/);
    expect(() => parseAuth('stratum', encrypted, 'Incorrect file password')).toThrow(/认证失败/);
    const tampered = Buffer.from(encrypted);
    tampered[tampered.length - 1]! ^= 1;
    expect(() => parseAuth('stratum', tampered, password)).toThrow(/认证失败/);
    expect(() => parseAuth('stratum', encrypted.subarray(0, header.length + 16), password)).toThrow(/上限/);
  });
  it('does not retype native Stratum OTPs or reset unverified counters', () => {
    const row = { Username: 'fixture-user', Secret: base32, Algorithm: 1, Period: 45, Digits: 8 };
    const backup = bin({ Authenticators: [
      { ...row, Type: 4, Issuer: 'Example' },
      { ...row, Type: 2, Issuer: 'Steam' },
      { ...row, Type: 2, Username: 'Steam:generic-user' },
      { ...row, Type: 1, Counter: 0 }, { ...row, Type: 1 }, { ...row, Type: 1, Counter: -1 },
      { ...row, Type: 1, Counter: 1.5 },
    ] });
    const result = parseAuth('stratum', backup);
    expect(result).toMatchObject({ unsupported: 2, invalid: 3 });
    expect(result.rows.map(codeAt)).toEqual(['R87JJ', independentCode('sha256', 0, 8)]);
  });
  it('rejects Stratum classifications exceeding the total label budget', () => {
    const row = { Username: 'fixture-user', Secret: base32, Type: 2 };
    const categories = Array.from({ length: 32 }, (_, i) => ({ Id: `${i}`, Name: `${i}`.padStart(256, 'x') }));
    const bytes = bin({ Authenticators: Array.from({ length: 513 }, () => row), Categories: categories,
      AuthenticatorCategories: categories.map(({ Id }) => ({ CategoryId: Id, AuthenticatorSecret: base32 })) });
    expect(() => parseAuth('stratum', bytes)).toThrow(/上限/);
  });
  it.skipIf(!process.env.VAULT_AUTH_FIXTURE_DIR)('imports the pinned Stratum strong backup from the upstream test suite', async () => {
    const dir = process.env.VAULT_AUTH_FIXTURE_DIR!;
    const readPinned = async (name: string, digest: string) => {
      const bytes = await readFile(join(dir, name));
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(digest);
      return bytes;
    };
    const strong = await readPinned('backup.strong.authpro', 'e8b5f262cde2ddef20db3867d628f0c5533d0adee755f2cd3f6c70821caebbd8');
    const report = parseAuth('stratum', strong, 'test');
    expect(report.rows.map(codeAt)).toEqual(['440725', '414410', '228515', '651512', '548791', '961004']);
    expect(report.rows[0]).toMatchObject({ title: 'Long', data: { username: 'Period', totpUri: expect.stringContaining('period=60') } });
    expect(report.rows[1].data.totpUri).toContain('algorithm=SHA256');
    expect(report.rows[2].data.totpUri).toContain('algorithm=SHA512');
    expect(report.unsupported).toBe(1); // Source sample includes a nine-digit TOTP.
    expect(report.rows.filter((row: { data: { totpUri: string } }) => row.data.totpUri.startsWith('otpauth://hotp/')))
      .toEqual([expect.objectContaining({ data: expect.objectContaining({ totpUri: expect.stringContaining('counter=10') }) })]);
    const legacy = await readPinned('backup.legacy.authpro', 'b541ec0d1b7c767442d292107d5a94deb3f987cc3e77a51abc02243415345593');
    expect(() => parseAuth('stratum', legacy, 'test')).toThrow(/旧版/);
    const plaintext = await readPinned('backup.unencrypted.authpro', 'ab49c51b3d3809d45e7677c8889504149c342600cb25c138084c0ae3605aaca8');
    const clear = parseAuth('stratum', plaintext);
    expect(clear.rows).toHaveLength(2);
    expect(clear.invalid).toBe(12); // Test placeholders do not satisfy Vault's Base32 seed checks.
    expect(clear.unsupported).toBe(1);
    expect(clear.rows).toMatchObject([
      { title: 'DigitalOcean', tags: ['Work'], data: { username: 'john@example.com' } },
      { tags: ['Banking'], data: { username: 'john@example.com', totpUri: expect.stringContaining('counter=4') } },
    ]);
    expect(clear.rows.map(codeAt)).toEqual(['591127', '391367']);
  });
  it('decrypts native andOTP AES backup bytes and rejects wrong passwords and out-of-range work', () => {
    const iterations = 150_000;
    const header = Buffer.alloc(4);
    header.writeUInt32BE(iterations);
    const password = 'andOTP 合成文件口令';
    const salt = Buffer.alloc(12, 2), nonce = Buffer.alloc(12, 3);
    const plaintext = bin([{ type: 'HOTP', label: 'fixture-user', issuer: 'Example', secret: base32,
      algorithm: 'SHA256', counter: 19, digits: 8, tags: ['Fixture Group'] }]);
    const key = pbkdf2Sync(password, salt, iterations, 32, 'sha1');
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([header, salt, nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    key.fill(0);
    const report = parseAuth('andotp', encrypted, password);
    expect(report).toEqual(parseAuth('andotp', plaintext));
    expect(report.rows[0]).toMatchObject({ tags: ['Fixture Group'], data: { username: 'fixture-user' } });
    expect(report.rows.map(codeAt)).toEqual([independentCode('sha256', 19, 8)]);
    expect(() => parseAuth('andotp', encrypted)).toThrow(/文件密码/);
    expect(() => parseAuth('andotp', encrypted, 'Incorrect file password')).toThrow(/认证失败/);
    const tampered = Buffer.from(encrypted);
    tampered[tampered.length - 1]! ^= 1;
    expect(() => parseAuth('andotp', tampered, password)).toThrow(/认证失败/);
    expect(() => parseAuth('andotp', encrypted.subarray(0, 28), password)).toThrow(/上限/);
    tampered.writeUInt32BE(160_001);
    expect(() => parseAuth('andotp', tampered, password)).toThrow(/参数/);
  });
  it('does not silently replace nonstandard andOTP Steam parameters or reset HOTP counters', () => {
    const row = { label: 'fixture-user', issuer: 'Example', secret: base32, algorithm: 'SHA1', type: 'STEAM', digits: 5, period: 30 };
    const result = parseAuth('andotp', bin([
      row, { ...row, period: 60 }, { ...row, digits: 7 }, { ...row, digits: undefined }, { ...row, algorithm: 'SHA256' },
      { ...row, issuer: '', label: 'Steam:generic-user', type: undefined, digits: 6 },
      { ...row, type: 'HOTP', digits: 6 }, { ...row, type: 'HOTP', digits: 6, counter: 0 },
    ]));
    expect(result).toMatchObject({ unsupported: 5, invalid: 1 });
    expect(result.rows.map(codeAt)).toEqual(['R87JJ', independentCode('sha1', 0, 6)]);
  });
  it.skipIf(!process.env.VAULT_AUTH_FIXTURE_DIR)('imports the pinned andOTP backup from the upstream interoperability tests', async () => {
    const dir = process.env.VAULT_AUTH_FIXTURE_DIR!;
    const source = await readFile(join(dir, 'andotp.encrypted.bin'));
    expect(createHash('sha256').update(source).digest('hex')).toBe('d7274dae68b819536c62bfc1ab6edd614d6789e9e9a7a87f90b8a15a89d804ae');
    const result = parseAuth('andotp', source, 'testtest');
    expect(result).toMatchObject({ invalid: 0, unsupported: 2 });
    expect(result.rows.map(codeAt)).toEqual(['440725', '961004', '414410', '228515', '651512', '548791', 'J5JV8']);
    expect(result.rows[0]).toMatchObject({ title: 'Long', data: { username: 'Period', totpUri: expect.stringContaining('period=60') } });
    expect(result.rows[4].data.totpUri).toContain('counter=10');
    expect(result.rows[6]).toMatchObject({ tags: ['Tag'], data: { username: 'Steam' } });
    const clear = await readFile(join(dir, 'andotp.unencrypted.json'));
    expect(createHash('sha256').update(clear).digest('hex')).toBe('b5ca6ff1ec1e3ab22c0a54f50117e1eb023cc0407be3b6c5bbf86c69635b77d8');
    expect(parseAuth('andotp', clear)).toEqual(result);
  });
  it('reassembles Google exports before activation and validates HOTP and TOTP', () => {
    const parts = [googleUri(1, 2), googleUri(0, 1), googleUri(1, 2)].join('\n');
    const report = parseAuth('google', Buffer.from(parts));
    expect([report.missingParts, report.repeatedParts]).toEqual([0, 1]);
    expect(report.rows.map(codeAt)).toEqual([independentCode('sha1', 7, 6), independentCode('sha1', Math.floor(now / 30), 6)]);
    expect(parseAuth('google', Buffer.from(googleUri(1, 2))).missingParts).toBe(1);
    expect(() => parseAuth('google', Buffer.from(`${parts}\n${googleUri(0, 1, 34)}`))).toThrow();
  });
  it('authenticates both 2FAS encrypted fields, preserving metadata and OTP settings', () => {
    const services = [{ name: 'Service', secret: base32, groupId: 'a', otp: { account: 'fixture-user', issuer: 'Example',
      algorithm: 'SHA256', digits: 8, period: 45 } }];
    const outer = { schemaVersion: 4, groups: [{ id: 'a', name: 'Fixture Group' }], reference: twofasSeal(1, Buffer.from('reference')),
      servicesEncrypted: twofasSeal(2, bin(services)) };
    const a = parseAuth('2fas', bin(outer), filePassword);
    expect(a.rows[0].tags).toEqual(['Fixture Group']);
    expect(codeAt(a.rows[0])).toBe(independentCode('sha256', Math.floor(now / 45), 8));
    expect(parseAuth('2fas', bin({ schemaVersion: 4, services })).rows).toHaveLength(1);
    expect(() => parseAuth('2fas', bin(outer), 'not-correct')).toThrow();
    expect(() => parseAuth('2fas', bin({ ...outer, reference: 'x:y:z' }), filePassword)).toThrow();
  });
  it('accepts the 256-byte salt used by 2FAS exports without accepting larger salts', () => {
    const services = [{ name: 'Service', secret: base32, otp: { tokenType: 'HOTP', algorithm: 'SHA1', digits: 8, counter: 7 } }];
    const input = { schemaVersion: 4, reference: twofasSeal(1, Buffer.from('reference'), 256),
      servicesEncrypted: twofasSeal(2, bin(services), 256) };
    const result = parseAuth('2fas', bin(input), filePassword);
    expect(result.rows.map(codeAt)).toEqual([independentCode('sha1', 7, 8)]);
    expect(() => parseAuth('2fas', bin(input), 'incorrect')).toThrow(/认证失败/);
    expect(() => parseAuth('2fas', bin({ ...input, servicesEncrypted: twofasSeal(2, bin(services), 257) }), filePassword)).toThrow(/上限/);
  });
  it('reads schema 2 2FAS services without mistaking the service type for an OTP type', () => {
    const service = { name: 'Service', secret: base32, type: 'Unknown',
      otp: { account: 'fixture-user', algorithm: 'SHA256', digits: 8, period: 50 } };
    const result = parseAuth('2fas', bin({ schemaVersion: 2, services: [
      service, { ...service, otp: { ...service.otp, tokenType: 'unsupported' } },
    ] }));
    expect(result.rows.map(codeAt)).toEqual([independentCode('sha256', Math.floor(now / 50), 8)]);
    expect(result.rows[0].data.username).toBe('fixture-user');
    expect(result.unsupported).toBe(1);
  });
  it('does not coerce malformed 2FAS OTP metadata to a TOTP credential', () => {
    const service = { name: 'Service', secret: base32, type: 'Unknown' };
    const malformed = [null, { tokenType: false }, { tokenType: '' }].map(otp => ({ ...service, otp }));
    const result = parseAuth('2fas', bin({ schemaVersion: 2, services: malformed }));
    expect(result.rows).toHaveLength(0);
    expect(result.invalid).toBe(malformed.length);
  });
  it('does not import plaintext services from an incomplete encrypted 2FAS backup', () => {
    const services = [{ name: 'Service', secret: base32, otp: { tokenType: 'TOTP' } }];
    const input = { schemaVersion: 4, reference: twofasSeal(1, Buffer.from('reference')), services };
    expect(() => parseAuth('2fas', bin(input), filePassword)).toThrow(/格式无效/);
  });
  it('authenticates Aegis password slots and database before retaining group and HOTP counter', () => {
    const outer = aegisSeal();
    const a = parseAuth('aegis', bin(outer), filePassword);
    expect(a.rows[0].note).toBe('Synthetic note');
    expect(a.rows[0].tags).toEqual(['Fixture Group']);
    expect(codeAt(a.rows[0])).toBe(independentCode('sha1', 7, 6));
    expect(() => parseAuth('aegis', bin(outer), 'not-correct')).toThrow();
    outer.header.params.tag = '11'.repeat(16);
    expect(() => parseAuth('aegis', bin(outer), filePassword)).toThrow();
    outer.header.slots[0]!.n = 2 ** 20;
    expect(() => parseAuth('aegis', bin(outer), filePassword)).toThrow();
  });
  it('matches Raivo JSON and ZIP, andOTP and the native Stratum algorithm enum', () => {
    const raivo = bin([{ kind: 'totp', account: 'fixture-user', issuer: 'Example', secret: base32, algorithm: 'SHA512', timer: 45, digits: 8 }]);
    const andotp = bin([{ type: 'TOTP', label: 'fixture-user', issuer: 'Example', secret: base32, algorithm: 'SHA512', period: 45, digits: 8 }]);
    const stratum = bin({ Authenticators: [{ Type: 2, Username: 'fixture-user', Issuer: 'Example', Secret: base32, Algorithm: 2, Period: 45, Digits: 8 }] });
    const expected = independentCode('sha512', Math.floor(now / 45), 8);
    for (const [format, bytes] of [
      ['raivo', raivo], ['raivo', zip({ 'raivo-otp-export.json': raivo })], ['andotp', andotp], ['stratum', stratum],
    ] as const) expect(codeAt(parseAuth(format, bytes).rows[0]), format).toBe(expected);
    expect(() => parseAuth('andotp', Buffer.from('Encrypted fixture'))).toThrow();
    expect(() => parseAuth('raivo', Buffer.alloc(4 * 1024 * 1024 + 1))).toThrow();
  });

  it('preserves Raivo native string pins, parameters and HOTP counters', () => {
    const raivo = bin([
      { kind: 'totp', account: 'time-fixture', issuer: 'Example', secret: base32, algorithm: 'SHA512', timer: '45', digits: '8', pinned: 'true' },
      { kind: 'hotp', account: 'counter-fixture', issuer: 'Example', secret: base32, algorithm: 'SHA1', counter: '13', digits: '6', pinned: 'false' },
    ]);
    for (const bytes of [raivo, zip({ 'raivo-otp-export.json': raivo })]) {
      const { rows, invalid, unsupported } = parseAuth('raivo', bytes);
      expect(invalid + unsupported).toBe(0);
      expect(rows).toMatchObject([
        { pinned: true, data: { username: 'time-fixture' } }, { pinned: false, data: { username: 'counter-fixture' } },
      ]);
      expect(rows.map(codeAt)).toEqual([independentCode('sha512', Math.floor(now / 45), 8), independentCode('sha1', 13, 6)]);
    }
  });
});

const origin = 'https://login.example.com', rpId = 'example.com', master = 'Synthetic-Only-Master#311';
const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const ed = generateKeyPairSync('ed25519');
function keyFixture(name: 'ec' | 'ed') {
  const pair = name === 'ec' ? ec : ed;
  const der = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  const credentialId = url64(Buffer.alloc(32, name === 'ec' ? 33 : 44));
  const userHandle = url64(Buffer.from('fixture-account'));
  const fields = { credentialId, rpId, username: 'fixture-account', userHandle };
  return { pair, der, fields, verifyAlgorithm: name === 'ec' ? 'sha256' : null };
}
const ck = keyFixture('ec'), ek = keyFixture('ed');
const cxf = bin({ version: { major: 1, minor: 0 }, exporterRpId: 'example.org', timestamp: now,
  accounts: [{ id: 'YQ', username: '', email: '', items: [{ id: 'Yg', title: 'Imported CXF', scope: { urls: [origin], androidApps: [] }, credentials: [
    { type: 'basic-auth', username: { fieldType: 'string', value: 'fixture-account' }, password: { fieldType: 'concealed-string', value: 'fixture-password' } },
    { type: 'note', content: { fieldType: 'string', value: 'Fixture note' } },
    { type: 'totp', username: 'fixture-account', secret: base32, period: 30, digits: 6, algorithm: 'sha1', issuer: 'Example' },
    ...[ck, ek].map(key => ({ type: 'passkey', ...key.fields, userDisplayName: 'Fixture Account', key: url64(key.der) })),
  ] }] }] });
const bitwarden = bin({ encrypted: false, folders: [], items: [{ type: 1, id: '12539750-d988-4daa-a446-cb21da866f99', name: 'Imported Bitwarden',
  login: { username: 'fixture-account', password: 'fixture-password', uris: [{ uri: origin }], fido2Credentials: [{
    ...ck.fields, userName: ck.fields.username, keyType: 'public-key', keyAlgorithm: 'ECDSA', keyValue: url64(ck.der), counter: '0', discoverable: 'true',
  }] } }] });
const onepassword = zip({ 'export.attributes': bin({ version: 3 }), 'files/example.txt': Buffer.from('Attachment'),
  'export.data': bin({ accounts: [{ attrs: { uuid: 'account' }, vaults: [{ attrs: { uuid: 'vault', name: 'Fixture Vault' }, items: [{
    uuid: 'item', categoryUuid: '001', createdAt: now, updatedAt: now, overview: { title: 'Imported 1PUX', url: origin },
    details: { loginFields: [{ designation: 'username', value: 'fixture-account' }, { designation: 'password', value: 'fixture-password' }],
      notesPlain: 'Fixture note', sections: [{ fields: [{ value: { totp: base32 } }] }], passkeys: [{ ...ek.fields, privateKey: url64(ek.der) }] },
  }] }] }] }) });
const proton = zip({ 'data.json': bin({ version: '1.21.2', encrypted: false, userId: 'fixture', vaults: { 'fixture-vault': { name: 'Fixture Vault', items: [{
  itemId: 'pass-item', state: 1, createTime: now, modifyTime: now, data: { type: 'login', metadata: { name: 'Imported Proton', note: 'Fixture note' },
    content: { itemUsername: 'fixture-account', password: 'fixture-password', urls: [origin], totpUri: base32,
      passkeys: [{ ...ck.fields, privateKey: ck.pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) }] },
  },
}] } } }) });
function protonExport(version: string, item: Record<string, unknown>) {
  return { version, vaults: { 'fixture-vault': { name: 'Fixture Vault', items: [item] } } };
}
function protonLogin(content: Record<string, unknown>, contentFormatVersion?: number) {
  return { itemId: 'fixture-item', contentFormatVersion, state: 1, createTime: now, modifyTime: now,
    data: { type: 'login', metadata: { name: 'Proton format fixture', note: 'Synthetic note' }, content } };
}
type PackingValue = string | number | null | PackingValue[] | { [name: string]: PackingValue };
// Only the MessagePack types needed to reproduce Proton's named fields and Vec<u8> arrays.
function packFixture(value: PackingValue): Buffer {
  if (value === null) return Buffer.of(0xc0);
  if (typeof value === 'number') {
    if (value >= -32 && value < 128) return Buffer.of(value & 255);
    if (value >= 128 && value <= 255) return Buffer.of(0xcc, value);
    throw new Error('Unexpected numeric fixture field');
  }
  if (typeof value === 'string') {
    const text = Buffer.from(value);
    return Buffer.concat([text.length < 32 ? Buffer.of(0xa0 | text.length) : Buffer.of(0xd9, text.length), text]);
  }
  if (Array.isArray(value)) {
    const header = value.length < 16 ? Buffer.of(0x90 | value.length) : Buffer.of(0xdc, value.length >>> 8, value.length & 255);
    return Buffer.concat([header, ...value.map(packFixture)]);
  }
  const fields = Object.entries(value);
  return Buffer.concat([Buffer.of(0x80 | fields.length), ...fields.flatMap(([name, field]) => [packFixture(name), packFixture(field)])]);
}
function protonNativeKey(fixture: typeof ck, options: { envelopeVersion?: number; counter?: number; badPublic?: boolean } = {}) {
  const jwk = fixture.pair.privateKey.export({ format: 'jwk' });
  const assigns = (v: string) => ({ t: 'assign', c: v });
  const pair = (label: number, value: PackingValue) => [{ t: 'int', c: label }, value];
  const bytes = (v: Uint8Array) => ({ t: 'bytes', c: [...v] });
  const curve = Buffer.alloc(16);
  curve[0] = jwk.kty === 'EC' ? 1 : 6;
  const x = dec(jwk.x!);
  if (options.badPublic) x[0] = x[0]! ^ 1;
  const inner = packFixture({
    key: { kty: assigns(jwk.kty === 'EC' ? 'EC2' : 'OKP'), kid: [], alg: assigns(jwk.kty === 'EC' ? 'ES256' : 'EdDSA'),
      kops: [assigns('Sign')], biv: [], par: [
        pair(-1, { t: 'int', c: { inner: [...curve] } }), pair(-2, bytes(x)),
        ...(jwk.y ? [pair(-3, bytes(dec(jwk.y)))] : []), pair(-4, bytes(dec(jwk.d!))),
      ] },
    cid: [...dec(fixture.fields.credentialId)], rid: rpId, uhd: [...dec(fixture.fields.userHandle)],
    cnt: options.counter ?? null, ext: { hmac_secret: null }, un: fixture.fields.username, udn: 'Synthetic fixture',
  });
  return { ...fixture.fields, userName: fixture.fields.username,
    credentialId: b64(dec(fixture.fields.credentialId)), userHandle: b64(dec(fixture.fields.userHandle)),
    content: b64(packFixture({ c: [...inner], v: options.envelopeVersion ?? 1 })) };
}

function fresh() {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const created = wasm_create_new_vault(master, 32768, 2, 4, key, now * 1000);
  try {
    const head = created.head_bytes, snap = created.snap_bytes;
    return { key, wrap: wasm_unlock_head_with_password(head, master, key), head, snap };
  } finally { created.free(); }
}
function imported(v: ReturnType<typeof fresh>, format: string, bytes: Uint8Array, password = '', commit = true) {
  const result = wasm_portable_import(format, v.key, v.wrap, v.head, v.snap, bytes, password, now * 1000, commit);
  try { return { report: JSON.parse(result.report), count: result.count, head: result.head, snap: result.snap }; }
  finally { result.free(); }
}
function restoredItems(v: ReturnType<typeof fresh>) {
  const engine = new WasmVaultEngine();
  try {
    engine.restore_from_session(v.key, v.wrap, v.head, v.snap);
    const summaries: { id: string }[] = JSON.parse(engine.list_summaries_json());
    return summaries.map(summary => JSON.parse(engine.get_item_json(summary.id, true)));
  } finally { engine.lock_and_zeroize(); engine.free(); }
}
function restoredItem(v: ReturnType<typeof fresh>) {
  return restoredItems(v)[0];
}

describe('Dashlane native CSV ZIP migration', () => {
  const header = 'username,username2,username3,title,password,note,url,category,otpUrl\r\n';
  const credentials = Buffer.from('\ufeff' + header +
    'fixture-login,fixture-alias,,Login fixture," spaced, ""quoted"" ","Line 1\r\nLine 2",https://example.test,Work,' +
    'otpauth://totp/?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&lock=false');
  const notes = Buffer.from('title,note,category\r\nNote fixture," note body ",Work');
  const payments = Buffer.from('type,account_name\r\ncredit_card,Unsupported fixture');

  it('restores logins and notes without creating CSV files and reports other types', () => {
    const vault = fresh();
    const bytes = zip({ 'credentials.csv': credentials, 'securenotes.csv': notes, 'payments.csv': payments });
    const preview = imported(vault, 'dashlane-zip', bytes, '', false);
    expect(preview.report).toMatchObject({ ready: 2, invalid: 0, unsupported: 1, ignoredOtp: 0 });
    expect(preview.head).toHaveLength(0);
    expect(preview.snap).toHaveLength(0);
    expect(JSON.stringify(preview.report)).not.toMatch(/quoted|note body|fixture-alias|JBSWY/);
    const state = { ...vault, ...imported(vault, 'dashlane-zip', bytes) };
    const records = restoredItems(state);
    expect(records.find(item => item.title === 'Login fixture')).toMatchObject({
      note: 'Line 1\r\nLine 2', tags: ['Work'],
      data: { username: 'fixture-login', password: ' spaced, "quoted" ', uris: [{ uri: 'https://example.test' }] },
      customFields: expect.arrayContaining([expect.objectContaining({ name: 'CSV 源自定义字段', value: expect.stringContaining('fixture-alias'), hidden: true })]),
    });
    expect(records.find(item => item.title === 'Note fixture')).toMatchObject({
      note: ' note body ', tags: ['Work'], requireReprompt: true, data: { kind: 'developer', subtype: 'secure_note' },
    });
    expect(imported(state, 'dashlane-zip', bytes, '', false).report).toMatchObject({ ready: 0, skipped: 2 });
    const engine = new WasmVaultEngine();
    try {
      engine.restore_from_session(state.key, state.wrap, state.head, state.snap);
      const trashed = engine.set_trashed(records.find(item => item.title === 'Login fixture').id, true, now * 1000 + 1);
      try {
        const changed = { ...state, head: trashed.head_bytes, snap: trashed.snap_bytes };
        expect(imported(changed, 'dashlane-zip', bytes, '', false).report).toMatchObject({ ready: 0, skipped: 2 });
        expect(restoredItems(changed).find(item => item.title === 'Login fixture').trashed).toBe(true);
      } finally { trashed.free(); }
    } finally { engine.lock_and_zeroize(); engine.free(); }
  });

  it('keeps untitled notes and treats an unsafe URL as hidden source data', () => {
    const sourceRows = Buffer.from(header + 'fixture,,,,"  ",,https://fixture-user:fixture-token@example.test,,');
    const bytes = zip({ 'credentials.csv': sourceRows, 'securenotes.csv': Buffer.from('title,note\n,"Preserve me"\n'),
      'personalInfo.csv': Buffer.alloc(0), 'ids.csv': Buffer.from('type,number\n,\nmalformed\n') });
    const vault = fresh();
    const state = { ...vault, ...imported(vault, 'dashlane-zip', bytes) };
    expect(state.report).toMatchObject({ ready: 2, invalid: 1, unsupported: 1 });
    expect(JSON.stringify(state.report)).not.toContain('fixture-token');
    const records = restoredItems(state);
    expect(records.find(item => item.data.kind === 'login')).toMatchObject({
      data: { password: '  ', uris: [] },
      customFields: expect.arrayContaining([expect.objectContaining({ name: 'CSV 源自定义字段',
        value: expect.stringContaining('fixture-token'), hidden: true })]),
    });
    expect(records.find(item => item.data.kind === 'developer')).toMatchObject({ note: 'Preserve me', requireReprompt: true });
  });

  it('rejects duplicate members, unknown paths, mislabeled CSV and truncated archives', () => {
    const vault = fresh();
    const bytes = zip({ 'credentials.csv': credentials });
    const wrongSize = Buffer.from(bytes);
    const centralOffset = wrongSize.readUInt32LE(wrongSize.length - 6);
    wrongSize.writeUInt32LE(credentials.length + 1, centralOffset + 24);
    for (const bad of [
      zip([['credentials.csv', credentials], ['credentials.csv', credentials]]),
      zip({ 'credentials.csv': credentials, '../securenotes.csv': notes }),
      zip({ 'credentials.csv': notes }),
      bytes.subarray(0, bytes.length - 9),
      wrongSize,
    ]) {
      expect(() => imported(vault, 'dashlane-zip', bad, '', false)).toThrow();
    }
  });

  const fixtureDir = process.env.VAULT_VENDOR_FIXTURE_DIR;
  if (fixtureDir) it('replays the pinned public five-member Dashlane archive', async () => {
    const bytes = await readFile(join(fixtureDir, 'dashlane.zip'));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe('918826152068ee6520c7e429a270379b3e9a92e4ed4062b47f93189546d8e8c0');
    const vault = fresh();
    const state = { ...vault, ...imported(vault, 'dashlane-zip', bytes) };
    expect(state.report).toMatchObject({ ready: 11, invalid: 0, unsupported: 4 });
    expect(restoredItems(state).map(item => item.data.kind).filter(kind => kind === 'developer')).toHaveLength(3);
  });
});

describe('Enpass desktop JSON migration', () => {
  const field = (type: string, value: string, extra = {}) => ({ type, value, label: type, sensitive: 0, deleted: 0, ...extra });
  const entry = (uuid: string, title: string, extra = {}) => ({
    uuid, title, template_type: 'login.default', favorite: 0, archived: 0, trashed: 0, fields: [], ...extra,
  });

  it('previews without writing and restores typed logins, notes, and source state without overwrite', () => {
    const vault = fresh(), secret = ' fixture-password! ', note = 'Line 1\nLine 2\n ';
    const login = entry('fixture-login', 'Enpass login', {
      favorite: 1, auto_submit: 1, note, folders: ['child', 'other'],
      fields: [
        field('email', 'backup@example.test'), field('username', 'fixture-user'),
        field('password', secret, { sensitive: 1 }),
        field('password', 'deleted-password', { deleted: 1 }),
        field('url', 'https://login.example.test/path'), field('url', 'https://second.example.org'),
        field('url', 'https://user:pass@ignored.example.test'), field('.Android#', 'com.example.fixture'),
        field('totp', base32), field('pin', 'fixture-pin'),
        field('script', 'fixture-opaque'),
      ],
    });
    const source = {
      folders: [
        { uuid: 'root', title: 'Home', parent_uuid: '' },
        { uuid: 'child', title: 'Web', parent_uuid: 'root' },
        { uuid: 'other', title: 'Work', parent_uuid: '' },
      ],
      items: [
        login,
        entry('fixture-archived', 'Archived login', { archived: 1, fields: [
          field('password', 'archived-password'), field('url', 'https://old.example.test'), field('totp', 'bad seed!'),
        ] }),
        entry('fixture-note', 'Enpass note', { template_type: 'note.default', note: 'Offline\nnote' }),
        entry('fixture-deleted', 'Trashed login', { trashed: 1, fields: [field('password', 'trashed-password')] }),
      ],
    };
    const bytes = Buffer.from('\uFEFF' + str(source));
    const preview = imported(vault, 'enpass', bytes, '', false);
    expect(preview.report).toMatchObject({ ready: 4, invalid: 0, unsupported: 3, ignoredOtp: 1, passkeys: 0 });
    expect(str(preview.report)).not.toMatch(/fixture-password|fixture-pin|fixture-opaque|GEZDGNBV|trashed-password/);
    expect(preview.head.length).toBe(0);
    expect(preview.snap.length).toBe(0);
    expect(restoredItems(vault)).toHaveLength(0);

    const saved = imported(vault, 'enpass', bytes), opened = { ...vault, ...saved };
    const records = restoredItems(opened);
    const item = records.find(item => item.title === 'Enpass login');
    expect(item).toMatchObject({ pinned: true, note, tags: ['Home/Web', 'Work'], data: {
      kind: 'login', username: 'fixture-user', password: secret,
      uris: [{ uri: 'https://login.example.test/path', matchRule: 'host' }, { uri: 'https://second.example.org', matchRule: 'host' }],
    } });
    expect(codeAt(item)).toBe(independentCode('sha1', Math.floor(now / 30), 6));
    expect(item.customFields).toEqual(expect.arrayContaining([expect.objectContaining({ name: '厂商 JSON 源字段', hidden: true })]));
    expect(records.find(item => item.title === 'Archived login')).toMatchObject({
      trashed: false, data: { uris: [{ uri: 'https://old.example.test', matchRule: 'never' }] },
    });
    expect(records.find(item => item.title === 'Enpass note')).toMatchObject({
      note: 'Offline\nnote', data: { kind: 'developer', subtype: 'secure_note' },
    });
    expect(records.find(item => item.title === 'Trashed login')).toMatchObject({ trashed: true });
    const again = imported(opened, 'enpass', bytes);
    expect(again.report).toMatchObject({ ready: 0, skipped: 4 });
    expect(again.snap.length).toBe(0);
    const replacement = entry('fixture-login', 'Changed title', { fields: [field('password', 'changed-password')] });
    expect(imported(opened, 'enpass', bin({ ...source, items: [replacement] })).report).toMatchObject({ ready: 0, skipped: 1 });
  });

  it('rejects unrelated wrappers, and counts malformed or oversized records without activating them', () => {
    const vault = fresh();
    for (const source of [{ encrypted: false, items: [] }, { items: [] }, { folders: [], items: {} }, { folders: [], items: [], version: 99 }]) {
      expect(() => imported(vault, 'enpass', bin(source))).toThrow();
    }
    const duplicate = str({ folders: [], items: [entry('archived', 'Archived duplicate', {
      archived: 1, fields: [field('password', 'fixture-secret'), field('url', 'https://example.test')],
    })] }).replace('"archived":1', '"archived":1,"arch\\u0069ved":0');
    expect(() => imported(vault, 'enpass', Buffer.from(duplicate))).toThrow();
    const preview = imported(vault, 'enpass', bin({ folders: [], items: [
      entry('flag', 'Unrecognized state', { archived: 'true', fields: [field('password', 'fixture-secret')] }),
      entry('width', 'Too many fields', { fields: Array.from({ length: 257 }, () => field('password', 'fixture-secret')) }),
      entry('unknown', 'Unknown template', { template_type: 'unknown.export', fields: [field('password', 'fixture-secret')] }),
      entry('broken-field', 'Malformed password', { fields: [
        field('url', 'https://wrong.example.test'), { type: 'password', value: 42 },
      ] }),
    ] }), '', false);
    expect(preview.report).toMatchObject({ ready: 0, invalid: 3, unsupported: 1 });
  });

  it('keeps distinct source state and recovers known computer passwords without web autofill', () => {
    const vault = fresh();
    const fields = [field('password', ' ambiguous-looking password '), field('url', 'https://fixture.example.test/login')];
    const source = { folders: [], items: [
      entry('live', 'Similar title', { fields: [...fields, field('pin', 'active pin')] }),
      entry('trash', 'Similar title', { trashed: 1, fields: [...fields, field('pin', 'active pin')] }),
      entry('different-pin', 'Similar title', { fields: [...fields, field('pin', 'other pin')] }),
      entry('server', 'Server account', { template_type: 'computer.server', fields, note: 'Offline note' }),
    ] };
    const saved = imported(vault, 'enpass', bin(source));
    expect(saved.report).toMatchObject({ ready: 4, skipped: 0 });
    const records = restoredItems({ ...vault, ...saved });
    expect(records.filter(item => item.title === 'Similar title')).toHaveLength(3);
    expect(records.find(item => item.trashed)).toMatchObject({ trashedAtMs: now * 1000 });
    expect(records.find(item => item.title === 'Server account')).toMatchObject({ note: 'Offline note',
      data: { kind: 'login', password: fields[0]!.value, uris: [] },
    });
    const duplicateId = { ...source, items: [source.items[0], { ...source.items[0], trashed: 1 }] };
    expect(() => imported(vault, 'enpass', bin(duplicateId))).toThrow();
  });
});

describe('vendor CLI JSON migration', () => {
  it('maps Dashlane password and secure-note output, keeping protection and exact URL constraints', () => {
    const vault = fresh();
    const account = {
      id: 'fixture-dashlane', anonId: 'fixture-anon', lastBackupTime: '1760000000', localeFormat: 'UNIVERSAL',
      title: 'Dashlane login', url: 'https://dashlane.example.test/base', userSelectedUrl: 'https://selected.example.test/only-here',
      login: 'fixture-dash-user',
      secondaryLogin: 'alternate', password: ' fixture-dash-password ', note: 'Dashlane\r\nnote',
      category: 'Personal', autoProtected: 'true', subdomainOnly: 'true', useFixedUrl: 'true',
      otpSecret: 'foreign or invalid fallback', otpUrl: `otpauth://totp/?secret=${base32}&period=30&digits=6&lock=false`,
    };
    const note = { id: 'fixture-note', anonId: '', lastBackupTime: '1760000001', localeFormat: 'UNIVERSAL',
      title: 'Dashlane note', content: 'Fixture secure note', secured: 'true', type: 'NO_TYPE' };
    const bytes = bin([account, { ...account, id: 'fixture-invalid', autoProtected: '?' }]);
    const preview = imported(vault, 'dashlane-json', bytes, '', false);
    expect(preview.report).toMatchObject({ ready: 1, invalid: 1, ignoredOtp: 0, passkeys: 0 });
    expect(str(preview.report)).not.toMatch(/fixture-dash-password|GEZDGNBV|alternate/);
    expect(preview.snap.length).toBe(0);
    const login = imported(vault, 'dashlane-json', bytes);
    const opened = { ...vault, ...login };
    const saved = restoredItem(opened);
    expect(saved).toMatchObject({ title: 'Dashlane login', tags: ['Personal'], requireReprompt: true, note: account.note, data: {
      kind: 'login', username: account.login, password: account.password, uris: [{ uri: account.userSelectedUrl, matchRule: 'exact' }],
    } });
    expect(codeAt(saved)).toBe(independentCode('sha1', Math.floor(now / 30), 6));
    const noteResult = imported(opened, 'dashlane-json', bin([note]));
    expect(restoredItems({ ...opened, ...noteResult }).find(item => item.title === note.title)).toMatchObject({
      requireReprompt: true, note: note.content, data: { kind: 'developer', subtype: 'secure_note' },
    });
    expect(imported(opened, 'dashlane-json', bytes).report).toMatchObject({ ready: 0, skipped: 1, invalid: 1 });
    expect(() => imported(vault, 'dashlane-json', bin([{ title: 'generic', username: 'me', password: 'p', url: account.url }]))).toThrow();
    const duplicate = str([account]).replace('"autoProtected":"true"', '"autoProtected":"true","autoProtected":"false"');
    expect(() => imported(vault, 'dashlane-json', Buffer.from(duplicate))).toThrow();
  });

  it('keeps Dashlane path scopes with fixed URL off and does not collapse different reprompt states', () => {
    const vault = fresh();
    const item = {
      id: 'one', anonId: '', lastBackupTime: '1760000000', localeFormat: 'UNIVERSAL',
      title: 'Path restricted', url: 'https://dashlane.example.test/tenant-a/login', login: 'fixture',
      password: 'synthetic', useFixedUrl: 'false', subdomainOnly: 'true', autoProtected: 'false',
    };
    const saved = imported(vault, 'dashlane-json', bin([item, { ...item, id: 'two', autoProtected: 'true' }]));
    expect(saved.report).toMatchObject({ ready: 2, skipped: 0 });
    const records = restoredItems({ ...vault, ...saved });
    expect(records.map(row => row.requireReprompt).sort()).toEqual([false, true]);
    for (const row of records) expect(row.data.uris).toEqual([{ uri: item.url, matchRule: 'exact' }]);
  });

  it('maps LastPass CLI records and the http://sn note marker, without inferring unknown protections or OTP', () => {
    const vault = fresh(), item = {
      id: '0001', name: 'LastPass login', fullname: 'Shared/Archive/LastPass login', group: 'Archive', share: 'Shared',
      username: 'fixture-lp-user', password: ' fixture-lp-password ', url: 'https://lastpass.example.test/login',
      last_modified_gmt: '1760000000', last_touch: '1760000001', note: 'LP\r\nnote',
    };
    const note = { ...item, id: '0002', name: 'LastPass note', fullname: 'Archive/LastPass note', share: undefined,
      url: 'http://sn', username: '', password: '', note: 'NoteType:Server\nFixture note contents' };
    const bytes = bin([item, note]);
    const preview = imported(vault, 'lastpass-json', bytes, '', false);
    expect(preview.report).toMatchObject({ ready: 2, ignoredOtp: 0, unsupported: 0 });
    expect(str(preview.report)).not.toMatch(/fixture-lp-password|Fixture note contents/);
    expect(preview.snap.length).toBe(0);
    const saved = imported(vault, 'lastpass-json', bytes), opened = { ...vault, ...saved };
    const records = restoredItems(opened);
    expect(records.find(row => row.title === item.name)).toMatchObject({ tags: ['Shared/Archive'], requireReprompt: true,
      note: item.note, data: { kind: 'login', password: item.password, username: item.username, uris: [{ uri: item.url, matchRule: 'host' }] },
    });
    expect(records.find(row => row.title === note.name)).toMatchObject({ requireReprompt: true, note: note.note,
      data: { kind: 'developer', subtype: 'secure_note' } });
    const repeat = imported(opened, 'lastpass-json', bin([{ ...item, name: 'Changed name', password: 'changed-password' }, note]));
    expect(repeat.report).toMatchObject({ ready: 0, skipped: 2 });
    expect(repeat.snap.length).toBe(0);
    expect(() => imported(vault, 'dashlane-json', bytes)).toThrow();
    expect(() => imported(vault, 'lastpass-json', bin({ encrypted: true, data: [item] }))).toThrow();
  });
});

type OnePuxField = { id: string; value: Record<string, unknown> };
type OnePuxSourceItem = {
  categoryUuid: string;
  overview: { title: string; url?: string };
  details: { notesPlain: string; loginFields?: { designation: string; value: string }[]; sections?: { fields?: OnePuxField[] }[] };
};

async function readPublishedFixture(file: string, gitBlob: string) {
  const bytes = await readFile(file);
  const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
  expect(blob).toBe(gitBlob);
  return bytes;
}

async function exportedFixtureLiteral(file: string, gitBlob: string, constant: string, enpassLoginFields?: unknown[]) {
  const ts = (await import('typescript')).default;
  const bytes = await readPublishedFixture(file, gitBlob);
  const source = ts.createSourceFile('public-fixture.ts', bytes.toString('utf8'), ts.ScriptTarget.Latest, true);
  function literal(node: import('typescript').Node): unknown {
    if (ts.isObjectLiteralExpression(node)) return Object.fromEntries(node.properties.map(prop => {
      if (!ts.isPropertyAssignment(prop) || !(ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name) || ts.isNumericLiteral(prop.name))) {
        throw new Error('Expected a literal fixture property');
      }
      return [prop.name.text, literal(prop.initializer)];
    }));
    if (ts.isArrayLiteralExpression(node)) return node.elements.flatMap(element => {
      if (ts.isSpreadElement(element) && enpassLoginFields && element.expression.getText(source) === 'login.items[0].fields') {
        return enpassLoginFields;
      }
      return [literal(element)];
    });
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(node.operand)) {
      return -Number(node.operand.text);
    }
    if (node.kind === ts.SyntaxKind.NullKeyword) return null;
    if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword) return node.kind === ts.SyntaxKind.TrueKeyword;
    throw new Error('Expected a literal fixture value');
  }
  const value = source.statements.flatMap(node => ts.isVariableStatement(node) ? [...node.declarationList.declarations] : [])
    .find(node => node.name.getText() === constant)?.initializer;
  if (!value) throw new Error('Expected the pinned public fixture');
  return literal(value);
}

const vendorFixtures = process.env.VAULT_VENDOR_FIXTURE_DIR;
if (vendorFixtures) {
  it('imports the independently published Enpass login, note, folders, and Android fixture layouts', async () => {
    const types = [
      ['login', '6626b8c9e4b61cd759eb9ed5e955c92a108a6e66', 'login', 'login', 1, 0],
      ['note', '37c1658b5175f7f17639ca0331235bbc5fe420b6', 'note', 'developer', 0, 0],
      ['folders', '9af44f057bfc9feb907b46e4ce411ce3cb1f3262', 'folders', 'developer', 0, 0],
      ['login-android-url', '91dca5fe99ab14e8172fb7bf5363ced0cbc856d8', 'loginAndroidUrl', 'login', 1, 4],
    ] as const;
    const vault = fresh();
    let enpassLoginFields: unknown[] | undefined;
    for (const [file, digest, constant, kind, ignoredOtp, unsupported] of types) {
      const source = await exportedFixtureLiteral(join(vendorFixtures, file + '.ts'), digest, constant, enpassLoginFields) as {
        items: { note: string; title: string; fields?: { type: string; value: string }[] }[];
      };
      const saved = imported(vault, 'enpass', bin(source));
      const item = source.items[0]!, restored = restoredItem({ ...vault, ...saved });
      expect(saved.report).toMatchObject({ ready: 1, invalid: 0, unsupported, ignoredOtp });
      expect(restored).toMatchObject({ title: item.title, note: item.note, data: { kind } });
      if (file === 'folders') expect(restored.tags).toEqual(['Social/Twitter']);
      if (file === 'login') enpassLoginFields = item.fields;
      if (kind === 'login') {
        expect(restored.data).toMatchObject({ username: item.fields?.find(x => x.type === 'email')?.value,
          password: item.fields?.find(x => x.type === 'password')?.value, totpUri: null,
          uris: [{ uri: item.fields?.find(x => x.type === 'url')?.value, matchRule: 'host' }] });
      }
    }
  });

  it('imports the pinned LastPass CLI JSON emitted by its native mock test', async () => {
    const raw = await readPublishedFixture(join(vendorFixtures, 'lastpass-tests'), 'b64a1ee4fad33c9c0c61948277dc469700338b8f');
    const output = /function test_show_json\n\{[\s\S]*?<<__EOM__\n([\s\S]*?\n)__EOM__\n/.exec(raw.toString('utf8'))?.[1];
    if (!output) throw new Error('Pinned LastPass fixture output missing');
    expect(createHash('sha256').update(output).digest('hex')).toBe('d172623adbb87b81ca5564be35b51d6daf6b57c9eaa99ab33802439b5489fc5d');
    const [source] = JSON.parse(output);
    const vault = fresh(), saved = imported(vault, 'lastpass-json', Buffer.from(output));
    expect(saved.report).toMatchObject({ ready: 1, invalid: 0, passkeys: 0, ignoredOtp: 0 });
    expect(restoredItem({ ...vault, ...saved })).toMatchObject({ title: source.name, note: source.note, tags: [source.group],
      requireReprompt: true, data: { kind: 'login', username: source.username, password: source.password,
        uris: [{ uri: source.url, matchRule: 'host' }] } });
  });
}

type VerifyingKey = { fields: { credentialId: string; userHandle: string }; pair: { publicKey: KeyObject }; verifyAlgorithm: string | null };
function checkSignature(v: ReturnType<typeof fresh>, key: VerifyingKey, discoverable: boolean) {
  const challenge = url64(Buffer.alloc(32, 77));
  const request = str({ kind: 'assert', origin, rpId, challenge, credentialIds: discoverable ? [] : [key.fields.credentialId], uv: 'required' });
  const candidates: { id: string; itemId: string }[] = JSON.parse(wasm_passkey_candidates(v.key, v.wrap, v.head, v.snap, request));
  const choice = candidates.find(({ id }) => id === key.fields.credentialId);
  if (!choice) throw new Error(`Missing ${discoverable ? 'discoverable' : 'allow-listed'} fixture credential`);
  const result = wasm_passkey_perform(v.key, v.wrap, v.head, v.snap, request, str({ itemId: choice.itemId, credentialId: choice.id,
    verified: true, increment: false, now: now * 1000 }), new Uint8Array(), new Uint8Array());
  try {
    const reply = JSON.parse(result.reply), auth = dec(reply.authenticatorData), client = dec(reply.clientDataJson);
    expect(JSON.parse(client.toString())).toMatchObject({ challenge, origin, type: 'webauthn.get' });
    expect(reply.userHandle).toBe(discoverable ? key.fields.userHandle : undefined);
    expect(auth.subarray(0, 32)).toEqual(createHash('sha256').update(rpId).digest());
    expect(auth[32]! & 0x1d).toBe(0x0d);
    expect(verify(key.verifyAlgorithm, Buffer.concat([auth, createHash('sha256').update(client).digest()]), key.pair.publicKey, dec(reply.signature))).toBe(true);
    expect(result.snap.length).toBe(0);
  } finally { result.free(); }
}

describe('portable import writes sealed credentials that can sign', () => {
  it('preserves the 1PUX software registration code in the license field', () => {
    const bytes = zip({ 'export.attributes': bin({ version: 3 }), 'export.data': bin({ accounts: [{
      attrs: { uuid: 'fixture-account' }, vaults: [{ attrs: { uuid: 'fixture-vault', name: 'Fixture' }, items: [{
        uuid: 'fixture-license', categoryUuid: '100', overview: { title: 'Fixture software' },
        details: { notesPlain: 'Synthetic note', sections: [{ fields: [
          { id: 'reg_code', title: 'license key', value: { string: 'SYNTHETIC-LICENSE' } },
        ] }] },
      }] }],
    }] }) });
    const vault = fresh(), saved = imported(vault, 'onepassword', bytes);
    expect(saved.count).toBe(1);
    expect(restoredItem({ ...vault, ...saved })).toMatchObject({ note: 'Synthetic note',
      data: { kind: 'developer', subtype: 'license_key', serviceOrProduct: 'Fixture software', tokenOrLicense: 'SYNTHETIC-LICENSE' },
    });
  });

  it('preserves 1PUX API credential expiry and exports its standalone note without API details', () => {
    const bytes = zip({ 'export.attributes': bin({ version: 3 }), 'export.data': bin({ accounts: [{
      vaults: [{ items: [{
        uuid: 'fixture-api', categoryUuid: '112', overview: { title: 'Fixture API' },
        details: { notesPlain: 'API notes', sections: [{ fields: [
          { id: 'credential', title: 'credential', value: { concealed: 'SYNTHETIC-TOKEN' } },
          { id: 'expires', title: 'expiry date', value: { date: now } },
        ] }] },
      }, {
        uuid: 'fixture-note', categoryUuid: '003', overview: { title: 'Fixture note' },
        details: { notesPlain: 'Synthetic standalone 1PUX note' },
      }] }],
    }] }) });
    const vault = fresh(), saved = imported(vault, 'onepassword', bytes);
    expect(saved.count).toBe(2);
    expect(restoredItems({ ...vault, ...saved }).find(item => item.title === 'Fixture API')).toMatchObject({
      data: { subtype: 'api_token', tokenOrLicense: 'SYNTHETIC-TOKEN', expiresAtMs: now * 1000 },
    });
    const cxf = JSON.parse(wasm_portable_export('cxf', vault.key, vault.wrap, saved.head, saved.snap, '', now * 1000));
    expect(cxf).toMatchObject({ count: 1, skipped: 1 });
    expect(JSON.parse(cxf.text).accounts[0].items).toMatchObject([{ title: 'Fixture note',
      credentials: [{ type: 'note', content: { value: 'Synthetic standalone 1PUX note' } }] }]);
    expect(cxf.text).not.toContain('SYNTHETIC-TOKEN');
  });

  const onePuxFixture = process.env.VAULT_ONEPUX_FIXTURE;
  if (onePuxFixture) it('replays an unmodified public 1PUX export payload with the supported types and no invented Passkeys', async () => {
    const source = await exportedFixtureLiteral(onePuxFixture, 'bf1e87c9c1d8e61223873c83e5dd9a997f603ffb', 'SanitizedExport') as {
      accounts: { vaults: { items: OnePuxSourceItem[] }[] }[];
    };
    const items = source.accounts.flatMap(account => account.vaults.flatMap(vault => vault.items));
    const fields = (item: OnePuxSourceItem) => (item.details.sections ?? []).flatMap(section => section.fields ?? []);
    const get = (item: OnePuxSourceItem, id: string, type: string) => fields(item).find(field => field.id === id)?.value[type];
    const bytes = zip({ 'export.attributes': bin({ version: 3 }), 'export.data': bin(source),
      'files/synthetic-attachment.txt': Buffer.from('Synthetic unsupported attachment') });
    const vault = fresh(), preview = imported(vault, 'onepassword', bytes, '', false);
    expect(preview.report).toMatchObject({ ready: 17, unsupported: 12, invalid: 0, passkeys: 0, ignoredPasskeys: 0, ignoredOtp: 1 });
    expect(preview.head).toHaveLength(0);
    expect(preview.snap).toHaveLength(0);
    expect(() => imported(vault, 'onepassword', bytes.subarray(0, -50))).toThrow();
    const saved = imported(vault, 'onepassword', bytes);
    const restored = { ...vault, ...saved };
    const byTitle = new Map(restoredItems(restored).map(row => [row.title, row]));
    expect(saved.count).toBe(preview.report.ready);
    const check = (category: string, kind: string, data: (item: OnePuxSourceItem) => unknown) => {
      const item = items.find(item => item.categoryUuid === category)!;
      expect(byTitle.get(item.overview.title)).toMatchObject({ note: item.details.notesPlain, data: { kind, ...data(item) as object } });
    };
    const login = items.find(item => item.categoryUuid === '001' && fields(item).some(field => field.value.totp))!;
    const row = byTitle.get(login.overview.title);
    expect(row).toMatchObject({ note: login.details.notesPlain, data: {
      username: login.details.loginFields!.find(field => field.designation === 'username')!.value,
      password: login.details.loginFields!.find(field => field.designation === 'password')!.value,
      // The upstream sanitized payload replaces its only seed with a 10-character placeholder.
      totpUri: null,
    } });
    check('002', 'payment_card', item => ({ cardNumber: get(item, 'ccnum', 'creditCardNumber'), cvv: get(item, 'cvv', 'concealed') }));
    check('004', 'identity', item => ({ company: get(item, 'company', 'string'),
      addressLine: (get(item, 'address', 'address') as { street: string }).street }));
    check('112', 'developer', item => ({ subtype: 'api_token', tokenOrLicense: get(item, 'credential', 'concealed'),
      expiresAtMs: Number(get(item, 'expires', 'date')) * 1000 }));
    check('100', 'developer', item => ({ subtype: 'license_key', tokenOrLicense: get(item, 'reg_code', 'string') }));
    expect(imported(restored, 'onepassword', bytes).count).toBe(0);
  });

  it('reads official Proton ZIP and JSON exports without treating the application version as a schema version', () => {
    const common = { password: 'synthetic-password', urls: [origin], totpUri: base32 };
    const current = protonExport('5.0.0.99', protonLogin({ ...common, itemUsername: 'modern-account' }, 8));
    const legacy = protonExport('1.17.4-rc3', protonLogin({ ...common, username: 'legacy-account' }));
    const vault = fresh();
    for (const [bytes, username] of [
      [zip({ 'Proton Pass/data.json': bin(current) }), 'modern-account'],
      [bin(legacy), 'legacy-account'],
    ] as const) {
      const preview = imported(vault, 'proton', bytes, '', false);
      expect(preview.snap).toHaveLength(0);
      expect(preview.report.sample[0].account).toBe(username);
      const saved = imported(vault, 'proton', bytes);
      const row = restoredItem({ ...vault, ...saved });
      expect(row).toMatchObject({ note: 'Synthetic note', data: { username, password: common.password } });
      expect(codeAt(row)).toBe(independentCode('sha1', Math.floor(now / 30), 6));
      expect(imported({ ...vault, ...saved }, 'proton', bytes).count).toBe(0);
    }
    expect(() => imported(vault, 'proton', zip({ 'Proton Pass/data.pgp': Buffer.from('Synthetic unsupported wrapper') }))).toThrow(/PGP/);
    expect(() => imported(vault, 'proton', bin({ ...current, version: 'unknown' }))).toThrow(/版本/);
  });

  it('opens password-encrypted Proton ZIPs locally without committing during preview', async () => {
    const armor = await readFile(new URL('../../../crates/vault-importers/tests/fixtures/proton-password.pgp', import.meta.url));
    const name = 'Proton Pass/data.pgp';
    const bytes = zip({ [name]: armor, 'Proton Pass/files/ignored.txt': Buffer.from('synthetic attachment') });
    const vault = fresh();
    expect(() => imported(vault, 'proton', bytes)).toThrow(/文件密码/);
    expect(() => imported(vault, 'proton', bytes, 'wrong fixture password')).toThrow(/PGP.*密码错误或.*损坏/);
    const invalid = Buffer.from(armor);
    const data = invalid.indexOf('\n\n') + 2;
    const position = data + 125;
    invalid[position] = invalid[position] === 65 ? 66 : 65;
    expect(() => imported(vault, 'proton', zip({ [name]: invalid }), filePassword)).toThrow(/PGP.*损坏/);
    expect(() => imported(vault, 'proton', zip([[name, armor], [name, armor]]), filePassword)).toThrow(/一份/);
    expect(() => imported(vault, 'proton', zip({ [name]: armor, 'data.pgp': armor }), filePassword)).toThrow(/一份/);
    expect(() => imported(vault, 'proton', zip({ [name]: armor, 'Proton Pass/data.json': bin({}) }), filePassword)).toThrow(/一份/);

    const preview = imported(vault, 'proton', bytes, filePassword, false);
    expect(preview.snap).toHaveLength(0);
    expect(preview.head).toHaveLength(0);
    expect(preview.report).toMatchObject({ ready: 1, unsupported: 1, invalid: 0, passkeys: 0 });
    expect(str(preview.report)).not.toMatch(/synthetic-password|GEZDGNBV/);
    const saved = imported(vault, 'proton', bytes, filePassword);
    expect(saved.count).toBe(1);
    const restored = { ...vault, ...saved };
    const row = restoredItem(restored);
    expect(row).toMatchObject({ title: 'Proton encrypted fixture', note: 'Fixture note', tags: ['Fixture Vault'],
      data: { username: 'fixture-account', password: 'synthetic-password', uris: [{ uri: 'https://example.test' }] } });
    expect(codeAt(row)).toBe(independentCode('sha1', Math.floor(now / 30), 6));
    expect(imported(restored, 'proton', bytes, filePassword)).toMatchObject({ count: 0, snap: new Uint8Array(0) });
  });

  it('imports Kaspersky printed websites, app logins and multiline notes without treating note text as a password field', () => {
    const source = Buffer.from('\uFEFF' + [
      'Websites', '', 'Website name: Fixture', 'Website URL: example.test', 'Login name: Fixture web',
      'Login: fixture-user', 'Password:  fixture-password ', 'Comment: first line', 'second line', '---', '',
      'Applications', '', 'Application: Editor', 'Login name: Fixture app', 'Login: offline-user', 'Password: app password',
      'Comment:', '---', '', 'Notes', '', 'Name: Secure note', 'Text: plain text', 'Password: literal text', '---',
      'Name: a literal example', 'still the same note', '---', '',
    ].join('\r\n'));
    const vault = fresh();
    expect(() => imported(vault, 'kaspersky', Buffer.from('Name,Url,Login,Pwd'))).toThrow(/英文 UTF-8/);
    const preview = imported(vault, 'kaspersky', source, '', false);
    expect(preview.snap).toHaveLength(0);
    expect(preview.report).toMatchObject({ ready: 3, invalid: 0, unsupported: 0 });
    expect(str(preview.report)).not.toMatch(/fixture-password|app password|literal text/);
    const restored = { ...vault, ...imported(vault, 'kaspersky', source) };
    expect(restoredItems(restored)).toEqual(expect.arrayContaining([
      expect.objectContaining({ title: 'Fixture web', note: 'first line\nsecond line',
        data: expect.objectContaining({ username: 'fixture-user', password: ' fixture-password ',
          uris: [{ uri: 'https://example.test', matchRule: 'host' }] }) }),
      expect.objectContaining({ title: 'Editor / Fixture app', data: expect.objectContaining({ uris: [] }) }),
      expect.objectContaining({ title: 'Secure note', note: 'plain text\nPassword: literal text\n---\nName: a literal example\nstill the same note',
        data: expect.objectContaining({ kind: 'developer', subtype: 'secure_note' }) }),
    ]));
    expect(imported(restored, 'kaspersky', source)).toMatchObject({ count: 0, snap: new Uint8Array(0) });
  });

  it('rejects unknown Proton item content versions and malformed items without committing a partial import', () => {
    const vault = fresh();
    const good = protonLogin({ password: 'synthetic-password', itemUsername: 'fixture-account' }, 8);
    for (const entry of [
      { item: { ...good, contentFormatVersion: 255 }, reason: /版本/ },
      { item: { ...good, data: { ...good.data, content: null } }, reason: /无效/ },
      { item: protonLogin({ password: 'synthetic-password', passkeys: { content: 'invalid' } }, 8), reason: /通行密钥列表/ },
    ]) {
      const exportData = protonExport('5.0.0.99', good);
      exportData.vaults['fixture-vault'].items.push(entry.item);
      expect(() => imported(vault, 'proton', bin(exportData))).toThrow(entry.reason);
      expect(restoredItems(vault)).toHaveLength(0);
    }
  });

  it('imports native Proton signing keys and validates ES256 and Ed25519 against independent public keys', () => {
    const input = (passkeys: unknown[]) => bin(protonExport('1.44.0', protonLogin({ itemUsername: 'fixture-account',
      password: 'synthetic-password', urls: [origin], passkeys }, 8)));
    const vault = fresh(), bytes = input([protonNativeKey(ck), protonNativeKey(ek)]);
    const preview = imported(vault, 'proton', bytes, '', false);
    expect(preview.report).toMatchObject({ passkeys: 2, ignoredPasskeys: 0 });
    expect(preview.snap).toHaveLength(0);
    const result = imported(vault, 'proton', zip({ 'Proton Pass/data.json': bytes }));
    expect(result.count).toBe(1);
    const restored = { ...vault, ...result };
    for (const fixture of [ck, ek]) checkSignature(restored, fixture, true);
    expect(imported(restored, 'proton', bytes).count).toBe(0);
    const bad = input([
      { ...protonNativeKey(ck), rpId: 'different.example.org' },
      protonNativeKey(ck, { badPublic: true }),
      protonNativeKey(ek, { envelopeVersion: 2 }),
      { ...protonNativeKey(ek), content: b64(Buffer.concat([Buffer.from(protonNativeKey(ek).content, 'base64'), Buffer.of(0)])) },
      protonNativeKey(ek, { counter: 7 }),
    ]);
    expect(imported(vault, 'proton', bad, '', false).report)
      .toMatchObject({ passkeys: 0, ignoredPasskeys: 4, suspendedPasskeys: 1, unsupportedPasskeyVersions: 1 });
  });

  const protonFixture = process.env.VAULT_PROTON_FIXTURE;
  if (protonFixture) it.each([
    ['protonpass_1.17.zip', '8a0a84ca4d44bfa9bd8a06012def901dd2a3a79599d1c74785fbc324fe1f8db3', 4],
    ['protonpass.zip', 'f2efd4718384790c6851f9c80671b9c79b6d2156d8e14b700bb4f76e4919f21d', 9],
  ] as const)('restores passwords and notes from the unmodified Proton archive %s', async (name, digest, count) => {
    const path = join(protonFixture, name), bytes = await readFile(path);
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(digest);
    const source = JSON.parse(execFileSync('tar', ['-xOf', path, 'Proton Pass/data.json'], { encoding: 'utf8', windowsHide: true }));
    const vault = fresh(), preview = imported(vault, 'proton', bytes, '', false);
    expect(preview.report).toMatchObject({ ready: count, passkeys: 1, ignoredPasskeys: 0, ignoredOtp: 1 });
    expect(preview.snap).toHaveLength(0);
    const saved = imported(vault, 'proton', bytes);
    const rows = restoredItems({ ...vault, ...saved });
    expect(saved.count).toBe(count);
    for (const value of Object.values(source.vaults) as { items: { data: {
      type: string; content: Record<string, string>; metadata: { name: string; note: string };
    } }[] }[]) {
      for (const { data } of value.items) {
        if (data.type !== 'login') continue;
        const { content } = data;
        const row = rows.find(row => row.title === data.metadata.name);
        expect(row).toMatchObject({ note: data.metadata.note, data: {
          username: content.itemUsername || content.itemEmail || content.username || '', password: content.password, totpUri: null,
        } });
      }
    }
    expect(imported({ ...vault, ...saved }, 'proton', bytes).count).toBe(0);
  });

  const cxfSource = process.env.VAULT_CXF_FIXTURE;
  const cxfReceiver = process.env.VAULT_CXF_RECEIVER;
  if (cxfSource && cxfReceiver) it.each([
    ['login_passkey_totp_scope.json', 'a0f9812f7b3efa76fcd56ec626475664a7221af5', 1, 0],
    ['full_library_baseline.json', 'aa2966742368ae6b2ba4cb5a838a4611f515ac74', 2, 11],
  ] as const)('imports independent CXF %s and verifies what the Bitwarden CXF reader receives', async (name, digest, passkeys, unsupported) => {
    const bytes = await readPublishedFixture(join(cxfSource, name), digest);
    type Credential = { type: string } & Record<string, any>;
    type Item = { title: string; credentials: Credential[] };
    const allItems = (document: { accounts: { items: Item[] }[] }) => document.accounts.flatMap(account => account.items);
    const input = allItems(JSON.parse(bytes.toString('utf8')));
    const inputCredentials = input.flatMap(item => item.credentials);
    const original = inputCredentials.filter(cred => cred.type === 'passkey');
    const { secret, algorithm, period, digits } = inputCredentials.find(cred => cred.type === 'totp')!;
    const bits = Array.from(secret as string, char => {
      const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char.toUpperCase());
      expect(index).toBeGreaterThanOrEqual(0);
      return index.toString(2).padStart(5, '0');
    }).join('');
    const otpSeed = Buffer.from((bits.match(/.{8}/g) ?? []).map(byte => Number.parseInt(byte, 2)));
    const originalVerifier = (cred: Credential) => createPublicKey(createPrivateKey({ key: dec(cred.key), format: 'der', type: 'pkcs8' }));
    const vault = fresh();
    const preview = imported(vault, 'cxf', bytes, '', false);
    expect(preview.report).toMatchObject({ passkeys, unsupported, ignoredOtp: 0, ignoredPasskeys: 0 });
    expect(preview.snap).toHaveLength(0);
    const saved = imported(vault, 'cxf', bytes), restored = { ...vault, ...saved };
    for (const cred of original) {
      expect(cred.rpId).toBe(rpId);
      checkSignature(restored, { fields: { credentialId: cred.credentialId, userHandle: cred.userHandle },
        pair: { publicKey: originalVerifier(cred) }, verifyAlgorithm: 'sha256' }, true);
    }
    const login = restoredItems(restored).find(row => row.data.kind === 'login');
    const password = inputCredentials.find(cred => cred.type === 'basic-auth')!;
    expect(login.data).toMatchObject({ username: password.username.value, password: password.password.value });
    expect(codeAt(login)).toBe(independentCode(algorithm, Math.floor(now / period), digits, otpSeed));
    const exported = JSON.parse(wasm_portable_export('cxf', vault.key, vault.wrap, saved.head, saved.snap, '', now * 1000));
    const received = JSON.parse(execFileSync(cxfReceiver, [], { input: exported.text, encoding: 'utf8', windowsHide: true }));
    const delivered = allItems(received).flatMap(item => item.credentials);
    expect(delivered.find(cred => cred.type === 'basic-auth')).toMatchObject({ username: password.username, password: password.password });
    expect(delivered.find(cred => cred.type === 'totp')).toMatchObject({ secret, algorithm, period, digits });
    expect(delivered.filter(cred => cred.type === 'note')).toMatchObject(inputCredentials.filter(cred => cred.type === 'note'));
    const clientHash = createHash('sha256').update('synthetic receiving party challenge').digest();
    for (const cred of original) {
      const key = delivered.find(value => value.type === 'passkey' && value.credentialId === cred.credentialId)!;
      expect(key).toMatchObject({ rpId: cred.rpId, userHandle: cred.userHandle });
      const material = createPrivateKey({ key: dec(key.key), format: 'der', type: 'pkcs8' });
      const authenticatorData = Buffer.concat([createHash('sha256').update(cred.rpId).digest(), Buffer.of(9, 0, 0, 0, 0)]);
      const signed = Buffer.concat([authenticatorData, clientHash]);
      expect(verify('sha256', signed, originalVerifier(cred), sign('sha256', signed, material))).toBe(true);
    }
  });

  it.each([
    ['cxf', cxf, [ck, ek]], ['bitwarden', bitwarden, [ck]], ['onepassword', onepassword, [ek]], ['proton', proton, [ck]],
  ] as const)('validates %s using the fixture public key', (format, bytes, keys) => {
    const v = fresh();
    const preview = imported(v, format, bytes, '', false);
    expect(preview.head).toHaveLength(0);
    expect(preview.report.passkeys).toBe(keys.length);
    expect(str(preview.report)).not.toContain('fixture-password');
    const result = imported(v, format, bytes);
    expect(result.count).toBe(1);
    expect(imported({ ...v, ...result }, format, bytes).count).toBe(0);
    if (format === 'onepassword') expect(codeAt(restoredItem({ ...v, ...result }))).toBe(independentCode('sha1', Math.floor(now / 30), 6));
    for (const key of keys) {
      checkSignature({ ...v, ...result }, key, false);
      checkSignature({ ...v, ...result }, key, true);
    }
  });
  it('activates a retained Bitwarden key in place without replacing the old passwords or card', () => {
    const vault = fresh();
    const legacy = JSON.parse(bitwarden.toString('utf8'));
    legacy.items[0].login.totp = base32;
    legacy.items.push({ type: 3, id: '94be8abf-924a-44e6-b834-d8e830a45979', name: 'Synthetic card',
      card: { cardholderName: 'Fixture', number: '4111111111111111', expMonth: '12', expYear: '2040' } });
    const engine = new WasmVaultEngine();
    engine.restore_from_session(vault.key, vault.wrap, vault.head, vault.snap);
    const { rows } = JSON.parse(wasm_parse_bitwarden(bin(legacy), ''));
    const stored = engine.import_records_json(str({ prepared: true, rows }), now * 1000, true);
    const oldVault = { ...vault, head: stored.head_bytes, snap: stored.snap_bytes };
    stored.free();
    engine.free();
    const before = restoredItems(oldVault);
    expect(before).toHaveLength(2);
    expect(() => checkSignature(oldVault, ck, true)).toThrow('Missing discoverable fixture credential');

    const preview = imported(oldVault, 'bitwarden-retained', Buffer.alloc(0), '', false);
    expect(preview.report).toMatchObject({ ready: 1, passkeys: 1, ignoredPasskeys: 0 });
    expect(preview.snap).toHaveLength(0);
    const updated = imported(oldVault, 'bitwarden-retained', Buffer.alloc(0));
    const restored = { ...vault, ...updated };
    const after = restoredItems(restored);
    expect(after.map(item => item.id)).toEqual(before.map(item => item.id));
    const loginBefore = before.find(item => item.data.kind === 'login');
    const loginAfter = after.find(item => item.data.kind === 'login');
    expect(loginAfter.data).toMatchObject({ username: loginBefore.data.username, password: loginBefore.data.password, totpUri: loginBefore.data.totpUri });
    expect(after.find(item => item.data.kind === 'payment_card')).toEqual(before.find(item => item.data.kind === 'payment_card'));
    checkSignature(restored, ck, true);
    expect(imported(restored, 'bitwarden-retained', Buffer.alloc(0)).count).toBe(0);
  });
  it('recovers CXF from authenticated JWE, refuses the wrong password and verifies both keys again', () => {
    const v = fresh(), loaded = imported(v, 'cxf', cxf);
    const { text } = JSON.parse(wasm_portable_export('cxf', v.key, v.wrap, loaded.head, loaded.snap, filePassword, now * 1000));
    expect(text.split('.')).toHaveLength(5);
    expect(text).not.toContain('fixture-password');
    const dest = fresh();
    expect(() => imported(dest, 'cxf', Buffer.from(text), 'incorrect')).toThrow();
    const recovered = imported(dest, 'cxf', Buffer.from(text), filePassword);
    for (const key of [ck, ek]) checkSignature({ ...dest, ...recovered }, key, true);
  });
  it('restores a CXF TOTP when the exporter omits the optional username', () => {
    const vault = fresh();
    const bytes = bin({ version: { major: 1, minor: 0 }, exporterRpId: 'example.org', accounts: [{
      id: 'YQ', items: [{ id: 'Yg', title: 'Steam: Synthetic title', credentials: [{
        type: 'totp', secret: base32, period: 30, digits: 6, algorithm: 'sha1',
      }] }],
    }] });
    const preview = imported(vault, 'cxf', bytes, '', false);
    expect(preview.report).toMatchObject({ ready: 1, ignoredOtp: 0 });
    const saved = imported(vault, 'cxf', bytes);
    expect(codeAt(restoredItem({ ...vault, ...saved }))).toBe(independentCode('sha1', Math.floor(now / 30), 6));
    const { text } = JSON.parse(wasm_portable_export('cxf', vault.key, vault.wrap, saved.head, saved.snap, '', now * 1000));
    expect(JSON.parse(text).accounts[0].items[0]).toMatchObject({
      title: 'Steam: Synthetic title',
      credentials: [{ type: 'totp', secret: base32, period: 30, digits: 6, algorithm: 'sha1' }],
    });
  });
  it('round-trips a standalone CXF note as a note without exporting developer credential fields', () => {
    const note = { type: 'note', content: { fieldType: 'string', value: 'Synthetic standalone note' } };
    const v = fresh();
    const loaded = imported(v, 'cxf', bin({ version: { major: 1, minor: 0 }, exporterRpId: 'example.org',
      accounts: [{ id: 'YQ', items: [{ id: 'Yg', title: 'Standalone note', credentials: [note] }] }],
    }));
    const developer = imported({ ...v, ...loaded }, 'onepassword', zip({ 'export.attributes': bin({ version: 3 }),
      'export.data': bin({ accounts: [{ vaults: [{ items: [{ uuid: 'api', categoryUuid: '112', overview: { title: 'Internal API' },
        details: { notesPlain: 'Do not export this separate developer item', sections: [{ fields: [
          { id: 'credential', title: 'credential', value: { concealed: 'SYNTHETIC-API-SECRET' } },
        ] }] } }] }] }] }),
    }));
    const result = JSON.parse(wasm_portable_export('cxf', v.key, v.wrap, developer.head, developer.snap, '', now * 1000));
    expect(result).toMatchObject({ count: 1, skipped: 1 });
    expect(result.text).not.toContain('SYNTHETIC-API-SECRET');
    expect(JSON.parse(result.text).accounts[0].items).toMatchObject([{ title: 'Standalone note', credentials: [note] }]);
    const destination = fresh(), recovered = imported(destination, 'cxf', Buffer.from(result.text));
    expect(restoredItem({ ...destination, ...recovered })).toMatchObject({ title: 'Standalone note', note: note.content.value });
  });
});
