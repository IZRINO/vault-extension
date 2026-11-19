import { createCipheriv, createHash, createHmac, generateKeyPairSync, pbkdf2Sync, scryptSync, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { crc32 } from 'node:zlib';
import { beforeAll, describe, expect, it } from 'vitest';
import initCore, { wasm_create_new_vault, wasm_unlock_head_with_password } from '../../../crates/vault-core/pkg/vault_core.js';
import initImport, { wasm_parse_authenticator_backup, wasm_portable_export, wasm_portable_import } from '../../../crates/vault-importers/pkg/vault_importers.js';
import initOtp, { wasm_otp_at } from '../../../crates/vault-otp/pkg/vault_otp.js';
import initKeys, { wasm_passkey_candidates, wasm_passkey_perform } from '../../../crates/vault-passkeys/pkg/vault_passkeys.js';

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

function independentCode(hash: string, moving: number, digits: number) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(moving));
  const mac = createHmac(hash, seed).update(counter).digest();
  return String((mac.readUInt32BE(mac.at(-1)! & 15) & 0x7fffffff) % 10 ** digits).padStart(digits, '0');
}
function aesSeal(key: Buffer, nonce: Buffer, body: Buffer) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  return { body: Buffer.concat([cipher.update(body), cipher.final()]), tag: cipher.getAuthTag() };
}
function twofasSeal(n: number, bytes: Buffer) {
  const salt = Buffer.alloc(32, 10 + n), nonce = Buffer.alloc(12, 12 + n);
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
function zip(files: Record<string, Buffer>) {
  const local: Buffer[] = [], directory: Buffer[] = [];
  let offset = 0;
  for (const [file, body] of Object.entries(files)) {
    const name = Buffer.from(file);
    const entry = Buffer.alloc(30), header = Buffer.alloc(46), crc = crc32(body);
    entry.writeUInt32LE(0x04034b50, 0); entry.writeUInt16LE(20, 4); entry.writeUInt32LE(crc, 14);
    entry.writeUInt32LE(body.length, 18); entry.writeUInt32LE(body.length, 22); entry.writeUInt16LE(name.length, 26);
    header.writeUInt32LE(0x02014b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(20, 6);
    header.writeUInt32LE(crc, 16); header.writeUInt32LE(body.length, 20); header.writeUInt32LE(body.length, 24);
    header.writeUInt16LE(name.length, 28); header.writeUInt32LE(offset, 42);
    local.push(entry, name, body); directory.push(header, name);
    offset += entry.length + name.length + body.length;
  }
  const central = Buffer.concat(directory), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(local.length / 3, 8); end.writeUInt16LE(local.length / 3, 10);
  end.writeUInt32LE(central.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, central, end]);
}
const parseAuth = (format: string, bytes: Uint8Array, password = '') => JSON.parse(wasm_parse_authenticator_backup(format, bytes, password));
const codeAt = (row: { data: { totpUri: string } }) => JSON.parse(wasm_otp_at(row.data.totpUri, now, 0)).value;

describe('authenticator migration with independently generated fixtures', () => {
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
function checkSignature(v: ReturnType<typeof fresh>, key: typeof ck, discoverable: boolean) {
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
    for (const key of keys) {
      checkSignature({ ...v, ...result }, key, false);
      checkSignature({ ...v, ...result }, key, true);
    }
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
});
