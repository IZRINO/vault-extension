const assert = require('node:assert/strict');
const { createHash, createPublicKey, randomBytes } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const pinned = {
  'protonpass_1.17.zip': '8a0a84ca4d44bfa9bd8a06012def901dd2a3a79599d1c74785fbc324fe1f8db3',
  'protonpass.zip': 'f2efd4718384790c6851f9c80671b9c79b6d2156d8e14b700bb4f76e4919f21d',
  'worker/package.json': 'd56bc29bf9e9daeb2d548511d59cb31c1c058144f1f6f5b6c123bae619e5e783',
  'worker/proton_pass_web.js': '27ae0337ddfb2abe039c36f642ca2aa44b5ceaef4a92ef99183ab4c09cb53c78',
  'worker/proton_pass_web_bg.js': '2e106bbfc917b683a34803d951ca7581cb26714064cf0abeca8542b74dce9f38',
  'worker/proton_pass_web_bg.wasm': 'a5414895eedf3bf96cd491a3774787fe31c10cc5469bbbfd084118258def001c',
};
const b64 = bytes => Buffer.from(bytes).toString('base64');

async function makeProtonFixture(directory, origin) {
  assert(directory, 'Supply the pinned Proton fixture directory');
  assert.equal(new URL(origin).hostname, 'localhost');
  const artifacts = new Map();
  for (const [file, sha256] of Object.entries(pinned)) {
    const bytes = await fs.readFile(path.resolve(directory, file));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256, `${file}: unexpected fixture digest`);
    artifacts.set(file, bytes);
  }
  const fixtures = [];
  const fetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('The Proton fixture generator must not make network requests'); };
  try {
    const proton = await import(pathToFileURL(path.resolve(directory, 'worker/proton_pass_web.js')).href);
    assert.equal(proton.library_version(), '2.3.4');
    for (const alg of [-7, -8]) {
      const username = `proton-fixture-${alg}`;
      const request = { challenge: randomBytes(32).toString('base64url'), rp: { id: 'localhost', name: 'Local verifier' },
        user: { id: randomBytes(20).toString('base64url'), name: username, displayName: 'Synthetic Proton user' },
        pubKeyCredParams: [{ type: 'public-key', alg }], authenticatorSelection: { residentKey: 'required' }, attestation: 'none' };
      const key = await proton.generate_passkey(origin, JSON.stringify(request), true);
      const response = key.credential.response;
      assert.equal(response.public_key_algorithm, alg);
      assert.equal(response.authenticator_data[32] & 0x18, 0x18);
      assert.equal(Buffer.from(response.authenticator_data).readUInt32BE(33), 0);
      assert.equal(b64(key.credential_id), b64(key.credential.raw_id));
      const publicKey = createPublicKey({ key: Buffer.from(response.public_key), type: 'spki', format: 'der' });
      const passkey = { content: b64(key.passkey), credentialId: b64(key.credential_id), keyId: key.key_id, domain: key.domain,
        rpId: key.rp_id, rpName: key.rp_name, userId: b64(key.user_id), userHandle: b64(key.user_handle),
        userName: key.user_name, userDisplayName: key.user_display_name };
      const item = { itemId: `fixture-${alg}`, contentFormatVersion: 8, state: 1, data: { type: 'login',
        metadata: { name: `Synthetic Proton ${alg}`, note: 'Offline registration fixture' },
        content: { itemUsername: username, password: 'Synthetic-Proton-Pass-Migration#2026', urls: [origin], passkeys: [passkey] } } };
      fixtures.push({ item, alg, id: key.credential.id, publicKey });
    }
  } finally { globalThis.fetch = fetch; }
  const bytes = Buffer.from(JSON.stringify({ version: '5.0.0.99', vaults: { synthetic: {
    name: 'Synthetic Proton vault', items: fixtures.map(({ item }) => item),
  } } }));
  return { bytes, credentials: fixtures.map(({ alg, id, publicKey }) => ({ alg, id, publicKey })),
    archives: ['protonpass_1.17.zip', 'protonpass.zip'].map(name => artifacts.get(name)) };
}

module.exports = { makeProtonFixture };
