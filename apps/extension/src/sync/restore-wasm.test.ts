import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { beforeAll, expect, it } from 'vitest';
import initCore, { WasmVaultEngine, wasm_create_new_vault } from '../../../../crates/vault-core/pkg/vault_core.js';
import initKeys, { wasm_passkey_candidates, wasm_passkey_perform } from '../../../../crates/vault-passkeys/pkg/vault_passkeys.js';
import initSync, { wasm_otp_at, wasm_sync_authenticate_head, wasm_sync_compact, wasm_sync_create_genesis,
  wasm_sync_restore_content } from '../../../../crates/vault-sync/pkg/vault_sync.js';

beforeAll(async () => {
  await Promise.all([
    initCore({ module_or_path: await readFile(new URL('../../../../crates/vault-core/pkg/vault_core_bg.wasm', import.meta.url)) }),
    initKeys({ module_or_path: await readFile(new URL('../../../../crates/vault-passkeys/pkg/vault_passkeys_bg.wasm', import.meta.url)) }),
    initSync({ module_or_path: await readFile(new URL('../../../../crates/vault-sync/pkg/vault_sync_bg.wasm', import.meta.url)) }),
  ]);
});

type Files = { head: Uint8Array; snap: Uint8Array };
const takeFiles = (result: Files & { free(): void }): Files => {
  try { return { head: result.head, snap: result.snap }; }
  finally { result.free(); }
};
const takeLocal = (result: { head_bytes: Uint8Array; snap_bytes: Uint8Array; free(): void }): Files => {
  try { return { head: result.head_bytes, snap: result.snap_bytes }; }
  finally { result.free(); }
};
const digest = (input: string | Buffer) => createHash('sha256').update(input).digest();
const decode = (value: string) => Buffer.from(value, 'base64url');

it('authenticates WebDAV history, keeps verified counts across HOTP periods and pauses unknown HOTP/Passkeys', () => {
  const key = randomBytes(32), empty = new Uint8Array();
  const opened = wasm_create_new_vault('Synthetic restore fixture', 32768, 2, 1, key, 1000);
  const wrap = opened.session_wrap_bytes;
  let local = takeLocal(opened);
  const rpId = 'example.com', origin = `https://${rpId}`;
  const request = (kind: string) => ({ kind, rpId, origin, uv: 'required', challenge: randomBytes(32).toString('base64url') });
  const user = { id: 'dGVzdC1hY2NvdW50', name: 'fixture user', display: 'Fixture Account' };
  const webauthn = (files: Files, json: string, selection: object) => wasm_passkey_perform(
    key, wrap, files.head, files.snap, json, JSON.stringify({ now: 5000, verified: true, increment: false, ...selection }), empty, empty);
  const withEngine = <T,>(files: Files, work: (engine: WasmVaultEngine) => T): T => {
    const engine = new WasmVaultEngine();
    try { engine.restore_from_session(key, wrap, files.head, files.snap); return work(engine); }
    finally { engine.free(); }
  };
  const oldId = '00000000001800_09abcd11_00000000000001';
  const currentId = '00000000002000_09abcd11_00000000000002';
  const hotp = 'otpauth://hotp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0&period=60';
  try {
    local = withEngine(local, engine => takeLocal(engine.upsert_item_json(JSON.stringify({
      title: 'HOTP fixture', data: { kind: 'login', username: 'hotp', totpUri: hotp },
    }), 2000)));
    const [otpItem] = withEngine(local, engine => JSON.parse(engine.list_summaries_json())) as { id: string }[];
    if (!otpItem) throw new Error('The HOTP fixture was not saved');
    const otpId = otpItem.id;
    const registered = ([[-7, true], [-8, true], [-7, false]] as const).map(([algorithm, increment]) => {
      const result = webauthn(local, JSON.stringify({ ...request('register'), user, algorithms: [algorithm], resident: true }), { increment });
      const reply = JSON.parse(result.reply) as { id: string; publicKey: string };
      local = takeFiles(result);
      return { algorithm, increment, id: reply.id, publicKey: createPublicKey({ key: decode(reply.publicKey), format: 'der', type: 'spki' }) };
    });
    const historical = takeFiles(wasm_sync_create_genesis(key, wrap, local.head, local.snap, oldId));
    const authenticated = wasm_sync_authenticate_head(historical.head, key, wrap);
    try { local = { head: authenticated.local_head, snap: historical.snap }; }
    finally { authenticated.free(); }

    const checkSign = (files: Files, credential: typeof registered[number], count: number | null): Files => {
      const ask = request('assert');
      const json = JSON.stringify(ask);
      const choices = JSON.parse(wasm_passkey_candidates(key, wrap, files.head, files.snap, json)) as { id: string; itemId: string; suspended: boolean }[];
      const choice = choices.find(entry => entry.id === credential.id);
      expect(choice?.suspended).toBe(count === null);
      const perform = () => webauthn(files, json, { itemId: choice!.itemId, credentialId: choice!.id });
      if (count === null) { expect(perform).toThrow('counter is unverified'); return files; }
      const signed = perform();
      try {
        const reply = JSON.parse(signed.reply);
        const data = decode(reply.authenticatorData), client = decode(reply.clientDataJson);
        expect(reply.id).toBe(credential.id);
        expect(reply.userHandle).toBe(user.id);
        expect(JSON.parse(client.toString())).toMatchObject({ origin, challenge: ask.challenge, type: 'webauthn.get' });
        expect(data.subarray(0, 32)).toEqual(digest(rpId));
        expect(data.readUInt32BE(33)).toBe(count);
        expect(verify(credential.algorithm === -7 ? 'sha256' : null, Buffer.concat([data, digest(client)]),
          credential.publicKey, decode(reply.signature))).toBe(true);
        expect(signed.snap.length > 0).toBe(credential.increment);
        return signed.snap.length > 0 ? { head: signed.head, snap: signed.snap } : files;
      } finally { signed.free(); }
    };
    for (const credential of registered) local = checkSign(local, credential, credential.increment ? 1 : 0);
    local = withEngine(local, engine => {
      const row = JSON.parse(engine.get_item_json(otpId, true));
      const issued = JSON.parse(wasm_otp_at(row.data.totpUri, 0, 0));
      expect(issued).toMatchObject({ counter: '0', value: '755224' });
      row.data.totpUri = issued.nextSetupKey.replace('&period=60', '&period=45');
      return takeLocal(engine.upsert_item_json(JSON.stringify(row), 5100));
    });
    const compacted = takeFiles(wasm_sync_compact(key, wrap, historical.head, local.head, local.snap, currentId));
    const restore = (from: Files) => takeFiles(wasm_sync_restore_content(
      key, wrap, compacted.head, from.head, from.snap, `snap_${oldId}`, historical.snap));
    const otpSetup = (files: Files) => withEngine(files, engine => JSON.parse(engine.get_item_json(otpId, true)).data.totpUri as string);

    const restored = restore(local);
    expect(JSON.parse(wasm_otp_at(otpSetup(restored), 0, 0))).toMatchObject({ counter: '1', value: '287082' });
    for (const credential of registered) checkSign(restored, credential, credential.increment ? 2 : 0);

    const withoutEvidence = withEngine(local, engine => {
      const entries = JSON.parse(engine.list_summaries_json()) as { id: string }[];
      for (const { id } of entries) engine.set_trashed(id, true, 5300).free();
      return takeLocal(engine.empty_trash(5400));
    });
    const unverified = restore(withoutEvidence);
    expect(() => wasm_otp_at(otpSetup(unverified), 0, 0)).toThrow('无法确认');
    for (const credential of registered) checkSign(unverified, credential, credential.increment ? null : 0);
  } finally { key.fill(0); wrap.fill(0); }
});
