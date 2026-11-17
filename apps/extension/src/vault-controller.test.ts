import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFile } from 'node:fs/promises';
import init, * as wasm from '../../../crates/vault-core/pkg/vault_core.js';
import initCsv, { wasm_export_ente_auth, wasm_parse_browser_csv, wasm_parse_ente_auth } from '../../../crates/vault-importers/pkg/vault_importers.js';
import initOtp, { wasm_otp_at, wasm_totp_at, wasm_validate_totp } from '../../../crates/vault-otp/pkg/vault_otp.js';
import { prepareBrowserCsv } from './browser-csv';
import { isVaultPage } from './sender-policy';
import { VaultController } from './vault-controller';
import type { BackupExport, BrowserCsvPreview, EntePreview, OtpCode, VaultStatus, VaultItem, ItemSummary } from './vault-messages';
import type { LocalSettings, SessionState, VaultFiles } from './vault-storage';

const state = vi.hoisted(() => ({ files: undefined as VaultFiles | undefined, session: undefined as SessionState | undefined,
  settings: { autoLockMinutes: 15, pinFailures: 0 } as LocalSettings, pause: undefined as Promise<void> | undefined,
  failSave: false, pendingHotp: undefined as Uint8Array | undefined }));
vi.mock('./vault-storage', () => ({
  loadVaultFiles: async () => structuredClone(state.files),
  saveVaultFiles: async (files: VaultFiles, queueHotpChange = false) => {
    if (state.failSave) throw new Error('Test disk write failed');
    state.files = structuredClone(files);
    if (queueHotpChange) state.pendingHotp = new Uint8Array(files.snap);
  },
  loadSessionState: async () => structuredClone(state.session),
  saveSessionState: async (session: SessionState) => { state.session = structuredClone(session); },
  clearSessionState: async () => { state.session = undefined; },
  loadSettings: async () => structuredClone(state.settings),
  saveSettings: async (settings: LocalSettings) => { state.settings = structuredClone(settings); },
}));
vi.mock('./vault-core', () => ({ loadVaultCore: async () => wasm, randomBytes: (length: number) => crypto.getRandomValues(new Uint8Array(length)) }));
vi.mock('./bridge', () => ({
  offscreen: vi.fn(),
  derive: async (operation: keyof typeof wasm | 'parse-browser-csv' | 'validate-totp' | 'generate-hotp' | 'parse-ente' | 'export-ente', args: unknown[]) => {
    if (operation === 'parse-browser-csv') return prepareBrowserCsv(wasm_parse_browser_csv(args[0] as Uint8Array));
    if (operation === 'parse-ente') return wasm_parse_ente_auth(args[0] as Uint8Array, args[1] as string);
    if (operation === 'export-ente') return wasm_export_ente_auth(args[0] as string);
    if (operation === 'generate-hotp') return wasm_otp_at(args[0] as string, 0, 0);
    if (operation === 'validate-totp') {
      try { wasm_validate_totp(args[0] as string); }
      catch (error) { throw new Error(String(error)); }
      return null;
    }
    if (state.pause && operation === 'wasm_unlock_head_with_password') await state.pause;
    const result = (wasm[operation] as (...a: unknown[]) => unknown)(...args);
    if (result instanceof Uint8Array) return Array.from(result);
    if (result instanceof wasm.WasmInitVaultOutput) {
      const value = { head: Array.from(result.head_bytes), snap: Array.from(result.snap_bytes), wrap: Array.from(result.session_wrap_bytes),
        vaultId: result.vault_id, keyEpoch: Number(result.key_epoch), recoveryCode: result.recovery_code };
      result.free(); return value;
    }
    if (result instanceof wasm.WasmHeadRotationOutput) {
      const value = { head: Array.from(result.head_bytes), wrap: Array.from(result.session_wrap_bytes), keyEpoch: Number(result.key_epoch) };
      result.free(); return value;
    }
    return result;
  },
}));
const password = 'Correct-Master-Password#2026';
const proof = { method: 'master' as const, secret: password };
const record = (title = 'MyUniqueTestSecret_9981', requireReprompt = false): VaultItem => ({
  id: '', title, data: { kind: 'login', username: 'tester', password: 'Unique-Secret-Pass#719', uris: [{ uri: 'https://example-bank.com' }] },
  note: '', customFields: [], tags: [], pinned: false, requireReprompt, trashed: false,
});
let fixture: VaultFiles;
let recoveryCode: string;
beforeAll(async () => {
  await init({ module_or_path: await readFile(new URL('../../../crates/vault-core/pkg/vault_core_bg.wasm', import.meta.url)) });
  await initCsv({ module_or_path: await readFile(new URL('../../../crates/vault-importers/pkg/vault_importers_bg.wasm', import.meta.url)) });
  await initOtp({ module_or_path: await readFile(new URL('../../../crates/vault-otp/pkg/vault_otp_bg.wasm', import.meta.url)) });
  const output = wasm.wasm_create_new_vault(password, 32768, 2, 4, crypto.getRandomValues(new Uint8Array(32)), Date.now());
  fixture = { head: output.head_bytes, snap: output.snap_bytes, vaultId: output.vault_id, keyEpoch: Number(output.key_epoch), updatedAtMs: Date.now(), changesSinceBackup: 0 };
  recoveryCode = output.recovery_code;
  output.free();
});
beforeEach(() => {
  state.files = structuredClone(fixture); state.session = undefined; state.pause = undefined;
  state.failSave = false;
  state.pendingHotp = undefined;
  state.settings = { autoLockMinutes: 15, pinFailures: 0 };
  vi.stubGlobal('browser', { alarms: { create: vi.fn(), clear: vi.fn() }, runtime: { sendMessage: async () => undefined },
    storage: { session: { get: async () => ({}), set: vi.fn() } } });
});
async function unlocked() { const controller = new VaultController(); await controller.handle({ type: 'unlock', password }); return controller; }
describe('real WASM + background session integration', () => {
  it('restores after service worker recreation, then rejects the expired session', async () => {
    await unlocked();
    const recreated = new VaultController();
    expect((await recreated.handle({ type: 'status' }) as VaultStatus).unlocked).toBe(true);
    state.session!.lastActivityMs = Date.now() - 16 * 60000;
    const expired = new VaultController();
    expect((await expired.handle({ type: 'status' }) as VaultStatus).unlocked).toBe(false);
    expect(state.session).toBeUndefined();
    await expect(expired.handle({ type: 'list' })).rejects.toThrow('解锁');
  });
  it('destroys the PIN wrapper on the fifth failed attempt and refuses a correct sixth PIN', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'create-pin', pin: '734928', proof });
    await controller.lock();
    for (let attempt = 0; attempt < 5; attempt++) {
      await expect(new VaultController().handle({ type: 'unlock-pin', pin: '111111' })).rejects.toBeDefined();
      expect(state.settings.pinFailures).toBe(attempt + 1);
    }
    expect(state.settings).not.toHaveProperty('pinWrap');
    await expect(new VaultController().handle({ type: 'unlock-pin', pin: '734928' })).rejects.toThrow('PIN 已禁用');
  });
  it('accepts a correct fifth attempt and resets failures', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'create-pin', pin: '734928', proof });
    await controller.lock();
    state.settings.pinFailures = 4;
    expect((await controller.handle({ type: 'unlock-pin', pin: '734928' }) as VaultStatus).unlocked).toBe(true);
    expect(state.settings.pinFailures).toBe(0);
    expect(state.settings.pinWrap).toBeInstanceOf(Uint8Array);
  });
  it('requires actual proof for protected reads and updates, including forged booleans', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Protected', true)) });
    const [summary] = await controller.handle({ type: 'list' }) as ItemSummary[];
    await expect(controller.handle({ type: 'get', id: summary!.id, ...{ repromptVerified: true } })).rejects.toThrow('再次验证');
    const item = await controller.handle({ type: 'get', id: summary!.id, proof }) as VaultItem;
    await expect(controller.handle({ type: 'upsert', itemJson: JSON.stringify({ ...item, requireReprompt: false }) })).rejects.toThrow('再次验证');
    expect(item.title).toBe('Protected');
  });
  it('persists ciphertext only and serializes concurrent edits without dropping either record', async () => {
    const controller = await unlocked();
    await Promise.all([controller.handle({ type: 'upsert', itemJson: JSON.stringify(record()) }), controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Second')) })]);
    expect(await controller.handle({ type: 'list' })).toHaveLength(2);
    for (const marker of ['MyUniqueTestSecret_9981', 'example-bank.com', 'Unique-Secret-Pass#719']) {
      expect(new TextDecoder().decode(state.files!.head)).not.toContain(marker);
      expect(new TextDecoder().decode(state.files!.snap)).not.toContain(marker);
      expect(JSON.stringify(state.settings)).not.toContain(marker);
    }
  });
  it('clears only the entire trash the user confirmed and refuses a stale confirmation', async () => {
    const controller = await unlocked();
    for (const title of ['Match', 'Hidden by search', 'Still active']) {
      await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record(title)) });
    }
    const items = await controller.handle({ type: 'list' }) as ItemSummary[];
    const id = (title: string) => items.find(item => item.title === title)!.id;
    const confirmed = [id('Match'), id('Hidden by search')];
    await controller.handle({ type: 'trash', id: confirmed[0]!, trashed: true });
    await controller.handle({ type: 'trash', id: confirmed[1]!, trashed: true });
    await expect(controller.handle({ type: 'empty-trash', expectedIds: [confirmed[0]!] })).rejects.toThrow('重新核对');
    await controller.handle({ type: 'trash', id: confirmed[1]!, trashed: false });
    await controller.handle({ type: 'trash', id: id('Still active'), trashed: true });
    await expect(controller.handle({ type: 'empty-trash', expectedIds: confirmed })).rejects.toThrow('重新核对');
    expect(await controller.handle({ type: 'list' })).toHaveLength(3);
    await controller.handle({ type: 'trash', id: id('Still active'), trashed: false });
    await controller.handle({ type: 'trash', id: confirmed[1]!, trashed: true });
    expect(await controller.handle({ type: 'empty-trash', expectedIds: confirmed })).toBe(2);
    expect(await controller.handle({ type: 'list' })).toMatchObject([{ title: 'Still active', trashed: false }]);
  });
  it('rejects an oversized save and retains the last readable vault on disk and in memory', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Keep this')) });
    const stored = structuredClone(state.files);
    const item = record('Too big');
    item.note = 'x'.repeat(32 * 1024 * 1024);
    await expect(controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) })).rejects.toThrow('32 MiB');
    expect(state.files).toEqual(stored);
    expect(await controller.handle({ type: 'list' })).toMatchObject([{ title: 'Keep this' }]);
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Next edit')) });
    await controller.lock();
    expect(await (await unlocked()).handle({ type: 'list' })).toHaveLength(2);
  });
  it('retains the backup reminder until confirmed and never clears edits made after exporting', async () => {
    const controller = await unlocked();
    const exportBackup = async () => await controller.handle({ type: 'export', password: 'Test-Backup-Password#2026', proof }) as BackupExport;
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('First')) });
    const first = await exportBackup();
    expect(first.bytes.length).toBeGreaterThan(0);
    expect(state.files!.changesSinceBackup).toBe(1);
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Second')) });
    const second = await exportBackup();
    expect(state.files!.changesSinceBackup).toBe(2);
    const recreated = new VaultController();
    await recreated.handle({ type: 'backup-saved', receipt: first.receipt });
    expect(state.files!.changesSinceBackup).toBe(1);
    await recreated.handle({ type: 'backup-saved', receipt: second.receipt });
    await recreated.handle({ type: 'upsert', itemJson: JSON.stringify(record('Third')) });
    await recreated.handle({ type: 'backup-saved', receipt: first.receipt });
    await recreated.handle({ type: 'backup-saved', receipt: second.receipt });
    expect(state.files!.changesSinceBackup).toBe(1);
  });
  it('previews CSV without writing, rejects stale previews, and adds only new site/account pairs', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Existing', true)) });
    const [original] = await controller.handle({ type: 'list' }) as ItemSummary[];
    await controller.handle({ type: 'trash', id: original!.id, trashed: true });
    const bytes = Array.from(new TextEncoder().encode([
      'name,url,username,password,note,OTPAuth',
      'Do not replace,https://EXAMPLE-bank.com:443/settings,tester,Other-Password,,',
      'New login,https://new.example/a,person,New-Test-Password,"A, B",',
      'Same CSV account,https://new.example/b,person,Different-Password,,',
      'Non-web,ftp://other.example,user,Invalid-Password,,not-imported',
    ].join('\n')));
    const before = structuredClone(state.files);
    const preview = () => controller.handle({ type: 'preview-browser-csv', bytes }) as Promise<BrowserCsvPreview>;
    const importCsv = (stamp: string, check = proof, source = bytes) =>
      controller.handle({ type: 'import-browser-csv', bytes: source, stamp, proof: check });
    const old = await preview();
    expect(old).toMatchObject({
      ready: 1, skipped: 2, invalid: 1, ignoredOtp: 1,
      sample: [{ title: 'New login', site: 'new.example', username: 'person' }],
    });
    expect(JSON.stringify(old)).not.toContain('New-Test-Password');
    expect(state.files).toEqual(before);
    await expect(importCsv(old.stamp, proof, [...bytes, 10])).rejects.toThrow('重新预览');
    await expect(importCsv(old.stamp, { method: 'master', secret: 'Wrong-Test-Password' })).rejects.toThrow('主密码验证失败');
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Different after preview')) });
    await expect(importCsv(old.stamp)).rejects.toThrow('重新预览');
    expect(await importCsv((await preview()).stamp)).toBe(1);
    const imported = (await controller.handle({ type: 'list' }) as ItemSummary[]).find(item => item.title === 'New login')!;
    expect((await controller.handle({ type: 'get', id: imported.id }) as VaultItem).note).toBe('A, B');
    expect((await controller.handle({ type: 'get', id: original!.id, proof }) as VaultItem).data.password).toBe('Unique-Secret-Pass#719');
    const after = structuredClone(state.files);
    const repeated = await preview();
    expect(repeated.ready).toBe(0);
    expect(await importCsv(repeated.stamp)).toBe(0);
    expect(state.files).toEqual(after);
    expect(new TextDecoder().decode(state.files!.snap)).not.toContain('New-Test-Password');
  });
  it('rejects invalid TOTP settings and restores a valid protected setup from ciphertext', async () => {
    const controller = await unlocked();
    const item = record('Two-step login', true);
    item.data.totpUri = '123456';
    await expect(controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) })).rejects.toThrow('设置密钥无效');
    expect(await controller.handle({ type: 'list' })).toEqual([]);
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    item.data.totpUri = secret;
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    expect(new TextDecoder().decode(state.files!.snap)).not.toContain(secret);
    await controller.lock();
    const restored = await unlocked();
    const [summary] = await restored.handle({ type: 'list' }) as ItemSummary[];
    expect(summary!.hasTotp).toBe(true);
    await expect(restored.handle({ type: 'get', id: summary!.id })).rejects.toThrow('再次验证');
    const loaded = await restored.handle({ type: 'get', id: summary!.id, proof }) as VaultItem;
    expect(wasm_totp_at(String(loaded.data.totpUri), 59)).toBe('287082:60');
  });
  it('recovery rotates only the header and invalidates shortcuts', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'create-pin', pin: '734928', proof });
    const previous = new Uint8Array(state.files!.snap);
    await controller.lock();
    await controller.handle({ type: 'recover', recoveryCode, newPassword: 'New-Correct-Password#2026' });
    expect(state.files!.snap).toEqual(previous);
    expect(state.files!.keyEpoch).toBe(fixture.keyEpoch + 1);
    expect(state.settings.pinWrap).toBeUndefined();
    await controller.lock();
    await expect(controller.handle({ type: 'unlock', password })).rejects.toBeDefined();
  });
  it('does not resurrect a session if lock is requested during password derivation', async () => {
    const controller = new VaultController();
    await controller.handle({ type: 'status' });
    let release!: () => void;
    state.pause = new Promise<void>(resolve => { release = resolve; });
    const pending = controller.handle({ type: 'unlock', password });
    const rejected = expect(pending).rejects.toThrow('已锁定');
    const queued = controller.handle({ type: 'unlock', password });
    const queuedRejected = expect(queued).rejects.toThrow('已锁定');
    await new Promise(resolve => setTimeout(resolve, 30));
    await controller.lock(); release(); await rejected; await queuedRejected;
    expect(state.session).toBeUndefined();
  });
});
describe('Ente migration and counter-based codes', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const bytesOf = (text: string) => Array.from(new TextEncoder().encode(text));
  const token = (kind = 'totp', label = 'GitHub%3Atester', extra = '') =>
    `otpauth://${kind}/${label}?secret=${secret}&issuer=GitHub${extra}`;

  async function addHotp(controller: VaultController, protectedItem = false) {
    const item = record('Counter token', protectedItem);
    item.data.totpUri = token('hotp', 'GitHub%3Atester', '&counter=0');
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    return (await controller.handle({ type: 'list' }) as ItemSummary[])[0]!.id;
  }

  it('commits distinct HOTP counters for concurrent callers and resumes after worker recreation', async () => {
    const controller = await unlocked();
    const id = await addHotp(controller);
    const results = await Promise.all([controller.handle({ type: 'next-hotp', id }), controller.handle({ type: 'next-hotp', id })]) as { code: OtpCode; item: VaultItem }[];
    expect(results.map(result => result.code.value)).toEqual(['755224', '287082']);
    expect(results.map(result => result.code.counter)).toEqual(['0', '1']);
    expect(state.files!.changesSinceBackup).toBe(3);
    expect(state.pendingHotp).toEqual(state.files!.snap);
    expect(new TextDecoder().decode(state.pendingHotp)).not.toContain(secret);
    const restored = new VaultController();
    const third = await restored.handle({ type: 'next-hotp', id }) as { code: OtpCode; item: VaultItem };
    expect(third.code.value).toBe('359152');
    expect(String(third.item.data.totpUri)).toContain('counter=3');
    await expect(controller.handle({ type: 'upsert', itemJson: JSON.stringify(results[0]!.item) })).rejects.toThrow('其他窗口更新');
    expect(new TextDecoder().decode(state.files!.snap)).not.toContain(secret);
  });

  it('does not expose or consume a HOTP code when saving fails, and enforces item protection', async () => {
    const controller = await unlocked();
    const id = await addHotp(controller, true);
    const before = structuredClone(state.files);
    await expect(controller.handle({ type: 'next-hotp', id })).rejects.toThrow('再次验证');
    state.failSave = true;
    await expect(controller.handle({ type: 'next-hotp', id, proof })).rejects.toThrow('disk write failed');
    expect(state.files).toEqual(before);
    expect(state.pendingHotp).toBeUndefined();
    state.failSave = false;
    const first = await controller.handle({ type: 'next-hotp', id, proof }) as { code: OtpCode };
    expect(first.code.value).toBe('755224');
    expect(first.code.counter).toBe('0');
    await controller.handle({ type: 'trash', id, trashed: true });
    await expect(controller.handle({ type: 'next-hotp', id, proof })).rejects.toThrow('没有可用');
  });

  it('previews without secrets or writes and merges only an explicitly selected matching account', async () => {
    const controller = await unlocked();
    const old = record('GitHub login', true);
    old.data.uris = [{ uri: 'https://github.com/login' }];
    old.tags = ['existing']; old.note = 'Original note';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(old) });
    const id = (await controller.handle({ type: 'list' }) as ItemSummary[])[0]!.id;
    const display = encodeURIComponent(JSON.stringify({ note: 'Imported note', tags: ['work'], pinned: true }));
    const bytes = bytesOf(token('totp', 'GitHub%3Atester', `&codeDisplay=${display}`));
    const before = structuredClone(state.files);
    const preview = await controller.handle({ type: 'preview-ente', bytes }) as EntePreview;
    expect(preview).toMatchObject({ ready: 1, invalid: 0, skipped: 0, suggestions: [{ row: 0, id }] });
    expect(JSON.stringify(preview)).not.toContain(secret);
    expect(JSON.stringify(preview)).not.toContain('Original note');
    expect(state.files).toEqual(before);
    await expect(controller.handle({ type: 'import-ente', bytes, stamp: preview.stamp, merges: [], proof: { method: 'master', secret: 'Wrong password#' } })).rejects.toThrow('主密码验证失败');
    await expect(controller.handle({ type: 'import-ente', bytes, stamp: preview.stamp, merges: [{ row: 0, id: 'forged-id' }], proof })).rejects.toThrow('重新预览');
    expect(await controller.handle({ type: 'import-ente', bytes, stamp: preview.stamp, merges: [{ row: 0, id }], proof })).toBe(1);
    const merged = await controller.handle({ type: 'get', id, proof }) as VaultItem;
    expect(merged.data.password).toBe(old.data.password);
    expect(merged.requireReprompt).toBe(true);
    expect(merged.note).toBe('Original note\n\nImported note');
    expect(merged.tags).toEqual(['existing', 'work']);
    expect(merged.pinned).toBe(true);
    expect((await controller.handle({ type: 'list' }) as ItemSummary[]).length).toBe(1);
    const repeat = await controller.handle({ type: 'preview-ente', bytes }) as EntePreview;
    expect(repeat).toMatchObject({ ready: 0, skipped: 1 });
  });

  it('preserves independent tokens and trash and rejects a stale import after file or vault changes', async () => {
    const controller = await unlocked();
    const bytes = bytesOf(token('steam', 'Steam%3Aaccount', '&digits=5&codeDisplay=' + encodeURIComponent(JSON.stringify({ trashed: true, tags: ['saved'], note: 'Keep me' }))));
    const first = await controller.handle({ type: 'preview-ente', bytes }) as EntePreview;
    expect(first).toMatchObject({ ready: 1, trashed: 1, suggestions: [] });
    await expect(controller.handle({ type: 'import-ente', bytes: [...bytes, 10], stamp: first.stamp, merges: [], proof })).rejects.toThrow('重新预览');
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Added after preview')) });
    await expect(controller.handle({ type: 'import-ente', bytes, stamp: first.stamp, merges: [], proof })).rejects.toThrow('重新预览');
    const latest = await controller.handle({ type: 'preview-ente', bytes }) as EntePreview;
    state.failSave = true;
    await expect(controller.handle({ type: 'import-ente', bytes, stamp: latest.stamp, merges: [], proof })).rejects.toThrow('disk write failed');
    expect((await controller.handle({ type: 'list' }) as ItemSummary[]).length).toBe(1);
    state.failSave = false;
    await controller.handle({ type: 'import-ente', bytes, stamp: latest.stamp, merges: [], proof });
    const saved = (await controller.handle({ type: 'list' }) as ItemSummary[]).find(item => item.hasTotp)!;
    expect(saved.trashed).toBe(true);
    expect(saved.trashedAtMs).toBeGreaterThan(0);
    const item = await controller.handle({ type: 'get', id: saved.id }) as VaultItem;
    expect(item.data.uris).toEqual([]);
    expect(item.note).toBe('Keep me');
  });

  it('never suggests merging a different account, deceptive domain, existing token or ambiguous match', async () => {
    const controller = await unlocked();
    for (const [title, username, site, setup] of [
      ['Wrong user', 'different', 'https://github.com', null],
      ['Deceptive domain', 'tester', 'https://github.com.evil.test', null],
      ['Has code', 'tester', 'https://github.com', token('hotp', 'GitHub%3Atester', '&counter=10')],
      ['First match', 'tester', 'https://github.com', null],
      ['Second match', 'tester', 'https://github.com', null],
    ]) {
      const item = record(String(title));
      item.data = { ...item.data, username, uris: [{ uri: site }], totpUri: setup };
      await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    }
    const preview = await controller.handle({ type: 'preview-ente', bytes: bytesOf(token()) }) as EntePreview;
    expect(preview.ready).toBe(1);
    expect(preview.suggestions).toEqual([]);
  });

  it('requires a master password and explicit plaintext consent for a lossless export', async () => {
    const controller = await unlocked();
    const id = await addHotp(controller, true);
    await controller.handle({ type: 'next-hotp', id, proof });
    await controller.handle({ type: 'trash', id, trashed: true });
    await expect(controller.handle({ type: 'export-ente', proof, confirmPlaintext: false })).rejects.toThrow('确认风险');
    await expect(controller.handle({ type: 'export-ente', proof: { method: 'pin', secret: '734928' }, confirmPlaintext: true })).rejects.toThrow('主密码');
    await expect(controller.handle({ type: 'export-ente', proof: { method: 'master', secret: 'Wrong-Password' }, confirmPlaintext: true })).rejects.toThrow('主密码验证失败');
    const exported = await controller.handle({ type: 'export-ente', proof, confirmPlaintext: true }) as string;
    expect(exported).toContain('counter=1');
    expect(exported).not.toContain('Unique-Secret-Pass#719');
    const decoded = JSON.parse(wasm_parse_ente_auth(new TextEncoder().encode(exported), '[]'));
    expect(decoded.rows[0].trashed).toBe(true);
    const original = await controller.handle({ type: 'preview-ente', bytes: bytesOf(token('hotp', 'GitHub%3Atester', '&counter=0')) }) as EntePreview;
    expect(original).toMatchObject({ ready: 0, skipped: 1 });
  });
});

describe('message source boundary', () => {
  const id = 'trusted-extension';
  it('allows only extension UI, including full page tabs', () => {
    expect(isVaultPage({ id, url: 'chrome-extension://' + id + '/popup.html', origin: 'chrome-extension://' + id }, id)).toBe(true);
    expect(isVaultPage({ id, url: 'chrome-extension://' + id + '/sidepanel.html', tab: { url: 'chrome-extension://' + id + '/sidepanel.html' } }, id)).toBe(true);
    for (const sender of [
      { id, url: 'https://example.com', origin: 'https://example.com', tab: { url: 'https://example.com' } },
      { id, url: 'chrome-extension://' + id + '/popup.html', origin: 'https://example.com' },
      { id, url: 'chrome-extension://' + id + '/popup.html', tab: { url: 'https://example.com' } },
      { id, url: 'chrome-extension://' + id + '/offscreen.html' },
      { id: 'other', url: 'chrome-extension://' + id + '/popup.html' },
    ]) expect(isVaultPage(sender, id)).toBe(false);
  });
});
