import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFile } from 'node:fs/promises';
import init, * as wasm from '../../../crates/vault-core/pkg/vault_core.js';
import { isVaultPage } from './sender-policy';
import { VaultController } from './vault-controller';
import type { VaultStatus, VaultItem, ItemSummary } from './vault-messages';
import type { LocalSettings, SessionState, VaultFiles } from './vault-storage';

const state = vi.hoisted(() => ({ files: undefined as VaultFiles | undefined, session: undefined as SessionState | undefined,
  settings: { autoLockMinutes: 15, pinFailures: 0 } as LocalSettings, pause: undefined as Promise<void> | undefined }));
vi.mock('./vault-storage', () => ({
  loadVaultFiles: async () => structuredClone(state.files),
  saveVaultFiles: async (files: VaultFiles) => { state.files = structuredClone(files); },
  loadSessionState: async () => structuredClone(state.session),
  saveSessionState: async (session: SessionState) => { state.session = structuredClone(session); },
  clearSessionState: async () => { state.session = undefined; },
  loadSettings: async () => structuredClone(state.settings),
  saveSettings: async (settings: LocalSettings) => { state.settings = structuredClone(settings); },
}));
vi.mock('./vault-core', () => ({ loadVaultCore: async () => wasm, randomBytes: (length: number) => crypto.getRandomValues(new Uint8Array(length)) }));
vi.mock('./bridge', () => ({
  offscreen: vi.fn(),
  derive: async (operation: keyof typeof wasm, args: unknown[]) => {
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
  const output = wasm.wasm_create_new_vault(password, 32768, 2, 4, crypto.getRandomValues(new Uint8Array(32)), Date.now());
  fixture = { head: output.head_bytes, snap: output.snap_bytes, vaultId: output.vault_id, keyEpoch: Number(output.key_epoch), updatedAtMs: Date.now(), changesSinceBackup: 0 };
  recoveryCode = output.recovery_code;
  output.free();
});
beforeEach(() => {
  state.files = structuredClone(fixture); state.session = undefined; state.pause = undefined;
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
