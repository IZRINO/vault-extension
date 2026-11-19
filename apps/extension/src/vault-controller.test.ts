import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFile } from 'node:fs/promises';
import init, * as wasm from '../../../crates/vault-core/pkg/vault_core.js';
import initCsv, { wasm_export_ente_auth, wasm_parse_browser_csv, wasm_parse_ente_auth, wasm_csv_headers, wasm_parse_mapped_csv, wasm_export_login_csv,
  wasm_parse_authenticator_backup, wasm_portable_import, wasm_portable_export } from '../../../crates/vault-importers/pkg/vault_importers.js';
import initOtp, { wasm_otp_at, wasm_totp_at, wasm_validate_totp } from '../../../crates/vault-otp/pkg/vault_otp.js';
import initPreferences, { wasm_open_preferences, wasm_seal_preferences, wasm_open_webdav, wasm_seal_webdav,
  wasm_sign_authorization, wasm_verify_authorization } from '../../../crates/vault-preferences/pkg/vault_preferences.js';
import initSync, { wasm_make_local_wal, wasm_sync_import_pack, wasm_verify_local_wal } from '../../../crates/vault-sync/pkg/vault_sync.js';
import { prepareBrowserCsv } from './browser-csv';
import { isVaultPage } from './sender-policy';
import { VaultController } from './vault-controller';
import { offscreen } from './bridge';
import type { BackupExport, BrowserCsvPreview, EntePreview, HotpCode, ItemDetailData, VaultStatus, VaultItem, ItemSummary, VaultMessage } from './vault-messages';
import type { JournalCommit, LocalSettings, SessionState, VaultFiles } from './vault-storage';

const state = vi.hoisted(() => ({ files: undefined as VaultFiles | undefined, session: undefined as SessionState | undefined,
  settings: { autoLockMinutes: 15, pinFailures: 0 } as LocalSettings, pause: undefined as Promise<void> | undefined,
  pauseSessionClear: undefined as Promise<void> | undefined, idleState: 'active' as 'active' | 'locked',
  failSave: false, pendingWal: [] as JournalCommit[], legacy: false, local: {} as Record<string, unknown> }));
vi.mock('./vault-storage', () => ({
  loadVaultFiles: async () => structuredClone(state.files),
  loadRemoteAnchor: async () => undefined,
  loadJournal: async () => ({ clock: structuredClone(state.pendingWal.at(-1)?.state), legacy: state.legacy }),
  saveVaultFiles: async (files: VaultFiles, change?: JournalCommit) => {
    if (state.failSave) throw new Error('Test disk write failed');
    state.files = structuredClone(files);
    if (change) {
      state.pendingWal.push(structuredClone(change));
      if (change.replaceLegacy) state.legacy = false;
    }
  },
  loadSessionState: async () => structuredClone(state.session),
  saveSessionState: async (session: SessionState) => { state.session = structuredClone(session); },
  clearSessionState: async () => {
    if (state.pauseSessionClear) await state.pauseSessionClear;
    state.session = undefined;
  },
  loadSettings: async () => structuredClone(state.settings),
  saveSettings: async (settings: LocalSettings) => { state.settings = structuredClone(settings); },
}));
vi.mock('./vault-core', () => ({ loadVaultCore: async () => wasm, randomBytes: (length: number) => crypto.getRandomValues(new Uint8Array(length)) }));
vi.mock('./bridge', () => ({
  offscreen: vi.fn(),
  derive: async (operation: string, args: unknown[]) => {
    if (operation === 'sync:local-wal') return Array.from(wasm_make_local_wal(...args as Parameters<typeof wasm_make_local_wal>));
    if (operation === 'sync:import-pack') {
      const result = wasm_sync_import_pack(...args as Parameters<typeof wasm_sync_import_pack>);
      try { return { head: Array.from(result.head), snap: Array.from(result.snap), added: result.added, updated: result.updated, skipped: result.skipped }; }
      finally { result.free(); }
    }
    if (operation === 'sign-authorization') return Array.from(wasm_sign_authorization(...args as Parameters<typeof wasm_sign_authorization>));
    if (operation === 'verify-authorization') return wasm_verify_authorization(...args as Parameters<typeof wasm_verify_authorization>);
    if (operation === 'seal-preferences') return Array.from(wasm_seal_preferences(args[0] as Uint8Array, args[1] as Uint8Array, args[2] as string));
    if (operation === 'open-preferences') return wasm_open_preferences(args[0] as Uint8Array, args[1] as Uint8Array, args[2] as Uint8Array);
    if (operation === 'seal-webdav') return Array.from(wasm_seal_webdav(args[0] as Uint8Array, args[1] as Uint8Array, args[2] as string));
    if (operation === 'open-webdav') return wasm_open_webdav(args[0] as Uint8Array, args[1] as Uint8Array, args[2] as Uint8Array);
    if (operation === 'parse-authenticator-backup') return wasm_parse_authenticator_backup(...args as Parameters<typeof wasm_parse_authenticator_backup>);
    if (operation === 'portable-import') {
      const result = wasm_portable_import(...args as Parameters<typeof wasm_portable_import>);
      try { return { report: result.report, head: Array.from(result.head), snap: Array.from(result.snap), count: result.count }; }
      finally { result.free(); }
    }
    if (operation === 'portable-export') return wasm_portable_export(...args as Parameters<typeof wasm_portable_export>);
    if (operation === 'csv-headers') return wasm_csv_headers(args[0] as Uint8Array);
    if (operation === 'parse-mapped-csv') return wasm_parse_mapped_csv(args[0] as Uint8Array, args[1] as string);
    if (operation === 'export-login-csv') return wasm_export_login_csv(args[0] as string);
    if (operation === 'parse-browser-csv') return prepareBrowserCsv(wasm_parse_browser_csv(args[0] as Uint8Array));
    if (operation === 'parse-ente') return wasm_parse_ente_auth(args[0] as Uint8Array, args[1] as string);
    if (operation === 'export-ente') return wasm_export_ente_auth(args[0] as string);
    if (operation === 'generate-hotp' || operation === 'generate-otp') return wasm_otp_at(args[0] as string, args[1] as number ?? 0, args[2] as number ?? 0);
    if (operation === 'validate-totp') {
      try { wasm_validate_totp(args[0] as string); }
      catch (error) { throw new Error(String(error)); }
      return null;
    }
    if (state.pause && operation === 'wasm_unlock_head_with_password') await state.pause;
    const result = (wasm[operation as keyof typeof wasm] as (...a: unknown[]) => unknown)(...args);
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
  await initPreferences({ module_or_path: await readFile(new URL('../../../crates/vault-preferences/pkg/vault_preferences_bg.wasm', import.meta.url)) });
  await initSync({ module_or_path: await readFile(new URL('../../../crates/vault-sync/pkg/vault_sync_bg.wasm', import.meta.url)) });
  const output = wasm.wasm_create_new_vault(password, 32768, 2, 4, crypto.getRandomValues(new Uint8Array(32)), Date.now());
  fixture = { head: output.head_bytes, snap: output.snap_bytes, vaultId: output.vault_id, keyEpoch: Number(output.key_epoch), updatedAtMs: Date.now(), changesSinceBackup: 0 };
  recoveryCode = output.recovery_code;
  output.free();
});
beforeEach(() => {
  state.files = structuredClone(fixture); state.session = undefined; state.pause = undefined;
  state.pauseSessionClear = undefined;
  state.idleState = 'active';
  state.failSave = false;
  state.pendingWal = [];
  state.legacy = false;
  state.local = {};
  state.settings = { autoLockMinutes: 15, pinFailures: 0 };
  vi.stubGlobal('browser', { alarms: { create: vi.fn(), clear: vi.fn() }, runtime: { sendMessage: async () => undefined },
    idle: { queryState: async () => state.idleState },
    storage: { session: { get: async () => ({}), set: vi.fn() }, local: {
      get: async () => structuredClone(state.local),
      set: async (values: Record<string, unknown>) => { Object.assign(state.local, structuredClone(values)); },
      remove: async (key: string) => { delete state.local[key]; },
    } } });
});
async function unlocked() { const controller = new VaultController(); await controller.handle({ type: 'unlock', password }); return controller; }
describe('real WASM + background session integration', () => {
  it('tests new WebDAV settings read-only, persists a circuit break and applies opt-in HTTPS time to codes', async () => {
    const time = Math.floor(Date.now() / 30_000) * 30_000 + 95_000;
    const input = { provider: 'nutstore', base: '', folder: 'test', username: 'private-fixture-account', password: 'fixture-secret-for-this-test' } as const;
    const listed = () => new Response('<multistatus xmlns="DAV:"><response><href>/dav/test/</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>',
      { status: 207, headers: { Date: new Date(time + 45_000).toUTCString() } });
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => listed());
    const date = vi.spyOn(Date, 'now').mockReturnValue(time);
    try {
      state.files = undefined;
      const setupController = new VaultController();
      await expect(setupController.handle({ type: 'webdav-test', input })).resolves.toMatchObject({ kind: 'empty', offsetSeconds: 45 });
      expect(state.local).toEqual({});
      state.files = structuredClone(fixture);
      const controller = await unlocked();
      fetchMock.mockResolvedValueOnce(new Response(null, { status: 429 }));
      await expect(controller.handle({ type: 'webdav-test', input, remember: true })).rejects.toThrow('请求过于频繁');
      const restarted = new VaultController();
      await expect(restarted.handle({ type: 'webdav-status' })).resolves.toMatchObject({ saved: false, paused: 429 });
      await expect(restarted.handle({ type: 'webdav-test', input, remember: true })).resolves.toMatchObject({ writeAllowed: false });
      await expect(restarted.handle({ type: 'webdav-status' })).resolves.toEqual({ saved: true, paused: undefined, offsetSeconds: 45, compensation: false });
      const stored = JSON.stringify(state.local);
      expect(stored).not.toContain(input.password);
      expect(stored).not.toContain(input.username);
      expect(stored).not.toContain('jianguoyun');
      const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
      const item = record('Clock sample');
      item.data.totpUri = secret;
      await restarted.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
      const [saved] = await restarted.handle({ type: 'list' }) as ItemSummary[];
      const id = saved!.id;
      const detail = await restarted.handle({ type: 'get', id }) as ItemDetailData;
      const message = { type: 'read-otp', id, handle: detail.otp?.kind === 'time' ? detail.otp.handle! : '' } as const;
      const site = { type: 'autofill-read', id, kind: 'otp', groups: [], url: 'https://example-bank.com' } as const;
      const localCode = wasm_totp_at(secret, time / 1000).split(':')[0]!;
      const [adjustedCode, validTo] = wasm_totp_at(secret, time / 1000 + 45).split(':');
      expect(adjustedCode).not.toBe(localCode);
      await expect(restarted.handle(message)).resolves.toMatchObject({ value: localCode });
      await restarted.handle({ type: 'webdav-clock', enabled: true });
      await expect(restarted.handle(message)).resolves.toMatchObject({ value: adjustedCode, validTo: Number(validTo) - 45 });
      await expect(restarted.handle({ ...site, groups: [] })).resolves.toEqual({ values: { otp: adjustedCode } });
      await restarted.handle({ type: 'webdav-clock', enabled: false });
      await expect(restarted.handle(message)).resolves.toMatchObject({ value: localCode });
      await restarted.lock();
      const total = fetchMock.mock.calls.length;
      await expect(restarted.handle({ type: 'webdav-test', input })).rejects.toThrow('先解锁');
      expect(fetchMock).toHaveBeenCalledTimes(total);
      expect(fetchMock.mock.calls.every(call => call[1]?.method === 'PROPFIND')).toBe(true);
    } finally { fetchMock.mockRestore(); date.mockRestore(); }
  });

  it('cleans the next copy even if the previous alarm was still removing its record', async () => {
    await unlocked();
    const clipboardAlarm = 'vault-clipboard';
    const id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    let listenMessage!: (message: unknown, sender: unknown, respond: (reply: { ok: boolean; error?: string }) => void) => void;
    let listenAlarm!: (alarm: { name: string }) => void;
    let pending: unknown;
    let clipboardText = '';
    let allowRemoval!: () => void;
    let markRemoval!: () => void;
    const removalRequested = new Promise<void>(resolve => { markRemoval = resolve; });
    const pauseRemoval = new Promise<void>(resolve => { allowRemoval = resolve; });
    vi.stubGlobal('browser', {
      storage: {
        session: {
          setAccessLevel: async () => undefined,
          get: async () => ({ clipboard: structuredClone(pending) }),
          set: async (entry: { clipboard: unknown }) => { pending = structuredClone(entry.clipboard); },
          remove: async () => { markRemoval(); await pauseRemoval; pending = undefined; },
        },
        local: { setAccessLevel: async () => undefined },
      },
      idle: { queryState: async () => 'active', setDetectionInterval() {}, onStateChanged: { addListener() {} } },
      runtime: {
        id, onMessage: { addListener: (listener: typeof listenMessage) => { listenMessage = listener; } },
        onConnect: { addListener() {} },
        onInstalled: { addListener() {} }, onStartup: { addListener() {} },
      },
      tabs: { onRemoved: { addListener() {} }, onUpdated: { addListener() {} }, onActivated: { addListener() {} } },
      windows: { onRemoved: { addListener() {} } },
      commands: { onCommand: { addListener() {} } },
      contextMenus: { onClicked: { addListener() {} } },
      alarms: { create: async () => undefined, onAlarm: { addListener: (listener: typeof listenAlarm) => { listenAlarm = listener; } } },
    });
    vi.stubGlobal('defineBackground', (main: () => void) => main);
    const { default: startBackground } = await import('../entrypoints/background');
    (startBackground as unknown as () => void)();
    const sendCopy = (value: string) => new Promise<void>((resolve, reject) => {
      listenMessage({ target: 'vault', type: 'copy-sensitive', value }, { id, url: `chrome-extension://${id}/sidepanel.html` },
        reply => reply.ok ? resolve() : reject(new Error(reply.error)));
    });
    vi.mocked(offscreen).mockImplementation(async (operation, payload) => {
      if (operation === 'copy') {
        clipboardText = String(payload);
        return 'digest:' + clipboardText;
      }
      if (operation === 'clear-clipboard' && payload === 'digest:' + clipboardText) clipboardText = '';
      return null;
    });
    const clock = vi.spyOn(Date, 'now');
    let stamp = Date.now();
    clock.mockImplementation(() => stamp);
    try {
      await sendCopy('first clipboard fixture');
      stamp += 30001;
      listenAlarm({ name: clipboardAlarm });
      await removalRequested;
      const laterCopy = sendCopy('second clipboard fixture');
      await new Promise<void>(resolve => setImmediate(resolve));
      allowRemoval();
      await laterCopy;
      expect(clipboardText).toBe('second clipboard fixture');
      stamp += 30001;
      listenAlarm({ name: clipboardAlarm });
      await new Promise<void>(resolve => setImmediate(resolve));
      expect(clipboardText).toBe('');
    } finally {
      allowRemoval();
      clock.mockRestore();
      vi.mocked(offscreen).mockReset();
    }
  });
  it('keeps website preferences encrypted, preserves them across password rotation and rejects tampering', async () => {
    const flags = { inlineDisabled: true, saveDisabled: true, passkeyDisabled: false };
    const controller = await unlocked();
    await controller.handle({ type: 'set-autofill-site', origin: 'https://private.example', flags });
    await controller.handle({ type: 'set-equivalent-domains', groups: [['example.com', 'example.net']] });
    expect(JSON.stringify(state.local)).not.toContain('private.example');
    expect(JSON.stringify(state.local)).not.toContain('example.net');
    expect(state.local).not.toHaveProperty('autofill');
    await controller.handle({ type: 'change-password', currentPassword: password, newPassword: 'Rotated-Master-Password#2026' });
    await controller.lock();
    expect(await controller.handle({ type: 'autofill-settings' })).toEqual({ sites: {}, equivalentDomains: [] });
    const recreated = new VaultController();
    await recreated.handle({ type: 'unlock', password: 'Rotated-Master-Password#2026' });
    expect(await recreated.handle({ type: 'autofill-settings' })).toEqual({
      sites: { 'https://private.example': flags }, equivalentDomains: [['example.com', 'example.net']],
    });
    await recreated.lock();
    const saved = state.local.autofillSealed as { bytes: number[] };
    saved.bytes[saved.bytes.length - 1]! ^= 1;
    const damaged = new VaultController();
    await damaged.handle({ type: 'unlock', password: 'Rotated-Master-Password#2026' });
    await expect(damaged.handle({ type: 'autofill-settings' })).rejects.toBeDefined();
  });
  it('migrates development plaintext preferences only after an encrypted save succeeds', async () => {
    const legacy = { sites: {}, equivalentDomains: [['example.com', 'example.net']] };
    state.local.autofill = legacy;
    const controller = await unlocked();
    vi.spyOn(browser.storage.local, 'set').mockRejectedValueOnce(new Error('Test preference write failed'));
    await expect(controller.handle({ type: 'autofill-settings' })).rejects.toThrow('preference write failed');
    expect(state.local.autofill).toEqual(legacy);
    expect(state.local).not.toHaveProperty('autofillSealed');
    expect(await controller.handle({ type: 'autofill-settings' })).toEqual(legacy);
    expect(state.local).toHaveProperty('autofillSealed');
    expect(state.local).not.toHaveProperty('autofill');
    state.local.autofill = legacy; // The old worker could stop between the encrypted save and cleanup.
    expect(await new VaultController().handle({ type: 'autofill-settings' })).toEqual(legacy);
    expect(state.local).not.toHaveProperty('autofill');
  });
  it('requires consent for each online lookup even when autofill already grants the website permission', async () => {
    const lookup = vi.fn(async () => new Response(''));
    vi.stubGlobal('fetch', lookup);
    Object.assign(browser, { permissions: { contains: vi.fn(async () => true) } });
    try {
      const controller = await unlocked();
      await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record()) });
      const id = (await controller.handle({ type: 'list' }) as ItemSummary[])[0]!.id;
      await expect(controller.handle({ type: 'hibp', id, confirmOnline: false })).rejects.toThrow('本次联网');
      expect(lookup).not.toHaveBeenCalled();
      expect(await controller.handle({ type: 'hibp', id, confirmOnline: true })).toBe(0);
      expect(lookup).toHaveBeenCalledOnce();
    } finally { vi.unstubAllGlobals(); }
  });
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
  it('does not restore an unlocked session while a cold worker is clearing it for a lock', async () => {
    await unlocked();
    const recreated = new VaultController();
    let finishClear!: () => void;
    state.pauseSessionClear = new Promise<void>(resolve => { finishClear = resolve; });
    const lock = recreated.lock();
    const status = recreated.handle({ type: 'status' });
    await new Promise<void>(resolve => setImmediate(resolve));
    finishClear();
    await lock;
    expect(await status).toMatchObject({ configured: true, unlocked: false });
    await expect(recreated.handle({ type: 'list' })).rejects.toThrow('解锁');
  });
  it('leaves the vault locked when a new worker finds Windows already locked', async () => {
    await unlocked();
    state.idleState = 'locked';
    const recreated = new VaultController();
    expect(await recreated.handle({ type: 'status' })).toMatchObject({ configured: true, unlocked: false });
    expect(state.session).toBeUndefined();
  });
  it('opens a cold vault with status and protected item summaries in the same reply', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Protected fixture', true)) });
    const recreated = new VaultController();
    const opened = await recreated.handle({ type: 'open' });
    expect(opened).toMatchObject({
      status: { configured: true, unlocked: true },
      items: [{ title: 'Protected fixture', requireReprompt: true }],
    });
    expect(JSON.stringify(opened)).not.toContain('Unique-Secret-Pass#719');
    await recreated.lock();
    expect(await new VaultController().handle({ type: 'open' })).toEqual({
      status: expect.objectContaining({ configured: true, unlocked: false }),
    });
  });
  it('clears a corrupted saved session before opening a cold vault', async () => {
    await unlocked();
    state.session!.wrap[0]! ^= 1;
    expect(await new VaultController().handle({ type: 'open' })).toEqual({
      status: expect.objectContaining({ configured: true, unlocked: false }),
    });
    expect(state.session).toBeUndefined();
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
  it('requires the current master password for every whole-vault export but allows PIN for individual items', async () => {
    const controller = await unlocked();
    const pin = { method: 'pin', secret: '736498' } as const;
    await controller.handle({ type: 'create-pin', pin: pin.secret, proof });
    const item = record('Protected authenticator', true);
    item.data.totpUri = 'JBSWY3DPEHPK3PXP';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    const [saved] = await controller.handle({ type: 'list' }) as ItemSummary[];
    const filePassword = 'Independent-Backup#2026';
    const requests = [
      { type: 'export', password: filePassword },
      { type: 'export-migration', format: 'csv', confirmPlaintext: true },
      { type: 'export-migration', format: 'bitwarden', confirmPlaintext: true },
      { type: 'export-migration', format: 'bitwarden', encrypted: true, password: filePassword, confirmPlaintext: false },
      { type: 'export-ente', confirmPlaintext: true },
    ] as const;
    for (const message of requests) {
      await expect(controller.handle({ ...message, proof: pin })).rejects.toThrow('主密码');
      await expect(controller.handle(message as VaultMessage)).rejects.toThrow('主密码');
      await expect(controller.handle({ ...message, proof: { method: 'master', secret: filePassword } })).rejects.toThrow('主密码验证失败');
      expect(await controller.handle({ ...message, proof })).toBeTruthy();
    }
    await expect(controller.handle({ type: 'get', id: saved!.id, proof: pin })).resolves.toMatchObject({ title: item.title });
    expect(state.files!.changesSinceBackup).toBe(1);
  });
  it('retains the reminder without an authentic export receipt and never clears edits made after exporting', async () => {
    const controller = await unlocked();
    const exportBackup = async () => await controller.handle({ type: 'export', password: 'Test-Backup-Password#2026', proof }) as BackupExport;
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('First')) });
    const first = await exportBackup();
    expect(first.bytes.length).toBeGreaterThan(0);
    expect(state.files!.changesSinceBackup).toBe(1);
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Second')) });
    await expect(controller.handle({ type: 'backup-saved', receipt: { ...first.receipt, changeCount: 2 } })).rejects.toThrow('无法确认');
    expect(state.files!.changesSinceBackup).toBe(2);
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
    item.customFields.push({ name: 'CSV 未识别的验证码设置', value: 'Unrecognized-secret-fixture', hidden: true });
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    expect(new TextDecoder().decode(state.files!.snap)).not.toContain(secret);
    await controller.lock();
    const restored = await unlocked();
    const [summary] = await restored.handle({ type: 'list' }) as ItemSummary[];
    expect(summary!.hasTotp).toBe(true);
    await expect(restored.handle({ type: 'get', id: summary!.id })).rejects.toThrow('再次验证');
    const id = summary!.id;
    const detail = await restored.handle({ type: 'get', id, proof }) as ItemDetailData;
    expect(JSON.stringify(detail)).not.toContain(secret);
    expect(JSON.stringify(detail)).not.toContain('Unrecognized-secret-fixture');
    expect(detail.otp).toMatchObject({ kind: 'time', handle: expect.any(String) });
    const handle = detail.otp?.kind === 'time' ? detail.otp.handle! : '';
    const start = Date.now();
    // Advance to the same RFC test window within the current clock cycle.
    const fixtureTime = Math.floor(start / 60000) * 60000 + 59000;
    const date = vi.spyOn(Date, 'now').mockReturnValue(fixtureTime);
    try {
      const phaseCode = (timestamp: number) => wasm_totp_at(secret, timestamp).split(':')[0];
      const freshWorker = new VaultController();
      const read = { type: 'read-otp', id, handle } as const;
      await expect(freshWorker.handle({ ...read, handle: 'invalid' })).rejects.toThrow('重新打开');
      const lastTouch = state.session!.lastActivityMs;
      await expect(freshWorker.handle(read)).resolves.toEqual({
        kind: 'totp', value: phaseCode(fixtureTime / 1000), validTo: Math.floor(fixtureTime / 1000) + 1,
        nextValue: phaseCode(fixtureTime / 1000 + 1),
      });
      expect(state.session!.lastActivityMs).toBe(lastTouch);
      date.mockReturnValue(fixtureTime + 1000);
      await expect(freshWorker.handle(read)).resolves.toMatchObject({ value: phaseCode(fixtureTime / 1000 + 1), nextValue: null });
      await freshWorker.lock();
      await freshWorker.handle({ type: 'unlock', password });
      await expect(freshWorker.handle(read)).rejects.toThrow('重新打开');
      const edit = await freshWorker.handle({ type: 'get-edit', id, proof }) as VaultItem;
      expect(edit.data.totpUri).toBe(secret);
      expect(edit.customFields[0]?.value).toBe('Unrecognized-secret-fixture');
    } finally { date.mockRestore(); }
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
    const results = await Promise.all([controller.handle({ type: 'next-hotp', id }), controller.handle({ type: 'next-hotp', id })]);
    expect(results).toEqual([{ kind: 'hotp', value: '755224', counter: '0' }, { kind: 'hotp', value: '287082', counter: '1' }]);
    expect(state.files!.changesSinceBackup).toBe(3);
    expect(state.pendingWal).toHaveLength(3);
    const last = state.pendingWal.at(-1)!;
    expect(last.bytes).not.toEqual(state.files!.snap);
    expect(new TextDecoder().decode(last.bytes)).not.toContain(secret);
    expect(wasm_verify_local_wal(state.session!.key, state.session!.wrap, last.id, last.bytes)).toBe(true);
    const staleEdit = await controller.handle({ type: 'get-edit', id });
    const restored = new VaultController();
    expect(await restored.handle({ type: 'next-hotp', id })).toEqual({ kind: 'hotp', value: '359152', counter: '2' });
    expect((await restored.handle({ type: 'get-edit', id }) as VaultItem).data.totpUri).toContain('counter=3');
    await expect(restored.handle({ type: 'upsert', itemJson: JSON.stringify(staleEdit) })).rejects.toThrow('其他窗口更新');
    expect(new TextDecoder().decode(state.files!.snap)).not.toContain(secret);
  });

  it('does not expose or consume a HOTP code when saving fails, and enforces item protection', async () => {
    const controller = await unlocked();
    const id = await addHotp(controller, true);
    const before = structuredClone(state.files);
    state.legacy = true;
    await expect(controller.handle({ type: 'next-hotp', id })).rejects.toThrow('再次验证');
    state.failSave = true;
    await expect(controller.handle({ type: 'next-hotp', id, proof })).rejects.toThrow('disk write failed');
    expect(state.files).toEqual(before);
    expect(state.pendingWal).toHaveLength(1);
    expect(state.legacy).toBe(true);
    state.failSave = false;
    const first = await controller.handle({ type: 'next-hotp', id, proof }) as HotpCode;
    expect(first).toEqual({ kind: 'hotp', value: '755224', counter: '0' });
    expect(state.legacy).toBe(false);
    expect(state.pendingWal).toHaveLength(2);
    expect(state.pendingWal.at(-1)?.replaceLegacy).toBe(true);
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
      { id, url: 'chrome-extension://' + id + '/inline-menu.html', origin: 'chrome-extension://' + id },
      { id: 'other', url: 'chrome-extension://' + id + '/popup.html' },
    ]) expect(isVaultPage(sender, id)).toBe(false);
  });
});

describe('phase two migration transactions and autofill reads', () => {
  const bytes = Array.from(new TextEncoder().encode(JSON.stringify({ encrypted: false, items: [
    { id: 'source-login', type: 1, name: 'Migration fixture', reprompt: 1, login: { username: 'fixture', password: 'Hidden-Password#2026',
      uris: [{ uri: 'https://example.com/login' }], totp: 'JBSWY3DPEHPK3PXP' } },
    { id: 'source-card', type: 3, name: 'Card fixture', card: { number: '4111111111111111', code: '123' } },
  ] })));
  it('binds preview to source and snapshot and rolls back a failed batch without partial data', async () => {
    const controller = await unlocked();
    const before = structuredClone(state.files);
    const preview = await controller.handle({ type: 'preview-migration', format: 'bitwarden', bytes }) as { ready: number; stamp: string };
    expect(preview.ready).toBe(2);
    expect(JSON.stringify(preview)).not.toContain('Hidden-Password');
    expect(state.files).toEqual(before);
    state.failSave = true;
    await expect(controller.handle({ type: 'import-migration', format: 'bitwarden', bytes, stamp: preview.stamp, proof })).rejects.toThrow('disk write failed');
    expect(await controller.handle({ type: 'list' })).toEqual([]);
    state.failSave = false;
    expect(await controller.handle({ type: 'import-migration', format: 'bitwarden', bytes, stamp: preview.stamp, proof })).toBe(2);
    await expect(controller.handle({ type: 'import-migration', format: 'bitwarden', bytes, stamp: preview.stamp, proof })).rejects.toThrow('重新预览');
    const repeat = await controller.handle({ type: 'preview-migration', format: 'bitwarden', bytes }) as { ready: number; skipped: number };
    expect(repeat).toMatchObject({ ready: 0, skipped: 2 });
    const login = (await controller.handle({ type: 'list' }) as ItemSummary[]).find(item => item.kind === 'login')!;
    await expect(controller.handle({ type: 'autofill-read', id: login.id, url: 'https://example.com', kind: 'login', groups: [] })).rejects.toThrow('再次验证');
    await expect(controller.handle({ type: 'autofill-read', id: login.id, url: 'https://example.com.evil.test', kind: 'login', groups: [], proof })).rejects.toThrow('不匹配');
    const fill = await controller.handle({ type: 'autofill-read', id: login.id, url: 'https://example.com', kind: 'username', groups: [], proof });
    expect(fill).toEqual({ values: { username: 'fixture' } });
    expect(JSON.stringify(fill)).not.toContain('Hidden-Password');
    const item = await controller.handle({ type: 'get', id: login.id, proof }) as VaultItem;
    item.customFields.push({ name: 'department', value: 'Visible department', hidden: true },
      { name: 'CSV 未识别的验证码设置', value: 'Reserved-Seed-Do-Not-Fill', hidden: true });
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item), proof });
    const fields = ['department', 'Bitwarden 保留字段', 'CSV 未识别的验证码设置'];
    const custom = await controller.handle({ type: 'autofill-read', id: login.id, url: 'https://example.com', kind: 'login', fields, groups: [], proof });
    expect(custom).toMatchObject({ custom: { department: 'Visible department' } });
    expect(JSON.stringify(custom)).not.toContain('Reserved-Seed');
    expect(JSON.stringify(custom)).not.toContain('sourceId');
    expect(await controller.handle({ type: 'autofill-read', id: login.id, url: 'https://example.com', kind: 'username', fields, groups: [], proof }))
      .toEqual({ values: { username: 'fixture' } });
  });
  it('requires a master proof and explicit plaintext consent for full-vault migration exports', async () => {
    const controller = await unlocked();
    await expect(controller.handle({ type: 'export-migration', format: 'bitwarden', proof, confirmPlaintext: false })).rejects.toThrow('风险');
    await expect(controller.handle({ type: 'export-migration', format: 'bitwarden', proof: { method: 'pin', secret: '123456' }, confirmPlaintext: true })).rejects.toThrow('主密码');
    await expect(controller.handle({ type: 'export-migration', format: 'bitwarden', proof: { method: 'master', secret: 'Wrong master' }, confirmPlaintext: true })).rejects.toThrow('主密码验证失败');
  });
  it('copies only time codes with clipboard expiry and never advances HOTP as part of login filling', async () => {
    vi.mocked(offscreen).mockClear();
    vi.mocked(offscreen).mockResolvedValue('fixture-clipboard-hash');
    const controller = await unlocked();
    const value = record('OTP copy fixture', true);
    value.data.uris = [{ uri: 'https://example.com' }];
    value.data.totpUri = 'JBSWY3DPEHPK3PXP';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(value) });
    const id = (await controller.handle({ type: 'list' }) as ItemSummary[])[0]!.id;
    await expect(controller.handle({ type: 'autofill-copy-otp', id, url: 'https://example.com', groups: [] })).rejects.toThrow('再次验证');
    expect(await controller.handle({ type: 'autofill-copy-otp', id, url: 'https://example.com', groups: [], proof })).toBe(true);
    expect(offscreen).toHaveBeenCalledWith('copy', expect.stringMatching(/^\d{6}$/));
    expect(browser.storage.session.set).toHaveBeenCalledWith({ clipboard: { hash: 'fixture-clipboard-hash', expiresAt: expect.any(Number) } });
    const latest = await controller.handle({ type: 'get', id, proof }) as VaultItem;
    latest.data.totpUri = 'otpauth://hotp/Fixture?secret=JBSWY3DPEHPK3PXP&counter=5';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(latest), proof });
    vi.mocked(offscreen).mockClear();
    expect(await controller.handle({ type: 'autofill-copy-otp', id, url: 'https://example.com', groups: [], proof })).toBeNull();
    expect(offscreen).not.toHaveBeenCalled();
    expect((await controller.handle({ type: 'get-edit', id, proof }) as VaultItem).data.totpUri).toContain('counter=5');
  });
});
