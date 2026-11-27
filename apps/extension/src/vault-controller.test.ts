import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import init, * as wasm from '../../../crates/vault-core/pkg/vault_core.js';
import initCsv, { wasm_parse_browser_csv, wasm_csv_headers, wasm_parse_mapped_csv, wasm_export_login_csv,
  wasm_parse_authenticator_backup, wasm_portable_import, wasm_portable_export } from '../../../crates/vault-importers/pkg/vault_importers.js';
import initEnte, { wasm_export_ente_auth, wasm_parse_ente_auth } from '../../../crates/vault-ente-auth/pkg/vault_ente_auth.js';
import initAudit, { wasm_audit_snapshot } from '../../../crates/vault-audit/pkg/vault_audit.js';
import initOtp, { wasm_otp_at, wasm_totp_at, wasm_validate_totp } from '../../../crates/vault-otp/pkg/vault_otp.js';
import initPreferences, { wasm_open_preferences, wasm_seal_preferences, wasm_open_webdav, wasm_seal_webdav,
  wasm_sign_authorization, wasm_verify_authorization, wasm_sync_pack_material, wasm_sync_pack_record_sign } from '../../../crates/vault-preferences/pkg/vault_preferences.js';
import { wasm_sync_authenticate_head, wasm_sync_create_genesis, wasm_sync_verify_snapshot } from '../../../crates/vault-sync/pkg/vault_sync.js';
import initSync, { wasm_make_local_wal, wasm_sync_conflicts, wasm_sync_devices, wasm_sync_device_change, wasm_sync_guard_staged, wasm_sync_import_pack,
  wasm_sync_pack_edit, wasm_sync_pack_merge, wasm_sync_verify_recovery, wasm_verify_local_wal } from '../../../crates/vault-sync/pkg/vault_sync.js';
import { prepareBrowserCsv } from './browser-csv';
import { isVaultPage } from './sender-policy';
import { endpointFingerprint } from './sync/bootstrap';
import { saveDavConnection } from './sync/connection';
import { preparePackVersion } from './sync/pack-transport';
import { openPackContent } from './sync/pack-content';
import { savePackSetup } from './vault-storage';
import { webDavConfig } from './sync/webdav';
import { VaultController } from './vault-controller';
import { AutofillController } from './autofill-controller';
import { markKey, markSetKey, type LoginMark, type MarkDraft } from './login-marks';
import { offscreen } from './bridge';
import { zip } from './test-fixtures/zip';
import type { AuthBackupPreview, BackupExport, BrowserCsvPreview, EntePreview, HotpCode, ItemDetailData, MigrationPreview, VaultPackPreview, VaultStatus, VaultItem, ItemSummary, VaultMessage } from './vault-messages';
import type { JournalCommit, LocalSettings, RemoteAnchor, SessionState, VaultFiles } from './vault-storage';

const state = vi.hoisted(() => ({ files: undefined as VaultFiles | undefined, session: undefined as SessionState | undefined,
  settings: { autoLockMinutes: 15, pinFailures: 0 } as LocalSettings, pause: undefined as Promise<void> | undefined,
  pauseEnte: undefined as (() => Promise<void>) | undefined,
  pauseAudit: undefined as ((signal: AbortSignal | undefined) => Promise<void>) | undefined,
  pauseSessionClear: undefined as Promise<void> | undefined, idleState: 'active' as 'active' | 'locked',
  failSave: false, pendingWal: [] as JournalCommit[], legacy: false, local: {} as Record<string, unknown>,
  packAnchor: undefined as RemoteAnchor | undefined,
  packClock: undefined as JournalCommit['state'] | undefined,
  observedKeyUpdate: undefined as { observedHead: Uint8Array; observedKeyEpoch: number } | undefined,
  remoteVaultId: undefined as string | undefined, remotePoll: undefined as Pick<RemoteAnchor, 'endpoint' | 'objects' | 'checkedAt'> | undefined }));
vi.mock('./vault-storage', () => ({
  loadVaultFiles: async () => structuredClone(state.files),
  loadPackSetup: async () => undefined,
  savePackSetup: vi.fn(),
  loadRemoteAnchor: async (vaultId: string) => structuredClone(state.packAnchor ?? state.observedKeyUpdate ??
    (state.remoteVaultId === vaultId ? { vaultId, ...state.remotePoll } : undefined)),
  loadJournal: async () => ({ clock: structuredClone(state.packClock ?? state.pendingWal.at(-1)?.state), legacy: state.legacy }),
  hasPendingWal: async () => state.pendingWal.length > 0,
  saveRemoteAnchor: async (anchor: RemoteAnchor, files: VaultFiles, clock?: JournalCommit['state']) => {
    if (state.failSave) throw new Error('Test disk write failed');
    state.packAnchor = structuredClone(anchor);
    state.files = structuredClone(files);
    if (clock) state.packClock = structuredClone(clock);
  },
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
  derive: async (operation: string, args: unknown[], signal?: AbortSignal) => {
    if (operation === 'sync-pack-material') return Array.from(wasm_sync_pack_material(...args as Parameters<typeof wasm_sync_pack_material>));
    if (operation === 'sync:authenticate-head') {
      const head = wasm_sync_authenticate_head(...args as Parameters<typeof wasm_sync_authenticate_head>);
      try { return { vaultId: head.vault_id, keyEpoch: head.key_epoch, localHead: Array.from(head.local_head) }; } finally { head.free(); }
    }
    if (operation === 'sync:genesis') {
      const genesis = wasm_sync_create_genesis(...args as Parameters<typeof wasm_sync_create_genesis>);
      try { return { head: Array.from(genesis.head), snap: Array.from(genesis.snap) }; } finally { genesis.free(); }
    }
    if (operation === 'sync:local-wal') return Array.from(wasm_make_local_wal(...args as Parameters<typeof wasm_make_local_wal>));
    if (operation === 'sync:verify-recovery') return wasm_sync_verify_recovery(...args as Parameters<typeof wasm_sync_verify_recovery>);
    if (operation === 'sync:guard-staged') return wasm_sync_guard_staged(...args as Parameters<typeof wasm_sync_guard_staged>);
    if (operation === 'sync:devices') return wasm_sync_devices(...args as Parameters<typeof wasm_sync_devices>);
    if (operation === 'sync:pack-edit') {
      const result = wasm_sync_pack_edit(...args as Parameters<typeof wasm_sync_pack_edit>);
      try { return result ? { head: Array.from(result.head), snap: Array.from(result.snap) } : null; } finally { result?.free(); }
    }
    if (operation === 'sync:device-change') {
      const result = wasm_sync_device_change(...args as Parameters<typeof wasm_sync_device_change>);
      try { return { head: Array.from(result.head), snap: Array.from(result.snap), conflicts: Array.from(result.conflicts), count: result.count,
        conflictCount: result.conflict_count, draftCount: result.draft_count }; } finally { result.free(); }
    }
    if (operation === 'sync:import-pack') {
      const result = wasm_sync_import_pack(...args as Parameters<typeof wasm_sync_import_pack>);
      try { return { head: Array.from(result.head), snap: Array.from(result.snap), conflicts: Array.from(result.conflicts),
        added: result.added, updated: result.updated, skipped: result.skipped }; }
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
    if (operation === 'parse-ente') {
      if (state.pauseEnte) await state.pauseEnte();
      return wasm_parse_ente_auth(args[0] as Uint8Array, args[1] as string, args[2] as string | undefined);
    }
    if (operation === 'export-ente') return wasm_export_ente_auth(args[0] as string);
    if (operation === 'audit-snapshot') {
      const report = wasm_audit_snapshot(...args as Parameters<typeof wasm_audit_snapshot>);
      await state.pauseAudit?.(signal);
      return report;
    }
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
  await initEnte({ module_or_path: await readFile(new URL('../../../crates/vault-ente-auth/pkg/vault_ente_auth_bg.wasm', import.meta.url)) });
  await initAudit({ module_or_path: await readFile(new URL('../../../crates/vault-audit/pkg/vault_audit_bg.wasm', import.meta.url)) });
  await initOtp({ module_or_path: await readFile(new URL('../../../crates/vault-otp/pkg/vault_otp_bg.wasm', import.meta.url)) });
  await initPreferences({ module_or_path: await readFile(new URL('../../../crates/vault-preferences/pkg/vault_preferences_bg.wasm', import.meta.url)) });
  await initSync({ module_or_path: await readFile(new URL('../../../crates/vault-sync/pkg/vault_sync_bg.wasm', import.meta.url)) });
  const output = wasm.wasm_create_new_vault(password, 32768, 2, 4, crypto.getRandomValues(new Uint8Array(32)), Date.now());
  fixture = { head: output.head_bytes, snap: output.snap_bytes, vaultId: output.vault_id, keyEpoch: Number(output.key_epoch), updatedAtMs: Date.now(), changesSinceBackup: 0 };
  recoveryCode = output.recovery_code;
  output.free();
});
beforeEach(() => {
  // Each test uses fresh service workers; callbacks from old workers cannot
  // wake up into another test's shared IndexedDB/session fixture.
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  state.files = structuredClone(fixture); state.session = undefined; state.pause = undefined;
  state.pauseEnte = undefined;
  state.pauseAudit = undefined;
  state.pauseSessionClear = undefined;
  state.idleState = 'active';
  state.failSave = false;
  state.pendingWal = [];
  state.legacy = false;
  state.local = {};
  state.observedKeyUpdate = undefined;
  state.remoteVaultId = undefined;
  state.remotePoll = undefined;
  state.packAnchor = undefined;
  state.packClock = undefined;
  state.settings = { autoLockMinutes: 15, pinFailures: 0 };
  vi.stubGlobal('browser', { alarms: { get: async () => undefined, create: vi.fn(), clear: vi.fn() }, runtime: { sendMessage: async () => undefined },
    idle: { queryState: async () => state.idleState },
    storage: { session: { get: async () => ({}), set: vi.fn() }, local: {
      get: async () => structuredClone(state.local),
      set: async (values: Record<string, unknown>) => { Object.assign(state.local, structuredClone(values)); },
      remove: async (key: string) => { delete state.local[key]; },
    } } });
});
afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});
async function unlocked() { const controller = new VaultController(); await controller.handle({ type: 'unlock', password }); return controller; }

const packInput = { provider: 'custom', base: 'https://dav.example.test/', folder: 'pack', username: 'fixture', password: 'fixture' } as const;
const davListing = (path: string, date?: number) => new Response(`<multistatus xmlns="DAV:"><response><href>${path}</href><propstat>` +
  '<prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>',
  { status: 207, headers: date === undefined ? {} : { Date: new Date(date).toUTCString() } });

async function linkedPack() {
  const controller = await unlocked();
  const session = state.session!, files = state.files!, config = webDavConfig(packInput);
  const remote = wasm_sync_create_genesis(session.key, session.wrap, files.head, files.snap, '00000000000001_01020304_00000000000001');
  const head = remote.head;
  remote.free();
  const root = await preparePackVersion({ id: 'a'.repeat(32), parents: [], vaultId: files.vaultId, createdAt: 1,
    keyEpoch: files.keyEpoch, head }, Uint8Array.of(1));
  const fields = [1, root.id, root.vaultId, [], root.sha256, root.bytes, root.createdAt, root.keyEpoch, btoa(String.fromCharCode(...head))];
  const key = wasm_sync_pack_material(session.key, session.wrap);
  const mac = btoa(String.fromCharCode(...wasm_sync_pack_record_sign(key, root.vaultId, new TextEncoder().encode(JSON.stringify(fields)))));
  key.fill(0);
  root.recordAuth = { etag: '"genesis"', mac };
  state.packAnchor = { vaultId: files.vaultId, endpoint: await endpointFingerprint(config.url), head, snap: files.snap, objects: [],
    appliedHead: files.head, appliedSnap: files.snap, hasRecords: false, pack: { base: root.id, known: [root], dirty: false,
      baseRules: new Uint8Array(), baseConflicts: new Uint8Array(), siteRules: 'applied' } };
  await saveDavConnection({ ...config, writeVerified: true }, session, files.vaultId, undefined, () => {});
  return controller;
}

describe('webpage password capture with the encrypted vault', () => {
  const url = 'https://example-bank.com/login';
  const source = { id: 'fixture-extension', url, origin: new URL(url).origin,
    documentId: 'login-document', frameId: 0, tab: { id: 7, url } };
  const menu = { ...source, url: 'chrome-extension://fixture-extension/inline-menu.html',
    origin: 'chrome-extension://fixture-extension', documentId: 'menu-document', frameId: 1 };

  function startCapture(controller: VaultController) {
    Object.assign(browser.runtime, { id: source.id, getURL: (path: string) => menu.origin + path });
    Object.assign(browser, { tabs: { get: async () => source.tab, sendMessage: async () => null } });
    return new AutofillController(controller);
  }

  it('updates TOTP and HOTP logins without returning or dropping their seeds or metadata (#39)', async () => {
    const controller = await unlocked();
    const capture = startCapture(controller);
    for (const type of ['totp', 'hotp']) {
      const initial = record(type, true);
      initial.data.username = type;
      initial.data.totpUri = `otpauth://${type}/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ${type === 'hotp' ? '&counter=2' : ''}`;
      initial.customFields = [{ name: 'Vault 迁移来源', value: 'Fixture source', hidden: true },
        { name: 'Extra', value: 'Fixture custom field', hidden: false }];
      await controller.handle({ type: 'upsert', itemJson: JSON.stringify(initial) });
      const { id } = (await controller.handle({ type: 'list' }) as ItemSummary[]).find(item => item.title === type)!;
      const nextPassword = `New fixture password for ${type}`;
      const begin = () => capture.handle({ type: 'capture', username: type, password: nextPassword }, source) as Promise<{ token: string }>;
      const cancelled = await begin();
      await capture.handle({ type: 'close', token: cancelled.token }, menu);
      expect(await controller.handle({ type: 'get-edit', id, proof })).toMatchObject({ data: initial.data });
      const { token } = await begin();
      const prompt = await capture.handle({ type: 'menu', token }, menu);
      expect(JSON.stringify(prompt)).not.toContain('GEZDGNBV');
      const save = { type: 'save' as const, token, confirmCrossOrigin: false };
      await expect(capture.handle(save, menu)).rejects.toThrow('再次验证');
      expect(await controller.handle({ type: 'get-edit', id, proof })).toMatchObject({ data: initial.data });
      await capture.handle({ ...save, proof }, menu);
      const restarted = await unlocked();
      const detail = await restarted.handle({ type: 'get', id, proof }) as ItemDetailData;
      expect(detail).toMatchObject({ data: { password: nextPassword }, requireReprompt: true });
      expect(detail.data).not.toHaveProperty('totpUri');
      const edit = await restarted.handle({ type: 'get-edit', id, proof }) as VaultItem;
      expect(edit.data.totpUri).toBe(initial.data.totpUri);
      expect(edit.customFields).toEqual(initial.customFields);
      expect(detail.data.passwordHistory).toEqual([expect.objectContaining({ password: initial.data.password })]);
      if (type === 'hotp') await expect(restarted.handle({ type: 'next-hotp', id, proof })).resolves.toMatchObject({ counter: '2' });
    }
  });

  it('after a same-origin form submission updates the exact login URL, not the landing page credential', async () => {
    const controller = await unlocked();
    const capture = startCapture(controller);
    const destination = new URL('/success', url).href;
    let current = url;
    Object.assign(browser.tabs, { get: async () => ({ id: source.tab.id, url: current }) });
    for (const path of [url, destination]) {
      const item = record(path);
      item.data.uris = [{ uri: path, matchRule: 'exact' }];
      await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    }
    const { token } = await capture.handle({ type: 'capture', username: 'tester', password: 'Submitted fixture' }, source) as { token: string };
    current = destination;
    const landed = { ...source, url: current, tab: { ...source.tab, url: current }, documentId: 'landed' };
    expect(await capture.handle({ type: 'pending' }, landed)).toEqual({ token });
    const prompt = { ...menu, tab: landed.tab, documentId: 'new-menu' };
    expect(await capture.handle({ type: 'menu', token }, prompt)).toMatchObject({ capture: { updating: true, ambiguous: false } });
    await capture.handle({ type: 'save', token, confirmCrossOrigin: false }, prompt);
    const rows = await controller.handle({ type: 'list' }) as ItemSummary[];
    expect(rows).toHaveLength(2);
    for (const row of rows) expect(await controller.handle({ type: 'get', id: row.id })).toMatchObject({
      data: { password: row.title === url ? 'Submitted fixture' : 'Unique-Secret-Pass#719' },
    });
  });

  it('distinguishes a sole match, a duplicate, and no match beyond the menu limit (#43)', async () => {
    const controller = await unlocked();
    const capture = startCapture(controller);
    const add = (title: string, username: string, pinned = false) => {
      const item = record(title);
      item.data.username = username;
      item.pinned = pinned;
      return controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    };
    const login = async (username: string, newPassword: string) => {
      const { token } = await capture.handle({ type: 'capture', username, password: newPassword }, source) as { token: string };
      const prompt = await capture.handle({ type: 'menu', token }, menu);
      const save = () => capture.handle({ type: 'save', token, confirmCrossOrigin: false }, menu);
      return { prompt, save };
    };
    await add('Outside the menu', 'same-user');
    for (let i = 1; i <= 30; i++) await add(`Pinned #${i}`, `user-${i}`, true);
    const original = (await controller.handle({ type: 'list' }) as ItemSummary[]).at(-1)!;
    expect(original.title).toBe('Outside the menu');
    const update = await login('same-user', 'First confirmed new password');
    expect(update.prompt).toMatchObject({ capture: { updating: true } });
    await update.save();
    expect(await controller.handle({ type: 'get', id: original.id })).toMatchObject({ data: {
      password: 'First confirmed new password', passwordHistory: [expect.objectContaining({ password: 'Unique-Secret-Pass#719' })],
    } });
    expect(await controller.handle({ type: 'list' })).toHaveLength(31);
    await add('Pinned duplicate', 'same-user', true);
    const ambiguous = await login('same-user', 'Second, ambiguous password');
    await expect(ambiguous.save()).rejects.toThrow('多条同账号');
    expect(await controller.handle({ type: 'get', id: original.id })).toMatchObject({ data: { password: 'First confirmed new password' } });
    expect(await controller.handle({ type: 'list' })).toHaveLength(32);
    await (await login('new-user', 'Password for a new record')).save();
    expect(await controller.handle({ type: 'list' })).toHaveLength(33);
  });

  it('persists only an approved top-level mark and rejects reuse after a document change', async () => {
    const controller = await unlocked();
    const autofill = startCapture(controller);
    const vaultPage = { id: source.id, url: `${menu.origin}/popup.html`, origin: menu.origin };
    const draft: MarkDraft = { form: { id: 'fixture_signin' }, fields: { password: { type: 'password', name: 'fixture_private_field' } } };
    let activeUrl = `${url}?session=fixture_private_query`;
    let page = { ...source, url: activeUrl, tab: { ...source.tab, url: activeUrl } };
    let selection = '';
    const get = async () => ({ ...source.tab, url: activeUrl });
    Object.assign(browser, { tabs: { get, query: async () => [await get()],
      sendMessage: async (_: number, message: { type: string; token: string }) => {
        if (message.type !== 'mark-open') return null;
        selection = message.token;
        await autofill.handle({ type: 'mark-ready', token: selection }, page);
        return { ready: true };
      } } });
    await expect(autofill.handle({ type: 'mark-start' }, page)).rejects.toThrow('仅密码库');
    await autofill.handle({ type: 'mark-start' }, vaultPage);
    await autofill.handle({ type: 'mark-cancel', token: selection }, page);
    expect(state.local.loginMarksSealed).toBeUndefined();
    await autofill.handle({ type: 'mark-start' }, vaultPage);
    await expect(autofill.handle({ type: 'mark-save', token: selection, draft }, { ...page, frameId: 1 })).rejects.toThrow('标记会话');
    await expect(autofill.handle({ type: 'mark-save', token: selection, draft }, { ...page, documentId: 'new-document' })).rejects.toThrow('标记会话');
    const [saved] = await autofill.handle({ type: 'mark-save', token: selection, draft }, page) as [LoginMark];
    expect(saved).toMatchObject({ origin: new URL(url).origin, version: 1, enabled: true, ...draft });
    expect(state.local.loginMarksSealed).toBeDefined();
    for (const privateText of ['fixture_private_field', 'fixture_private_query', 'example-bank.com']) {
      expect(JSON.stringify(state.local.loginMarksSealed)).not.toContain(privateText);
    }
    activeUrl = url;
    page = { ...source, documentId: 'refreshed-document' };
    const restarted = new AutofillController(new VaultController());
    expect(await restarted.handle({ type: 'mark-get' }, page)).toEqual([saved]);
    expect(await restarted.marking.read(url.replace('/login', '/other'))).toEqual([]);
    expect(await restarted.marking.read(url.replace('.com', '.com:7443'))).toEqual([]);
    await expect(restarted.handle({ type: 'begin', kind: 'login' }, page)).rejects.toThrow('标记已变化');
    const nextStep: MarkDraft = { form: draft.form, fields: { username: { type: 'text', id: 'account_step' } } };
    await autofill.handle({ type: 'mark-start' }, vaultPage);
    const [first, second] = await autofill.handle({ type: 'mark-save', token: selection, draft: nextStep }, page) as [LoginMark, LoginMark];
    expect(first).toEqual(saved);
    expect(second).toMatchObject({ ...nextStep, revision: 1 });
    expect(second.id).not.toBe(first.id);
    await expect(restarted.handle({ type: 'begin', kind: 'login', markId: markKey(first), markSet: markSetKey([first]) }, page))
      .rejects.toThrow('标记已变化');
    await expect(restarted.handle({ type: 'begin', kind: 'username', markId: markKey(second), markSet: markSetKey([first, second]) }, page))
      .resolves.toMatchObject({ token: expect.any(String) });
    const edited: MarkDraft = { form: { id: 'replacement' }, fields: draft.fields };
    await autofill.handle({ type: 'mark-start', key: markKey(saved) }, vaultPage);
    const [replacement, unchanged] = await autofill.handle({ type: 'mark-save', token: selection, draft: edited }, page) as [LoginMark, LoginMark];
    expect(replacement).toMatchObject({ ...edited, id: saved.id, revision: saved.revision + 1 });
    expect(unchanged).toEqual(second);
    await autofill.handle({ type: 'mark-start', key: markKey(replacement) }, vaultPage);
    const updated = await restarted.handle({ type: 'mark-enable', key: markKey(replacement), enabled: false }, vaultPage) as { marks: [LoginMark, LoginMark] };
    expect(updated.marks[0]).toMatchObject({ id: saved.id, revision: replacement.revision + 1, enabled: false });
    await expect(autofill.handle({ type: 'mark-save', token: selection, draft }, page)).rejects.toThrow('已经变化');
    await restarted.handle({ type: 'mark-delete', key: markKey(updated.marks[0]) }, vaultPage);
    expect(await restarted.handle({ type: 'mark-get' }, page)).toEqual([second]);
  });
});

describe('real WASM + background session integration', () => {
  it.each(['note', 'HOTP'])('keeps a stale edit from overwriting synced %s at the same revision (#41)', async (remoteField) => {
    const controller = await unlocked();
    const initial = record('Base');
    initial.data.totpUri = 'otpauth://hotp/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=2';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(initial) });
    const [{ id }] = await controller.handle({ type: 'list' }) as [ItemSummary];
    const baseFiles = structuredClone(state.files!);
    const base = await controller.handle({ type: 'get-edit', id }) as VaultItem;
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify({ ...base, title: 'Saved local title' }) });
    const local = await controller.handle({ type: 'get-edit', id }) as VaultItem;
    const draft = { ...local, title: 'My unsaved input' };
    const { key, wrap } = state.session!;
    const synced = new wasm.WasmVaultEngine();
    try {
      synced.restore_from_session(key, wrap, baseFiles.head, baseFiles.snap);
      const item = JSON.parse(synced.get_item_json(id, true)) as VaultItem;
      item.title = local.title;
      if (remoteField === 'note') item.note = 'Remote note merged into the local title';
      else item.data.totpUri = (item.data.totpUri as string).replace('counter=2', 'counter=3');
      // Simulate the authenticated snapshot being installed while the form stays open.
      const result = synced.upsert_item_json(JSON.stringify(item), local.updatedAtMs!, 'peer');
      try {
        state.files = { ...state.files!, head: result.head_bytes, snap: result.snap_bytes };
      } finally { result.free(); }
    } finally { synced.free(); }
    const resumed = new VaultController();
    const current = await resumed.handle({ type: 'get-edit', id }) as VaultItem;
    expect(current.revision).toBe(local.revision);
    expect(current.updatedAtMs).toBe(local.updatedAtMs);
    await expect(resumed.handle({ type: 'upsert', itemJson: JSON.stringify(draft) })).rejects.toThrow('其他窗口更新');
    const saved = await resumed.handle({ type: 'get-edit', id }) as VaultItem;
    expect(saved).toEqual(current);
    if (remoteField === 'HOTP') await expect(resumed.handle({ type: 'next-hotp', id })).resolves.toMatchObject({ counter: '3' });
    else {
      await resumed.handle({ type: 'upsert', itemJson: JSON.stringify({ ...saved, title: draft.title }) });
      expect(await resumed.handle({ type: 'get', id })).toMatchObject({ title: draft.title, note: current.note });
    }
  });

  it('audits the authenticated snapshot without exposing secrets or keeping reports across lock', async () => {
    const controller = await unlocked();
    const item = record('Sensitive fixture', true);
    item.data.password = 'password';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    const id = (await controller.handle({ type: 'list' }) as ItemSummary[])[0]!.id;
    const before = structuredClone(state.files);
    const report = await controller.handle({ type: 'audit' });
    expect(report).toMatchObject({ missing2faItemIds: [id], weakItems: [{ itemId: id, title: item.title }] });
    const finding = (report as { weakItems: Record<string, unknown>[] }).weakItems[0];
    expect(finding).not.toHaveProperty('password');
    expect(finding).not.toHaveProperty('username');
    expect(state.files).toEqual(before);
    const { key, wrap } = state.session!;
    const damaged = state.files!.snap.slice();
    damaged[damaged.length - 1] = damaged.at(-1)! ^ 1;
    expect(() => wasm_audit_snapshot(key, wrap, state.files!.head, damaged)).toThrow();
    const started = Promise.withResolvers<void>();
    const finish = Promise.withResolvers<void>();
    let auditSignal: AbortSignal | undefined;
    state.pauseAudit = signal => { auditSignal = signal; started.resolve(); return finish.promise; };
    const pending = controller.handle({ type: 'audit' });
    const rejected = expect(pending).rejects.toThrow('密码库已锁定');
    await started.promise;
    try { await controller.lock(); } finally { finish.resolve(); }
    expect(auditSignal?.aborted).toBe(true);
    await rejected;
    await expect(controller.handle({ type: 'audit' })).rejects.toThrow('解锁');
  });

  it.each([401, 403, 429])('requires a corrected saved application password and a successful probe after HTTP %s', async status => {
    const input = { provider: 'koofr', base: '', folder: 'fixture', username: 'fixture-account', password: 'retired-app-password' } as const;
    const corrected = { ...input, password: 'replacement-app-password' };
    const listed = () => new Response('<multistatus xmlns="DAV:"><response><href>/dav/Koofr/fixture/</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>',
      { status: 207 });
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => listed());
    const setBadgeText = vi.fn();
    vi.stubGlobal('browser', { ...browser, action: { setBadgeText, setBadgeBackgroundColor: vi.fn() } });
    const controller = await unlocked();
    let restarted: VaultController | undefined;
    try {
      await expect(controller.handle({ type: 'webdav-test', input, remember: true })).resolves.toMatchObject({ kind: 'empty' });
      const before = structuredClone(state.local.webDavSealed);
      fetchMock.mockResolvedValueOnce(new Response(null, { status }));
      await expect(controller.handle({ type: 'webdav-test' })).rejects.toThrow();
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(setBadgeText).toHaveBeenLastCalledWith({ text: '!' });

      state.remoteVaultId = fixture.vaultId;
      restarted = new VaultController();
      await expect(restarted.handle({ type: 'webdav-scheduled' })).resolves.toMatchObject({ kind: 'paused' });
      await expect(restarted.handle({ type: 'webdav-test' })).rejects.toThrow('修正连接设置');
      await expect(restarted.handle({ type: 'webdav-test', input, remember: true })).rejects.toThrow('更换应用专用密码');
      await expect(restarted.handle({ type: 'webdav-test', input: corrected })).rejects.toThrow('修正连接设置');
      expect(fetchMock).toHaveBeenCalledTimes(2);

      fetchMock.mockResolvedValueOnce(new Response(null, { status: 404 }));
      await expect(restarted.handle({ type: 'webdav-test', input: corrected, remember: true })).resolves.toMatchObject({ kind: 'missing' });
      await expect(restarted.handle({ type: 'webdav-status' })).resolves.toMatchObject({ saved: true, paused: status });
      expect(state.local.webDavSealed).toEqual(before);
      expect(setBadgeText).toHaveBeenLastCalledWith({ text: '!' });

      await expect(restarted.handle({ type: 'webdav-test', input: corrected, remember: true })).resolves.toMatchObject({ kind: 'empty', writeAllowed: false });
      await expect(restarted.handle({ type: 'webdav-status' })).resolves.toMatchObject({ saved: true, paused: undefined });
      expect(state.local.webDavSealed).not.toEqual(before);
      expect(setBadgeText).toHaveBeenLastCalledWith({ text: '' });
      expect(fetchMock).toHaveBeenCalledTimes(4);
      expect(fetchMock.mock.calls.every(call => call[1]?.method === 'PROPFIND')).toBe(true);
      expect(JSON.stringify(state.local)).not.toContain(corrected.password);
    } finally {
      await restarted?.lock();
      await controller.lock();
      fetchMock.mockRestore();
    }
  });

  it.each([401, 403, 429])('stops an already-running pack sync when a second operation receives HTTP %s', async status => {
    const controller = await linkedPack();
    const started = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    const request = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'GET') { started.resolve(); await release.promise; return new Response(null, { status: 304 }); }
      return String(url).endsWith('/versions/') ? davListing('/pack/versions/') : new Response(null, { status });
    });
    try {
      const syncing = controller.handle({ type: 'webdav-sync' }).catch(error => error);
      await started.promise;
      await expect(controller.handle({ type: 'webdav-test' })).rejects.toThrow();
      release.resolve();
      await syncing;
      expect(request.mock.calls.map(([url]) => new URL(String(url)).pathname)).toEqual(['/pack/pack-root.txt', '/pack/']);
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ paused: status, writeVerified: false });
    } finally { release.resolve(); await controller.lock(); request.mockRestore(); }
  });

  it('revokes writing on a short published root in history, including an ongoing sync and a reopened worker', async () => {
    const controller = await linkedPack();
    const pack = state.packAnchor!.pack!;
    const cipher = Uint8Array.of(3, 5, 8);
    const version = await preparePackVersion({ id: 'b'.repeat(32), vaultId: fixture.vaultId, parents: [pack.base],
      createdAt: 2, keyEpoch: 1 }, cipher);
    pack.outbox = { ciphertext: cipher, version };
    const before = structuredClone({ files: state.files, outbox: pack.outbox });
    const started = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    const request = vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(async () => { started.resolve(); await release.promise; return new Response(null, { status: 304 }); })
      .mockResolvedValueOnce(new Response(null, { headers: { 'Content-Length': '700' } }))
      .mockImplementation(async () => davListing('/pack/versions/'));
    try {
      const syncing = controller.handle({ type: 'webdav-sync' }).catch(error => error);
      await started.promise;
      await expect(controller.handle({ type: 'webdav-history' })).rejects.toThrow(/700 字节.*0 字节/);
      await expect(new VaultController().handle({ type: 'webdav-status' })).resolves.toMatchObject({ pending: true, writeVerified: false });
      release.resolve();
      await syncing;
      expect(request.mock.calls.map(([url]) => new URL(String(url)).pathname)).toEqual(['/pack/pack-root.txt', '/pack/pack-root.txt']);
      expect({ files: state.files, outbox: state.packAnchor?.pack?.outbox }).toEqual(before);
    } finally { release.resolve(); await controller.lock(); request.mockRestore(); }
  });

  it.each(['HTTP 503', 'interrupted transfer', 'newer record format'])('retains the write proof and pending edits after %s', async fault => {
    const controller = await linkedPack();
    state.packAnchor!.pack!.dirty = true;
    const request = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      if (fault === 'HTTP 503') return new Response(null, { status: 503 });
      if (fault === 'newer record format') return Response.json([[3, 'future fields'], 'future signature']);
      return new Response(new ReadableStream<Uint8Array>({ start(stream) {
        stream.enqueue(Uint8Array.of(91)); stream.error(new TypeError('network interrupted'));
      } }), { headers: { 'Content-Length': '700' } });
    });
    try {
      await expect(controller.handle({ type: 'webdav-sync' })).rejects.toThrow();
      await expect(new VaultController().handle({ type: 'webdav-status' })).resolves.toMatchObject({ pending: true, writeVerified: true });
      expect(request).toHaveBeenCalledTimes(1);
    } finally { await controller.lock(); request.mockRestore(); }
  });

  it('reports a damaged local outbox without revoking the remote write proof or replacing the outbox', async () => {
    const controller = await linkedPack();
    const pack = state.packAnchor!.pack!;
    const version = await preparePackVersion({ id: 'b'.repeat(32), vaultId: fixture.vaultId, parents: [pack.base],
      createdAt: 2, keyEpoch: 1 }, Uint8Array.of(1, 2));
    pack.outbox = { version, ciphertext: Uint8Array.of(0, 1) };
    const before = structuredClone(pack.outbox);
    const request = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) =>
      init?.method === 'GET' ? new Response(null, { status: 304 }) : davListing('/pack/versions/'));
    try {
      await expect(controller.handle({ type: 'webdav-sync' })).rejects.toThrow(/本机待发布/);
      expect(request.mock.calls.map(([, init]) => init?.method)).toEqual(['GET', 'PROPFIND']);
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ writeVerified: true, pending: true });
      expect(state.packAnchor!.pack!.outbox).toEqual(before);
    } finally { await controller.lock(); request.mockRestore(); }
  });

  it.each(['short directory response', 'repeated member', 'unavailable directory entry'] as const)(
    'distinguishes failure to authenticate a versions listing from a temporary error for %s', async fault => {
      const controller = await linkedPack();
      const request = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => {
        if (init?.method === 'GET') return new Response(null, { status: 304 });
        const own = '<response><href>/pack/versions/</href><propstat><prop><resourcetype><collection/></resourcetype>' +
          '</prop><status>HTTP/1.1 200 OK</status></propstat></response>';
        const skipped = '<response><href>/pack/versions/unavailable</href><status>HTTP/1.1 503 Unavailable</status></response>';
        const body = `<multistatus xmlns="DAV:">${own}${fault === 'repeated member' ? own : fault === 'unavailable directory entry' ? skipped : ''}</multistatus>`;
        return new Response(body, { status: 207, headers: fault === 'short directory response' ? { 'Content-Length': String(body.length + 20) } : {} });
      });
      try {
        await expect(controller.handle({ type: 'webdav-sync' })).rejects.toThrow();
        await expect(new VaultController().handle({ type: 'webdav-status' })).resolves.toMatchObject({
          writeVerified: fault === 'unavailable directory entry',
        });
      } finally { await controller.lock(); request.mockRestore(); }
    });

  it.each(['switch', 'lock'] as const)('ignores a late stop from a retired connection after %s', async action => {
    const controller = await linkedPack();
    const started = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    const request = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'GET') { started.resolve(); await release.promise; return new Response(null, { status: 401 }); }
      return davListing(new URL(String(url)).pathname);
    });
    try {
      const syncing = controller.handle({ type: 'webdav-sync' }).catch(error => error);
      await started.promise;
      if (action === 'lock') await controller.lock();
      else await controller.handle({ type: 'webdav-test', input: { ...packInput, folder: 'new-target' }, remember: true });
      release.resolve();
      await syncing;
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ paused: undefined });
      expect(request).toHaveBeenCalledTimes(action === 'lock' ? 1 : 2);
    } finally { release.resolve(); await controller.lock(); request.mockRestore(); }
  });

  it.each([207, 404])('keeps a stop on the old connection when its reply arrives during an HTTP %s switch', async status => {
    const controller = await linkedPack();
    const polling = Promise.withResolvers<void>(), releasePoll = Promise.withResolvers<void>();
    const testing = Promise.withResolvers<void>(), releaseTest = Promise.withResolvers<void>();
    const request = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (init?.method === 'GET') { polling.resolve(); await releasePoll.promise; return new Response(null, { status: 429 }); }
      testing.resolve(); await releaseTest.promise;
      return status === 404 ? new Response(null, { status }) : davListing(new URL(String(url)).pathname);
    });
    try {
      const sync = controller.handle({ type: 'webdav-sync' }).catch(error => error);
      await polling.promise;
      const test = controller.handle({ type: 'webdav-test', input: { ...packInput, folder: 'new-target' }, remember: true });
      await testing.promise;
      releasePoll.resolve();
      await vi.waitFor(() => expect(state.local.webDavPaused).toBe(429));
      releaseTest.resolve();
      await Promise.all([sync, test]);
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ paused: status === 404 ? 429 : undefined, writeVerified: false });
    } finally { releasePoll.resolve(); releaseTest.resolve(); await controller.lock(); request.mockRestore(); }
  });

  it('refreshes an opted-in clock from the current pack versions directory and ignores late samples after switching', async () => {
    let now = 1_800_000_005_000;
    state.settings.autoLockMinutes = 240;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => now);
    const controller = await linkedPack();
    const started = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
    let delay = false;
    const request = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (init?.method === 'GET') return new Response(null, { status: 304 });
      if (delay && path === '/pack/versions/') { started.resolve(); await release.promise; }
      return davListing(path, now + (path === '/second/' ? 72 : 45) * 1000);
    });
    try {
      await expect(controller.handle({ type: 'webdav-scheduled', reason: 'interval' })).resolves.toEqual({ kind: 'unchanged', pending: false });
      await controller.handle({ type: 'webdav-clock', enabled: true });
      now += 29 * 60_000;
      await controller.handle({ type: 'webdav-scheduled', reason: 'interval' });
      now += 2 * 60_000;
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ compensation: true, offsetSeconds: 45 });
      now += 31 * 60_000;
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ compensation: true, offsetSeconds: null });
      delay = true;
      const syncing = controller.handle({ type: 'webdav-scheduled', reason: 'interval' }).catch(error => error);
      await started.promise;
      await controller.handle({ type: 'webdav-test', input: { ...packInput, folder: 'second' }, remember: true });
      release.resolve();
      await syncing;
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ offsetSeconds: 72 });
    } finally { release.resolve(); await controller.lock(); request.mockRestore(); clock.mockRestore(); }
  });

  it.each([403, 429])('restarts linked polling after a non-Koofr HTTP %s without replacing a valid password', async status => {
    const input = { provider: 'custom', base: 'https://dav.example.test/', folder: 'fixture', username: 'unprivileged', password: 'app-fixture-password' } as const;
    const correctAccount = status === 403 ? { ...input, username: 'authorized' } : input;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async url => {
      const name = new URL(String(url)).pathname;
      return new Response(`<multistatus xmlns="DAV:"><response><href>${name}</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>`,
        { status: 207 });
    });
    let controller: VaultController | undefined, restarted: VaultController | undefined;
    try {
      controller = await unlocked();
      await controller.handle({ type: 'webdav-test', input, remember: true });
      fetchMock.mockResolvedValueOnce(new Response(null, { status }));
      await expect(controller.handle({ type: 'webdav-test' })).rejects.toThrow();
      await controller.lock();
      state.remoteVaultId = fixture.vaultId;
      state.remotePoll = { endpoint: await endpointFingerprint(webDavConfig(input).url), objects: [], checkedAt: Date.now() };
      restarted = await unlocked();
      const handle = vi.spyOn(restarted, 'handle');
      const scheduled = () => handle.mock.results[handle.mock.calls.map(([message]) => message.type).lastIndexOf('webdav-scheduled')]?.value;
      await vi.advanceTimersByTimeAsync(1200);
      await expect(scheduled()).resolves.toMatchObject({ kind: 'paused' });
      expect(fetchMock).toHaveBeenCalledTimes(2);
      await expect(restarted.handle({ type: 'webdav-test', input: { ...correctAccount, folder: 'different' }, remember: true }))
        .rejects.toThrow('不同');
      expect(fetchMock).toHaveBeenCalledTimes(2);

      await expect(restarted.handle({ type: 'webdav-test', input: correctAccount, remember: true })).resolves.toMatchObject({ kind: 'empty' });
      expect(fetchMock).toHaveBeenCalledTimes(3);
      await expect(restarted.handle({ type: 'webdav-status' })).resolves.toMatchObject({ linked: true, writeVerified: false });
      handle.mockClear();
      await vi.advanceTimersByTimeAsync(1200);
      await expect(scheduled()).resolves.toEqual({ kind: 'unchanged', pending: false });
      expect(fetchMock).toHaveBeenCalledTimes(4);
      expect(fetchMock.mock.lastCall?.[0]).toBe('https://dav.example.test/fixture/wal/');
      const last = fetchMock.mock.lastCall?.[1];
      expect(last?.method).toBe('PROPFIND');
      expect(new Headers(last?.headers).get('Authorization')).toBe('Basic ' + btoa(`${correctAccount.username}:${correctAccount.password}`));
    } finally {
      await restarted?.lock();
      await controller?.lock();
      fetchMock.mockRestore();
    }
  });

  it('refreshes opted-in OTP time on unchanged WebDAV polls, falls back offline, and resumes (#19)', async () => {
    let now = 1_800_000_005_000, dateHeader = true;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => now);
    const remote = vi.spyOn(globalThis, 'fetch').mockImplementation(async url => {
      const path = new URL(String(url)).pathname;
      return new Response(`<multistatus xmlns="DAV:"><response><href>${path}</href><propstat><prop><resourcetype><collection/></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>`,
        { status: 207, headers: dateHeader ? { Date: new Date(now + 45_000).toUTCString() } : {} });
    });
    state.settings.autoLockMinutes = 240;
    const controller = await unlocked();
    const input = { provider: 'custom', base: 'https://dav.example.test/', folder: 'vault', username: 'fixture', password: 'fixture' } as const;
    try {
      const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
      const item = record('Polling time');
      item.data.totpUri = secret;
      await controller.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
      const [{ id }] = await controller.handle({ type: 'list' }) as [ItemSummary];
      await controller.handle({ type: 'webdav-test', input, remember: true });
      await controller.handle({ type: 'webdav-clock', enabled: true });
      state.remoteVaultId = fixture.vaultId;
      state.pendingWal = []; // Initial login is already present at the last common head.
      const poll = async () => {
        state.remotePoll = { endpoint: await endpointFingerprint(webDavConfig(input).url), objects: [], checkedAt: now };
        await expect(controller.handle({ type: 'webdav-scheduled' })).resolves.toEqual({ kind: 'unchanged', pending: false });
        expect(remote.mock.lastCall?.[0]).toBe('https://dav.example.test/vault/wal/');
      };
      const codes = async (offset: number) => {
        const detail = await controller.handle({ type: 'get', id }) as ItemDetailData;
        if (detail.otp?.kind !== 'time') throw new Error('Expected a timed code');
        const expected = wasm_totp_at(secret, now / 1000 + offset).split(':')[0];
        const read = await controller.handle({ type: 'read-otp', id, handle: detail.otp.handle! }) as { value: string };
        const fill = await controller.handle({ type: 'autofill-read', id, kind: 'otp', groups: [], url: 'https://example-bank.com' }) as { values: { otp: string } };
        expect(read.value === expected && fill.values.otp === expected).toBe(true);
      };
      await codes(45);
      now += 29 * 60_000; await poll();
      now += 2 * 60_000; await codes(45);
      now += 31 * 60_000; // No successful communication.
      await codes(0);
      await expect(controller.handle({ type: 'webdav-status' })).resolves.toMatchObject({ compensation: true, offsetSeconds: null });
      await poll(); await codes(45);
      dateHeader = false; await poll(); await codes(0);
      dateHeader = true; await poll();
      await controller.handle({ type: 'webdav-clock', enabled: false });
      await poll(); await codes(0);
      expect(remote.mock.calls.every(([url, init]) => String(url).startsWith(input.base) && init?.method === 'PROPFIND')).toBe(true);
    } finally { await controller.lock(); remote.mockRestore(); clock.mockRestore(); }
  });

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
      fetchMock.mockResolvedValueOnce(new Response(null, { status: 404 }));
      await expect(restarted.handle({ type: 'webdav-test', input, remember: true })).resolves.toMatchObject({ kind: 'missing', writeAllowed: false });
      await expect(restarted.handle({ type: 'webdav-status' })).resolves.toMatchObject({ saved: false, paused: 429 });
      await expect(restarted.handle({ type: 'webdav-test', input, remember: true })).resolves.toMatchObject({ writeAllowed: false });
      await expect(restarted.handle({ type: 'webdav-status' })).resolves.toEqual({ saved: true, paused: undefined,
        offsetSeconds: 45, clockExpiresAt: time + 30 * 60_000 + 1, compensation: false });
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
      windows: { onRemoved: { addListener() {} }, onFocusChanged: { addListener() {} }, getAll: async () => [] },
      commands: { onCommand: { addListener() {} } },
      contextMenus: { onClicked: { addListener() {} } },
      alarms: { get: async () => undefined, create: async () => undefined, clear: async () => true,
        onAlarm: { addListener: (listener: typeof listenAlarm) => { listenAlarm = listener; } } },
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
        clipboardText = (await (payload as () => Promise<{ text: string }>)()).text;
        return Date.now();
      }
      if (operation === 'clear-clipboard' && payload === createHash('sha256').update(clipboardText).digest('hex')) clipboardText = '';
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

  it('seals wildcard restrictions and applies them to Passkey after reopening the vault', async () => {
    const rule = 'https://*.example.com:8443', origin = 'https://login.example.com:8443';
    const controller = await unlocked();
    await controller.handle({ type: 'set-autofill-site', origin: rule, flags: { passkeyDisabled: true } });
    const saved = await controller.handle({ type: 'set-autofill-site', origin: rule, flags: { saveDisabled: true } });
    expect(saved).toEqual({ inlineDisabled: false, saveDisabled: true, passkeyDisabled: true });
    await controller.handle({ type: 'set-autofill-site', origin, flags: { inlineDisabled: true } });
    expect(JSON.stringify(state.local)).not.toContain('example.com');
    await controller.lock();
    const reopened = await unlocked();
    expect(await reopened.passkeyAvailable(origin)).toBe(false);
    expect(await reopened.passkeyAvailable('https://eu.login.example.com:8443')).toBe(false);
    expect(await reopened.passkeyAvailable('https://example.com:8443')).toBe(true);
    expect(await reopened.passkeyAvailable('https://login.example.com')).toBe(true);
    await expect(reopened.handle({ type: 'set-autofill-site', origin: 'https://*.github.io', flags: { passkeyDisabled: true } })).rejects.toThrow();
    await reopened.handle({ type: 'set-autofill-site', origin: rule, flags: { passkeyDisabled: false, saveDisabled: false } });
    expect(await reopened.passkeyAvailable(origin)).toBe(true);
    expect(await reopened.handle({ type: 'autofill-settings' })).toEqual({
      sites: { [origin]: { inlineDisabled: true, saveDisabled: false, passkeyDisabled: false } },
      equivalentDomains: [],
    });
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

  it.each([true, undefined])('requires the new master password if rotation was durably observed before session cleanup (%s)', async remoteKeyUpdate => {
    const controller = await unlocked();
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Offline edit')) });
    state.files = { ...state.files!, remoteKeyUpdate };
    const previousFiles = structuredClone(state.files);
    const pending = structuredClone(state.pendingWal);
    const observation = {
      // Only the durable observation is needed here; sync bootstrap tests authenticate the actual remote head.
      observedHead: new Uint8Array([1]),
      observedKeyEpoch: fixture.keyEpoch + 1,
    };
    state.observedKeyUpdate = observation;
    const restarted = new VaultController();
    await expect(restarted.handle({ type: 'open' })).resolves.toEqual({
      status: expect.objectContaining({ configured: true, unlocked: false, remoteKeyUpdate: true }),
    });
    expect(state.session).toBeUndefined();
    await expect(restarted.handle({ type: 'list' })).rejects.toThrow('先解锁');
    await expect(restarted.handle({ type: 'unlock', password })).rejects.toThrow('新主密码');
    expect(state.files).toEqual(previousFiles);
    expect(state.pendingWal).toEqual(pending);
  });
  it('notifies panels and keeps operations locked when persistent session cleanup fails', async () => {
    const controller = await unlocked();
    const notify = vi.spyOn(browser.runtime, 'sendMessage');
    state.pauseSessionClear = Promise.reject(new Error('Test session storage cleanup failed'));
    try {
      await expect(controller.lock()).rejects.toThrow('Test session storage cleanup failed');
      expect(notify).toHaveBeenCalledWith({ target: 'vault-event', type: 'locked' });
      await expect(controller.handle({ type: 'open' })).rejects.toThrow('Test session storage cleanup failed');
    } finally {
      notify.mockRestore();
      state.pauseSessionClear = undefined;
      await controller.lock();
    }
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
  it('does not return cold opening summaries if the vault locks while renewing the session alarm', async () => {
    const controller = await unlocked();
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Protected fixture', true)) });
    let beginAlarm!: () => void;
    let finishAlarm!: () => void;
    const alarmEntered = new Promise<void>(resolve => { beginAlarm = resolve; });
    const alarmFinished = new Promise<void>(resolve => { finishAlarm = resolve; });
    vi.spyOn(browser.alarms, 'create').mockImplementationOnce(() => {
      beginAlarm();
      return alarmFinished;
    });
    const recreated = new VaultController();
    const opening = recreated.handle({ type: 'open' });
    const rejected = expect(opening).rejects.toThrow('密码库已锁定');
    try {
      await alarmEntered;
      await recreated.lock();
    } finally { finishAlarm(); }
    await rejected;
    expect(state.session).toBeUndefined();
    expect(await recreated.handle({ type: 'open' })).toEqual({ status: expect.objectContaining({ unlocked: false }) });
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
      { type: 'export-migration', format: 'cxf', confirmPlaintext: true },
      { type: 'export-migration', format: 'cxf', encrypted: true, password: filePassword, confirmPlaintext: false },
      { type: 'export-ente', confirmPlaintext: true },
    ] as const;
    for (const message of requests) {
      await expect(controller.handle({ ...message, proof: pin })).rejects.toThrow('主密码');
      await expect(controller.handle(message as VaultMessage)).rejects.toThrow('主密码');
      await expect(controller.handle({ ...message, proof: { method: 'master', secret: filePassword } })).rejects.toThrow('主密码验证失败');
      expect(await controller.handle({ ...message, proof })).toBeTruthy();
    }
    await expect(controller.handle({ type: 'export-migration', format: 'cxf', proof, confirmPlaintext: false })).rejects.toThrow('风险');
    await expect(controller.handle({ type: 'get', id: saved!.id, proof: pin })).resolves.toMatchObject({ title: item.title });
    expect(state.files!.changesSinceBackup).toBe(1);
  });
  it('attributes existing credentials to the device that creates a new pack and pairs them with the authenticated genesis head', async () => {
    const controller = await unlocked();
    Object.assign(browser.runtime, { getPlatformInfo: async () => ({ os: 'win', arch: 'x86-64' }), getManifest: () => ({ version: '1' }) });
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('Saved before linking')) });
    const [{ id }] = await controller.handle({ type: 'list' }) as [ItemSummary];
    const input = { provider: 'custom', base: 'https://dav.example.test/', folder: 'fixture', username: 'desktop', password: 'fixture' } as const;
    // Inspect the real prepared ciphertext before the first request to the DAV server.
    vi.mocked(savePackSetup).mockRejectedValueOnce(new Error('fixture disk boundary'));
    await expect(controller.handle({ type: 'webdav-create', input, masterPassword: password, deviceName: 'Origin desktop' }))
      .rejects.toThrow('fixture disk boundary');
    const [, setup] = vi.mocked(savePackSetup).mock.calls.at(-1)!;
    const { key, wrap } = state.session!;
    const view = await openPackContent(new Uint8Array(wasm_sync_pack_material(key, wrap)), setup.version, setup.ciphertext);
    const other = new wasm.WasmVaultEngine();
    const remote = wasm_sync_authenticate_head(setup.version.head!, key, wrap);
    try {
      other.restore_from_session(key, wrap, fixture.head, fixture.snap);
      const alternate = other.upsert_item_json(JSON.stringify({ ...record('Offline candidate'), id }), Date.now());
      const empty = new Uint8Array();
      try {
        const fork = wasm_sync_pack_merge(key, wrap, fixture.head, fixture.snap, alternate.head_bytes, alternate.snap_bytes,
          view.head, view.snap, empty, empty, view.conflicts);
        try { expect(JSON.parse(wasm_sync_conflicts(key, wrap, fork.conflicts, false))).toMatchObject([{ theirs: { source: 'Origin desktop' } }]); }
        finally { fork.free(); }
      } finally { alternate.free(); }
      expect(wasm_sync_verify_snapshot(key, wrap, remote.local_head, view.snap)).toBe(1);
      expect(view.head).toEqual(remote.local_head);
    } finally { remote.free(); other.free(); }
  });

  it('keeps the identity of a first edit on a joined device and shows its registered name in a remote review', async () => {
    const controller = await unlocked(), empty = new Uint8Array();
    Object.assign(browser.runtime, { getPlatformInfo: async () => ({ os: 'win', arch: 'x86-64' }), getManifest: () => ({ version: '1' }) });
    state.packAnchor = { vaultId: fixture.vaultId, endpoint: 'test', head: fixture.head, snap: empty, objects: [],
      appliedHead: fixture.head, appliedSnap: fixture.snap, checkedAt: 1, hasRecords: false,
      pack: { base: 'fixture', known: [], dirty: false, siteRules: 'applied', baseRules: empty, baseConflicts: empty } };
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(record('First joined edit')) });
    const devices = () => controller.handle({ type: 'webdav-devices' }) as Promise<{ active?: string; registered: boolean }>;
    const before = await devices();
    expect(before.active).toMatch(/^[0-9a-f-]{36}$/);
    await controller.handle({ type: 'webdav-device-change', action: 'register', name: 'Travel laptop', proof });
    expect(await devices()).toMatchObject({ active: before.active, registered: true });
    const [{ id }] = (await controller.handle({ type: 'list' }) as [ItemSummary]);
    const { key, wrap } = state.session!;
    const other = new wasm.WasmVaultEngine();
    try {
      other.restore_from_session(key, wrap, fixture.head, fixture.snap);
      const alternative = other.upsert_item_json(JSON.stringify({ ...record('Offline edit'), id }), Date.now());
      try {
        const merged = wasm_sync_pack_merge(key, wrap, fixture.head, fixture.snap, alternative.head_bytes, alternative.snap_bytes,
          state.files!.head, state.files!.snap, empty, empty, empty);
        try { expect(JSON.parse(wasm_sync_conflicts(key, wrap, merged.conflicts, false))).toMatchObject([{ theirs: { source: 'Travel laptop' } }]); }
        finally { merged.free(); }
      } finally { alternative.free(); }
    } finally { other.free(); }
  });

  it('publishes an explicitly restored .vaultpack entry and keeps the other permanent deletion reviewable', async () => {
    const controller = await unlocked();
    const add = (title: string) => controller.handle({ type: 'upsert', itemJson: JSON.stringify(record(title)) });
    await add('Backed up');
    const filePassword = 'Fixture-backup#2026';
    const { bytes } = await controller.handle({ type: 'export', password: filePassword, proof }) as BackupExport;
    await add('Stay deleted');
    const original = structuredClone(state.files!);
    const rows = await controller.handle({ type: 'list' }) as ItemSummary[];
    for (const { id } of rows) await controller.handle({ type: 'trash', id, trashed: true });
    await controller.handle({ type: 'empty-trash', expectedIds: rows.map(row => row.id) });
    const { key, wrap } = state.session!;
    const empty = new Uint8Array();
    function merge(base: VaultFiles, local: VaultFiles, remote: VaultFiles, stages = [empty, empty, empty] as Uint8Array[]) {
      const result = wasm_sync_pack_merge(key, wrap, base.head, base.snap, local.head, local.snap, remote.head, remote.snap,
        stages[0]!, stages[1]!, stages[2]!);
      try { return { files: { ...local, head: result.head, snap: result.snap }, conflicts: result.conflicts, count: result.count }; }
      finally { result.free(); }
    }
    const published = merge(original, state.files!, original);
    state.packAnchor = { vaultId: original.vaultId, endpoint: 'fixture', head: published.files.head, snap: empty, objects: [],
      appliedHead: published.files.head, appliedSnap: published.files.snap, checkedAt: 1, hasRecords: true, conflicts: published.conflicts,
      pack: { base: 'fixture', known: [], dirty: false, siteRules: 'applied', baseRules: empty, baseConflicts: published.conflicts } };
    const input = { bytes, password: filePassword, proof };
    const preview = await controller.handle({ type: 'preview-vaultpack', ...input }) as VaultPackPreview;
    expect(preview.added).toBe(1);
    expect(await controller.handle({ type: 'import', ...input, stamp: preview.stamp })).toBe(1);
    const next = merge(published.files, state.files!, published.files,
      [published.conflicts, state.packAnchor.conflicts!, published.conflicts]);
    expect(next.count).toBe(1);
    const offline = merge(fixture, original, next.files, [empty, empty, next.conflicts]);
    const conflicts = JSON.parse(wasm_sync_conflicts(key, wrap, offline.conflicts, false));
    expect(conflicts).toMatchObject([{ id: rows.find(row => row.title === 'Stay deleted')!.id, fields: ['$item'] }]);
  });

  it('imports a backup with the linked target recovery code without changing target identity or granting export', async () => {
    const source = await unlocked();
    const backupPassword = 'Separate-Pack-Password#2026';
    await source.handle({ type: 'upsert', itemJson: JSON.stringify(record()) });
    const { bytes } = await source.handle({ type: 'export', password: backupPassword, proof }) as BackupExport;
    await source.lock();
    state.files = undefined;
    state.pendingWal = [];
    const target = new VaultController();
    const targetPassword = 'Separate-Target-Master#2026';
    const kit = await target.handle({ type: 'create', masterPassword: targetPassword, calibrate: false }) as { vaultId: string; recoveryCode: string };
    try {
      const { keyEpoch } = await target.handle({ type: 'status' }) as VaultStatus;
      state.remoteVaultId = kit.vaultId;
      const targetProof = { method: 'recovery' as const, secret: kit.recoveryCode };
      const message = { type: 'preview-vaultpack' as const, bytes, password: backupPassword, proof: targetProof };
      const before = structuredClone(state.files);
      const preview = await target.handle(message) as VaultPackPreview;
      expect(preview).toMatchObject({ added: 1, updated: 0 });
      expect(state.files).toEqual(before);
      expect(state.pendingWal).toHaveLength(0);
      const confirm = { ...message, type: 'import' as const, stamp: preview.stamp };
      for (const secret of [recoveryCode, backupPassword]) {
        await expect(target.handle({ ...confirm, proof: { method: 'recovery', secret } })).rejects.toThrow('恢复码验证失败');
      }
      await expect(target.handle({ ...message, password: 'Wrong file password' })).rejects.toBeDefined();
      await expect(target.handle({ type: 'export', password: backupPassword, proof: targetProof } as unknown as VaultMessage)).rejects.toThrow('主密码');
      state.remoteVaultId = fixture.vaultId;
      await expect(target.handle(confirm)).rejects.toThrow('目标');
      expect(state.files).toEqual(before);
      expect(state.pendingWal).toHaveLength(0);
      state.remoteVaultId = kit.vaultId;
      await expect(target.handle(confirm)).resolves.toBe(1);
      expect(state.pendingWal).toHaveLength(1);
      await target.lock();
      await expect(target.handle({ type: 'unlock', password: targetPassword })).resolves.toMatchObject({ vaultId: kit.vaultId, keyEpoch, unlocked: true });
      await expect(target.handle(message)).resolves.toMatchObject({ added: 0, updated: 0 });
    } finally { await target.lock(); }
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
    await vi.advanceTimersByTimeAsync(30);
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

  it.each(['Ente', 'portable'] as const)('does not create a second live HOTP on %s reimport with a different period', async source => {
    const controller = await unlocked();
    const id = await addHotp(controller);
    for (const counter of ['0', '1']) await expect(controller.handle({ type: 'next-hotp', id })).resolves.toMatchObject({ counter });
    const stale = token('hotp', 'GitHub%3Atester', '&counter=0&period=60');
    if (source === 'Ente') {
      const bytes = bytesOf(stale);
      const preview = await controller.handle({ type: 'preview-ente', bytes }) as EntePreview;
      expect(preview).toMatchObject({ ready: 0, skipped: 1, invalid: 0 });
      expect(await controller.handle({ type: 'import-ente', bytes, stamp: preview.stamp, proof, merges: [] })).toBe(0);
    } else {
      const bytes = bytesOf(JSON.stringify({ encrypted: false, items: [{
        name: 'Counter token', type: 1, login: { username: 'tester', password: 'Unique-Secret-Pass#719',
          uris: [{ uri: 'https://example-bank.com' }], totp: stale },
      }] }));
      const input = { format: 'bitwarden', bytes } as const;
      const preview = await controller.handle({ type: 'preview-migration', ...input }) as MigrationPreview;
      expect(preview).toMatchObject({ ready: 0, skipped: 1, invalid: 0 });
      expect(await controller.handle({ type: 'import-migration', ...input, stamp: preview.stamp, proof })).toBe(0);
    }
    const items = await controller.handle({ type: 'list' }) as ItemSummary[];
    expect(items.map(item => item.id)).toEqual([id]);
    expect(await controller.handle({ type: 'next-hotp', id })).toEqual({ kind: 'hotp', counter: '2', value: '359152' });
  });

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

  it('previews and imports an Ente v1 password-encrypted backup without disclosing seeds or rolling back HOTP', async () => {
    const controller = await unlocked();
    const bytes = Array.from(await readFile(new URL(
      '../../../crates/vault-ente-auth/tests/fixtures/ente-auth-legacy.json', import.meta.url,
    )));
    const input = { bytes, password: ' Ente-夹具🔐 ' };
    const before = structuredClone(state.files);
    const pending = state.pendingWal.length;
    const preview = await controller.handle({ type: 'preview-ente', ...input }) as EntePreview;
    expect(preview).toMatchObject({ ready: 3, invalid: 0, skipped: 0, trashed: 1 });
    expect(preview.sample.map(row => row.kind)).toEqual(['totp', 'hotp', 'steam']);
    expect(JSON.stringify(preview)).not.toMatch(/GEZDGNBV|otpauth:|加密备份|Ente-夹具/);
    await expect(controller.handle({ type: 'preview-ente', bytes })).rejects.toThrow('文件密码');
    await expect(controller.handle({ type: 'import-ente', bytes, password: input.password.trim(),
      stamp: preview.stamp, merges: [], proof })).rejects.toThrow('文件密码');
    expect(state.files).toEqual(before);
    expect(state.pendingWal).toHaveLength(pending);
    expect(await controller.handle({ type: 'import-ente', ...input, stamp: preview.stamp, merges: [], proof })).toBe(3);
    const items = await controller.handle({ type: 'list' }) as ItemSummary[];
    const totp = items.find(item => item.title === 'GitHub')!;
    const hotp = items.find(item => item.title === 'Lab')!;
    expect(totp.pinned).toBe(true);
    expect(await controller.handle({ type: 'get', id: totp.id })).toMatchObject({ note: '加密备份', tags: ['工单', 'work'] });
    expect(items.find(item => item.title === 'Steam')?.trashed).toBe(true);
    expect(await controller.handle({ type: 'next-hotp', id: hotp.id, proof })).toEqual({ kind: 'hotp', counter: '1', value: '287082' });
    const repeat = await controller.handle({ type: 'preview-ente', ...input }) as EntePreview;
    expect(repeat).toMatchObject({ ready: 0, skipped: 3 });
    expect(await controller.handle({ type: 'next-hotp', id: hotp.id, proof })).toEqual({ kind: 'hotp', counter: '2', value: '359152' });
  });

  it('locks an expired session during Ente decryption and rejects its pending import', async () => {
    state.settings.autoLockMinutes = 1;
    const controller = await unlocked();
    const bytes = Array.from(await readFile(new URL(
      '../../../crates/vault-ente-auth/tests/fixtures/ente-auth-legacy.json', import.meta.url,
    )));
    const input = { bytes, password: ' Ente-夹具🔐 ' };
    const preview = await controller.handle({ type: 'preview-ente', ...input }) as EntePreview;
    const before = structuredClone(state.files);
    const started = Promise.withResolvers<void>();
    const resume = Promise.withResolvers<void>();
    state.pauseEnte = () => { started.resolve(); return resume.promise; };
    const completed = expect(controller.handle({ type: 'import-ente', ...input, stamp: preview.stamp, merges: [], proof }))
      .rejects.toThrow('密码库已锁定');
    await started.promise;
    const now = vi.spyOn(Date, 'now').mockReturnValue(state.session!.lastActivityMs + 60_000);
    try {
      await expect(controller.lockExpiredSession()).resolves.toBe(true);
      expect(state.session).toBeUndefined();
    } finally {
      now.mockRestore();
      resume.resolve();
      await completed;
    }
    expect(state.files).toEqual(before);
    expect(state.pendingWal).toHaveLength(0);
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
  it('requires the target master password before committing a KeePass migration', async () => {
    const controller = await unlocked();
    const bytes = Array.from(new TextEncoder().encode('"Account","Login Name","Password","Web Site","Comments"\n"Fixture","me","synthetic","https://example.com",""\n'));
    const preview = await controller.handle({ type: 'preview-migration', format: 'keepass', bytes }) as { stamp: string; ready: number };
    expect(preview.ready).toBe(1);
    const message = { type: 'import-migration' as const, format: 'keepass' as const, bytes, stamp: preview.stamp };
    const before = structuredClone(state.files);
    await expect(controller.handle({ ...message, proof: { method: 'pin', secret: '734928' } })).rejects.toThrow('需要再次验证主密码。');
    expect(state.files).toEqual(before);
    expect(await controller.handle({ ...message, proof })).toBe(1);
  });
  it('requires proof to commit a Dashlane ZIP and keeps secure note contents out of preview', async () => {
    const controller = await unlocked();
    const title = 'Dashlane archive note', note = '  Synthetic secure note\nsecond line  ';
    const bytes = Array.from(zip({ 'securenotes.csv': Buffer.from(`title,note\r\n${title},"${note}"\r\n`) }));
    const previewMessage = { type: 'preview-migration', format: 'dashlane-zip', bytes } as const;
    const before = structuredClone(state.files);
    const preview = await controller.handle(previewMessage) as MigrationPreview;
    expect(preview).toMatchObject({ ready: 1, invalid: 0, sample: [{ title }] });
    expect(JSON.stringify(preview)).not.toContain('Synthetic secure note');
    const commit = { ...previewMessage, type: 'import-migration', stamp: preview.stamp } as const;
    await expect(controller.handle({ ...commit, proof: { method: 'master', secret: 'Wrong test password' } }))
      .rejects.toThrow('主密码验证失败');
    expect(state.files).toEqual(before);
    expect(await controller.handle({ ...commit, proof })).toBe(1);
    await expect(controller.handle({ ...commit, proof })).rejects.toThrow('重新预览');
    expect(await controller.handle(previewMessage)).toMatchObject({ ready: 0, skipped: 1 });
    const [item] = await controller.handle({ type: 'list' }) as ItemSummary[];
    expect(item).toMatchObject({ title, requireReprompt: true, devSubtype: 'secure_note' });
    await expect(controller.handle({ type: 'get', id: item!.id })).rejects.toThrow('再次验证');
    expect(await controller.handle({ type: 'get', id: item!.id, proof })).toMatchObject({ note });
  });
  for (const [format, filename, filePassword, ready] of [
    ['stratum', 'backup.strong.authpro', 'test', 6],
    ['andotp', 'andotp.encrypted.bin', 'testtest', 7],
  ] as const) {
    it.skipIf(!process.env.VAULT_AUTH_FIXTURE_DIR)(`authenticates ${format} before saving and preserves the HOTP counter`, async () => {
      const controller = await unlocked();
      const bytes = Array.from(await readFile(join(process.env.VAULT_AUTH_FIXTURE_DIR!, filename)));
      const entry = { type: 'preview-auth-backup', format, bytes, password: filePassword } as const;
      const before = structuredClone(state.files);
      const preview = await controller.handle(entry) as AuthBackupPreview;
      expect(preview.ready).toBe(ready);
      expect(JSON.stringify(preview)).not.toContain('otpauth:');
      const commit = { ...entry, type: 'import-auth-backup', stamp: preview.stamp, proof } as const;
      await expect(controller.handle({ ...commit, password: 'Wrong source password' })).rejects.toThrow('认证失败');
      expect(state.files).toEqual(before);
      expect(state.pendingWal).toHaveLength(0);
      expect(await controller.handle(commit)).toBe(ready);
      const summaries = await controller.handle({ type: 'list' }) as ItemSummary[];
      const details = await Promise.all(summaries.map(({ id }) => controller.handle({ type: 'get', id }) as Promise<ItemDetailData>));
      const hotp = details.find(row => row.otp?.kind === 'hotp');
      expect(hotp).toBeDefined();
      expect(hotp!.data).not.toHaveProperty('totpUri');
      expect(await controller.handle({ type: 'next-hotp', id: hotp!.id })).toMatchObject({ counter: '10', value: '651512' });
      expect(await controller.handle(entry)).toMatchObject({ ready: 0, skipped: ready });
    });
  }
  it('deduplicates a native HOTP with the Steam issuer even after its account label changes', async () => {
    const controller = await unlocked();
    const source = (label: string, counter: number) => Array.from(Buffer.from(JSON.stringify([{
      type: 'HOTP', label, issuer: 'Steam', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      algorithm: 'SHA1', digits: 6, counter,
    }])));
    const entry = { type: 'preview-auth-backup', format: 'andotp', bytes: source('Original account', 10) } as const;
    const preview = await controller.handle(entry) as AuthBackupPreview;
    expect(preview.ready).toBe(1);
    expect(await controller.handle({ ...entry, type: 'import-auth-backup', stamp: preview.stamp, proof })).toBe(1);
    const [item] = await controller.handle({ type: 'list' }) as ItemSummary[];
    expect(await controller.handle({ type: 'next-hotp', id: item!.id })).toMatchObject({ counter: '10' });
    expect(await controller.handle({ ...entry, bytes: source('Former label', 1) })).toMatchObject({ ready: 0, skipped: 1 });
  });
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
    const item = await controller.handle({ type: 'get-edit', id: login.id, proof }) as VaultItem;
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
  it('does not partially import a complete Google QR batch with a damaged record', async () => {
    const controller = await unlocked();
    const otp = Buffer.from([0x20, 1, 0x28, 1, 0x30, 2]);
    const valid = Buffer.concat([Buffer.from([0x0a, 20]), Buffer.alloc(20, 0x31), otp]);
    const part = Buffer.concat([Buffer.from([0x0a, valid.length]), valid,
      Buffer.from([0x0a, otp.length]), otp, Buffer.from([0x10, 1, 0x18, 1])]);
    const bytes = Array.from(Buffer.from('otpauth-migration://offline?data=' + encodeURIComponent(part.toString('base64'))));
    const before = structuredClone(state.files);
    const preview = await controller.handle({ type: 'preview-auth-backup', format: 'google', bytes }) as AuthBackupPreview;
    expect(preview).toMatchObject({ ready: 1, invalid: 1, missingParts: 0 });
    await expect(controller.handle({ type: 'import-auth-backup', format: 'google', bytes, stamp: preview.stamp, proof })).rejects.toThrow('有损坏的条目');
    expect(state.files).toEqual(before);
    expect(state.pendingWal).toHaveLength(0);
    await expect(controller.handle({ type: 'list' })).resolves.toEqual([]);
  });
  it.each(['aegis', '2fas', 'raivo'] as const)('keeps verified HOTP counters and reports unknown counters in %s backups', async format => {
    const controller = await unlocked();
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const rows = [
      ['Known zero', 'HOTP', 'SHA1', 6, 0],
      ['Known positive', 'HOTP', 'SHA1', 8, 7],
      ['Missing', 'HOTP', 'SHA256', 6, undefined],
      ['Fraction', 'HOTP', 'SHA256', 8, 1.5],
      ['Negative', 'HOTP', 'SHA512', 6, -1],
      ['Timed', 'TOTP', 'SHA1', 6, undefined],
    ] as const;
    const records = rows.map(([name, kind, algorithm, digits, counter]) => {
      if (format === 'aegis') return { name, type: kind.toLowerCase(), info: { secret, algo: algorithm, digits, counter } };
      if (format === '2fas') return { name, secret, otp: { tokenType: kind, account: name, algorithm, digits, counter } };
      return { account: name, kind: kind.toLowerCase(), secret, algorithm, digits: String(digits), counter: counter?.toString() };
    });
    const source = format === 'aegis' ? { version: 1, db: { version: 3, entries: records } }
      : format === '2fas' ? { schemaVersion: 4, services: records } : records;
    const bytes = Array.from(Buffer.from(JSON.stringify(source)));
    const message = { type: 'preview-auth-backup', format, bytes } as const;

    const before = structuredClone(state.files);
    const preview = await controller.handle(message) as AuthBackupPreview;
    expect(preview).toMatchObject({ ready: 3, invalid: 3, skipped: 0, unknownHotpCounters: 3 });
    expect(JSON.stringify(preview)).not.toMatch(/GEZDGNBV|otpauth:/);
    expect(state.files).toEqual(before);
    expect(await controller.handle({ type: 'list' })).toEqual([]);

    expect(await controller.handle({ ...message, type: 'import-auth-backup', stamp: preview.stamp, proof })).toBe(3);
    const items = await controller.handle({ type: 'list' }) as ItemSummary[];
    expect(items.map(item => item.title).sort()).toEqual(['Known positive', 'Known zero', 'Timed']);
    const id = (title: string) => items.find(item => item.title === title)!.id;
    for (const [title, counter, next, value] of [
      ['Known zero', '0', '1', '755224'], ['Known positive', '7', '8', '82162583'],
    ] as const) {
      expect(await controller.handle({ type: 'next-hotp', id: id(title) })).toMatchObject({ counter, value });
      expect(await controller.handle({ type: 'next-hotp', id: id(title) })).toMatchObject({ counter: next });
    }
    expect(await controller.handle({ type: 'get', id: id('Timed') })).toMatchObject({ otp: { kind: 'time' } });
  });
  it('round-trips Vault login CSV with offline logins and standalone authenticators', async () => {
    const source = await unlocked();
    const title = 'Standalone authenticator';
    const otp = 'otpauth://totp/Fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const offline = record('Offline login');
    offline.data.uris = [];
    const timed = { ...record(title), data: { kind: 'login', username: 'token account', password: '', uris: [], totpUri: otp } };
    const online = record('Website login');
    const onlineUrl = 'https://online.example.test/login';
    online.data.uris = [{ uri: onlineUrl }];
    const otherOffline = { ...offline, title: 'Second offline account' };
    const trashedOffline = { ...offline, trashed: true };
    for (const item of [offline, otherOffline, trashedOffline, timed, online, { ...record('Not a login'), data: { kind: 'developer', subtype: 'secure_note' } }]) {
      await source.handle({ type: 'upsert', itemJson: JSON.stringify(item) });
    }
    const request = { type: 'export-migration', format: 'csv', proof, confirmPlaintext: true } as const;
    await expect(source.handle({ ...request, confirmPlaintext: false })).rejects.toThrow('明文文件的风险');
    await expect(source.handle({ ...request, proof: { method: 'pin', secret: '123456' } })).rejects.toThrow('主密码');
    const exported = await source.handle(request) as { text: string; count: number; skipped: number };
    expect(exported).toMatchObject({ count: 5, skipped: 1 });

    await source.lock();
    state.files = undefined;
    state.pendingWal = [];
    const target = new VaultController();
    await target.handle({ type: 'create', masterPassword: password, calibrate: false });
    const bytes = [...Buffer.from(exported.text)];
    const headers = await target.handle({ type: 'csv-headers', bytes }) as { vendor?: string; mapping?: Record<string, number> };
    const mapping = headers.mapping ?? { title: 0, url: 1, username: 2, password: 3, note: 4, totp: 5, tags: 6, trashed: 7 };
    const message = { type: 'preview-migration', format: 'csv', bytes, mapping } as const;
    const before = structuredClone(state.files);
    const preview = await target.handle(message) as MigrationPreview;
    expect(preview).toMatchObject({ ready: 5, skipped: 0, invalid: 0, ignoredOtp: 0 });
    expect(headers.vendor).toBe('Vault');
    expect(JSON.stringify(preview)).not.toMatch(/GEZDGNBV|Unique-Secret-Pass/);
    expect(state.files).toEqual(before);
    expect(await target.handle({ type: 'list' })).toEqual([]);
    expect(await target.handle({ ...message, type: 'import-migration', stamp: preview.stamp, proof })).toBe(5);
    const items = await target.handle({ type: 'list' }) as ItemSummary[];
    expect(items).toHaveLength(5);
    expect(items.filter(item => item.title === offline.title).map(item => item.trashed).sort()).toEqual([false, true]);
    expect(items.find(item => item.title === otherOffline.title)?.trashed).toBe(false);
    const id = (title: string) => items.find(item => item.title === title)!.id;
    expect(await target.handle({ type: 'get-edit', id: id(offline.title) }))
      .toMatchObject({ data: { password: offline.data.password, uris: [] } });
    expect(await target.handle({ type: 'get-edit', id: id(online.title) }))
      .toMatchObject({ data: { password: online.data.password, uris: [{ uri: onlineUrl }] } });
    expect(await target.handle({ type: 'get-edit', id: id(title) })).toMatchObject({ data: { password: '', uris: [], totpUri: otp } });
    expect(await target.handle(message)).toMatchObject({ ready: 0, skipped: 5 });
    const detail = await target.handle({ type: 'get', id: id(title) }) as ItemDetailData;
    expect(detail.otp?.kind).toBe('time');
    if (detail.otp?.kind !== 'time') throw new Error('Expected timed OTP');
    expect(await target.handle({ type: 'read-otp', id: detail.id, handle: detail.otp.handle! }))
      .toMatchObject({ kind: 'totp', value: expect.stringMatching(/^\d{6}$/) });

    const foreign = { ...message, bytes: [...Buffer.from('Website,Pass,Name\n,secret,Offline\nhttps://third.example,,No password')],
      mapping: { url: 0, password: 1, title: 2 } };
    expect(await target.handle(foreign)).toMatchObject({ ready: 0, invalid: 2 });
    await expect(target.handle({ ...foreign, mapping: { password: 1 } })).rejects.toThrow('请映射网站和密码列');
  });
  it('requires a master proof and explicit plaintext consent for full-vault migration exports', async () => {
    const controller = await unlocked();
    await expect(controller.handle({ type: 'export-migration', format: 'bitwarden', proof, confirmPlaintext: false })).rejects.toThrow('风险');
    await expect(controller.handle({ type: 'export-migration', format: 'bitwarden', proof: { method: 'pin', secret: '123456' }, confirmPlaintext: true })).rejects.toThrow('主密码');
    await expect(controller.handle({ type: 'export-migration', format: 'bitwarden', proof: { method: 'master', secret: 'Wrong master' }, confirmPlaintext: true })).rejects.toThrow('主密码验证失败');
  });
  it('copies only time codes with clipboard expiry and never advances HOTP as part of login filling', async () => {
    vi.mocked(offscreen).mockClear();
    let copied = '';
    vi.mocked(offscreen).mockImplementation(async (operation, payload) => {
      if (operation === 'copy') {
        copied = (await (payload as () => Promise<{ text: string }>)()).text;
        return Date.now();
      }
    });
    const controller = await unlocked();
    const value = record('OTP copy fixture', true);
    value.data.uris = [{ uri: 'https://example.com' }];
    value.data.totpUri = 'JBSWY3DPEHPK3PXP';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(value) });
    const id = (await controller.handle({ type: 'list' }) as ItemSummary[])[0]!.id;
    await expect(controller.handle({ type: 'autofill-copy-otp', id, url: 'https://example.com', groups: [] })).rejects.toThrow('再次验证');
    expect(await controller.handle({ type: 'autofill-copy-otp', id, url: 'https://example.com', groups: [], proof })).toBe(true);
    expect(copied).toMatch(/^\d{6}$/);
    expect(browser.storage.session.set).toHaveBeenCalledWith({ clipboard: {
      hash: createHash('sha256').update(copied).digest('hex'), expiresAt: expect.any(Number),
    } });
    const latest = await controller.handle({ type: 'get-edit', id, proof }) as VaultItem;
    latest.data.totpUri = 'otpauth://hotp/Fixture?secret=JBSWY3DPEHPK3PXP&counter=5';
    await controller.handle({ type: 'upsert', itemJson: JSON.stringify(latest), proof });
    vi.mocked(offscreen).mockClear();
    expect(await controller.handle({ type: 'autofill-copy-otp', id, url: 'https://example.com', groups: [], proof })).toBeNull();
    expect(offscreen).not.toHaveBeenCalled();
    expect((await controller.handle({ type: 'get-edit', id, proof }) as VaultItem).data.totpUri).toContain('counter=5');
  });
});
