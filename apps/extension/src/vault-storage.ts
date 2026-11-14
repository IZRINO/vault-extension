import { openDB, type DBSchema, type IDBPDatabase } from 'idb';

interface VaultDbSchema extends DBSchema {
  vault: { key: string; value: VaultFiles };
  pendingChanges: { key: string; value: Uint8Array };
}
export interface VaultFiles {
  head: Uint8Array; snap: Uint8Array; vaultId: string; keyEpoch: number;
  updatedAtMs: number; changesSinceBackup: number;
  /** Absolute change count covered by the latest confirmed backup; absent on older vaults. */
  backedUpChangeCount?: number;
}
export interface SessionState {
  key: Uint8Array; wrap: Uint8Array; unlockedAtMs: number; lastActivityMs: number;
}
export interface LocalSettings {
  pinWrap?: Uint8Array; pinFailures: number; autoLockMinutes: number;
  prf?: { credentialId: number[]; salt: number[]; wrap: number[] };
}
let dbPromise: Promise<IDBPDatabase<VaultDbSchema>> | undefined;
function database() {
  dbPromise ??= openDB<VaultDbSchema>('vault-extension', 2, {
    upgrade(db) {
      if (!db.objectStoreNames.contains('vault')) db.createObjectStore('vault');
      if (!db.objectStoreNames.contains('pendingChanges')) db.createObjectStore('pendingChanges');
    },
  });
  return dbPromise;
}
export async function loadVaultFiles(): Promise<VaultFiles | undefined> {
  return (await database()).get('vault', 'active');
}
export async function saveVaultFiles(files: VaultFiles): Promise<void> {
  await (await database()).put('vault', { ...files, head: new Uint8Array(files.head), snap: new Uint8Array(files.snap) }, 'active');
}
export async function loadSessionState(): Promise<SessionState | undefined> {
  const { active } = await browser.storage.session.get<{ active: { key: number[]; wrap: number[]; unlockedAtMs: number; lastActivityMs: number } }>('active');
  if (!active || !Array.isArray(active.key) || active.key.length !== 32 || !Array.isArray(active.wrap)
    || !Number.isFinite(active.lastActivityMs) || !Number.isFinite(active.unlockedAtMs)) return undefined;
  return { ...active, key: new Uint8Array(active.key), wrap: new Uint8Array(active.wrap) };
}
export async function saveSessionState(state: SessionState): Promise<void> {
  await browser.storage.session.set({ active: { ...state, key: Array.from(state.key), wrap: Array.from(state.wrap) } });
}
export async function clearSessionState(): Promise<void> {
  await browser.storage.session.remove('active');
}
export async function loadSettings(): Promise<LocalSettings> {
  const { settings } = await browser.storage.local.get<{ settings: Partial<Omit<LocalSettings, 'pinWrap'> & { pinWrap: number[] }> }>('settings');
  const minutes = settings?.autoLockMinutes;
  return {
    pinWrap: settings?.pinWrap ? new Uint8Array(settings.pinWrap) : undefined,
    pinFailures: Math.max(0, Number(settings?.pinFailures) || 0),
    autoLockMinutes: typeof minutes === 'number' && Number.isInteger(minutes) && minutes >= 1 && minutes <= 240 ? minutes : 15,
    prf: settings?.prf,
  };
}
export async function saveSettings(settings: LocalSettings): Promise<void> {
  // Omit the key altogether after PIN lockout; no empty wrapper remains in storage.
  const record: Record<string, unknown> = { pinFailures: settings.pinFailures, autoLockMinutes: settings.autoLockMinutes };
  if (settings.pinWrap) record.pinWrap = Array.from(settings.pinWrap);
  if (settings.prf) record.prf = settings.prf;
  await browser.storage.local.set({ settings: record });
}
