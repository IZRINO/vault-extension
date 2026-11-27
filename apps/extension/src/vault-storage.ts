import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import type { JournalClock } from './sync/journal-device';
import type { RemoteWal } from './sync/bootstrap';
import type { WholePackState } from './sync/pack-sync';
import type { PackVersion } from './sync/pack-transport';

interface VaultDbSchema extends DBSchema {
  vault: { key: string; value: VaultFiles };
  pendingChanges: { key: string; value: Uint8Array };
  pendingWal: { key: string; value: PendingWal };
  journal: { key: string; value: JournalClock };
  remoteState: { key: string; value: RemoteAnchor };
  packSetup: { key: string; value: PendingPackSetup };
}
export interface PendingWal { vaultId: string; bytes: Uint8Array }
export interface JournalCommit { id: string; state: JournalClock; bytes: Uint8Array; replaceLegacy: boolean }
export interface PendingPackSetup {
  version: PackVersion;
  ciphertext: Uint8Array<ArrayBuffer>;
  clock: JournalClock;
  source?: string;
  recovery?: Uint8Array<ArrayBuffer>;
}
export interface RemoteAnchor {
  vaultId: string; endpoint: string; head: Uint8Array; snap: Uint8Array; etag?: string;
  objects: RemoteWal[];
  appliedHead: Uint8Array; appliedSnap: Uint8Array; hasRecords: boolean;
  outbox?: RemoteWal & { priorIds: string[]; source: VaultFiles; capacityVersion?: 1 };
  checkedAt?: number;
  conflicts?: Uint8Array;
  conflictCount?: number;
  draftCount?: number;
  pendingResolutions?: Uint8Array;
  pendingCompaction?: { id: string; digest: string; priorHistory: string[] };
  localRestoreHeld?: boolean;
  rotationFrom?: number;
  observedKeyEpoch?: number;
  observedHead?: Uint8Array;
  pack?: WholePackState;
  // Head and snapshot remain authenticated ciphertext; do not store a plaintext copy of the root or records.
}
export interface VaultFiles {
  head: Uint8Array; snap: Uint8Array; vaultId: string; keyEpoch: number;
  updatedAtMs: number; changesSinceBackup: number;
  /** Saved with the remote anchor so a cold worker can reject an obsolete session without loading the anchor. */
  remoteKeyUpdate?: boolean;
  /** Absolute change count covered by the latest confirmed backup; absent on older vaults. */
  backedUpChangeCount?: number;
  everHadRecords?: boolean;
  /** Authenticated, vault-scoped preferences copied into whole-vault sync packages. */
  packRules?: Uint8Array;
  /** Local preferences when this device declines the cloud rules. */
  localPackRules?: Uint8Array;
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
  dbPromise ??= openDB<VaultDbSchema>('vault-extension', 5, {
    upgrade(db) {
      if (!db.objectStoreNames.contains('vault')) db.createObjectStore('vault');
      if (!db.objectStoreNames.contains('pendingChanges')) db.createObjectStore('pendingChanges');
      if (!db.objectStoreNames.contains('pendingWal')) db.createObjectStore('pendingWal');
      if (!db.objectStoreNames.contains('journal')) db.createObjectStore('journal');
      if (!db.objectStoreNames.contains('remoteState')) db.createObjectStore('remoteState');
      if (!db.objectStoreNames.contains('packSetup')) db.createObjectStore('packSetup');
    },
  });
  return dbPromise;
}
export async function loadVaultFiles(): Promise<VaultFiles | undefined> {
  return (await database()).get('vault', 'active');
}
export async function loadJournal(vaultId: string): Promise<{ clock?: JournalClock; legacy: boolean }> {
  const tx = (await database()).transaction(['journal', 'pendingChanges']);
  const [clock, key] = await Promise.all([tx.objectStore('journal').get(vaultId), tx.objectStore('pendingChanges').getKey('hotp-snapshot')]);
  return { clock, legacy: key !== undefined };
}
export async function loadRemoteAnchor(vaultId: string) { return (await database()).get('remoteState', vaultId); }
export async function loadPackSetup(endpoint: string) { return (await database()).get('packSetup', endpoint); }
export async function savePackSetup(endpoint: string, setup: PendingPackSetup) {
  const tx = (await database()).transaction('packSetup', 'readwrite', { durability: 'strict' });
  await Promise.all([tx.store.put(setup, endpoint), tx.done]);
}
export async function clearPackSetup(endpoint: string) { await (await database()).delete('packSetup', endpoint); }
export async function hasPendingWal(vaultId: string) {
  const db = await database();
  const tx = db.transaction(['pendingWal', 'pendingChanges']);
  if (await tx.objectStore('pendingChanges').getKey('hotp-snapshot') !== undefined) return true;
  for (let cursor = await tx.objectStore('pendingWal').openCursor(null, 'prev'); cursor; cursor = await cursor.continue())
    if (cursor.value.vaultId === vaultId) return true;
  return false;
}
export async function saveRemoteAnchor(anchor: RemoteAnchor, files: VaultFiles, clock?: JournalClock, newVault = false, consume = true) {
  const tx = (await database()).transaction(['vault', 'remoteState', 'journal', 'pendingWal', 'pendingChanges'], 'readwrite', { durability: 'strict' });
  const vault = tx.objectStore('vault');
  const current = await vault.get('active');
  if (newVault ? !!current : current?.vaultId !== anchor.vaultId) {
    tx.abort();
    await tx.done.catch(() => undefined);
    throw new Error('此设备已有密码库，未覆盖本机数据。');
  }
  if (consume) {
    const pending = tx.objectStore('pendingWal');
    for (let cursor = await pending.openCursor(); cursor; cursor = await cursor.continue())
      if (cursor.value.vaultId === anchor.vaultId) await cursor.delete();
  }
  await Promise.all([tx.objectStore('remoteState').put(anchor, anchor.vaultId),
    vault.put({ ...files, remoteKeyUpdate: !!anchor.observedHead }, 'active'),
    consume ? tx.objectStore('pendingChanges').delete('hotp-snapshot') : undefined,
    clock ? tx.objectStore('journal').put(clock, anchor.vaultId) : undefined, tx.done]);
}
export async function adoptRemoteVault(source: VaultFiles, anchor: RemoteAnchor, target: VaultFiles, change: JournalCommit | JournalClock) {
  const tx = (await database()).transaction(['vault', 'remoteState', 'journal', 'pendingWal', 'pendingChanges'], 'readwrite', { durability: 'strict' });
  const vault = tx.objectStore('vault'), remote = tx.objectStore('remoteState');
  const [current, known] = await Promise.all([vault.get('active'), remote.get(source.vaultId)]);
  const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((value, i) => value === b[i]);
  if (!current || current.vaultId !== source.vaultId || !same(current.head, source.head) || !same(current.snap, source.snap) ||
      known || source.vaultId === target.vaultId || target.vaultId !== anchor.vaultId) {
    tx.abort();
    await tx.done.catch(() => undefined);
    throw new Error('本机或目标库已经变化，未切换密码库。请重新预览。');
  }
  await Promise.all([
    vault.add(current, `merged-source:${current.vaultId}`),
    vault.put(target, 'active'),
    remote.put(anchor, target.vaultId),
    tx.objectStore('journal').put('state' in change ? change.state : change, target.vaultId),
    'bytes' in change ? tx.objectStore('pendingWal').add({ vaultId: target.vaultId, bytes: change.bytes }, change.id) : undefined,
    tx.objectStore('pendingChanges').delete('hotp-snapshot'),
    tx.done,
  ]);
}
export async function saveVaultFiles(files: VaultFiles, change?: JournalCommit, anchor?: RemoteAnchor): Promise<void> {
  const db = await database();
  const saved = { ...files, head: new Uint8Array(files.head), snap: new Uint8Array(files.snap) };
  if (!change) { await db.put('vault', saved, 'active'); return; }
  const tx = db.transaction(['vault', 'journal', 'pendingWal', 'pendingChanges', 'remoteState'], 'readwrite', { durability: 'strict' });
  await Promise.all([
    tx.objectStore('vault').put(saved, 'active'),
    tx.objectStore('journal').put(change.state, files.vaultId),
    tx.objectStore('pendingWal').add({ vaultId: files.vaultId, bytes: change.bytes }, change.id),
    anchor ? tx.objectStore('remoteState').put(anchor, files.vaultId) : undefined,
    change.replaceLegacy ? tx.objectStore('pendingChanges').delete('hotp-snapshot') : undefined,
    tx.done,
  ]);
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
