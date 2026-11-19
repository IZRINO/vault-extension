export type Proof = { method: 'master' | 'pin'; secret: string };
export const MAX_VAULTPACK_BYTES = 16 * 1024 * 1024;
export const MAX_BROWSER_CSV_BYTES = 2 * 1024 * 1024;
export const MAX_ENTE_BYTES = 2 * 1024 * 1024;
export const MAX_MIGRATION_BYTES = 16 * 1024 * 1024;
export const MAX_AUTH_BACKUP_BYTES = 4 * 1024 * 1024;
export const AUTH_BACKUP_FORMATS = ['google', '2fas', 'aegis', 'raivo', 'andotp', 'stratum'] as const;
export type AuthBackupFormat = typeof AUTH_BACKUP_FORMATS[number];
export type AuthBackupInput = { format: AuthBackupFormat; bytes?: number[]; images?: string[]; password?: string };
export const PORTABLE_FORMATS = ['bitwarden', 'bitwarden-retained', 'cxf', 'keepass', 'onepassword', 'proton'] as const;
export type MigrationFormat = typeof PORTABLE_FORMATS[number] | 'csv';
export type CsvMapping = Partial<Record<'title' | 'url' | 'username' | 'password' | 'note' | 'totp' | 'tags' | 'trashed', number>>;
export interface MigrationPreview {
  stamp: string; ready: number; skipped: number; invalid: number; unsupported: number; ignoredOtp: number;
  sample: { title: string; kind: string; account: string }[];
  passkeys?: number;
  suspendedPasskeys?: number;
  ignoredPasskeys?: number;
}
export type AuthBackupPreview = MigrationPreview & { missingParts: number; repeatedParts: number };
export interface MigrationExport { text: string; count: number; skipped: number; skippedPasskeys?: number }
export const MAX_OTP_SETUP_LENGTH = 64 * 1024;
export interface BackupReceipt { vaultId: string; changeCount: number; authorization: string }
export interface BackupExport { bytes: number[]; receipt: BackupReceipt }
export interface BrowserCsvPreview {
  stamp: string; ready: number; skipped: number; invalid: number; ignoredOtp: number;
  sample: { title: string; site: string; username: string }[];
}
export interface EnteMerge { row: number; id: string }
export interface EntePreview {
  stamp: string; ready: number; skipped: number; invalid: number; trashed: number;
  sample: { title: string; account: string; kind: string }[];
  suggestions: { row: number; id: string; title: string; account: string }[];
}
/** Internal worker result; never return this object to a vault panel or webpage. */
export interface OtpWorkerCode {
  kind: 'totp' | 'hotp' | 'steam'; value: string; validTo: number | null;
  nextValue: string | null; counter: string | null; nextSetupKey: string | null;
}
export interface TimedOtpCode { kind: 'totp' | 'steam'; value: string; validTo: number; nextValue: string | null }
export interface HotpCode { kind: 'hotp'; value: string; counter: string }
export interface QrScan {
  values: string[];
  timings: { captureMs: number; imageMs: number; grayscaleMs: number; wasmWaitMs: number; decodeMs: number };
}
export interface ConflictVersion { title: string; time: number; source?: string; trashed: boolean; values: Record<string, unknown> }
export interface VaultConflict {
  id: string; fields: string[]; protected: boolean;
  base: ConflictVersion | null; ours: ConflictVersion | null; theirs: ConflictVersion | null;
}
export interface ConflictReview { stamp: string; rows: VaultConflict[] }
export interface DavJoinPreview { stamp: string; sourceCount: number; targetCount: number; mergedCount: number; conflicts: number }
export interface ConflictRule {
  id: string; mode: 'ours' | 'theirs' | 'both' | 'fields'; fields?: Record<string, 'ours' | 'theirs'>;
  title?: string; note?: string;
}
export interface SyncHistoryEntry { id: string; time: number; epoch: number; count: number; current: boolean }
export interface SyncRestorePreview { id: string; before: number; after: number; removed: number; blocked: boolean; bulk: boolean; stamp: string; readOnly?: boolean }
export interface VaultPackPreview { added: number; updated: number; skipped: number; stamp: string }
export interface SyncDevice { id: string; name: string; system: string; browser: string; version: string; created: number; lastSeen: number }
export interface SyncDevices { active?: string; rows: SyncDevice[]; system: string; browser: string; registered: boolean }
export function capacityErrorText(error: unknown): string | undefined {
  if (typeof error !== 'string') return;
  const prefix = ['COMPACT_OBJECT_TOO_LARGE: ', 'VAULTPACK_TOO_LARGE: '].find(value => error.startsWith(value));
  return prefix ? error.slice(prefix.length) : undefined;
}
export type VaultMessage =
  | { type: 'webdav-status' }
  | { type: 'webdav-test'; input?: import('./sync/webdav').WebDavInput; remember?: boolean }
  | { type: 'webdav-clock'; enabled: boolean }
  | { type: 'webdav-create'; input?: import('./sync/webdav').WebDavInput; scratchFolder: string; masterPassword: string }
  | { type: 'webdav-join'; input: import('./sync/webdav').WebDavInput; method: 'master' | 'recovery'; secret: string }
  | { type: 'webdav-merge'; input: import('./sync/webdav').WebDavInput; method: 'master' | 'recovery'; secret: string; proof: Proof; stamp?: string }
  | { type: 'webdav-enable-write'; scratchFolder: string; masterPassword: string }
  | { type: 'webdav-update-key'; password: string }
  | { type: 'webdav-sync'; confirmation?: { stamp: string; proof: Proof } }
  | { type: 'webdav-conflicts'; reveal?: Proof }
  | { type: 'webdav-resolve'; stamp: string; rules: ConflictRule[]; proof: Proof }
  | { type: 'webdav-history' }
  | { type: 'webdav-history-preview'; id: string }
  | { type: 'webdav-history-restore'; id: string; stamp: string; proof: Proof; destination: 'local' | 'remote' }
  | { type: 'webdav-devices' }
  | { type: 'webdav-device-change'; action: 'register' | 'claim' | 'rename' | 'remove'; id?: string; name?: string; proof: Proof }
  | { type: 'webdav-scheduled' }
  | { type: 'csv-headers'; bytes: number[] }
  | ({ type: 'preview-auth-backup' } & AuthBackupInput)
  | ({ type: 'import-auth-backup'; stamp: string; proof: Proof } & AuthBackupInput)
  | { type: 'preview-migration'; format: MigrationFormat; bytes: number[]; password?: string; mapping?: CsvMapping }
  | { type: 'import-migration'; format: MigrationFormat; bytes: number[]; password?: string; mapping?: CsvMapping; stamp: string; proof: Proof }
  | { type: 'export-migration'; format: MigrationFormat; proof: Proof; encrypted?: boolean; password?: string; confirmPlaintext: boolean }
  | { type: 'scan-otp' }
  | { type: 'autofill-candidates'; url: string; kind: import('./autofill-messages').FillKind; groups: string[][] }
  | { type: 'autofill-current'; url: string; username: string; password: string; groups: string[][] }
  | { type: 'autofill-copy-otp'; id: string; url: string; groups: string[][]; proof?: Proof }
  | { type: 'autofill-read'; id: string; url: string; kind: import('./autofill-messages').FillKind; groups: string[][]; fields?: string[]; proof?: Proof }
  | { type: 'set-equivalent-domains'; groups: string[][] }
  | { type: 'autofill-settings' }
  | { type: 'set-autofill-site'; origin: string; flags: import('./autofill-settings').SiteFlags }
  | { type: 'status' | 'open' | 'lock' | 'list' | 'audit' | 'remove-pin' | 'remove-prf' }
  | { type: 'create'; masterPassword: string; calibrate?: boolean }
  | { type: 'unlock'; password: string }
  | { type: 'unlock-pin'; pin: string }
  | { type: 'recover'; recoveryCode: string; newPassword: string }
  | { type: 'change-password'; currentPassword: string; newPassword: string }
  | { type: 'get' | 'get-edit'; id: string; proof?: Proof }
  | { type: 'upsert'; itemJson: string; proof?: Proof }
  | { type: 'trash'; id: string; trashed: boolean }
  | { type: 'delete'; id: string }
  | { type: 'empty-trash'; expectedIds: string[] }
  | { type: 'create-pin'; pin: string; proof: Proof }
  | { type: 'set-autolock'; minutes: number }
  | { type: 'generate-password' | 'generate-passphrase'; optionsJson: string }
  | { type: 'strength'; password: string; hints: string[] }
  | { type: 'copy-sensitive'; value: string }
  | { type: 'export'; password: string; proof: Proof }
  | { type: 'backup-saved'; receipt: BackupReceipt }
  | { type: 'preview-vaultpack'; bytes: number[]; password: string; proof: Proof }
  | { type: 'import'; bytes: number[]; password: string; proof: Proof; stamp: string }
  | { type: 'preview-browser-csv'; bytes: number[] }
  | { type: 'import-browser-csv'; bytes: number[]; stamp: string; proof: Proof }
  | { type: 'preview-ente'; bytes: number[] }
  | { type: 'import-ente'; bytes: number[]; stamp: string; merges: EnteMerge[]; proof: Proof }
  | { type: 'export-ente'; proof: Proof; confirmPlaintext: boolean }
  | { type: 'read-otp'; id: string; handle: string }
  | { type: 'next-hotp'; id: string; proof?: Proof }
  | { type: 'register-prf'; credentialId: number[]; salt: number[]; output: number[]; proof: Proof }
  | { type: 'unlock-prf'; output: number[] }
  | { type: 'hibp'; id: string; confirmOnline: boolean; proof?: Proof };

export interface VaultStatus {
  configured: boolean; unlocked: boolean; pinEnabled: boolean;
  prf?: { credentialId: number[]; salt: number[] };
  vaultId?: string; keyEpoch?: number; autoLockMinutes: number; changesSinceBackup: number;
  remoteKeyUpdate?: boolean;
}
export interface VaultOpening {
  status: VaultStatus;
  items?: ItemSummary[];
}
export interface ItemSummary {
  id: string; title: string; kind: string; subtitle: string;
  primaryDomain?: string | null; tags: string[]; pinned: boolean;
  requireReprompt: boolean; trashed: boolean; cardLast4?: string | null;
  trashedAtMs?: number | null;
  cardBrand?: string | null; devSubtype?: string | null; hasTotp?: boolean; updatedAtMs?: number;
}
export interface VaultItem {
  id: string; title: string; data: { kind: string; [key: string]: unknown };
  note: string; customFields: { name: string; value: string; hidden: boolean }[];
  tags: string[]; pinned: boolean; requireReprompt: boolean; trashed: boolean; revision?: number;
  createdAtMs?: number; updatedAtMs?: number;
  trashedAtMs?: number;
}
export interface ItemDetailData extends VaultItem {
  otp?: { kind: 'hotp' } | { kind: 'time'; handle?: string };
}
export type Reply<T = unknown> = { ok: true; value: T } | { ok: false; error: string };
export async function request<T = unknown>(message: VaultMessage): Promise<T> {
  const response: Reply<T> = await browser.runtime.sendMessage({ target: 'vault', ...message });
  if (!response?.ok) throw new Error(response?.error ?? '后台未响应，请重新打开扩展。');
  return response.value;
}
