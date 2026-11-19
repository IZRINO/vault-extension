export type Proof = { method: 'master' | 'pin'; secret: string };
export const MAX_VAULTPACK_BYTES = 16 * 1024 * 1024;
export const MAX_BROWSER_CSV_BYTES = 2 * 1024 * 1024;
export const MAX_ENTE_BYTES = 2 * 1024 * 1024;
export const MAX_MIGRATION_BYTES = 16 * 1024 * 1024;
export type MigrationFormat = 'bitwarden' | 'csv';
export type CsvMapping = Partial<Record<'title' | 'url' | 'username' | 'password' | 'note' | 'totp' | 'tags' | 'trashed', number>>;
export interface MigrationPreview {
  stamp: string; ready: number; skipped: number; invalid: number; unsupported: number; ignoredOtp: number;
  sample: { title: string; kind: string; account: string }[];
}
export interface MigrationExport { text: string; count: number; skipped: number }
export const MAX_OTP_SETUP_LENGTH = 64 * 1024;
export interface BackupReceipt { vaultId: string; changeCount: number }
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
export interface OtpCode {
  kind: 'totp' | 'hotp' | 'steam'; value: string; validTo: number | null;
  nextValue: string | null; counter: string | null; nextSetupKey: string | null;
}
export function capacityErrorText(error: unknown): string | undefined {
  if (typeof error !== 'string') return;
  const prefix = ['COMPACT_OBJECT_TOO_LARGE: ', 'VAULTPACK_TOO_LARGE: '].find(value => error.startsWith(value));
  return prefix ? error.slice(prefix.length) : undefined;
}
export type VaultMessage =
  | { type: 'csv-headers'; bytes: number[] }
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
  | { type: 'get'; id: string; proof?: Proof }
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
  | { type: 'import'; bytes: number[]; password: string; proof: Proof }
  | { type: 'preview-browser-csv'; bytes: number[] }
  | { type: 'import-browser-csv'; bytes: number[]; stamp: string; proof: Proof }
  | { type: 'preview-ente'; bytes: number[] }
  | { type: 'import-ente'; bytes: number[]; stamp: string; merges: EnteMerge[]; proof: Proof }
  | { type: 'export-ente'; proof: Proof; confirmPlaintext: boolean }
  | { type: 'next-hotp'; id: string; proof?: Proof }
  | { type: 'register-prf'; credentialId: number[]; salt: number[]; output: number[]; proof: Proof }
  | { type: 'unlock-prf'; output: number[] }
  | { type: 'hibp'; id: string; confirmOnline: boolean; proof?: Proof };

export interface VaultStatus {
  configured: boolean; unlocked: boolean; pinEnabled: boolean;
  prf?: { credentialId: number[]; salt: number[] };
  vaultId?: string; keyEpoch?: number; autoLockMinutes: number; changesSinceBackup: number;
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
export type Reply<T = unknown> = { ok: true; value: T } | { ok: false; error: string };
export async function request<T = unknown>(message: VaultMessage): Promise<T> {
  const response: Reply<T> = await browser.runtime.sendMessage({ target: 'vault', ...message });
  if (!response?.ok) throw new Error(response?.error ?? '后台未响应，请重新打开扩展。');
  return response.value;
}
