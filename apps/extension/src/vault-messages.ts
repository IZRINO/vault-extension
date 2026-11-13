export type Proof = { method: 'master' | 'pin'; secret: string };
export type VaultMessage =
  | { type: 'status' | 'lock' | 'list' | 'audit' | 'empty-trash' | 'remove-pin' | 'remove-prf' }
  | { type: 'create'; masterPassword: string; calibrate?: boolean }
  | { type: 'unlock'; password: string }
  | { type: 'unlock-pin'; pin: string }
  | { type: 'recover'; recoveryCode: string; newPassword: string }
  | { type: 'change-password'; currentPassword: string; newPassword: string }
  | { type: 'get'; id: string; proof?: Proof }
  | { type: 'upsert'; itemJson: string; proof?: Proof }
  | { type: 'trash'; id: string; trashed: boolean }
  | { type: 'delete'; id: string }
  | { type: 'create-pin'; pin: string; proof: Proof }
  | { type: 'set-autolock'; minutes: number }
  | { type: 'generate-password' | 'generate-passphrase'; optionsJson: string }
  | { type: 'strength'; password: string; hints: string[] }
  | { type: 'copy-sensitive'; value: string }
  | { type: 'export'; password: string; proof: Proof }
  | { type: 'import'; bytes: number[]; password: string; proof: Proof }
  | { type: 'register-prf'; credentialId: number[]; salt: number[]; output: number[]; proof: Proof }
  | { type: 'unlock-prf'; output: number[] }
  | { type: 'hibp'; id: string; proof?: Proof };

export interface VaultStatus {
  configured: boolean; unlocked: boolean; pinEnabled: boolean;
  prf?: { credentialId: number[]; salt: number[] };
  vaultId?: string; keyEpoch?: number; autoLockMinutes: number; changesSinceBackup: number;
}
export interface ItemSummary {
  id: string; title: string; kind: string; subtitle: string;
  primaryDomain?: string | null; tags: string[]; pinned: boolean;
  requireReprompt: boolean; trashed: boolean; cardLast4?: string | null;
  cardBrand?: string | null; devSubtype?: string | null; hasTotp?: boolean; updatedAtMs?: number;
}
export interface VaultItem {
  id: string; title: string; data: { kind: string; [key: string]: unknown };
  note: string; customFields: { name: string; value: string; hidden: boolean }[];
  tags: string[]; pinned: boolean; requireReprompt: boolean; trashed: boolean; revision?: number;
  createdAtMs?: number; updatedAtMs?: number;
}
export type Reply<T = unknown> = { ok: true; value: T } | { ok: false; error: string };
export async function request<T = unknown>(message: VaultMessage): Promise<T> {
  const response: Reply<T> = await browser.runtime.sendMessage({ target: 'vault', ...message });
  if (!response?.ok) throw new Error(response?.error ?? '后台未响应，请重新打开扩展。');
  return response.value;
}
