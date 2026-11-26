import type { Proof } from './vault-messages';
import type { SiteFlags } from './autofill-policy';
import type { MarkDraft } from './login-marks';

export type FillKind = 'login' | 'username' | 'otp' | 'card' | 'identity';
export interface FillSource { tabId: number; frameId: number; documentId: string; url: string; topUrl: string }
export interface FillCandidate { id: string; title: string; account: string; requireReprompt: boolean; otpKind?: string }
export interface FillPayload { values: Record<string, string>; custom?: Record<string, string> }
export type CaptureTarget = { kind: 'new' } | { kind: 'ambiguous' } | { kind: 'update'; id: string; requireReprompt: boolean };
export interface MenuState {
  site: string; topSite: string; crossOrigin: boolean; insecure: boolean; pinEnabled: boolean;
  kind: FillKind; candidates: FillCandidate[];
  capture?: { account: string; updating: boolean; ambiguous: boolean; requireReprompt: boolean };
}
export type MarkingMessage =
  | { type: 'mark-get' }
  | { type: 'mark-manage' }
  | { type: 'mark-start'; key?: string }
  | { type: 'mark-enable'; key: string; enabled: boolean }
  | { type: 'mark-delete'; key: string }
  | { type: 'mark-ready'; token: string }
  | { type: 'mark-cancel'; token: string }
  | { type: 'mark-save'; token: string; draft: MarkDraft };
export type AutofillMessage =
  | MarkingMessage
  | { type: 'begin'; kind: FillKind; manual?: true; markId?: string; markSet?: string }
  | { type: 'flags' }
  | { type: 'pending' }
  | { type: 'capture'; username: string; password: string }
  | { type: 'menu'; token: string }
  | { type: 'fill'; token: string; id: string; confirmCrossOrigin: boolean; copyOtp?: boolean; proof?: Proof }
  | { type: 'save'; token: string; confirmCrossOrigin: boolean; proof?: Proof }
  | { type: 'close'; token: string }
  | { type: 'site'; origin: string; flags?: Partial<SiteFlags> }
  | { type: 'site-rules'; origin: string };

export async function autofillRequest<T>(message: AutofillMessage): Promise<T> {
  const reply = await browser.runtime.sendMessage({ target: 'vault-autofill', ...message });
  if (!reply?.ok) throw new Error(reply?.error ?? '填充服务未响应，请重试。');
  return reply.value;
}
