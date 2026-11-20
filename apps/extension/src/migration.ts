import type { MigrationPreview, VaultItem } from './vault-messages';
import { localHost } from './autofill-policy';

export const BITWARDEN_META = 'Bitwarden 保留字段';
export interface MigrationBatch { rows: VaultItem[]; invalid: number; unsupported: number; ignoredOtp: number }
function sourceId(item: VaultItem): string {
  try {
    const meta = JSON.parse(item.customFields.find(field => field.name === BITWARDEN_META)?.value ?? '{}');
    return meta.version === 1 && typeof meta.sourceId === 'string' ? meta.sourceId : '';
  } catch { return ''; }
}
function otpIdentity(raw: unknown) {
  if (typeof raw !== 'string' || !raw) return '';
  const clean = (value: string) => value.toUpperCase().replace(/[\s=-]/g, '');
  try {
    const url = new URL(raw);
    const kind = url.hostname === 'steam' || url.searchParams.get('issuer')?.toLowerCase() === 'steam' ? 'steam' : url.hostname;
    return [kind, clean(url.searchParams.get('secret') ?? ''), url.searchParams.get('algorithm')?.toUpperCase() ?? 'SHA1',
      url.searchParams.get('digits') ?? (kind === 'steam' ? '5' : '6'), kind === 'hotp' ? '' : url.searchParams.get('period') ?? '30'].join(':');
  } catch { return ['totp', clean(raw), 'SHA1', '6', '30'].join(':'); }
}
function fingerprint(item: VaultItem): string {
  const data = item.data;
  let content: unknown;
  const pick = (names: string[]) => names.map(key => typeof data[key] === 'string' ? data[key] : '');
  if (data.kind === 'login') {
    const uris = (Array.isArray(data.uris) ? data.uris : []).map(entry => {
      const rule = entry.matchRule ?? 'base_domain';
      try {
        const url = new URL(entry.uri);
        // The stored model infers Host for local addresses; either rule already isolates origin there.
        return JSON.stringify([url.href, rule === 'host' && localHost(url.hostname) ? 'base_domain' : rule]);
      } catch { return JSON.stringify([entry.uri, rule]); }
    }).sort();
    content = [data.kind, ...pick(['username', 'password']), uris, otpIdentity(data.totpUri)];
  } else if (data.kind === 'payment_card') {
    content = [data.kind, ...pick(['cardholderName', 'cardNumber', 'expMonth', 'expYear', 'cvv', 'cardPin', 'billingAddress'])];
  } else if (data.kind === 'identity') {
    content = [data.kind, ...pick(['fullName', 'phone', 'email', 'nationalIdOrPassport', 'country', 'province', 'city', 'addressLine', 'postalCode', 'company', 'taxId'])];
  } else {
    content = [data.kind, ...pick(['subtype', 'serviceOrProduct', 'tokenOrLicense', 'publicKey', 'privateKey'])];
  }
  // Ignore a HOTP counter so importing an old export cannot reintroduce an earlier counter.
  return JSON.stringify([content, item.note ?? '', !!item.requireReprompt, [...(item.tags ?? [])].sort(),
    item.customFields.filter(field => field.name !== BITWARDEN_META).map(field => [field.name, field.value, field.hidden])]);
}
export function planMigration(batch: MigrationBatch, existing: VaultItem[]) {
  const sources = new Set(existing.map(sourceId).filter(Boolean));
  const known = new Set(existing.map(fingerprint));
  const hotp = new Set(existing.map(item => otpIdentity(item.data.totpUri)).filter(value => value.startsWith('hotp:')));
  const items: VaultItem[] = [];
  let skipped = 0, invalid = batch.invalid;
  for (const item of batch.rows) {
    // CSV requires a valid website; Bitwarden can also contain standalone authenticators and app URIs.
    if (!item.title?.trim() || !['login', 'payment_card', 'identity', 'developer'].includes(item.data?.kind)) { invalid++; continue; }
    const source = sourceId(item), identity = fingerprint(item);
    const otp = otpIdentity(item.data.totpUri);
    if (source && sources.has(source) || known.has(identity) || otp.startsWith('hotp:') && hotp.has(otp)) { skipped++; continue; }
    if (source) sources.add(source);
    if (otp.startsWith('hotp:')) hotp.add(otp);
    known.add(identity); items.push({ ...item, id: '' });
  }
  const preview: Omit<MigrationPreview, 'stamp'> = {
    ready: items.length, skipped, invalid, unsupported: batch.unsupported, ignoredOtp: batch.ignoredOtp,
    sample: items.slice(0, 5).map(item => ({ title: item.title, kind: item.data.kind,
      account: typeof item.data.username === 'string' ? item.data.username : '' })),
  };
  return { items, preview };
}
