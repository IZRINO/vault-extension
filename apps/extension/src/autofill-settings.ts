export interface SiteFlags { inlineDisabled: boolean; saveDisabled: boolean; passkeyDisabled: boolean }
export interface AutofillSettings { sites: Record<string, SiteFlags>; equivalentDomains: string[][] }
export interface SiteRuleState {
  exact: SiteFlags;
  wildcardRules: { rule: string; flags: SiteFlags }[];
  effective: SiteFlags;
}
export const SITE_FLAG_KEYS = ['inlineDisabled', 'saveDisabled', 'passkeyDisabled'] as const;
export const defaultFlags = (): SiteFlags => ({ inlineDisabled: false, saveDisabled: false, passkeyDisabled: false });

export function validSiteFlags(flags: unknown, partial = false): flags is Partial<SiteFlags> {
  if (!flags || typeof flags !== 'object' || Array.isArray(flags)) return false;
  const entries = Object.entries(flags);
  return entries.length > 0 && (partial || entries.length === SITE_FLAG_KEYS.length) &&
    entries.every(([key, value]) => SITE_FLAG_KEYS.some(name => name === key) && typeof value === 'boolean');
}
