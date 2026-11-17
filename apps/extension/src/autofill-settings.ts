export interface SiteFlags { inlineDisabled: boolean; saveDisabled: boolean; passkeyDisabled: boolean }
export interface AutofillSettings { sites: Record<string, SiteFlags>; equivalentDomains: string[][] }
export const defaultFlags = (): SiteFlags => ({ inlineDisabled: false, saveDisabled: false, passkeyDisabled: false });
