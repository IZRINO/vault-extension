import { expect, it, vi } from 'vitest';
import type { SessionState } from '../vault-storage';
import { emptySiteRules, mergePackRules, openPackRules, resolvePackRuleConflict, sealPackRules } from './pack-settings';

vi.mock('../bridge', () => ({ derive: async (op: string, args: [unknown, unknown, string | Uint8Array]) => {
  if (op === 'open-preferences') return new TextDecoder().decode(args[2] as Uint8Array);
  if (op === 'seal-preferences') return Array.from(new TextEncoder().encode(args[2] as string));
  throw new Error(`Unexpected operation ${op}`);
} }));

it('holds overlapping domain changes for review and applies independent rules', async () => {
  const session: SessionState = { key: new Uint8Array(), wrap: new Uint8Array(), unlockedAtMs: 0, lastActivityMs: 0 };
  const before = await sealPackRules(session, { ...emptySiteRules(), equivalentDomains: [['example.com', 'example.net']] });
  const local = await sealPackRules(session, { ...emptySiteRules(), equivalentDomains: [['example.com', 'example.org'], ['acme.com', 'acme.net']] });
  const remote = await sealPackRules(session, { ...emptySiteRules(), equivalentDomains: [['example.com', 'example.edu']],
    sites: { 'https://site.example.com': { inlineDisabled: true, saveDisabled: false, passkeyDisabled: false } } });
  const merged = await openPackRules(session, await mergePackRules(session, before, local, remote));
  expect(merged.equivalentDomains).toEqual([['acme.com', 'acme.net']]);
  expect(merged.sites['https://site.example.com']?.inlineDisabled).toBe(true);
  expect(merged.domainConflicts).toEqual([{ first: [['example.com', 'example.edu']], second: [['example.com', 'example.org']] }]);
  expect(resolvePackRuleConflict(merged, 0, 'second').equivalentDomains).toEqual([
    ['acme.com', 'acme.net'], ['example.com', 'example.org'],
  ]);
});
