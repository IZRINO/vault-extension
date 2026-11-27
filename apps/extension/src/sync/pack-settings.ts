import { derive } from '../bridge';
import { validateGroups, validateSiteRule } from '../autofill-policy';
import { defaultFlags, SITE_FLAG_KEYS, validSiteFlags, type AutofillSettings, type SiteFlags } from '../autofill-settings';
import type { SessionState } from '../vault-storage';

export const emptySiteRules = (): AutofillSettings => ({ sites: {}, equivalentDomains: [] });
export interface PackRuleConflict { first: string[][]; second: string[][] }
export interface PackRules extends AutofillSettings { domainConflicts?: PackRuleConflict[] }
const canonicalGroups = (groups: unknown) => validateGroups(groups).map(group => group.sort()).sort();

export function validatePackRules(value: unknown): PackRules {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !['sites', 'equivalentDomains', 'domainConflicts'].includes(key))) throw new Error('网站规则包含不支持的字段。');
  const { sites, equivalentDomains, domainConflicts } = value as PackRules;
  if (!sites || typeof sites !== 'object' || Array.isArray(sites) || Object.keys(sites).length > 1000)
    throw new Error('网站规则最多保存 1,000 个网站。');
  const normalized: Record<string, SiteFlags> = {};
  for (const rule of Object.keys(sites).sort()) {
    validateSiteRule(rule);
    const flags = sites[rule];
    if (!validSiteFlags(flags)) throw new Error('网站规则包含不支持的开关。');
    normalized[rule] = {
      inlineDisabled: flags.inlineDisabled, saveDisabled: flags.saveDisabled, passkeyDisabled: flags.passkeyDisabled,
    };
  }
  const rules: PackRules = { sites: normalized, equivalentDomains: canonicalGroups(equivalentDomains) };
  if (domainConflicts !== undefined) {
    if (!Array.isArray(domainConflicts) || domainConflicts.length > 32) throw new Error('关联域名冲突数量超出限制。');
    const choices = new Map<string, PackRuleConflict>();
    for (const entry of domainConflicts) {
      if (!entry || typeof entry !== 'object' || Object.keys(entry).some(key => key !== 'first' && key !== 'second'))
        throw new Error('关联域名冲突包含不支持的字段。');
      const first = canonicalGroups(entry.first), second = canonicalGroups(entry.second);
      if (JSON.stringify(first) === JSON.stringify(second)) throw new Error('关联域名冲突缺少可选方案。');
      const pair = JSON.stringify(first) < JSON.stringify(second) ? { first, second } : { first: second, second: first };
      choices.set(JSON.stringify(pair), pair);
    }
    if (choices.size) rules.domainConflicts = [...choices.keys()].sort().map(key => choices.get(key)!);
  }
  return rules;
}

export async function sealPackRules(session: SessionState, rules: PackRules) {
  const json = JSON.stringify(validatePackRules(rules));
  if (new TextEncoder().encode(json).length > 256 * 1024) throw new Error('网站规则超过 256 KiB。');
  return new Uint8Array(await derive<number[]>('seal-preferences', [session.key, session.wrap, json]));
}

export async function openPackRules(session: SessionState, rules: Uint8Array) {
  const json = await derive<string>('open-preferences', [session.key, session.wrap, rules]);
  return validatePackRules(JSON.parse(json));
}

const groupKey = (group: string[]) => JSON.stringify(group);
const touches = (group: string[], domains: Set<string>) => group.some(domain => domains.has(domain));
const conflictDomains = (conflict: PackRuleConflict) => new Set([...conflict.first, ...conflict.second].flat());

function mergeSet<T>(base: T[], ours: T[], theirs: T[], identity: (value: T) => string) {
  const before = new Set(base.map(identity)), local = new Set(ours.map(identity)), remote = new Set(theirs.map(identity));
  const candidates = new Map([...base, ...ours, ...theirs].map(value => [identity(value), value]));
  return [...candidates.keys()].sort().filter(key => local.has(key) === before.has(key) ? remote.has(key) : local.has(key))
    .map(key => candidates.get(key)!);
}

function mergeGroups(base: string[][], ours: string[][], theirs: string[][]) {
  const universe = new Map([...base, ...ours, ...theirs].map(group => [groupKey(group), group]));
  const before = new Set(base.map(groupKey)), local = new Set(ours.map(groupKey)), remote = new Set(theirs.map(groupKey));
  const left = new Set<string>(), right = new Set<string>();
  for (const [key, group] of universe) {
    const changedLeft = before.has(key) !== local.has(key), changedRight = before.has(key) !== remote.has(key);
    if (changedLeft && !changedRight) group.forEach(domain => left.add(domain));
    if (changedRight && !changedLeft) group.forEach(domain => right.add(domain));
  }
  const conflicts: PackRuleConflict[] = [];
  for (const domain of left) {
    if (!right.has(domain) || conflicts.some(conflict => conflictDomains(conflict).has(domain))) continue;
    const affected = new Set([domain]);
    // Keep each connected set of disputed groups together. A choice installs
    // one set of explicitly configured groups, without transitive expansion.
    for (let size = 0; size !== affected.size;) {
      size = affected.size;
      for (const group of universe.values()) if (touches(group, affected)) group.forEach(member => affected.add(member));
    }
    const first = ours.filter(group => touches(group, affected)), second = theirs.filter(group => touches(group, affected));
    if (JSON.stringify(first) !== JSON.stringify(second)) conflicts.push({ first, second });
  }
  const merged = mergeSet(base, ours, theirs, groupKey);
  return { merged, conflicts };
}

export function preservePackRuleConflicts(before: PackRules, updated: AutofillSettings): PackRules {
  const next = validatePackRules(updated);
  for (const conflict of before.domainConflicts ?? []) {
    const scope = conflictDomains(conflict);
    if (JSON.stringify(before.equivalentDomains.filter(group => touches(group, scope))) !==
        JSON.stringify(next.equivalentDomains.filter(group => touches(group, scope)))) {
      throw new Error('这些关联域名有待裁决的同步修改，请在网盘设置中选择方案。');
    }
  }
  return { ...next, domainConflicts: before.domainConflicts };
}

export function resolvePackRuleConflict(rules: PackRules, index: number, choice: 'first' | 'second'): PackRules {
  const conflicts = [...rules.domainConflicts ?? []];
  if (!Number.isSafeInteger(index) || index < 0 || index >= conflicts.length || (choice !== 'first' && choice !== 'second'))
    throw new Error('请选择要采用的关联域名方案。');
  const conflict = conflicts.splice(index, 1)[0]!;
  const scope = conflictDomains(conflict);
  const stillHeld = conflicts.map(conflictDomains);
  const equivalentDomains = [...rules.equivalentDomains.filter(group => !touches(group, scope)),
    ...conflict[choice].filter(group => stillHeld.every(other => !touches(group, other)))];
  return validatePackRules({ ...rules, equivalentDomains, domainConflicts: conflicts });
}

export async function restorePackRules(session: SessionState, current: Uint8Array, history: Uint8Array) {
  const [active, target] = await Promise.all([openPackRules(session, current), openPackRules(session, history)]);
  if (!active.domainConflicts?.length) return { rules: history, ruleConflicts: 0 };
  const scopes = active.domainConflicts.map(conflictDomains);
  const equivalentDomains = target.equivalentDomains.filter(group => scopes.every(scope => !touches(group, scope)));
  const rules = await sealPackRules(session, { ...target, equivalentDomains, domainConflicts: active.domainConflicts });
  return { rules, ruleConflicts: active.domainConflicts.length };
}

export async function mergePackRules(session: SessionState, base: Uint8Array, ours: Uint8Array, theirs: Uint8Array) {
  const [before, local, remote] = await Promise.all([base, ours, theirs].map(bytes => openPackRules(session, bytes)));
  const sites: AutofillSettings['sites'] = {};
  const names = new Set([...Object.keys(before!.sites), ...Object.keys(local!.sites), ...Object.keys(remote!.sites)]);
  for (const name of [...names].sort()) {
    const initial = before!.sites[name] ?? defaultFlags(), left = local!.sites[name] ?? defaultFlags(), right = remote!.sites[name] ?? defaultFlags();
    const flags = defaultFlags();
    for (const flag of SITE_FLAG_KEYS) flags[flag] = left[flag] === initial[flag] ? right[flag] : left[flag];
    if (SITE_FLAG_KEYS.some(flag => flags[flag])) sites[name] = flags;
  }
  const groups = mergeGroups(before!.equivalentDomains, local!.equivalentDomains, remote!.equivalentDomains);
  const conflicts = [...mergeSet(before!.domainConflicts ?? [], local!.domainConflicts ?? [], remote!.domainConflicts ?? [], conflict =>
    JSON.stringify(conflict)), ...groups.conflicts];
  const equivalentDomains = groups.merged.filter(group => conflicts.every(conflict => {
    if (!touches(group, conflictDomains(conflict))) return true;
    const key = groupKey(group);
    return conflict.first.some(item => groupKey(item) === key) && conflict.second.some(item => groupKey(item) === key);
  }));
  const merged = validatePackRules({ sites, equivalentDomains, domainConflicts: conflicts });
  const json = JSON.stringify(merged);
  if (json === JSON.stringify(local)) return ours;
  if (json === JSON.stringify(remote)) return theirs;
  return sealPackRules(session, merged);
}
