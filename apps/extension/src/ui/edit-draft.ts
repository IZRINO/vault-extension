import type { VaultItem } from '../vault-messages';
import { fieldSets } from './lib';

type Field = { key: string; label: string; data?: boolean };
export type DraftConflict = Field & { mine: unknown; canUseMine: boolean };
const top: Field[] = Object.entries({ title: '名称', note: '备注', tags: '标签', pinned: '置顶',
  requireReprompt: '再次验证设置', customFields: '自定义字段' }).map(([key, label]) => ({ key, label }));
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const hotp = (value: unknown) => typeof value === 'string' && /^otpauth:\/\/hotp\//i.test(value.trim());
const read = (item: VaultItem, field: Field) => field.data ? item.data[field.key] : item[field.key as keyof VaultItem];
const write = (item: VaultItem, field: Field, value: unknown): VaultItem => field.data
  ? { ...item, data: { ...item.data, [field.key]: structuredClone(value) } } : { ...item, [field.key]: structuredClone(value) };

export const applyDraftField = (item: VaultItem, conflict: DraftConflict): VaultItem =>
  conflict.canUseMine ? write(item, conflict, conflict.mine) : item;

export function rebaseDraft(base: VaultItem, draft: VaultItem, latest: VaultItem) {
  if (!base.id || base.id !== latest.id || base.id !== draft.id || latest.trashed || latest.data.kind !== base.data.kind) {
    throw new Error('条目已删除、移入回收站或改变类型。当前草稿仍保留，不会覆盖它。');
  }
  let item = structuredClone(latest);
  const conflicts: DraftConflict[] = [];
  const extras = latest.data.kind === 'login' ? [{ key: 'uris', label: '网站与匹配规则' }, { key: 'totpUri', label: '两步验证码' }] :
    latest.data.kind === 'developer' ? [{ key: 'subtype', label: '凭证类型' }, { key: 'expiresAtMs', label: '到期日期' }] : [];
  const fields = [...top, ...[...(fieldSets[latest.data.kind] ?? []), ...extras].map(field => ({ ...field, data: true }))];
  for (const field of fields) {
    const previous = read(base, field), mine = read(draft, field), current = read(latest, field);
    if (same(previous, mine) || same(current, mine)) continue;
    // Never replay an old counter or replace an edited authenticator/retained migration data with its stale copy.
    const changedRemotely = !same(previous, current);
    const guarded = field.key === 'totpUri' && (hotp(previous) || hotp(current) || changedRemotely) ||
      field.key === 'customFields' && changedRemotely;
    if (changedRemotely || guarded) conflicts.push({ ...field, mine, canUseMine: !guarded });
    else item = write(item, field, mine);
  }
  return { item, conflicts };
}
