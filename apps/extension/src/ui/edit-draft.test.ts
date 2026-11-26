import { expect, it } from 'vitest';
import type { VaultItem } from '../vault-messages';
import { applyDraftField, rebaseDraft } from './edit-draft';

const base: VaultItem = { id: 'account', title: 'Initial', data: { kind: 'login', password: 'initial', passwordHistory: ['old'] },
  note: '', customFields: [], tags: [], pinned: false, requireReprompt: false, trashed: false, revision: 4, editStamp: 'old' };

it('reapplies independent draft edits to the latest version without writing or copying internal fields', () => {
  const latest = { ...base, note: 'remote note', requireReprompt: true, editStamp: 'fresh', data: { ...base.data, passwordHistory: ['new'] } };
  const draft = { ...base, title: 'my title', data: { ...base.data, passkeyData: 'old-bundle' } };
  const result = rebaseDraft(base, draft, latest);
  expect(result).toEqual({ item: { ...latest, title: 'my title' }, conflicts: [] });
  expect(latest.title).toBe('Initial');
});

it('keeps overlapping values at their latest version until the user explicitly chooses', () => {
  const draft = { ...base, title: 'mine' };
  const latest = { ...base, title: 'theirs', editStamp: 'fresh' };
  const result = rebaseDraft(base, draft, latest);
  expect(result.item).toEqual(latest);
  expect(result.conflicts).toHaveLength(1);
  const conflict = result.conflicts[0]!;
  expect(conflict.label).toBe('名称');
  expect(applyDraftField(result.item, conflict)).toEqual({ ...latest, title: 'mine' });
});

it('never reapplies a stale HOTP or internal migration values, even on an explicit overlap choice', () => {
  const account = (counter: number) => ({ ...base, data: { ...base.data, totpUri: `otpauth://hotp/Synthetic?counter=${counter}` },
    customFields: [{ name: 'Bitwarden 保留字段', value: `version-${counter}`, hidden: true }] });
  const result = rebaseDraft(account(3), account(1), account(8));
  expect(result.conflicts.map(conflict => conflict.label).sort()).toEqual(['两步验证码', '自定义字段'].sort());
  for (const conflict of result.conflicts) {
    expect(conflict.canUseMine).toBe(false);
    expect(applyDraftField(result.item, conflict)).toEqual(account(8));
  }
});
