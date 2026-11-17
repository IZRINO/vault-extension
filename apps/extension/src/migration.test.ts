import { describe, expect, it } from 'vitest';
import { planMigration, BITWARDEN_META } from './migration';
import type { VaultItem } from './vault-messages';

const item = (counter: string): VaultItem => ({
  id: '', title: 'Fixture', data: { kind: 'login', username: 'user', password: 'password',
    uris: [{ uri: 'https://example.com' }], totpUri: `otpauth://hotp/Fixture?secret=JBSWY3DPEHPK3PXP&counter=${counter}` },
  note: '', customFields: [], tags: [], pinned: false, requireReprompt: false, trashed: false,
});
describe('migration deduplication', () => {
  it('does not reintroduce earlier HOTP counters through renamed logins or new source IDs', () => {
    const existing = item('18446744073709551614'); existing.id = 'existing'; existing.trashed = true;
    const incoming = item('1'); incoming.title = 'Renamed'; incoming.data.password = 'different password';
    incoming.data.username = 'another user';
    const result = planMigration({ rows: [incoming], invalid: 0, unsupported: 0, ignoredOtp: 0 }, [existing]);
    expect(result.preview.skipped).toBe(1);
    expect(result.items).toEqual([]);
  });
  it('keeps previously imported source IDs authoritative for skipping instead of overwriting', () => {
    const existing = item('1'); existing.customFields = [{ name: BITWARDEN_META, value: JSON.stringify({ version: 1, sourceId: 'source-a' }), hidden: true }];
    const incoming = structuredClone(existing); incoming.data.totpUri = null; incoming.data.password = 'older password';
    const result = planMigration({ rows: [incoming], invalid: 0, unsupported: 0, ignoredOtp: 0 }, [existing]);
    expect(result.preview.skipped).toBe(1);
    expect(existing.data.password).toBe('password');
  });
});
