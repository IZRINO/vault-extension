import { describe, expect, it } from 'vitest';
import { nextJournalVersion } from './journal-device';

describe('offline journal identity', () => {
  it('creates opaque independent device identities and advances across restart and clock rollback', () => {
    const a = nextJournalVersion(undefined, 1_000_000);
    const b = nextJournalVersion(undefined, 1_000_000);
    expect(a.state.deviceId).toMatch(/^[0-9a-f-]{36}$/);
    expect(a.state.tag).toMatch(/^[0-9a-f]{8}$/);
    expect(a.state.deviceId).not.toBe(b.state.deviceId);
    expect(a.id).not.toBe(b.id);
    const later = nextJournalVersion(structuredClone(a.state), 500_000);
    expect(later.state.deviceId).toBe(a.state.deviceId);
    expect(later.state.tag).toBe(a.state.tag);
    expect(later.id).toMatch(/^[0-9a-f]{14}_[0-9a-f]{8}_[0-9a-f]{14}$/);
    expect(later.id > a.id).toBe(true);
    expect(later.state.sequence).toBe(a.state.sequence + 1);
  });
});
