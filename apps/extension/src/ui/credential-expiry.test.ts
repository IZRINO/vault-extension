import { describe, expect, it } from 'vitest';
import { expiryLabel, formatExpiryDate } from './lib';

describe('developer credential expiry reminders', () => {
  const end = Date.UTC(2030, 6, 1);
  const window = 30 * 24 * 60 * 60 * 1000;

  it('warns from 30 days before the saved time and marks expiry at the boundary', () => {
    expect(expiryLabel(end, end - window - 1)).toBe('');
    expect(expiryLabel(end, end - window)).toBe('30 天内到期');
    expect(expiryLabel(end, end - 1)).toBe('30 天内到期');
    expect(expiryLabel(end, end)).toBe('已到期');
    expect(expiryLabel(end + window + 1, end)).toBe('');
  });

  it('does not warn for missing or invalid dates and displays the stored UTC date', () => {
    for (const date of [undefined, null, -1, Number.NaN, Number.MAX_SAFE_INTEGER]) {
      expect(expiryLabel(date, end)).toBe('');
      expect(formatExpiryDate(date)).toBe('');
    }
    expect(formatExpiryDate(end)).toBe('2030-07-01');
    expect(formatExpiryDate(0)).toBe('1970-01-01');
  });
});
