import { offscreen } from './bridge';

export const CLIPBOARD_ALARM = 'vault-clipboard';
const cleanupDelayMs = 30_000;
interface ClipboardRecord { hash: string; expiresAt: number }

// The offscreen bridge only serializes document calls. Queue the matching storage
// changes here too, so an expired alarm cannot remove a newer copy's record.
let tail = Promise.resolve();
function enqueue(operation: () => Promise<void>): Promise<void> {
  const run = tail.then(operation);
  tail = run.catch(() => undefined);
  return run;
}

export function copyWithExpiry(value: string, checkUnlocked: () => void): Promise<void> {
  return enqueue(async () => {
    checkUnlocked();
    await browser.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + cleanupDelayMs });
    checkUnlocked();
    const hash = await offscreen<string>('copy', value);
    const expiresAt = Date.now() + cleanupDelayMs;
    // Keep the record even when the original requester was locked during the copy.
    await browser.storage.session.set({ clipboard: { hash, expiresAt } });
    await browser.alarms.create(CLIPBOARD_ALARM, { when: expiresAt });
  });
}

export function clearExpiredClipboard(): Promise<void> {
  return enqueue(async () => {
    try {
      const { clipboard } = await browser.storage.session.get<{ clipboard?: ClipboardRecord }>('clipboard');
      if (!clipboard) return;
      if (clipboard.expiresAt > Date.now()) {
        await browser.alarms.create(CLIPBOARD_ALARM, { when: clipboard.expiresAt });
        return;
      }
      await offscreen('clear-clipboard', clipboard.hash);
      await browser.storage.session.remove('clipboard');
    } catch {
      await browser.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + cleanupDelayMs });
    }
  });
}
