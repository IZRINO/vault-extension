import { offscreen, OffscreenRejected } from './bridge';
import { clipboardDigest } from './clipboard-digest';

export const CLIPBOARD_ALARM = 'vault-clipboard';
const cleanupDelayMs = 30_000;
interface ClipboardRecord { hash: string; expiresAt: number }

async function readRecords(): Promise<ClipboardRecord[]> {
  // A single record is also the format written by previous versions.
  const { clipboard } = await browser.storage.session.get<{ clipboard?: ClipboardRecord | ClipboardRecord[] }>('clipboard');
  if (!clipboard) return [];
  return Array.isArray(clipboard) ? clipboard : [clipboard];
}

function writeRecords(records: ClipboardRecord[]): Promise<void> {
  if (!records.length) return browser.storage.session.remove('clipboard');
  return browser.storage.session.set({ clipboard: records.length === 1 ? records[0] : records });
}

function arm(when: number): Promise<void> {
  // Delivery consumes a one-shot alarm even if its worker stops midway.
  return browser.alarms.create(CLIPBOARD_ALARM, { when, periodInMinutes: cleanupDelayMs / 60_000 });
}

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
    const previous = await readRecords();
    const hash = await clipboardDigest(value);
    let registered: ClipboardRecord | undefined;
    let dispatched = false;
    try {
      await offscreen('copy', async () => {
        checkUnlocked();
        const next = { hash, expiresAt: Date.now() + cleanupDelayMs };
        const candidates = [...previous, next];
        const firstExpiry = Math.min(...candidates.map(record => record.expiresAt));
        const alarm = await browser.alarms.get(CLIPBOARD_ALARM);
        if (!alarm?.periodInMinutes || alarm.scheduledTime > firstExpiry) await arm(firstExpiry);
        await writeRecords(candidates);
        registered = next;
        checkUnlocked();
        dispatched = true;
        return { text: value, expiresAt: next.expiresAt };
      });
    } catch (error) {
      // A lost response is ambiguous. Either value may still need cleaning.
      if (registered && (!dispatched || error instanceof OffscreenRejected)) await writeRecords(previous);
      throw error;
    }
    if (previous.length && registered) {
      // The earlier alarm and both digests already cover interrupted compaction.
      await writeRecords([registered]);
      await arm(registered.expiresAt);
    }
  });
}

export function clearExpiredClipboard(): Promise<void> {
  return enqueue(async () => {
    try {
      const records = await readRecords();
      if (!records.length) { await browser.alarms.clear(CLIPBOARD_ALARM); return; }
      const now = Date.now();
      const future = records.filter(record => record.expiresAt > now);
      for (const record of records) {
        if (record.expiresAt <= now) await offscreen('clear-clipboard', record.hash);
      }
      if (future.length) await arm(Math.min(...future.map(record => record.expiresAt)));
      if (future.length !== records.length) await writeRecords(future);
      if (!future.length) await browser.alarms.clear(CLIPBOARD_ALARM);
    } catch {
      await arm(Date.now() + cleanupDelayMs);
    }
  });
}
