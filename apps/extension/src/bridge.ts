import type { Reply } from './vault-messages';

let tail: Promise<unknown> = Promise.resolve();
// Serialize the shared offscreen document lifecycle, including clipboard alarms.
export function offscreen<T>(operation: string, payload: unknown): Promise<T> {
  const run = tail.then(async () => {
    if (!await browser.offscreen.hasDocument()) {
      await browser.offscreen.createDocument({ url: 'offscreen.html', reasons: ['WORKERS', 'CLIPBOARD'],
        justification: 'Run password derivation in an isolated worker and clear copied secrets.' });
    }
    try {
      const response: Reply<T> = await browser.runtime.sendMessage({ target: 'vault-offscreen', operation, payload });
      if (!response?.ok) throw new Error(response?.error ?? '离屏任务失败');
      return response.value;
    } finally { await browser.offscreen.closeDocument(); }
  });
  tail = run.catch(() => undefined);
  return run;
}
export function derive<T>(operation: string, args: unknown[]): Promise<T> {
  return offscreen<T>('derive', { operation, args: args.map(value =>
    value instanceof Uint8Array ? { bytes: Array.from(value) } : value) });
}
