import type { Reply } from './vault-messages';

let tail: Promise<unknown> = Promise.resolve();
let activeDocument: { opening: Promise<void>; clipboardCleanup: Promise<unknown> } | undefined;

async function send<T>(operation: string, payload: unknown): Promise<T> {
  const response: Reply<T> = await browser.runtime.sendMessage({ target: 'vault-offscreen', operation, payload });
  if (!response?.ok) throw new Error(response?.error ?? '离屏任务失败');
  return response.value;
}

// Serialize the shared document's lifecycle and worker jobs. Clipboard expiry
// can join the open document while a worker computes; teardown waits for it.
export function offscreen<T>(operation: string, payload: unknown): Promise<T> {
  if (operation === 'clear-clipboard' && activeDocument) {
    const active = activeDocument;
    const run = active.clipboardCleanup.then(() => active.opening).then(() => send<T>(operation, payload));
    active.clipboardCleanup = run.catch(() => undefined);
    return run;
  }
  const result = Promise.withResolvers<T>();
  const run = tail.then(async () => {
    const opening = (async () => {
      if (!await browser.offscreen.hasDocument()) {
        await browser.offscreen.createDocument({ url: operation === 'scan-otp' ? 'offscreen.html?scan' : 'offscreen.html', reasons: ['WORKERS', 'CLIPBOARD'],
          justification: 'Run local vault tasks in isolated workers and clear copied secrets.' });
      }
    })();
    const active = { opening, clipboardCleanup: Promise.resolve() as Promise<unknown> };
    activeDocument = active;
    try {
      // Capture can run while the privileged document starts. All lifecycle work remains serialized.
      const [, prepared] = await Promise.all([opening, typeof payload === 'function' ? payload() : payload]);
      // Deliver the completed task without paying document teardown latency.
      // `tail` still includes teardown, so the next operation cannot race it.
      result.resolve(await send<T>(operation, prepared));
    } catch (error) {
      result.reject(error);
    } finally {
      activeDocument = undefined;
      await opening.catch(() => undefined);
      await active.clipboardCleanup;
      if (await browser.offscreen.hasDocument()) await browser.offscreen.closeDocument();
    }
  });
  tail = run.catch(() => undefined);
  return result.promise;
}
export function derive<T>(operation: string, args: unknown[]): Promise<T> {
  return offscreen<T>('derive', { operation, args: args.map(value =>
    value instanceof Uint8Array ? { bytes: Array.from(value) } : value) });
}
