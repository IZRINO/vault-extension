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
export function offscreen<T>(operation: string, payload: unknown, signal?: AbortSignal): Promise<T> {
  if (operation === 'clear-clipboard' && activeDocument) {
    const active = activeDocument;
    const run = active.clipboardCleanup.then(() => active.opening).then(() => send<T>(operation, payload));
    active.clipboardCleanup = run.catch(() => undefined);
    return run;
  }
  const result = Promise.withResolvers<T>();
  const run = tail.then(async () => {
    if (signal?.aborted) { result.reject(signal.reason); return; }
    const opening = (async () => {
      if (!await browser.offscreen.hasDocument()) {
        await browser.offscreen.createDocument({ url: operation === 'scan-otp' ? 'offscreen.html?scan' : 'offscreen.html', reasons: ['WORKERS', 'CLIPBOARD'],
          justification: 'Run local vault tasks in isolated workers and clear copied secrets.' });
      }
    })();
    const active = { opening, clipboardCleanup: Promise.resolve() as Promise<unknown> };
    activeDocument = active;
    try {
      // A session-bound task must not copy its inputs until the receiver is ready.
      if (signal) { await opening; signal.throwIfAborted(); }
      // Capture can run while the privileged document starts. All lifecycle work remains serialized.
      const [, prepared] = await Promise.all([opening, typeof payload === 'function' ? payload() : payload]);
      signal?.throwIfAborted();
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
export function derive<T>(operation: string, args: unknown[], signal?: AbortSignal): Promise<T> {
  const wipeCopies = operation === 'audit-snapshot' || operation === 'parse-authenticator-backup';
  const copies: number[][] = [];
  const prepare = () => ({ operation, args: args.map(value => {
    if (!(value instanceof Uint8Array)) return value;
    const bytes = Array.from(value);
    if (wipeCopies) copies.push(bytes);
    return { bytes };
  }) });
  const result = offscreen<T>('derive', signal ? prepare : prepare(), signal);
  return wipeCopies ? result.finally(() => { for (const bytes of copies) bytes.fill(0); }) : result;
}
