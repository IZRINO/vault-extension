import type { Reply } from './vault-messages';

let tail: Promise<unknown> = Promise.resolve();
let activeDocument: { opening: Promise<void>; clipboardCleanup: Promise<unknown> } | undefined;

export class OffscreenRejected extends Error {}

async function send<T>(operation: string, payload: unknown, signal?: AbortSignal): Promise<T> {
  const jobId = crypto.randomUUID(), receipt = crypto.randomUUID();
  let available = true;
  // runtime.sendMessage notifies every extension page. Its response, on the
  // other hand, goes only to the caller: give inputs to the offscreen caller.
  const pull: Parameters<typeof browser.runtime.onMessage.addListener>[0] = (message, sender, respond) => {
    if (message?.target !== 'vault-offscreen-input' || message.jobId !== jobId) return;
    if (!available || sender.id !== browser.runtime.id || sender.tab ||
        ![browser.runtime.getURL('/offscreen.html'), browser.runtime.getURL('/offscreen.html') + '?scan'].includes(sender.url ?? '')) {
      respond(null); return;
    }
    // Chromium can omit documentId on messages from an offscreen document.
    // In that case inspect *all* contexts at the exact URL, never just the
    // offscreen matches: a second context with that URL must fail closed.
    const filter = sender.documentId ? { documentIds: [sender.documentId] } : { documentUrls: [sender.url!] };
    void browser.runtime.getContexts(filter).then(contexts => {
      const [context] = contexts;
      if (!available || signal?.aborted || contexts.length !== 1 || context?.contextType !== 'OFFSCREEN_DOCUMENT' ||
          context.documentUrl !== sender.url || (sender.documentId && context.documentId !== sender.documentId)) {
        respond(null); return;
      }
      available = false;
      respond({ operation, payload, receipt });
    }, () => respond(null));
    return true;
  };
  browser.runtime.onMessage.addListener(pull);
  try {
    const reply: Reply<T> & { receipt: string } = await browser.runtime.sendMessage({ target: 'vault-offscreen', jobId });
    signal?.throwIfAborted();
    if (!reply || available || reply.receipt !== receipt) throw new Error('离屏任务未获确认，请重试。');
    if (!reply.ok) throw new OffscreenRejected(reply.error);
    return reply.value;
  } finally {
    available = false;
    browser.runtime.onMessage.removeListener(pull);
  }
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
      if (signal || operation === 'copy') { await opening; signal?.throwIfAborted(); }
      // Capture can run while the privileged document starts. All lifecycle work remains serialized.
      const [, prepared] = await Promise.all([opening, typeof payload === 'function' ? payload() : payload]);
      signal?.throwIfAborted();
      // Deliver the completed task without paying document teardown latency.
      // `tail` still includes teardown, so the next operation cannot race it.
      result.resolve(await send<T>(operation, prepared, signal));
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
