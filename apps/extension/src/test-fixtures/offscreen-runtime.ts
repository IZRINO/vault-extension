import { vi } from 'vitest';

type Sender = { id?: string; url?: string; documentId?: string; tab?: { id: number } };
type Listener = (msg: any, sender: Sender, reply: (result: any) => void) => unknown;

// Runtime notifications fan out, but a response goes only to the caller.
export function offscreenRuntime() {
  const id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const getURL = (path: string) => `chrome-extension://${id}${path}`;
  const background = { id, url: getURL('/background.js') };
  const hidden = { id, url: getURL('/offscreen.html') }; // Edge omits MessageSender.documentId for this document.
  const listeners = new Set<Listener>();
  const deliver = (message: unknown, sender: Sender = background) => new Promise<any>(resolve => {
    let pending = false;
    for (const listener of listeners) {
      if (listener(structuredClone(message), sender, resolve) === true) pending = true;
    }
    if (!pending) resolve(undefined);
  });
  const notify = vi.fn((message: unknown) => deliver(message));
  const runtime = { id, getURL,
    onMessage: { addListener: (fn: Listener) => listeners.add(fn), removeListener: (fn: Listener) => listeners.delete(fn) },
    getContexts: async ({ documentIds, documentUrls }: { documentIds?: string[]; documentUrls?: string[] }) =>
      documentIds?.includes('hidden-document') || documentUrls?.includes(hidden.url)
        ? [{ contextType: 'OFFSCREEN_DOCUMENT', documentId: 'hidden-document', documentUrl: hidden.url }] : [],
    sendMessage: (message: any) => message.target === 'vault-offscreen-input' ? deliver(message, hidden) : notify(message),
  };
  return { runtime, notify, deliver, background, hidden };
}
