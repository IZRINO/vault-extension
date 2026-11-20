import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Reply } from './vault-messages';

type Listener = (message: unknown, sender: unknown, respond: (reply: Reply) => void) => boolean | undefined;
const id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const background = { id, url: `chrome-extension://${id}/background.js` };
const locked = { target: 'vault-event', type: 'locked' };

async function setup(ready = Promise.resolve()) {
  vi.resetModules();
  let listener!: Listener;
  let documentOpen = false;
  const opening = Promise.withResolvers<void>();
  const posted = Promise.withResolvers<void>();
  const post = vi.fn(() => posted.resolve());
  const terminate = vi.fn();
  vi.stubGlobal('location', { search: '' });
  vi.stubGlobal('Worker', class { postMessage = post; terminate = terminate; });
  const sendMessage = vi.fn((message: unknown) => new Promise<Reply>(resolve => {
    if (!listener(structuredClone(message), background, resolve)) resolve({ ok: true, value: undefined });
  }));
  vi.stubGlobal('browser', {
    runtime: { id, getURL: (path: string) => `chrome-extension://${id}${path}`, sendMessage,
      onMessage: { addListener: (value: Listener) => { listener = value; } } },
    offscreen: {
      hasDocument: async () => documentOpen,
      createDocument: async () => { opening.resolve(); await ready; documentOpen = true; },
      closeDocument: async () => { documentOpen = false; },
    },
  });
  await import('../entrypoints/offscreen/main');
  const { derive } = await import('./bridge');
  const signal = new AbortController();
  const start = () => derive('audit-snapshot', [Uint8Array.of(1), Uint8Array.of(2)], signal.signal);
  const dispatchLock = (sender: object) => listener(locked, sender, () => {});
  return { start, signal, sendMessage, post, terminate, opening, posted, dispatchLock };
}

afterEach(() => vi.unstubAllGlobals());

describe('the lock boundary for local audit', () => {
  it('does not ship session material if the vault locks during offscreen startup', async () => {
    const ready = Promise.withResolvers<void>();
    const fixture = await setup(ready.promise);
    const report = fixture.start();
    const rejected = expect(report).rejects.toThrow('锁定');
    await fixture.opening.promise;
    fixture.signal.abort(new Error('密码库已锁定'));
    ready.resolve();
    await rejected;
    expect(fixture.sendMessage).not.toHaveBeenCalled();
    expect(fixture.post).not.toHaveBeenCalled();
  });

  it('terminates a running audit and refuses late work after an authenticated lock', async () => {
    const fixture = await setup();
    const report = fixture.start();
    const rejected = expect(report).rejects.toThrow('锁定');
    await fixture.posted.promise;
    fixture.dispatchLock({ id, url: 'https://example.test', tab: { id: 1 } });
    expect(fixture.terminate).not.toHaveBeenCalled();
    fixture.signal.abort(new Error('密码库已锁定'));
    fixture.dispatchLock(background);
    expect(fixture.terminate).toHaveBeenCalledTimes(1);
    await rejected;
    await expect(fixture.start()).rejects.toThrow('锁定');
    await expect(fixture.sendMessage({ target: 'vault-offscreen', operation: 'derive',
      payload: { operation: 'audit-snapshot', args: [{ bytes: [1] }, { bytes: [2] }] } }))
      .resolves.toMatchObject({ ok: false, error: expect.stringContaining('锁定') });
    expect(fixture.post).toHaveBeenCalledTimes(1);
  });
});
