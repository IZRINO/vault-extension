import { afterEach, expect, it, vi } from 'vitest';
import { offscreen } from './bridge';

afterEach(() => vi.unstubAllGlobals());

it('clears an expired clipboard while the Ente worker is busy without closing its document', async () => {
  const started = Promise.withResolvers<void>();
  const completed = Promise.withResolvers<{ ok: true; value: string }>();
  const sendMessage = vi.fn(async ({ operation }) => {
    if (operation === 'derive') {
      started.resolve();
      return completed.promise;
    }
    return { ok: true, value: null };
  });
  const closeDocument = vi.fn();
  vi.stubGlobal('browser', {
    offscreen: { hasDocument: vi.fn(async () => true), closeDocument },
    runtime: { sendMessage },
  });
  const derive = offscreen('derive', { operation: 'parse-ente', args: [] });
  await started.promise;
  const clear = offscreen('clear-clipboard', 'fixture hash');
  try {
    await vi.waitFor(() => expect(sendMessage).toHaveBeenCalledWith({
      target: 'vault-offscreen', operation: 'clear-clipboard', payload: 'fixture hash',
    }));
    await expect(clear).resolves.toBeNull();
    expect(closeDocument).not.toHaveBeenCalled();
  } finally {
    completed.resolve({ ok: true, value: 'derived fixture' });
    await Promise.all([derive, clear]);
  }
  await expect(derive).resolves.toBe('derived fixture');
  await vi.waitFor(() => expect(closeDocument).toHaveBeenCalledTimes(1));
});
