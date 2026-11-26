import { afterEach, expect, it, vi } from 'vitest';
import { offscreen } from './bridge';
import { offscreenRuntime } from './test-fixtures/offscreen-runtime';

afterEach(() => vi.unstubAllGlobals());

it('sends ordinary extension pages only a job notification, never the inputs of a daily OTP calculation', async () => {
  let notificationKeys: string[] = [];
  const runtime = { onMessage: { addListener() {}, removeListener() {} },
    sendMessage: async (notification: Record<string, unknown>) => {
      notificationKeys = Object.keys(notification).sort();
      throw new Error('test receiver is closed');
    } };
  vi.stubGlobal('browser', { runtime, offscreen: { hasDocument: async () => true, closeDocument: async () => {} } });
  await expect(offscreen('derive', { operation: 'generate-otp', args: ['synthetic setup', 0, 0] })).rejects.toThrow();
  expect(notificationKeys).toEqual(['jobId', 'target']);
});

it('withholds the job from an ambiguous extension context when Chromium omits documentId', async () => {
  const { runtime, hidden, deliver } = offscreenRuntime();
  const contexts = await runtime.getContexts({ documentUrls: [hidden.url] });
  const getContexts = vi.fn(async () => [...contexts, { ...contexts[0]!, documentId: 'extra', contextType: 'POPUP' }]);
  runtime.onMessage.addListener((notice, _sender, respond) => {
    if (notice.target !== 'vault-offscreen') return;
    void deliver({ target: 'vault-offscreen-input', jobId: notice.jobId }, hidden).then(job => respond({ ok: job !== null }));
    return true;
  });
  vi.stubGlobal('browser', { runtime: { ...runtime, getContexts }, offscreen: { hasDocument: async () => true, closeDocument: async () => {} } });
  await expect(offscreen('derive', {})).rejects.toThrow('未获确认');
  expect(getContexts).toHaveBeenCalledWith({ documentUrls: [hidden.url] });
});

it('clears an expired clipboard while the Ente worker is busy without closing its document', async () => {
  const started = Promise.withResolvers<void>();
  const completed = Promise.withResolvers<{ ok: true; value: string }>();
  const { runtime, hidden, deliver } = offscreenRuntime();
  const received = vi.fn();
  runtime.onMessage.addListener((notification, _sender, respond) => {
    if (notification.target !== 'vault-offscreen') return;
    void deliver({ target: 'vault-offscreen-input', jobId: notification.jobId }, hidden).then(async job => {
      received(job.operation, job.payload);
      if (job.operation === 'derive') {
        started.resolve();
        respond({ ...await completed.promise, receipt: job.receipt });
      } else respond({ ok: true, value: null, receipt: job.receipt });
    });
    return true;
  });
  const closeDocument = vi.fn();
  vi.stubGlobal('browser', {
    offscreen: { hasDocument: vi.fn(async () => true), closeDocument },
    runtime,
  });
  const derive = offscreen('derive', { operation: 'parse-ente', args: [] });
  await started.promise;
  const clear = offscreen('clear-clipboard', 'fixture hash');
  try {
    await vi.waitFor(() => expect(received).toHaveBeenCalledWith('clear-clipboard', 'fixture hash'));
    await expect(clear).resolves.toBeNull();
    expect(closeDocument).not.toHaveBeenCalled();
  } finally {
    completed.resolve({ ok: true, value: 'derived fixture' });
    await Promise.all([derive, clear]);
  }
  await expect(derive).resolves.toBe('derived fixture');
  await vi.waitFor(() => expect(closeDocument).toHaveBeenCalledTimes(1));
});
