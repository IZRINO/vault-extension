import { afterEach, describe, expect, it, vi } from 'vitest';
import type { VaultController } from '../vault-controller';
import { PasskeyController } from './controller';

const origin = 'https://login.example.com:8443';
const href = `${origin}/login`;
const rule = 'https://*.example.com:8443';
const request = {
  kind: 'assert', challenge: 'a'.repeat(43), credentialIds: [], algorithms: [],
  conditional: true, resident: false, credProps: false, uv: 'discouraged',
};

function fixture() {
  const getTab = vi.fn(async () => ({ url: href, active: true }));
  const notify = vi.fn(async () => undefined);
  const available = vi.fn(async () => true);
  const candidates = vi.fn(async () => []);
  const storage: Record<string, unknown> = {};
  vi.stubGlobal('browser', {
    runtime: { id: 'vault-fixture' }, tabs: { get: getTab, sendMessage: notify },
    storage: { session: {
      get: async (key: string) => ({ [key]: structuredClone(storage[key]) }),
      set: async (value: Record<string, unknown>) => { Object.assign(storage, structuredClone(value)); },
    } },
  });
  const createController = () => new PasskeyController({ passkeyAvailable: available, passkeyCandidates: candidates } as unknown as VaultController);
  const controller = createController();
  const ticket = crypto.randomUUID();
  const connect = (target = controller, documentId = 'fixture-page') => {
    let receive: (message: unknown) => void = () => undefined;
    let disconnect: () => void = () => undefined;
    const send = vi.fn();
    const port = {
      sender: { id: 'vault-fixture', url: href, origin, documentId, frameId: 0,
        tab: { id: 4, windowId: 1, url: href } },
      postMessage: send,
      onMessage: { addListener: (listener: typeof receive) => { receive = listener; } },
      onDisconnect: { addListener: (listener: typeof disconnect) => { disconnect = listener; } },
    };
    target.connect(port as unknown as Parameters<PasskeyController['connect']>[0]);
    return { send, disconnect: () => disconnect(),
      begin: () => receive({ type: 'begin', request, ticket }),
      show: () => receive({ type: 'show', request, ticket }),
      discard: () => receive({ type: 'discard', ticket }),
    };
  };
  return { ...connect(), connect, controller, createController, getTab, available, candidates, notify, ticket };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it('waits for the first interaction without using up the confirmation time', async () => {
  vi.useFakeTimers();
  const test = fixture();
  try {
    test.begin();
    await vi.advanceTimersByTimeAsync(0);
    expect(test.send.mock.calls).toEqual([[{ type: 'conditional' }]]);
    test.disconnect();
    await vi.advanceTimersByTimeAsync(126_000);
    expect(test.send.mock.calls).toEqual([[{ type: 'conditional' }]]);
    expect(test.candidates).not.toHaveBeenCalled();

    const interaction = test.connect(test.createController());
    interaction.show();
    await vi.advanceTimersByTimeAsync(0);
    expect(interaction.send.mock.lastCall?.[0]).toEqual({ type: 'inline', ticket: expect.any(String) });
    await vi.advanceTimersByTimeAsync(59_999);
    expect(interaction.send).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(interaction.send.mock.lastCall?.[0]).toEqual({ type: 'cancel' });
    interaction.disconnect();
  } finally { test.disconnect(); }
});

it('revokes the waiting ticket on lock even after the worker has restarted', async () => {
  const test = fixture();
  test.begin();
  await vi.waitFor(() => expect(test.send).toHaveBeenCalledWith({ type: 'conditional' }));
  test.disconnect();

  const reactivated = test.createController();
  reactivated.stop();
  await vi.waitFor(() => expect(test.notify).toHaveBeenCalledWith(4,
    { target: 'vault-passkey-bridge', type: 'cancel', ticket: test.ticket }, { documentId: 'fixture-page' }));
  const interaction = test.connect(reactivated);
  interaction.show();
  await vi.waitFor(() => expect(interaction.send).toHaveBeenCalledWith({ type: 'cancel' }));
  expect(test.candidates).not.toHaveBeenCalled();
  interaction.disconnect();
});

it('will not present for a different document or reuse a discarded request', async () => {
  const test = fixture();
  test.begin();
  await vi.waitFor(() => expect(test.send).toHaveBeenCalledWith({ type: 'conditional' }));
  test.disconnect();

  const unrelated = test.connect(test.controller, 'different-document');
  unrelated.show();
  await vi.waitFor(() => expect(unrelated.send).toHaveBeenCalledWith({ type: 'cancel' }));
  unrelated.disconnect();
  const cancelled = test.connect();
  cancelled.discard();
  await vi.waitFor(() => expect(cancelled.send).toHaveBeenCalledWith({ type: 'discarded' }));
  cancelled.disconnect();
  const interaction = test.connect();
  interaction.show();
  await vi.waitFor(() => expect(interaction.send).toHaveBeenCalledWith({ type: 'cancel' }));
  expect(test.candidates).not.toHaveBeenCalled();
  interaction.disconnect();
});

describe('Passkey site rule changes', () => {
  it('returns a waiting conditional request to the browser only for a matching rule', async () => {
    const test = fixture();
    try {
      test.begin();
      await vi.waitFor(() => expect(test.send).toHaveBeenCalledWith({ type: 'conditional' }));
      test.disconnect();
      const reactivated = test.createController();
      reactivated.stop(undefined, 'https://*.example.com');
      reactivated.stop(undefined, rule);
      reactivated.stop(undefined, rule);
      await vi.waitFor(() => expect(test.notify.mock.calls).toEqual([[4,
        { target: 'vault-passkey-bridge', type: 'native', ticket: test.ticket }, { documentId: 'fixture-page' }]]));
    } finally { test.disconnect(); }
  });

  it('honors a rule written while the initiating tab is being revalidated', async () => {
    const test = fixture();
    const revalidation = Promise.withResolvers<{ url: string; active: boolean }>();
    test.getTab.mockResolvedValueOnce({ url: href, active: true }).mockReturnValueOnce(revalidation.promise);
    try {
      test.begin();
      await vi.waitFor(() => expect(test.getTab).toHaveBeenCalledTimes(2));
      test.available.mockResolvedValue(false);
      test.controller.stop(undefined, rule);
      revalidation.resolve({ url: href, active: true });
      await vi.waitFor(() => expect(test.send.mock.calls).toEqual([[{ type: 'native' }]]));
    } finally {
      revalidation.resolve({ url: href, active: true });
      test.disconnect();
    }
  });
});
