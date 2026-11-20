import { afterEach, describe, expect, it, vi } from 'vitest';
import type { VaultController } from '../vault-controller';
import { PasskeyController } from './controller';

const origin = 'https://login.example.com:8443';
const href = `${origin}/login`;
const rule = 'https://*.example.com:8443';

function fixture() {
  let receive: (message: unknown) => void = () => undefined;
  let disconnect: () => void = () => undefined;
  const getTab = vi.fn(async () => ({ url: href, active: true }));
  const available = vi.fn(async () => true);
  const send = vi.fn();
  vi.stubGlobal('browser', { runtime: { id: 'vault-fixture' }, tabs: { get: getTab } });
  const controller = new PasskeyController({ passkeyAvailable: available } as unknown as VaultController);
  const port = {
    sender: { id: 'vault-fixture', url: href, origin, documentId: 'fixture-page', frameId: 0,
      tab: { id: 4, windowId: 1, url: href } },
    postMessage: send,
    onMessage: { addListener: (listener: typeof receive) => { receive = listener; } },
    onDisconnect: { addListener: (listener: typeof disconnect) => { disconnect = listener; } },
  };
  controller.connect(port as unknown as Parameters<PasskeyController['connect']>[0]);
  return {
    controller, send, getTab, available, disconnect: () => disconnect(),
    begin: () => receive({ type: 'begin', request: {
      kind: 'assert', challenge: 'a'.repeat(43), credentialIds: [], algorithms: [],
      conditional: true, resident: false, credProps: false, uv: 'discouraged',
    } }),
  };
}

afterEach(() => vi.unstubAllGlobals());

describe('Passkey site rule changes', () => {
  it('returns a waiting conditional request to the browser only for a matching rule', async () => {
    const test = fixture();
    try {
      test.begin();
      await vi.waitFor(() => expect(test.send).toHaveBeenCalledWith({ type: 'conditional' }));
      test.controller.stop(undefined, 'https://*.example.com');
      expect(test.send).toHaveBeenCalledTimes(1);
      test.controller.stop(undefined, rule);
      test.controller.stop(undefined, rule);
      expect(test.send.mock.calls).toEqual([[{ type: 'conditional' }], [{ type: 'native' }]]);
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
