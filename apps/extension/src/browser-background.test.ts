import { afterEach, expect, it, vi } from 'vitest';
import type { VaultMessage } from './vault-messages';

const vault = vi.hoisted(() => ({ handle: vi.fn(async (_message: VaultMessage) => undefined),
  lock: vi.fn(async (): Promise<void> => undefined) }));
vi.mock('./vault-controller', () => ({
  VaultController: class {
    handle(message: VaultMessage) { return vault.handle(message); }
    lock() { return vault.lock(); }
  },
  DAV_LEGACY_ALARM: 'vault-webdav-legacy',
  LOCK_ALARM: 'vault-autolock',
  IDLE_DETECTION_SECONDS: 30,
}));

function event<T extends unknown[]>() {
  const listeners: ((...args: T) => void)[] = [];
  return {
    addListener: (listener: (...args: T) => void) => { listeners.push(listener); },
    emit: (...args: T) => { for (const listener of listeners) listener(...args); },
  };
}

async function browserLifecycle(initiallyFocused = false) {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  vi.stubGlobal('defineBackground', (start: () => void) => start);
  const onFocusChanged = event<[number]>(), onStartup = event<[]>(), onAlarm = event<[{ name: string }]>();
  const unused = { addListener() {} };
  const alarms = new Map<string, { periodInMinutes?: number }>();
  let focused = initiallyFocused;
  const storage = { setAccessLevel: async () => undefined, get: async () => ({}) };
  vi.stubGlobal('browser', {
    storage: { local: storage, session: storage },
    idle: { setDetectionInterval() {}, onStateChanged: unused },
    runtime: { onConnect: unused, onMessage: unused, onInstalled: unused, onStartup },
    tabs: { onRemoved: unused, onUpdated: unused, onActivated: unused },
    windows: { onRemoved: unused, onFocusChanged, getAll: async () => [{ focused }] },
    commands: { onCommand: unused },
    contextMenus: { onClicked: unused, removeAll: async () => undefined, create() {} },
    alarms: {
      onAlarm,
      get: async (name: string) => alarms.get(name),
      create: async (name: string, info: { periodInMinutes?: number }) => { alarms.set(name, info); },
      clear: async (name: string) => alarms.delete(name),
    },
  });
  const { default: start } = await import('../entrypoints/background');
  (start as unknown as () => void)();
  await vi.advanceTimersByTimeAsync(0);
  return {
    focus(id: number) { focused = id !== -1; onFocusChanged.emit(id); },
    startup: () => onStartup.emit(),
    alarm: (name = 'vault-webdav') => onAlarm.emit({ name }),
    interval: () => alarms.get('vault-webdav')?.periodInMinutes,
    settle: () => vi.advanceTimersByTimeAsync(1_000),
  };
}

afterEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it('coalesces a burst of focus notifications and only polls every five minutes in the foreground', async () => {
  const browser = await browserLifecycle();
  expect(browser.interval()).toBeUndefined();
  browser.focus(1);
  browser.focus(-1);
  browser.focus(2);
  await browser.settle();
  expect(browser.interval()).toBe(5);
  expect(vault.handle.mock.calls).toEqual([[{ type: 'webdav-scheduled', reason: 'focus' }]]);

  browser.alarm();
  await browser.settle();
  expect(vault.handle.mock.calls).toEqual([
    [{ type: 'webdav-scheduled', reason: 'focus' }],
    [{ type: 'webdav-scheduled', reason: 'interval' }],
  ]);

  browser.focus(-1);
  browser.alarm(); // An already queued alarm may arrive before the focus callback settles.
  await browser.settle();
  expect(browser.interval()).toBeUndefined();
  expect(vault.handle).toHaveBeenCalledTimes(2);
});

it('finishes locking at browser startup before requesting a check', async () => {
  const browser = await browserLifecycle(true);
  const locking = Promise.withResolvers<void>();
  vault.lock.mockImplementationOnce(() => locking.promise);
  browser.startup();
  await browser.settle();
  expect(vault.lock).toHaveBeenCalledOnce();
  expect(vault.handle).not.toHaveBeenCalled();
  locking.resolve();
  await browser.settle();
  expect(vault.handle.mock.calls).toEqual([[{ type: 'webdav-scheduled', reason: 'startup' }]]);
  expect(browser.interval()).toBe(5);
});

it('forwards the separate legacy alarm while browser windows are unfocused', async () => {
  const browser = await browserLifecycle();
  browser.alarm('vault-webdav-legacy');
  await browser.settle();
  expect(browser.interval()).toBeUndefined();
  expect(vault.handle.mock.calls).toEqual([[{ type: 'webdav-scheduled', reason: 'legacy-interval' }]]);
});
