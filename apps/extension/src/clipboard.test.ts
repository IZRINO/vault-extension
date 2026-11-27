import { afterEach, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import type { Reply } from './vault-messages';
import { offscreenRuntime } from './test-fixtures/offscreen-runtime';

// Exercise the real background queue, bridge and offscreen listener. Only browser
// APIs and the operating system clipboard are replaced.
async function setup() {
  vi.resetModules();
  const { runtime, notify: sendMessage, deliver } = offscreenRuntime();
  const clipboard = { text: 'ordinary text', writable: true };
  let field: { value: string };
  const doc = new EventTarget();
  vi.stubGlobal('document', Object.assign(doc, {
    createElement: () => {
      let value = '';
      return { get value() { return value; }, set value(text: string) { value = text.replace(/\r\n?/g, '\n'); },
        focus() {}, select() {}, remove() {} };
    },
    body: { append(element: typeof field) { field = element; } },
    execCommand(command: string) {
      if (command === 'copy' && !clipboard.writable) return false;
      const event = Object.assign(new Event(command, { cancelable: true }), {
        clipboardData: { types: ['text/plain'], getData: (type: string) => type === 'text/plain' ? clipboard.text : '',
          setData(type: string, text: string) { if (type === 'text/plain') clipboard.text = text; } },
      });
      if (doc.dispatchEvent(event)) {
        if (command === 'copy') clipboard.text = field.value;
        if (command === 'paste') field.value = clipboard.text;
      }
      return true;
    },
  }));
  const data: Record<string, unknown> = {};
  const session = {
    get: vi.fn(async (key: string) => ({ [key]: structuredClone(data[key]) })),
    set: vi.fn(async (changes: Record<string, unknown>) => { Object.assign(data, structuredClone(changes)); }),
    remove: async (key: string) => { delete data[key]; },
  };
  let alarm: { when: number; periodInMinutes?: number } | undefined;
  const createAlarm = vi.fn(async (_name: string, info: NonNullable<typeof alarm>) => { alarm = { ...info }; });
  const clock = vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const offscreen = { hasDocument: vi.fn(async () => true), closeDocument: async () => undefined };
  vi.stubGlobal('location', { search: '' });
  vi.stubGlobal('browser', {
    storage: { session },
    alarms: {
      get: async () => alarm && { scheduledTime: alarm.when, periodInMinutes: alarm.periodInMinutes },
      create: createAlarm,
      clear: async () => { alarm = undefined; },
    },
    offscreen,
    runtime,
  });
  await import('../entrypoints/offscreen/main');
  let worker = await import('./clipboard');
  const restart = async () => { vi.resetModules(); worker = await import('./clipboard'); };
  const startBackground = async () => {
    await restart();
    const event = { addListener() {} };
    vi.stubGlobal('browser', { ...browser,
      storage: { session: { ...session, setAccessLevel: async () => {} }, local: { setAccessLevel: async () => {}, get: async () => ({}) } },
      runtime: { ...browser.runtime, onConnect: event, onInstalled: event, onStartup: event },
      alarms: { ...browser.alarms, onAlarm: event },
      idle: { setDetectionInterval() {}, onStateChanged: event },
      tabs: { onRemoved: event, onUpdated: event, onActivated: event },
      windows: { onRemoved: event, onFocusChanged: event, getAll: async () => [] },
      commands: { onCommand: event }, contextMenus: { onClicked: event },
    });
    vi.stubGlobal('defineBackground', (start: () => void) => start);
    const start = (await import('../entrypoints/background')).default;
    (start as unknown as () => void)();
    await new Promise<void>(resolve => setImmediate(resolve));
  };
  const advanceTo = async (now: number) => {
    clock.mockReturnValue(now);
    if (alarm && alarm.when <= now) {
      alarm = alarm.periodInMinutes ? { ...alarm, when: now + alarm.periodInMinutes * 60_000 } : undefined;
      await worker.clearExpiredClipboard();
    }
  };
  return { clipboard, session, offscreen, sendMessage, deliver, restart, startBackground, createAlarm,
    copy: (text: string, check = () => {}) => worker.copyWithExpiry(text, check), advanceTo };
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('keeps the existing clipboard when cleanup cannot be registered', async () => {
  const f = await setup();
  f.session.set.mockRejectedValueOnce(new Error('session storage unavailable'));
  await expect(f.copy('sensitive fixture')).rejects.toThrow('session storage unavailable');
  expect(f.clipboard.text).toBe('ordinary text');
});

it('counts 30 seconds from the clipboard write when registration and the reply are slow', async () => {
  const f = await setup();
  const save = f.session.set.getMockImplementation()!;
  f.session.set.mockImplementationOnce(async changes => {
    await f.advanceTo(1_020_000);
    await save(changes);
  });
  f.sendMessage.mockImplementationOnce(async message => {
    const reply = await f.deliver(message);
    await f.advanceTo(1_025_000);
    return reply;
  });
  await f.copy('delayed fixture');
  await f.advanceTo(1_049_999);
  expect(f.clipboard.text === 'delayed fixture').toBe(true);
  await f.advanceTo(1_050_000);
  expect(f.clipboard.text.length).toBe(0);
});

it.each(['storage', 'alarm'])('reports a confirmed copy and recovers its cleanup after a %s maintenance failure', async failure => {
  const f = await setup();
  await f.copy('first fixture');
  await f.advanceTo(1_010_000);
  f.sendMessage.mockImplementationOnce(async message => {
    const reply = await f.deliver(message);
    const unavailable = new Error('maintenance unavailable');
    if (failure === 'storage') f.session.set.mockRejectedValueOnce(unavailable);
    else f.createAlarm.mockRejectedValueOnce(unavailable);
    return reply;
  });
  await expect(f.copy('replacement fixture')).resolves.toBeUndefined();
  await f.restart();
  await f.advanceTo(1_030_000);
  expect(f.clipboard.text === 'replacement fixture').toBe(true);
  await f.advanceTo(1_040_000);
  expect(f.clipboard.text.length).toBe(0);
});

it('clears the first secret at its original deadline when writing a replacement fails', async () => {
  const f = await setup();
  await f.copy('first fixture');
  await f.advanceTo(1_010_000);
  f.clipboard.writable = false;
  await expect(f.copy('replacement fixture')).rejects.toThrow('无法写入剪贴板');
  f.clipboard.writable = true;
  expect(f.clipboard.text).toBe('first fixture');
  await f.advanceTo(1_030_000);
  expect(f.clipboard.text).toBe('');
});

it('refuses to write if the vault locks while the offscreen document is opening', async () => {
  const f = await setup();
  const opening = Promise.withResolvers<void>();
  const ready = Promise.withResolvers<boolean>();
  f.offscreen.hasDocument.mockImplementationOnce(() => { opening.resolve(); return ready.promise; });
  let locked = false;
  const check = () => { if (locked) throw new Error('密码库已锁定'); };
  const copy = f.copy('sensitive fixture', check);
  await opening.promise;
  locked = true;
  ready.resolve(true);
  await expect(copy).rejects.toThrow('锁定');
  expect(f.clipboard.text).toBe('ordinary text');
});

it.each([false, true])('recovers after the worker stops without a reply (copy reached clipboard: %s)', async delivered => {
  const f = await setup();
  await f.copy('first fixture');
  await f.advanceTo(1_010_000);
  const stopped = Promise.withResolvers<void>();
  f.sendMessage.mockImplementationOnce(async message => {
    if (delivered) await f.deliver(message);
    stopped.resolve();
    return new Promise<Reply>(() => {});
  });
  void f.copy('replacement fixture');
  await stopped.promise;
  await f.restart();
  expect(JSON.stringify(f.session.set.mock.calls)).not.toMatch(/first fixture|replacement fixture/);
  await f.advanceTo(1_030_000);
  expect(f.clipboard.text).toBe(delivered ? 'replacement fixture' : '');
  await f.advanceTo(1_040_000);
  expect(f.clipboard.text).toBe('');
});

it('recovers when the worker stops during delivery of the cleanup alarm', async () => {
  const f = await setup();
  await f.copy('sensitive fixture');
  const stopped = Promise.withResolvers<void>();
  f.session.get.mockImplementationOnce(() => { stopped.resolve(); return new Promise(() => {}); });
  void f.advanceTo(1_030_000);
  await stopped.promise;
  await f.restart();
  await f.advanceTo(1_060_000);
  expect(f.clipboard.text).toBe('');
});

it.each([false, true])('only extends a repeated copy to a full new 30 seconds on confirmation: %s', async confirmed => {
  const f = await setup();
  await f.copy('repeated fixture');
  await f.advanceTo(1_010_000);
  if (confirmed) {
    await f.copy('repeated fixture');
  } else {
    f.sendMessage.mockRejectedValueOnce(new Error('no reply'));
    await expect(f.copy('repeated fixture')).rejects.toThrow('no reply');
  }
  await f.restart();
  await f.advanceTo(1_030_000);
  expect(f.clipboard.text).toBe(confirmed ? 'repeated fixture' : '');
  await f.advanceTo(1_040_000);
  expect(f.clipboard.text).toBe('');
});

it.each([
  { startup: true, matches: true }, { startup: true, matches: false },
  { startup: false, matches: true }, { startup: false, matches: false },
])('recovers a consumed legacy alarm (ordinary worker startup: $startup, clipboard matches: $matches)', async ({ startup, matches }) => {
    const f = await setup();
    // Installed versions stored just this one digest with a one-shot alarm.
    await f.session.set({ clipboard: { hash: createHash('sha256').update('legacy fixture').digest('hex'), expiresAt: 1_030_000 } });
    f.clipboard.text = matches ? 'legacy fixture' : 'ordinary text';
    if (startup) {
      await f.advanceTo(1_040_000);
      await f.startBackground();
      await f.advanceTo(1_040_000);
    } else {
      await f.advanceTo(1_010_000);
      f.sendMessage.mockRejectedValueOnce(new Error('lost reply'));
      await expect(f.copy('replacement fixture')).rejects.toThrow('lost reply');
      await f.restart();
      await f.advanceTo(1_030_000);
      expect(f.clipboard.text === (matches ? '' : 'ordinary text')).toBe(true);
      await f.advanceTo(1_040_000);
    }
    expect(f.clipboard.text === (matches ? '' : 'ordinary text')).toBe(true);
    expect((await f.session.get('clipboard')).clipboard).toBeUndefined();
});

it('starts a worker without opening the clipboard or scheduling an alarm when there is no cleanup', async () => {
  const f = await setup();
  await f.startBackground();
  expect(f.offscreen.hasDocument).not.toHaveBeenCalled();
  expect(f.createAlarm).not.toHaveBeenCalled();
});

it.each([
  { action: 'clears the copied text including CRLF and CR', copied: 'a\r\nb\rc', replacement: undefined },
  { action: 'retains other text with different newlines', copied: 'a\nb\nc', replacement: 'a\r\nb\rc' },
])('$action', async ({ copied, replacement }) => {
  const f = await setup();
  await f.copy(copied);
  expect(f.clipboard.text === copied).toBe(true);
  if (replacement !== undefined) f.clipboard.text = replacement;
  await f.advanceTo(1_030_000);
  expect(f.clipboard.text === (replacement ?? '')).toBe(true);
});
