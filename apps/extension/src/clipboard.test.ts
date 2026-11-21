import { afterEach, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import type { Reply } from './vault-messages';

type Receiver = (message: unknown, sender: unknown, respond: (reply: Reply) => void) => boolean | undefined;

// Exercise the real background queue, bridge and offscreen listener. Only browser
// APIs and the operating system clipboard are replaced.
async function setup() {
  vi.resetModules();
  const id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const getURL = (path: string) => `chrome-extension://${id}${path}`;
  let receive!: Receiver;
  const clipboard = { text: 'ordinary text', writable: true };
  let field: { value: string };
  const doc = new EventTarget();
  vi.stubGlobal('document', Object.assign(doc, {
    createElement: () => ({ value: '', focus() {}, select() {}, remove() {} }),
    body: { append(element: typeof field) { field = element; } },
    execCommand(command: string) {
      if (command === 'paste') { field.value = clipboard.text; return true; }
      if (!clipboard.writable) return false;
      doc.dispatchEvent(Object.assign(new Event('copy', { cancelable: true }), {
        clipboardData: { setData(_type: string, text: string) { clipboard.text = text; } },
      }));
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
  const clock = vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  const deliver = (message: unknown) => new Promise<Reply>(resolve => {
    receive(structuredClone(message), { id, url: getURL('/background.js') }, resolve);
  });
  const sendMessage = vi.fn(deliver);
  const offscreen = { hasDocument: vi.fn(async () => true), closeDocument: async () => undefined };
  vi.stubGlobal('location', { search: '' });
  vi.stubGlobal('browser', {
    storage: { session },
    alarms: {
      get: async () => alarm && { scheduledTime: alarm.when, periodInMinutes: alarm.periodInMinutes },
      create: async (_name: string, info: NonNullable<typeof alarm>) => { alarm = { ...info }; },
      clear: async () => { alarm = undefined; },
    },
    offscreen,
    runtime: { id, getURL, sendMessage, onMessage: { addListener(listener: Receiver) { receive = listener; } } },
  });
  await import('../entrypoints/offscreen/main');
  let worker = await import('./clipboard');
  const restart = async () => { vi.resetModules(); worker = await import('./clipboard'); };
  const advanceTo = async (now: number) => {
    clock.mockReturnValue(now);
    if (alarm && alarm.when <= now) {
      alarm = alarm.periodInMinutes ? { ...alarm, when: now + alarm.periodInMinutes * 60_000 } : undefined;
      await worker.clearExpiredClipboard();
    }
  };
  return { clipboard, session, offscreen, sendMessage, deliver, restart,
    copy: (text: string, check = () => {}) => worker.copyWithExpiry(text, check), advanceTo };
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it('keeps the existing clipboard when cleanup cannot be registered', async () => {
  const f = await setup();
  f.session.set.mockRejectedValueOnce(new Error('session storage unavailable'));
  await expect(f.copy('sensitive fixture')).rejects.toThrow('session storage unavailable');
  expect(f.clipboard.text).toBe('ordinary text');
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

it.each([['legacy fixture', ''], ['ordinary text', 'ordinary text']])(
  'recovers a legacy record with its alarm already consumed and the clipboard holding %s', async (text, expected) => {
    const f = await setup();
    // Installed versions stored just this one digest with a one-shot alarm.
    await f.session.set({ clipboard: { hash: createHash('sha256').update('legacy fixture').digest('hex'), expiresAt: 1_030_000 } });
    f.clipboard.text = text;
    await f.advanceTo(1_010_000);
    f.sendMessage.mockRejectedValueOnce(new Error('lost reply'));
    await expect(f.copy('replacement fixture')).rejects.toThrow('lost reply');
    await f.restart();
    await f.advanceTo(1_030_000);
    expect(f.clipboard.text).toBe(expected);
    await f.advanceTo(1_040_000);
    expect(f.clipboard.text).toBe(expected);
  },
);
