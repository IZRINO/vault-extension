import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AutofillController } from './autofill-controller';
import type { AutofillSettings } from './autofill-settings';
import type { VaultController } from './vault-controller';

const extensionId = 'fixture-extension';
const url = 'https://login.example.com/form', top = 'https://top.evil.test/';
const source = { id: extensionId, url, origin: 'https://login.example.com', documentId: 'document-a', frameId: 3, tab: { id: 1, url: top } };
const menu = { id: extensionId, url: `chrome-extension://${extensionId}/inline-menu.html`, origin: `chrome-extension://${extensionId}`, documentId: 'menu-a', frameId: 4, tab: { id: 1, url: top } };
let controller: AutofillController;
let tabUrl: string;
let unlocked: boolean;
let settings: AutofillSettings;
let tabWait: Promise<void> | undefined;
let handle: ReturnType<typeof vi.fn>;
let sendMessage: ReturnType<typeof vi.fn>;
beforeEach(() => {
  tabUrl = top; unlocked = true;
  settings = { sites: {}, equivalentDomains: [] };
  tabWait = undefined;
  handle = vi.fn(async (message: { type: string }) => {
    if (message.type === 'status') return { unlocked };
    if (message.type === 'autofill-settings') return settings;
    if (!unlocked) throw new Error('请先解锁密码库。');
    if (message.type === 'autofill-candidates') return [{ id: 'credential-a', title: 'Fixture account', account: 'user' }];
    if (message.type === 'autofill-read') return { values: { username: 'user', password: 'fixture-secret' } };
  });
  sendMessage = vi.fn(async (_tab, message, options) => {
    expect(options.documentId).toBe('document-a');
    if (message.type === 'probe') return { ready: true, url };
    return { filled: true };
  });
  vi.stubGlobal('browser', {
    runtime: { id: extensionId, getURL: (path: string) => `chrome-extension://${extensionId}${path}` },
    tabs: { get: async () => { await tabWait; return { id: 1, url: tabUrl }; }, sendMessage },
    storage: { local: { get: async () => ({}) } },
  });
  controller = new AutofillController({ handle } as unknown as VaultController);
});
describe('autofill authorization', () => {
  it('cannot reuse a grant removed while its tab is being checked', async () => {
    const { token } = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    const wait = Promise.withResolvers<void>();
    tabWait = wait.promise;
    const pending = controller.handle({ type: 'menu', token }, menu);
    controller.clear(source.tab.id);
    wait.resolve();
    await expect(pending).rejects.toThrow('失效');
    expect(handle).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'autofill-candidates' }));
  });

  it('keeps a save grant when another site or an independent preference changes', async () => {
    const { token } = await controller.handle({ type: 'capture', username: 'user', password: 'synthetic' }, source) as { token: string };
    controller.siteChanged('https://*.other.test', { saveDisabled: true });
    controller.siteChanged('https://*.example.com', { passkeyDisabled: true, inlineDisabled: true });
    await expect(controller.handle({ type: 'menu', token }, menu)).resolves.toMatchObject({ capture: { account: 'user' } });
    controller.siteChanged('https://*.example.com', { saveDisabled: true });
    await expect(controller.handle({ type: 'menu', token }, menu)).rejects.toThrow('失效');
  });

  it('rejects website rule management and applies new restrictions to pending fill and capture grants', async () => {
    const { sites } = settings;
    await expect(controller.handle({ type: 'site-rules', origin: source.origin }, source)).rejects.toThrow('仅密码库');
    await expect(controller.handle({ type: 'site', origin: 'https://*.example.com', flags: { inlineDisabled: true } }, source)).rejects.toThrow('仅密码库');
    const { token } = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    sites['https://*.example.com'] = { inlineDisabled: true, saveDisabled: false, passkeyDisabled: true };
    await expect(controller.handle({ type: 'menu', token }, menu)).rejects.toThrow('已停用');
    await expect(controller.handle({ type: 'begin', kind: 'login' }, source)).rejects.toThrow('已停用');
    const capture = await controller.handle({ type: 'capture', username: 'user', password: 'synthetic' }, source) as { token: string };
    sites['https://*.example.com'].saveDisabled = true;
    await expect(controller.handle({ type: 'pending' }, source)).resolves.toBeNull();
    await expect(controller.handle({ type: 'save', token: capture.token, confirmCrossOrigin: true }, menu)).rejects.toThrow('已停用');
    expect(handle).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'upsert' }));
  });

  it('keeps deliberate fill available when the website only disables the inline icon', async () => {
    settings.sites['https://*.example.com'] = { inlineDisabled: true, saveDisabled: true, passkeyDisabled: false };
    await expect(controller.handle({ type: 'begin', kind: 'login' }, source)).rejects.toThrow('已停用');
    const { token } = await controller.handle({ type: 'begin', kind: 'login', manual: true }, source) as { token: string };
    controller.siteChanged('https://*.example.com', { inlineDisabled: true });
    await expect(controller.handle({ type: 'fill', token, id: 'credential-a', confirmCrossOrigin: false }, menu)).rejects.toThrow('来源风险');
    await controller.handle({ type: 'fill', token, id: 'credential-a', confirmCrossOrigin: true }, menu);
    expect(sendMessage).toHaveBeenCalledTimes(2);
  });

  it('rejects source spoofing and returns only an opaque grant to a real content document', async () => {
    for (const sender of [{ ...source, id: 'other-extension' }, { ...source, origin: 'https://evil.test' },
      { ...source, documentId: undefined }, { ...source, tab: { id: 1, url: 'https://other.test' } }]) {
      await expect(controller.handle({ type: 'begin', kind: 'login' }, sender)).rejects.toThrow();
    }
    const result = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    expect(Object.keys(result)).toEqual(['token']); expect(result.token.length).toBe(72);
    expect(handle).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'autofill-candidates' }));
    await expect(controller.handle({ type: 'menu', token: result.token }, source)).rejects.toThrow('失效');
    await expect(controller.handle({ type: 'menu', token: result.token }, { ...menu, tab: { id: 2 } })).rejects.toThrow('失效');
    const choices = await controller.handle({ type: 'menu', token: result.token }, menu);
    expect(choices).toMatchObject({ crossOrigin: true, site: 'login.example.com', topSite: 'top.evil.test' });
    expect(JSON.stringify(choices)).not.toContain('fixture-secret');
    await expect(controller.handle({ type: 'menu', token: result.token }, { ...menu, documentId: 'different-menu' })).rejects.toThrow('失效');
  });
  it('requires cross-site confirmation, binds the exact original document and consumes success once', async () => {
    const { token } = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    await expect(controller.handle({ type: 'fill', token, id: 'credential-a', confirmCrossOrigin: false }, menu)).rejects.toThrow('来源风险');
    expect(sendMessage).not.toHaveBeenCalled();
    await controller.handle({ type: 'fill', token, id: 'credential-a', confirmCrossOrigin: true }, menu);
    expect(sendMessage.mock.calls[1]?.[1]).toMatchObject({ target: 'vault-fill', type: 'fill', url, token });
    await expect(controller.handle({ type: 'fill', token, id: 'credential-a', confirmCrossOrigin: true }, menu)).rejects.toThrow('失效');
  });
  it('rejects navigation, expired and lock-cleared capabilities before secret access', async () => {
    let result = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    tabUrl = 'https://different.test/';
    await expect(controller.handle({ type: 'menu', token: result.token }, menu)).rejects.toThrow('导航');
    tabUrl = top;
    result = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    controller.clear();
    await expect(controller.handle({ type: 'menu', token: result.token }, menu)).rejects.toThrow('失效');
    result = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 120001);
    try { await expect(controller.handle({ type: 'menu', token: result.token }, menu)).rejects.toThrow('失效'); }
    finally { vi.restoreAllMocks(); }
    expect(handle).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'autofill-read' }));
  });
  it('does not let a delayed capture replace a newer menu or a completed old fill delete it', async () => {
    let releaseCapture!: (value: boolean) => void;
    const checking = new Promise<boolean>(resolve => { releaseCapture = resolve; });
    let captureStarted!: () => void;
    const started = new Promise<void>(resolve => { captureStarted = resolve; });
    handle.mockImplementation(async (message: { type: string }) => {
      if (message.type === 'status') return { unlocked: true };
      if (message.type === 'autofill-settings') return { sites: {}, equivalentDomains: [] };
      if (message.type === 'autofill-current') { captureStarted(); return checking; }
      if (message.type === 'autofill-candidates') return [];
      if (message.type === 'autofill-read') return { values: { password: 'fixture' } };
    });
    const old = controller.handle({ type: 'capture', username: 'user', password: 'typed fixture' }, source);
    const rejectedOld = expect(old).rejects.toThrow('新的网页操作');
    await started;
    const latest = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    releaseCapture(false);
    await rejectedOld;
    await expect(controller.handle({ type: 'menu', token: latest.token }, menu)).resolves.toBeDefined();
    let finishFill!: () => void;
    const filling = new Promise<void>(resolve => { finishFill = resolve; });
    let fillStarted!: () => void;
    const submitted = new Promise<void>(resolve => { fillStarted = resolve; });
    sendMessage.mockImplementation(async (_tab, message) => {
      if (message.type === 'probe') return { ready: true, url };
      if (message.type === 'fill') { fillStarted(); await filling; }
      return { filled: true };
    });
    const oldFill = controller.handle({ type: 'fill', token: latest.token, id: 'credential-a', confirmCrossOrigin: true }, menu);
    await submitted;
    const newest = await controller.handle({ type: 'begin', kind: 'login' }, source) as { token: string };
    finishFill(); await oldFill;
    await expect(controller.handle({ type: 'menu', token: newest.token }, menu)).resolves.toBeDefined();
  });
});
