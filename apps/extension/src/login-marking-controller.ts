import type { FillSource, MarkingMessage } from './autofill-messages';
import { webUrl } from './autofill-policy';
import { markKey, markScope, type LoginMark } from './login-marks';
import { isVaultPage } from './sender-policy';
import type { VaultController } from './vault-controller';

export type WebSender = { id?: string; url?: string; origin?: string; documentId?: string; frameId?: number; tab?: { id?: number; url?: string } };
type Selection = { token: string; url: string; documentId?: string; expires: number; replaceKey?: string };
const expiryMs = 120_000;

export class LoginMarkingController {
  private selections = new Map<number, Selection>();
  constructor(private vault: VaultController, private contentSource: (sender: WebSender) => Promise<FillSource>) {}

  private send(tabId: number, options: { frameId: number } | { documentId: string }, message: Record<string, unknown>) {
    return browser.tabs.sendMessage(tabId, { target: 'vault-fill', ...message }, options);
  }

  clear(tabId?: number) {
    for (const [id, selection] of this.selections) {
      if (tabId != null && id !== tabId) continue;
      this.selections.delete(id);
      if (selection.documentId) void this.send(id, { documentId: selection.documentId },
        { type: 'mark-ended', token: selection.token }).catch(() => undefined);
    }
  }

  read(url: string) { return this.vault.handle({ type: 'login-mark', url }) as Promise<LoginMark[]>; }
  async enabled(url: string) { return (await this.read(url)).filter(mark => mark.enabled); }

  private async checkSelection(token: string, sender: WebSender, ready = false) {
    const source = await this.contentSource(sender);
    const selection = this.selections.get(source.tabId);
    if (source.frameId !== 0 || !selection || selection.token !== token || selection.url !== source.url ||
        selection.expires <= Date.now() || (!ready || selection.documentId) && selection.documentId !== source.documentId) {
      throw new Error('标记会话已结束，请从 Vault 重新打开。');
    }
    return { selection, source };
  }

  async handle(message: MarkingMessage, sender: WebSender) {
    if (message.type === 'mark-get') {
      const source = await this.contentSource(sender);
      return source.frameId === 0 ? this.enabled(source.url) : [];
    }
    if (message.type === 'mark-ready' || message.type === 'mark-cancel' || message.type === 'mark-save') {
      const { selection, source } = await this.checkSelection(message.token, sender, message.type === 'mark-ready');
      if (message.type === 'mark-ready') { selection.documentId = source.documentId; return null; }
      if (message.type === 'mark-cancel') { this.clear(source.tabId); return null; }
      const result = await this.vault.changeLoginMark({ type: 'login-mark', url: source.url,
        change: { action: 'replace', key: selection.replaceKey, draft: message.draft } }, async () => { await this.checkSelection(message.token, sender); }) as LoginMark[];
      if (this.selections.get(source.tabId) === selection) this.clear(source.tabId);
      return result.filter(mark => mark.enabled);
    }
    if (!isVaultPage(sender, browser.runtime.id)) throw new Error('仅密码库界面可以管理当前网页登录框。');
    const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab?.id == null) throw new Error('没有可标记的网页。');
    const tabId = tab.id;
    const url = webUrl(tab.url);
    if (message.type === 'mark-manage') return { origin: url.origin, marks: await this.read(url.href) };
    const confirmTab = async () => { if ((await browser.tabs.get(tabId)).url !== url.href) throw new Error('网页已变化，请重新打开网站设置。'); };
    if (message.type === 'mark-enable' || message.type === 'mark-delete') {
      const marks = await this.vault.changeLoginMark({ type: 'login-mark', url: url.href,
        change: message.type === 'mark-enable' ? { action: 'enable', key: message.key, enabled: message.enabled } :
          { action: 'delete', key: message.key } }, confirmTab);
      await this.send(tabId, { frameId: 0 }, { type: 'mark-changed' }).catch(() => undefined);
      return { origin: url.origin, marks };
    }
    if (message.type !== 'mark-start') throw new Error('无效的标记操作。');
    if (!await markScope(url)) throw new Error('此页面的地址不适合保存长期标记。');
    const marks = await this.read(url.href); // Fails while locked.
    if (message.key !== undefined && !marks.some(mark => markKey(mark) === message.key)) {
      throw new Error('此标记已经变化，请重新打开网站设置。');
    }
    await confirmTab();
    this.clear(tabId);
    const selection = { token: crypto.randomUUID(), url: url.href, expires: Date.now() + expiryMs, replaceKey: message.key };
    this.selections.set(tabId, selection);
    setTimeout(() => { if (this.selections.get(tabId) === selection) this.clear(tabId); }, expiryMs);
    try {
      const reply = await this.send(tabId, { frameId: 0 }, { type: 'mark-open', token: selection.token, url: url.href });
      if (!reply?.ready) throw new Error('此网页尚不能标记。请刷新网页后重试。');
    } catch {
      if (this.selections.get(tabId) === selection) this.clear(tabId);
      throw new Error('此网页尚不能标记。请刷新网页后重试。');
    }
    return null;
  }
}
