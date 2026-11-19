import type { VaultController } from '../vault-controller';
import { readRequest, type PasskeyCandidate, type PasskeyOutcome, type PasskeySelection, type TrustedRequest } from './protocol';

type Port = Parameters<Parameters<typeof browser.runtime.onConnect.addListener>[0]>[0];
type Sender = NonNullable<Port['sender']>;
type Source = { tabId: number; windowId: number; documentId: string; href: string; origin: string };
type Ceremony = {
  port: Port;
  source: Source;
  request: TrustedRequest;
  ticket: string;
  deadline: number;
  timer: ReturnType<typeof setTimeout>;
  candidates?: PasskeyCandidate[];
  inlineDocument?: string;
  popupDocument?: string;
  popup?: number;
  presenting?: boolean;
  performing?: boolean;
  chosen?: string;
};
const PROMPT = '/passkey-prompt.html';

export class PasskeyController {
  private pending = new Map<number, Ceremony>();
  constructor(private vault: VaultController) {}

  stop(tabId?: number, origin?: string) {
    for (const entry of this.pending.values()) {
      if ((tabId == null || entry.source.tabId === tabId) && (!origin || entry.source.origin === origin)) this.finish(entry, { type: 'cancel' });
    }
  }

  closed(windowId: number) {
    for (const entry of this.pending.values()) if (entry.popup === windowId) this.finish(entry, { type: 'cancel' });
  }

  selected(tabId: number, windowId: number) {
    for (const entry of this.pending.values()) {
      if (entry.source.windowId === windowId && entry.source.tabId !== tabId) this.finish(entry, { type: 'cancel' });
    }
  }

  private finish(entry: Ceremony, result: PasskeyOutcome) {
    if (this.pending.get(entry.source.tabId) !== entry) return;
    this.pending.delete(entry.source.tabId);
    clearTimeout(entry.timer);
    try { entry.port.postMessage(result); } catch { /* document already gone */ }
    if (entry.popup != null) void browser.windows.remove(entry.popup).catch(() => undefined);
  }

  private async source(sender?: Sender): Promise<Source> {
    if (sender?.id !== browser.runtime.id || sender.frameId !== 0 || sender.tab?.id == null || !sender.documentId ||
        !sender.tab.url || !sender.url || !sender.origin) throw new Error('无法确认网页来源。');
    const url = new URL(sender.url);
    if (!(url.protocol === 'https:' || (url.protocol === 'http:' && url.hostname === 'localhost')) ||
        sender.origin !== url.origin || new URL(sender.tab.url).href !== url.href) throw new Error('网页来源已改变。');
    const source = { tabId: sender.tab.id, windowId: sender.tab.windowId, documentId: sender.documentId, origin: url.origin, href: url.href };
    await this.revalidate(source);
    return source;
  }

  private async revalidate(source: Source, active = false) {
    const tab = await browser.tabs.get(source.tabId);
    if (!tab.url || new URL(tab.url).href !== source.href || (active && !tab.active)) throw new Error('网页已切换，请重新操作。');
  }

  connect(port: Port) {
    let live = true;
    let started = false;
    let entry: Ceremony | undefined;
    port.onDisconnect.addListener(() => {
      live = false;
      if (entry) this.finish(entry, { type: 'cancel' });
    });
    port.onMessage.addListener(message => {
      const send = (value: unknown) => { if (live) try { port.postMessage(value); } catch { live = false; } };
      if (message?.type === 'show' && entry?.request.conditional && !entry.presenting && !entry.candidates) {
        const target = entry;
        target.presenting = true;
        void (async () => {
          await this.revalidate(target.source, true);
          target.candidates = await this.vault.passkeyCandidates(target.request);
          this.current(target);
          send({ type: 'inline', ticket: target.ticket });
        })().catch(() => this.finish(target, { type: 'cancel' }));
        return;
      }
      if (started || message?.type !== 'begin') return;
      started = true;
      void (async () => {
        const source = await this.source(port.sender);
        const enabled = await this.vault.passkeyAvailable(source.origin);
        if (message.request === 'capability') { send({ type: 'capability', available: enabled }); return; }
        const request = readRequest(message.request);
        if (!live || !enabled || !request || this.pending.has(source.tabId) || this.pending.size >= 6) { send({ type: 'native' }); return; }
        const trusted: TrustedRequest = { ...request, origin: source.origin, rpId: request.rpId ?? new URL(source.origin).hostname };
        await this.revalidate(source, !trusted.conditional);
        if (!live || this.pending.has(source.tabId)) return send({ type: 'cancel' });
        const duration = trusted.conditional ? 120_000 : 60_000;
        const record: Ceremony = {
          port, source, request: trusted, ticket: crypto.randomUUID(), deadline: Date.now() + duration,
          timer: setTimeout(() => { this.finish(record, { type: 'cancel' }); }, duration),
        };
        entry = record;
        this.pending.set(source.tabId, record);
        if (trusted.conditional) send({ type: 'conditional' });
        else {
          record.candidates = await this.vault.passkeyCandidates(trusted);
          this.current(record);
          if (trusted.kind === 'assert' && record.candidates.length === 0) { this.finish(record, { type: 'native' }); return; }
          await this.popup(record);
        }
      })().catch(() => {
        if (entry) this.finish(entry, { type: 'native' });
        else send({ type: 'native' });
      });
    });
  }

  private current(entry: Ceremony) {
    if (this.pending.get(entry.source.tabId) !== entry || Date.now() >= entry.deadline) throw new Error('请求已结束，请回到网站重试。');
  }

  private async popup(entry: Ceremony) {
    this.current(entry);
    const window = await browser.windows.create({
      url: `${browser.runtime.getURL(PROMPT)}#${entry.ticket}`, type: 'popup', width: 440, height: 530, focused: true,
    });
    if (window?.id == null) throw new Error('无法打开 Vault 确认窗口。');
    entry.popup = window.id;
    try { this.current(entry); } catch (error) {
      void browser.windows.remove(window.id).catch(() => undefined);
      throw error;
    }
  }

  private prompt(ticket: unknown, sender: Sender) {
    if (typeof ticket !== 'string' || ticket.length !== 36 || sender.id !== browser.runtime.id ||
        !sender.documentId || !sender.url || sender.origin !== `chrome-extension://${browser.runtime.id}`) throw new Error('请求来源不允许。');
    const entry = [...this.pending.values()].find(value => value.ticket === ticket);
    if (!entry || !entry.candidates || !sender.tab) throw new Error('请求已结束，请回到网站重试。');
    const inline = entry.request.conditional && sender.tab.id === entry.source.tabId && sender.frameId !== 0 &&
      sender.url === `${browser.runtime.getURL(PROMPT)}#${ticket}.inline`;
    const popup = sender.frameId === 0 && sender.tab.windowId === entry.popup &&
      sender.url === `${browser.runtime.getURL(PROMPT)}#${ticket}`;
    if (!inline && !popup) throw new Error('请求来源不允许。');
    const field = inline ? 'inlineDocument' : 'popupDocument';
    if (entry[field] && entry[field] !== sender.documentId) throw new Error('确认页面已更换。');
    entry[field] = sender.documentId;
    this.current(entry);
    return { inline, entry };
  }

  async handle(message: { ticket?: unknown; type?: string; selection?: PasskeySelection }, sender: Sender) {
    const { inline, entry } = this.prompt(message.ticket, sender);
    await this.revalidate(entry.source);
    this.current(entry);
    if (message.type === 'prompt') return {
      kind: entry.request.kind, rpId: entry.request.rpId, origin: entry.source.origin, uv: entry.request.uv,
      account: entry.request.user?.name, candidates: entry.candidates!, chosen: entry.chosen,
    };
    if (message.type === 'native' || message.type === 'cancel') {
      if (entry.performing) throw new Error('正在完成本次请求。');
      this.finish(entry, { type: message.type });
      return;
    }
    const selection = message.selection;
    if (!selection || typeof selection !== 'object' || !['choose', 'approve'].includes(message.type ?? '')) throw new Error('确认内容无效。');
    const { itemId, credentialId, increment, proof } = selection;
    const match = entry.candidates!.find(candidate => candidate.itemId === itemId && (candidate.id ?? undefined) === credentialId);
    if (match?.suspended) throw new Error('计数待核实，请同步或在网站重新登记。');
    if ((!match && (entry.request.kind !== 'register' || itemId != null || credentialId != null)) ||
        (proof != null && (!['master', 'pin'].includes(proof.method) || typeof proof.secret !== 'string' || proof.secret.length > 1024))) {
      throw new Error('凭证不适用于此请求。');
    }
    if (inline) {
      if (message.type !== 'choose' || !match || entry.popup != null || entry.chosen || proof != null) throw new Error('确认内容无效。');
      entry.chosen = match.id ?? undefined;
      try { await this.popup(entry); } catch (error) { this.finish(entry, { type: 'cancel' }); throw error; }
      return;
    }
    if (message.type !== 'approve' || entry.performing || (entry.chosen && credentialId !== entry.chosen)) throw new Error('确认内容无效。');
    if ((match?.verify || entry.request.uv === 'required') && !proof) throw new Error('请重新验证主密码或 PIN。');
    entry.performing = true;
    try {
      const result = await this.vault.passkeyAnswer(entry.request, { itemId, credentialId, increment, proof }, () => this.current(entry));
      await this.revalidate(entry.source);
      this.current(entry);
      this.finish(entry, { type: 'answer', value: result });
    } finally { entry.performing = false; }
  }
}
