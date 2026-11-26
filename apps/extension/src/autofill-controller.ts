import type { VaultController } from './vault-controller';
import type { AutofillMessage, CaptureTarget, FillKind, FillSource, MarkingMessage, MenuState } from './autofill-messages';
import type { VaultStatus } from './vault-messages';
import { defaultFlags, resolveSiteFlags, sameSite, siteRuleMatches, siteRulesFor, validateSiteRule, webUrl, type AutofillSettings, type SiteFlags } from './autofill-policy';
import { isVaultPage } from './sender-policy';
import { LoginMarkingController, type WebSender as Sender } from './login-marking-controller';
import { markKey, markSetKey } from './login-marks';

interface Grant {
  source: FillSource; kind: FillKind; expires: number; menuDocument?: string;
  performing?: boolean;
  manual: boolean;
  markId?: string;
  markSet?: string;
  capture?: { username: string; password: string; submittedUrl: string; target?: CaptureTarget };
}
const kinds = new Set(['login', 'username', 'otp', 'card', 'identity']);
export class AutofillController {
  private grants = new Map<string, Grant>();
  private actions = new Map<number, { url: URL; capture: boolean; manual: boolean }>();
  private capturing = new Map<number, Promise<void>>();
  readonly marking: LoginMarkingController;
  constructor(private vault: VaultController) { this.marking = new LoginMarkingController(vault, sender => this.source(sender)); }
  clear(tabId?: number) {
    this.marking.clear(tabId);
    if (tabId == null) this.capturing.clear(); else this.capturing.delete(tabId);
    if (tabId == null) this.actions.clear(); else this.actions.delete(tabId);
    for (const [token, grant] of this.grants) {
      if (tabId == null || grant.source.tabId === tabId) {
        this.consume(token);
      }
    }
  }
  navigated(tabId: number, url: string) {
    let origin: string | undefined;
    try { origin = webUrl(url).origin; } catch { /* A non-web page cannot resume a capture. */ }
    const action = this.actions.get(tabId);
    if (action?.capture && action.url.origin !== origin) this.actions.delete(tabId);
    for (const [token, grant] of this.grants) {
      if (grant.capture && grant.source.tabId === tabId && webUrl(grant.source.topUrl).origin !== origin) this.consume(token);
    }
  }
  siteChanged(rule: string, flags: Partial<SiteFlags>) {
    if (!flags.inlineDisabled && !flags.saveDisabled) return;
    const disables = (url: URL, capture: boolean, manual: boolean) =>
      (capture ? flags.saveDisabled : !manual && flags.inlineDisabled) === true && siteRuleMatches(rule, url);
    for (const [tabId, action] of this.actions) {
      if (disables(action.url, action.capture, action.manual)) this.actions.delete(tabId);
    }
    for (const [token, grant] of this.grants) {
      if (disables(webUrl(grant.source.url), !!grant.capture, grant.manual)) this.consume(token);
    }
  }
  private consume(token: string) {
    const grant = this.grants.get(token);
    if (grant?.capture) grant.capture.password = '';
    this.grants.delete(token);
  }
  private async settings(): Promise<AutofillSettings> {
    return await this.vault.handle({ type: 'autofill-settings' }) as AutofillSettings;
  }
  private async source(sender: Sender): Promise<FillSource> {
    if (sender.id !== browser.runtime.id || !Number.isInteger(sender.tab?.id) || !Number.isInteger(sender.frameId) || !sender.documentId) {
      throw new Error('无法确认网页来源。');
    }
    const url = webUrl(sender.url);
    if (sender.origin !== url.origin || !sender.tab?.url) throw new Error('网页来源不一致。');
    const tab = await browser.tabs.get(sender.tab.id!);
    const top = webUrl(tab.url);
    if (top.href !== webUrl(sender.tab.url).href || (sender.frameId === 0 && top.href !== url.href)) throw new Error('网页已导航，请重新点击填充。');
    return { tabId: tab.id!, frameId: sender.frameId!, documentId: sender.documentId, url: url.href, topUrl: top.href };
  }
  private async grant(token: string, sender: Sender) {
    for (const [key, grant] of this.grants) {
      if (grant.expires <= Date.now()) { if (grant.capture) grant.capture.password = ''; this.grants.delete(key); }
    }
    const grant = this.grants.get(token);
    if (!grant || sender.id !== browser.runtime.id || sender.tab?.id !== grant.source.tabId || !sender.documentId ||
      sender.origin !== 'chrome-extension://' + browser.runtime.id ||
      sender.url !== browser.runtime.getURL('/inline-menu.html') ||
      (grant.menuDocument && grant.menuDocument !== sender.documentId)) throw new Error('填充窗口已失效，请重新点击网页中的锁图标。');
    const source = grant.source;
    const tab = await browser.tabs.get(source.tabId);
    if (this.grants.get(token) !== grant || grant.source !== source || grant.expires <= Date.now() ||
        (grant.menuDocument && grant.menuDocument !== sender.documentId)) throw new Error('填充窗口已失效，请重新点击网页中的锁图标。');
    if (webUrl(tab.url).href !== grant.source.topUrl) { this.consume(token); throw new Error('网页已导航，已取消填充。'); }
    grant.menuDocument = sender.documentId;
    return grant;
  }
  async handle(message: AutofillMessage, sender: Sender): Promise<unknown> {
    if (message.type !== 'capture') return this.dispatch(message, sender);
    if (sender.id !== browser.runtime.id || sender.frameId !== 0 || sender.tab?.id == null) {
      try { return await this.dispatch(message, sender); } finally { message.password = ''; }
    }
    const tabId = sender.tab.id;
    const result = this.dispatch(message, sender);
    // The destination document may ask for the prompt while the original submission is still being checked.
    const done = result.then(() => {}, () => {});
    this.capturing.set(tabId, done);
    try { return await result; }
    finally { message.password = ''; if (this.capturing.get(tabId) === done) this.capturing.delete(tabId); }
  }
  private async dispatch(message: AutofillMessage, sender: Sender): Promise<unknown> {
    if (message.type.startsWith('mark-')) return this.marking.handle(message as MarkingMessage, sender);
    if (message.type === 'site' || message.type === 'site-rules') {
      if (!isVaultPage(sender, browser.runtime.id)) throw new Error('仅密码库界面可以修改网站设置。');
      if (message.type === 'site' && message.flags !== undefined) {
        return await this.vault.handle({ type: 'set-autofill-site', origin: message.origin, flags: message.flags });
      }
      const { sites } = await this.settings();
      return message.type === 'site-rules'
        ? siteRulesFor(sites, webUrl(message.origin))
        : sites[validateSiteRule(message.origin)] ?? defaultFlags();
    }
    if (['begin', 'flags', 'capture', 'pending'].includes(message.type)) {
      const expires = Date.now() + 120_000;
      const manual = message.type === 'begin' && message.manual === true;
      const action = (message.type === 'begin' || message.type === 'capture') &&
        sender.id === browser.runtime.id && Number.isInteger(sender.tab?.id)
        ? { url: webUrl(sender.url), capture: message.type === 'capture', manual } : undefined;
      if (action) this.actions.set(sender.tab!.id!, action);
      const source = await this.source(sender);
      const settings = await this.settings();
      const flags = resolveSiteFlags(settings.sites, webUrl(source.url));
      if (message.type === 'flags') return flags;
      if (message.type === 'pending') {
        const checking = source.frameId === 0 && this.capturing.get(source.tabId);
        if (checking) { await checking; await this.source(sender); }
        for (const [token, grant] of this.grants) {
          if (grant.capture && grant.expires > Date.now() && grant.source.tabId === source.tabId &&
            (grant.source.documentId === source.documentId && grant.source.frameId === source.frameId ||
              grant.source.frameId === 0 && source.frameId === 0) &&
            webUrl(grant.source.url).origin === webUrl(source.url).origin &&
            webUrl(grant.source.topUrl).origin === webUrl(source.topUrl).origin && !flags.saveDisabled) {
            grant.source = source; grant.menuDocument = undefined; grant.capture.target = undefined;
            return { token };
          }
        }
        return null;
      }
      if (message.type !== 'begin' && message.type !== 'capture') throw new Error('无效操作。');
      const capturing = message.type === 'capture';
      if (capturing ? flags.saveDisabled : !manual && flags.inlineDisabled) throw new Error('此网站已停用这项功能。');
      if (capturing && (typeof message.username !== 'string' || message.username.length > 1024 ||
        typeof message.password !== 'string' || !message.password || message.password.length > 4096)) throw new Error('捕获的凭证无效。');
      if (!capturing && !kinds.has(message.kind)) throw new Error('不支持的填充类型。');
      const status = await this.vault.handle({ type: 'status' }) as VaultStatus;
      if (!status.unlocked) throw new Error('请先打开 Vault 解锁密码库，然后重新点击。');
      let markId: string | undefined, markSet: string | undefined;
      if (!capturing && source.frameId === 0 && ['login', 'username', 'otp'].includes(message.kind)) {
        const enabled = await this.marking.enabled(source.url);
        markSet = markSetKey(enabled);
        markId = message.markId;
        if (message.markSet !== markSet || (enabled.length ? !enabled.some(mark => markKey(mark) === markId) : markId !== undefined)) {
          throw new Error('登录框标记已变化，请重新选择或标记。');
        }
      }
      if (capturing && await this.vault.handle({ type: 'autofill-current', url: source.url,
        username: message.username, password: message.password, groups: settings.equivalentDomains })) return null;
      if (capturing && source.frameId === 0) {
        // The original top-level document passed exact validation above. A form submission can now
        // have navigated; only the same origin can pick up the prompt, never the password.
        const current = webUrl((await browser.tabs.get(source.tabId)).url);
        if (current.origin !== webUrl(source.topUrl).origin) throw new Error('网页已导航，已取消保存提示。');
      } else await this.source(sender);
      if (this.actions.get(source.tabId) !== action) throw new Error('已有新的网页操作，请重新点击填充。');
      if (Date.now() >= expires) throw new Error('本次网页操作已过期。');
      this.clear(source.tabId);
      if (this.grants.size >= 20) this.clear();
      const token = crypto.randomUUID() + crypto.randomUUID();
      this.grants.set(token, { source, kind: capturing ? 'login' : message.kind, expires, manual, markId, markSet,
        capture: capturing ? { username: message.username, password: message.password, submittedUrl: source.url } : undefined });
      setTimeout(() => {
        const grant = this.grants.get(token);
        if (!grant || grant.expires > Date.now()) return;
        if (grant.capture) grant.capture.password = '';
        this.grants.delete(token);
      }, Math.max(0, expires - Date.now()) + 1);
      return { token };
    }
    if (!('token' in message) || typeof message.token !== 'string') throw new Error('无效操作。');
    if (message.type === 'close' && sender.origin !== 'chrome-extension://' + browser.runtime.id) {
      const source = await this.source(sender);
      const grant = this.grants.get(message.token);
      if (grant && grant.source.tabId === source.tabId && grant.source.documentId === source.documentId) this.consume(message.token);
      return null;
    }
    const grant = await this.grant(message.token, sender);
    if (message.type === 'close') {
      this.consume(message.token);
      await browser.tabs.sendMessage(grant.source.tabId, { target: 'vault-fill', type: 'close', token: message.token }, { documentId: grant.source.documentId }).catch(() => undefined);
      return null;
    }
    const settings = await this.settings();
    const source = webUrl(grant.capture?.submittedUrl ?? grant.source.url), top = webUrl(grant.source.topUrl);
    const crossOrigin = !sameSite(source, top, settings.equivalentDomains);
    const flags = resolveSiteFlags(settings.sites, source);
    if (grant.capture ? flags.saveDisabled : !grant.manual && flags.inlineDisabled) {
      this.consume(message.token);
      throw new Error('此网站已停用这项功能。');
    }
    if (message.type === 'menu') {
      const status = await this.vault.handle({ type: 'status' }) as VaultStatus;
      const candidates = grant.capture ? [] : await this.vault.handle({ type: 'autofill-candidates', url: source.href, kind: grant.kind, groups: settings.equivalentDomains }) as MenuState['candidates'];
      let capture: MenuState['capture'];
      if (grant.capture) {
        const { username } = grant.capture;
        const target = await this.vault.handle({ type: 'autofill-save-target', url: source.href, username }) as CaptureTarget;
        await this.grant(message.token, sender);
        grant.capture.target = target;
        capture = { account: username, updating: target.kind === 'update', ambiguous: target.kind === 'ambiguous',
          requireReprompt: target.kind === 'update' && target.requireReprompt };
      }
      return { site: source.host, topSite: top.host, crossOrigin, insecure: source.protocol === 'http:',
        pinEnabled: status.pinEnabled, kind: grant.kind, candidates, capture } satisfies MenuState;
    }
    if (message.type !== 'fill' && message.type !== 'save') throw new Error('无效操作。');
    if (grant.performing) throw new Error('正在处理本次请求，请稍候。');
    if ((crossOrigin || source.protocol === 'http:') && message.confirmCrossOrigin !== true) throw new Error('请先确认网页来源风险。');
    grant.performing = true;
    try {
    if (message.type === 'fill') {
      if (grant.capture) throw new Error('此填充请求已失效。');
      const checkMark = async () => {
        if (grant.source.frameId !== 0 || !['login', 'username', 'otp'].includes(grant.kind)) return;
        if (markSetKey(await this.marking.enabled(grant.source.url)) !== grant.markSet) throw new Error('登录框标记已变化，请重新点击。');
      };
      await checkMark();
      // Ask the original document to revalidate its live target before decrypting.
      const valid = await browser.tabs.sendMessage(grant.source.tabId, { target: 'vault-fill', type: 'probe', token: message.token }, { documentId: grant.source.documentId });
      if (!valid?.ready || valid.url !== grant.source.url || valid.markId !== grant.markId) {
        throw new Error(grant.markId ? '已标记的输入框找不到或不唯一，请重新标记。' : '输入框或网页已改变，请重新点击。');
      }
      const payload = await this.vault.handle({ type: 'autofill-read', id: message.id, url: source.href,
        kind: grant.kind, groups: settings.equivalentDomains, fields: valid.fields, proof: message.proof });
      // Proof may take long enough for navigation to happen.
      await this.grant(message.token, sender);
      await checkMark();
      const result = await browser.tabs.sendMessage(grant.source.tabId, { target: 'vault-fill', type: 'fill',
        token: message.token, url: source.href, kind: grant.kind, payload }, { documentId: grant.source.documentId });
      this.consume(message.token);
      if (!result?.filled) throw new Error(grant.markId ? '已标记的输入框不再可用，请重新标记。' : '没有可安全填写的输入框。');
      if (grant.kind === 'login' && message.copyOtp === true && !result.needsRemark) {
        const copied = await this.vault.handle({ type: 'autofill-copy-otp', id: message.id, url: source.href,
          groups: settings.equivalentDomains, proof: message.proof }).catch(() => false);
        await browser.tabs.sendMessage(grant.source.tabId, { target: 'vault-fill', type: 'notice',
          text: copied ? '已填入密码，时间验证码已复制，30 秒后自动清理。' : '密码已填入。未能复制时间验证码，请在密码库中查看。' },
        { documentId: grant.source.documentId }).catch(() => undefined);
      }
      return null;
    }
    if (!grant.capture?.target || flags.saveDisabled) throw new Error('保存请求已失效。');
    const { username, password, target } = grant.capture;
    if (target.kind === 'ambiguous') throw new Error('有多条同账号凭证，请在密码库中手动选择更新。');
    await this.vault.commitCapturedLogin({ type: 'autofill-save', url: source.href, username, password, expected: target, proof: message.proof }, async () => {
      await this.grant(message.token, sender);
      if (grant.capture?.target !== target) throw new Error('保存请求已变化，请重新确认。');
    });
    this.consume(message.token);
    return null;
    } finally { grant.performing = false; }
  }
}
