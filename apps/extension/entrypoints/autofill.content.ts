import { autofillRequest, type FillKind, type FillPayload } from '../src/autofill-messages';
import { controls, fieldKey, fillControls, fillKind, safeAction, visible, type Control } from '../src/autofill-dom';
import { defaultFlags, type SiteFlags } from '../src/autofill-settings';

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  allFrames: true,
  runAt: 'document_idle',
  main(ctx) {
    let flags: SiteFlags = defaultFlags();
    let active: Control | undefined;
    let host: HTMLDivElement | undefined;
    let token: string | undefined;
    let menuTarget: Control | undefined;
    let menuKind: FillKind | undefined;
    let lastUrl = location.href;
    let restoring = false;
    let pendingSubmit = 0;
    let opening = false;
    let recentUsername = '';
    let stopHandshake: (() => void) | undefined;
    const extensionOrigin = 'chrome-extension://' + browser.runtime.id;
    const note = (message: string) => {
      const box = document.createElement('div');
      const root = box.attachShadow({ mode: 'closed' });
      const text = document.createElement('p');
      text.textContent = message;
      text.style.cssText = 'font:14px/1.5 system-ui;margin:0;padding:12px 16px;color:#fff;background:#1f2428;border-radius:8px;max-width:320px';
      root.append(text);
      box.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647';
      document.documentElement.append(box);
      setTimeout(() => box.remove(), 5000);
    };
    const remove = () => {
      stopHandshake?.(); stopHandshake = undefined;
      host?.remove(); host = undefined; token = undefined; menuTarget = undefined; menuKind = undefined;
    };
    const position = (box: HTMLElement, target?: Control, menu = false) => {
      const rect = target?.getBoundingClientRect();
      const width = menu ? Math.min(340, innerWidth - 16) : 30;
      const narrow = !!rect && rect.width < 90;
      const left = rect ? menu || narrow ? rect.left : rect.right - 32 : innerWidth - width - 12;
      const below = rect ? innerHeight - rect.bottom - 12 : innerHeight - 24;
      const above = rect ? rect.top - 12 : 0;
      const upwards = menu && !!rect && above > below;
      const height = menu ? Math.max(48, Math.min(420, upwards ? above : below)) : 28;
      const top = rect ? menu ? upwards ? rect.top - height - 4 : rect.bottom + 4 : narrow ? rect.top - 30 : rect.top + (rect.height - 28) / 2 : 12;
      box.style.cssText = `all:initial;position:fixed;left:${Math.max(8, Math.min(left, innerWidth - width - 8))}px;top:${Math.max(8, top)}px;width:${width}px;height:${height}px;z-index:2147483647;display:block`;
    };
    const showMenu = (value: string, target?: Control, kind?: FillKind) => {
      remove();
      token = value; menuTarget = target; menuKind = kind;
      host = document.createElement('div');
      host.setAttribute('data-vault-ui', '');
      position(host, target, true);
      const root = host.attachShadow({ mode: 'closed' });
      const iframe = document.createElement('iframe');
      iframe.src = browser.runtime.getURL('/inline-menu.html');
      iframe.title = 'Vault 安全填充';
      iframe.style.cssText = 'width:100%;height:100%;border:0;display:block;border-radius:8px;box-shadow:0 8px 24px #0003';
      const ready = (event: MessageEvent) => {
        if (event.source !== iframe.contentWindow || event.origin !== extensionOrigin || event.data?.target !== 'vault-menu-ready') return;
        iframe.contentWindow?.postMessage({ target: 'vault-menu', token: value }, extensionOrigin);
        window.removeEventListener('message', ready);
      };
      window.addEventListener('message', ready);
      stopHandshake = () => window.removeEventListener('message', ready);
      root.append(iframe);
      document.documentElement.append(host);
    };
    const begin = async () => {
      if (opening || token) return;
      if (!active || !visible(active) || !safeAction(active)) { note('请先选择可见的输入框。跨域提交的表单需要在原网站手动填写。'); return; }
      const kind = fillKind(active);
      if (!kind || flags.inlineDisabled) return;
      opening = true;
      try {
        const { token } = await autofillRequest<{ token: string }>({ type: 'begin', kind });
        if (!ctx.isInvalid && active && visible(active)) showMenu(token, active, kind);
      } catch (error) { note(error instanceof Error ? error.message : '无法打开填充菜单。'); }
      finally { opening = false; }
    };
    const icon = (target: Control) => {
      if (token) return;
      remove();
      if (flags.inlineDisabled || !fillKind(target) || !visible(target)) return;
      host = document.createElement('div');
      host.setAttribute('data-vault-ui', '');
      position(host, target);
      const root = host.attachShadow({ mode: 'closed' });
      const button = document.createElement('button');
      button.type = 'button';
      button.title = '使用 Vault 填充';
      button.setAttribute('aria-label', '使用 Vault 填充');
      button.textContent = 'Vault';
      button.style.cssText = 'width:30px;height:28px;border:1px solid #879089;border-radius:5px;background:#fff;color:#1f2428;font:600 9px system-ui;cursor:pointer;padding:0';
      button.addEventListener('click', event => { if (event.isTrusted) void begin(); });
      root.append(button);
      document.documentElement.append(host);
    };
    const fromEvent = (event: Event): Control | undefined => {
      const field = event.composedPath()[0];
      return field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement || field instanceof HTMLSelectElement ? field : undefined;
    };
    const refreshFlags = async () => {
      try { flags = await autofillRequest<SiteFlags>({ type: 'flags' }); }
      catch (error) {
        flags = { inlineDisabled: true, saveDisabled: true, passkeyDisabled: true };
        console.warn('[Vault] 无法确认网站设置：', error instanceof Error ? error.message : '消息失败');
      }
    };
    const pending = async () => {
      if (restoring || flags.saveDisabled) return;
      restoring = true;
      try {
        const response = await autofillRequest<{ token: string } | null>({ type: 'pending' });
        if (response && !ctx.isInvalid) showMenu(response.token);
      } catch { /* A page without an unlocked vault has no save prompt. */ }
      finally { restoring = false; }
    };
    const capture = (form: HTMLFormElement | null) => {
      if (flags.saveDisabled || Date.now() > pendingSubmit) return;
      pendingSubmit = 0;
      const fields = controls(form ?? document).filter(field => field.form === form && visible(field) && safeAction(field));
      const passwords = fields.filter(field => field instanceof HTMLInputElement && field.type === 'password' && field.value);
      const password = passwords.find(field => field.autocomplete.split(/\s+/).includes('new-password') ||
        /new|新密码/.test([field.id, field.name, field.getAttribute('placeholder')].join(' ').toLowerCase())) ?? passwords[0];
      if (!password || password.value.length > 4096) return;
      const username = fields.find(field => ['username', 'email'].includes(fieldKey(field) ?? ''))?.value ?? recentUsername;
      void autofillRequest<{ token: string } | null>({ type: 'capture', username, password: password.value })
        .then(response => { if (response && !ctx.isInvalid) showMenu(response.token); }).catch(() => undefined);
    };
    ctx.addEventListener(document, 'focusin', event => {
      if (!event.isTrusted) return;
      const target = fromEvent(event);
      if (!target) return;
      active = target;
      if (token) remove();
      icon(target);
    }, true);
    ctx.addEventListener(document, 'contextmenu', event => {
      if (event.isTrusted) active = fromEvent(event) ?? active;
    }, true);
    ctx.addEventListener(document, 'keydown', event => {
      const key = event as KeyboardEvent;
      if (!key.isTrusted) return;
      if (key.code === 'KeyL' && key.altKey && key.shiftKey && !key.ctrlKey && !key.metaKey) {
        key.preventDefault(); void begin(); return;
      }
      if (key.key === 'Escape') {
        if (token) void autofillRequest({ type: 'close', token }).catch(() => undefined);
        remove();
      }
      if (key.key === 'Enter') {
        const field = fromEvent(event);
        if (field && ['username', 'email'].includes(fieldKey(field) ?? '')) recentUsername = field.value;
        if (field?.form) { pendingSubmit = Date.now() + 1500; capture(field.form); }
      }
    }, true);
    ctx.addEventListener(document, 'click', event => {
      if (!event.isTrusted) return;
      const element = event.composedPath()[0];
      if (!(element instanceof Element)) return;
      const button = element.closest('button,input[type=submit]');
      const form = button instanceof HTMLButtonElement || button instanceof HTMLInputElement ? button.form : null;
      if (form) recentUsername = controls(form).find(field => ['username', 'email'].includes(fieldKey(field) ?? '') && visible(field))?.value ?? recentUsername;
      if (button instanceof HTMLButtonElement && button.type === 'submit' || button instanceof HTMLInputElement && button.type === 'submit') {
        pendingSubmit = Date.now() + 1500;
        capture(button.form);
      }
      else if (button instanceof HTMLButtonElement && /log.?in|sign.?in|save|submit|登录|登陆|注册|保存|修改密码|确认/.test(button.textContent?.toLowerCase() ?? '')) {
        pendingSubmit = Date.now() + 1500; capture(form);
      }
    }, true);
    ctx.addEventListener(document, 'submit', event => {
      if (event.isTrusted && event.target instanceof HTMLFormElement) capture(event.target);
    }, true);
    ctx.addEventListener(window, 'beforeunload', () => { if (pendingSubmit) capture(active?.form ?? null); });
    const observer = new MutationObserver(() => {
      if (active && !active.isConnected && !token) { active = undefined; remove(); }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    ctx.onInvalidated(() => { observer.disconnect(); remove(); });
    ctx.setInterval(() => {
      if (location.href !== lastUrl) {
        lastUrl = location.href; remove();
        void refreshFlags().then(pending);
      }
      if (active && host && !token) position(host, active);
    }, 350);
    const onMessage = (message: Record<string, unknown>, sender: { id?: string }, respond: (value: unknown) => void) => {
      if (sender.id !== browser.runtime.id || message?.target !== 'vault-fill') return;
      if (message.type === 'settings-changed') { remove(); void refreshFlags(); return; }
      if (message.type === 'notice' && typeof message.text === 'string') { note(message.text); return; }
      if (message.type === 'open') {
        let focused = document.activeElement;
        while (focused?.shadowRoot?.activeElement) focused = focused.shadowRoot.activeElement;
        if (document.hasFocus() && (focused === active || message.reason === 'context-menu')) void begin();
        return;
      }
      if (!token || message.token !== token) { respond({ ready: false, filled: false }); return; }
      if (message.type === 'probe') {
        host?.style.setProperty('visibility', 'hidden', 'important');
        try {
          const ready = !!menuTarget && visible(menuTarget) && safeAction(menuTarget);
          const fields = ready ? controls(menuTarget!.form ?? menuTarget!.getRootNode() as Document | ShadowRoot)
            .filter(field => field.form === menuTarget!.form && !fieldKey(field) && visible(field) && safeAction(field))
            .flatMap(field => [field.name, field.id]).filter(name => !!name && name.length <= 256).slice(0, 64) : [];
          respond({ ready, url: location.href, fields }); return;
        } finally { host?.style.removeProperty('visibility'); }
      }
      if (message.type === 'fill') {
        host?.style.setProperty('visibility', 'hidden', 'important');
        const filled = message.url === location.href && message.kind === menuKind && !!menuTarget &&
          fillControls(menuTarget, menuKind!, message.payload as FillPayload);
        remove(); respond({ filled });
      }
      if (message.type === 'close') { remove(); respond(null); }
    };
    browser.runtime.onMessage.addListener(onMessage);
    ctx.onInvalidated(() => browser.runtime.onMessage.removeListener(onMessage));
    void refreshFlags().then(pending);
  },
});
