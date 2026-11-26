import { PASSKEY_CHANNEL, PASSKEY_PORT } from '../src/passkeys/protocol';

export default defineContentScript({
  matches: ['https://*/*', 'http://localhost/*'],
  runAt: 'document_start',
  main() {
    if (window !== window.top || !window.isSecureContext) return;
    type Port = ReturnType<typeof browser.runtime.connect>;
    type Operation = { request: unknown; port?: Port; ticket?: string; conditional?: boolean; input?: HTMLInputElement; menu?: HTMLElement };
    const pending = new Map<string, Operation>();
    const send = (id: string, message: object) => window.postMessage({ ...message, channel: PASSKEY_CHANNEL, direction: 'receive', id }, location.origin);
    const disconnect = (operation: Operation) => {
      const port = operation.port;
      operation.port = undefined;
      try { port?.disconnect(); } catch { /* already disconnected */ }
    };
    const close = (id: string) => {
      const operation = pending.get(id);
      if (!operation) return;
      pending.delete(id);
      operation.menu?.remove();
      disconnect(operation);
      if (operation.ticket) {
        try {
          const port = browser.runtime.connect({ name: PASSKEY_PORT });
          const timer = setTimeout(() => port.disconnect(), 1300);
          port.onDisconnect.addListener(() => clearTimeout(timer));
          port.onMessage.addListener(() => { clearTimeout(timer); port.disconnect(); });
          port.postMessage({ type: 'discard', ticket: operation.ticket });
        } catch { /* the extension is unavailable */ }
      }
    };
    const invalidate = () => { for (const id of pending.keys()) { send(id, { type: 'cancel' }); close(id); } };
    window.addEventListener('pagehide', invalidate);
    browser.runtime.onMessage.addListener((message, sender) => {
      if (message?.target !== 'vault-passkey-bridge' || sender.id !== browser.runtime.id || sender.tab ||
          (sender.url && sender.url !== browser.runtime.getURL('/background.js')) ||
          !['cancel', 'native'].includes(message.type)) return;
      for (const [id, operation] of pending) if (operation.ticket && operation.ticket === message.ticket) {
        // The trusted background has already released this reservation.
        operation.ticket = undefined;
        send(id, { type: message.type });
        close(id);
      }
    });
    window.addEventListener('message', event => {
      const data = event.data;
      if (event.source !== window || event.origin !== location.origin || data?.channel !== PASSKEY_CHANNEL ||
          typeof data.id !== 'string' || !/^[a-f0-9-]{36}$/.test(data.id)) return;
      const id: string = data.id;
      if (data.direction === 'abort') { close(id); return; }
      if (data.direction !== 'begin' || pending.has(id) || pending.size >= 3) return;
      const request = data.request;
      if (request !== 'capability' && request?.conditional !== true && !navigator.userActivation.isActive) { send(id, { type: 'native' }); return; }
      const operation: Operation = { request, ticket: request?.conditional === true ? crypto.randomUUID() : undefined };
      pending.set(id, operation);
      connect(id, operation, 'begin');
    });
    function connect(id: string, operation: Operation, type: 'begin' | 'show') {
      try {
        const port = browser.runtime.connect({ name: PASSKEY_PORT });
        operation.port = port;
        if (type === 'begin') send(id, { type: 'received' });
        const current = () => pending.get(id) === operation && operation.port === port;
        port.onDisconnect.addListener(() => {
          if (current()) { send(id, { type: 'cancel' }); close(id); }
        });
        port.onMessage.addListener(message => {
          if (!current()) return;
          if (message.type === 'conditional') {
            operation.conditional = true;
            disconnect(operation);
            send(id, { type: 'waiting' });
          } else if (message.type === 'inline') {
            operation.ticket = undefined;
            showMenu(id, operation, message.ticket);
          } else if (['answer', 'already-registered', 'native', 'cancel', 'capability'].includes(message.type)) {
            send(id, message);
            close(id);
          }
        });
        port.postMessage({ type, request: operation.request, ticket: operation.ticket });
      } catch {
        send(id, { type: type === 'begin' ? 'native' : 'cancel' });
        close(id);
      }
    }
    function showMenu(id: string, operation: Operation, ticket: string) {
      const input = operation.input;
      if (!input?.isConnected) { send(id, { type: 'cancel' }); close(id); return; }
      const box = input.getBoundingClientRect();
      const width = Math.min(352, innerWidth - 16);
      const height = Math.min(282, innerHeight - 16);
      const top = box.bottom + height + 8 <= innerHeight ? box.bottom + 4 : Math.max(8, box.top - height - 4);
      const left = Math.max(8, Math.min(box.left, innerWidth - width - 8));
      const menu = document.createElement('div');
      menu.style.cssText = `all:initial;position:fixed;top:${top}px;left:${left}px;z-index:2147483647;width:${width}px;height:${height}px;display:block;`;
      const shadow = menu.attachShadow({ mode: 'closed' });
      const frame = document.createElement('iframe');
      frame.title = 'Vault 通行密钥';
      frame.src = `${browser.runtime.getURL('/passkey-prompt.html')}#${ticket}.inline`;
      frame.style.cssText = 'border:0;width:100%;height:100%;display:block;margin:0;';
      shadow.append(frame);
      operation.menu = menu;
      document.documentElement.append(menu);
    }
    function open(event: Event) {
      if (!event.isTrusted || document.visibilityState !== 'visible') return;
      const target = event.composedPath()[0];
      const input = target instanceof HTMLInputElement && !target.disabled && !target.readOnly &&
        target.autocomplete.toLowerCase().trim().split(/\s+/).at(-1) === 'webauthn' ? target : undefined;
      for (const [id, operation] of pending) {
        if (operation.menu && !event.composedPath().includes(operation.menu) && operation.input !== input) {
          send(id, { type: 'cancel' }); close(id);
        } else if (input && operation.conditional && !operation.input) {
          operation.input = input;
          send(id, { type: 'interaction' });
          connect(id, operation, 'show');
        }
      }
    }
    document.addEventListener('click', open, true);
    document.addEventListener('focusin', open, true);
    document.addEventListener('keydown', event => {
      if (event.isTrusted && event.key === 'Escape' && [...pending.values()].some(value => value.menu)) invalidate();
    }, true);
  },
});
