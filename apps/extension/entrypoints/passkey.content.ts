import { browserCredential, normalizeRequest, PASSKEY_CHANNEL, type PasskeyOutcome, type PasskeyRequest } from '../src/passkeys/protocol';

export default defineContentScript({
  matches: ['https://*/*', 'http://localhost/*'],
  runAt: 'document_start',
  world: 'MAIN',
  main() {
    if (window !== window.top || !window.isSecureContext || !navigator.credentials || !window.PublicKeyCredential) return;
    const credentials = navigator.credentials;
    const post = window.postMessage.bind(window);
    const listen = window.addEventListener.bind(window);
    const unlisten = window.removeEventListener.bind(window);
    const origin = location.origin;
    const abortError = () => new DOMException('The operation was cancelled or timed out.', 'NotAllowedError');

    function negotiate(request: PasskeyRequest | 'capability', signal?: AbortSignal): Promise<PasskeyOutcome | { type: 'capability'; available: boolean }> {
      const id = crypto.randomUUID();
      return new Promise((resolve, reject) => {
        const finish = (outcome?: PasskeyOutcome | { type: 'capability'; available: boolean }, error?: unknown) => {
          clearTimeout(handshake);
          clearTimeout(deadline);
          unlisten('message', receive);
          unlisten('pagehide', abort);
          signal?.removeEventListener('abort', abort);
          if (outcome) resolve(outcome);
          else {
            post({ channel: PASSKEY_CHANNEL, direction: 'abort', id }, origin);
            reject(error ?? abortError());
          }
        };
        const abort = () => finish(undefined, signal?.reason);
        const receive = (event: MessageEvent) => {
          const data = event.data;
          if (event.source !== window || event.origin !== origin || data?.channel !== PASSKEY_CHANNEL ||
              data.direction !== 'receive' || data.id !== id) return;
          if (data.type === 'received') clearTimeout(handshake);
          else if (['cancel', 'native', 'answer', 'capability'].includes(data.type)) finish(data);
        };
        const handshake = setTimeout(() => {
          post({ channel: PASSKEY_CHANNEL, direction: 'abort', id }, origin);
          finish({ type: 'native' });
        }, 1300);
        const deadline = setTimeout(abort, request === 'capability' ? 3200 : request.conditional ? 125_000 : 65_000);
        if (signal?.aborted) { abort(); return; }
        signal?.addEventListener('abort', abort, { once: true });
        listen('message', receive);
        listen('pagehide', abort, { once: true });
        post({ channel: PASSKEY_CHANNEL, direction: 'begin', id, request }, origin);
      });
    }

    function wrap<K extends 'create' | 'get'>(method: K) {
      const original = credentials[method];
      return async function (this: CredentialsContainer, options?: Parameters<CredentialsContainer[K]>[0]) {
        const native = () => Reflect.apply(original, this, arguments) as Promise<Credential | null>;
        let request: PasskeyRequest | undefined;
        try {
          if (this === credentials && !options?.signal?.aborted) {
            request = normalizeRequest(method === 'create' ? 'register' : 'assert', options);
            if (request && !request.conditional && !navigator.userActivation.isActive) request = undefined;
          }
        } catch { request = undefined; }
        if (!request) return native();
        const result = await negotiate(request, options?.signal);
        if (options?.signal?.aborted) throw options.signal.reason;
        if (result.type === 'native') return native();
        if (result.type === 'answer') return browserCredential(result.value, request);
        throw abortError();
      };
    }

    Object.defineProperties(credentials, {
      create: { configurable: true, writable: true, value: wrap('create') },
      get: { configurable: true, writable: true, value: wrap('get') },
    });
    const native = PublicKeyCredential.isConditionalMediationAvailable;
    Object.defineProperty(PublicKeyCredential, 'isConditionalMediationAvailable', {
      configurable: true, writable: true, value: async () => {
        try {
          const response = await negotiate('capability');
          if (response.type === 'capability' && response.available) return true;
        } catch { /* ask the actual browser */ }
        return native ? Reflect.apply(native, PublicKeyCredential, []) : false;
      },
    });
  },
});
