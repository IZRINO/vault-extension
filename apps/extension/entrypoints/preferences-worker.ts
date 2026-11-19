import init, { wasm_open_preferences, wasm_seal_preferences, wasm_open_webdav, wasm_seal_webdav,
  wasm_sign_authorization, wasm_verify_authorization } from '../../../crates/vault-preferences/pkg/vault_preferences.js';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: unknown[] }>) => {
    try {
      await init();
      const [key, wrap, payload] = data.args as [Uint8Array, Uint8Array, string | Uint8Array];
      let value: unknown;
      if (data.operation === 'seal-preferences' && typeof payload === 'string') {
        const sealed = wasm_seal_preferences(key, wrap, payload);
        value = Array.from(sealed);
      } else if (data.operation === 'open-preferences' && payload instanceof Uint8Array) {
        value = wasm_open_preferences(key, wrap, payload);
      } else if (data.operation === 'seal-webdav' && typeof payload === 'string') {
        value = Array.from(wasm_seal_webdav(key, wrap, payload));
      } else if (data.operation === 'open-webdav' && payload instanceof Uint8Array) {
        value = wasm_open_webdav(key, wrap, payload);
      } else if (data.operation === 'sign-authorization') {
        value = Array.from(wasm_sign_authorization(...data.args as Parameters<typeof wasm_sign_authorization>));
      } else if (data.operation === 'verify-authorization') {
        value = wasm_verify_authorization(...data.args as Parameters<typeof wasm_verify_authorization>);
      } else throw new Error('无效的网站偏好操作。');
      self.postMessage({ ok: true, value });
    } catch {
      const label = data.operation.endsWith('-authorization') ? '本机授权'
        : data.operation.endsWith('-webdav') ? '网盘设置' : '网站偏好';
      self.postMessage({ ok: false, error: `${label}处理失败，请重新解锁后重试。` });
    } finally {
      for (const arg of data.args) if (arg instanceof Uint8Array) arg.fill(0);
      data.args.length = 0;
      self.close();
    }
  };
});
