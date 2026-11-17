import init, { wasm_open_preferences, wasm_seal_preferences } from '../../../crates/vault-preferences/pkg/vault_preferences.js';

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
      } else throw new Error('无效的网站偏好操作。');
      self.postMessage({ ok: true, value });
    } catch {
      self.postMessage({ ok: false, error: '网站偏好无法解密或保存，请重新解锁后重试。' });
    } finally {
      for (const arg of data.args) if (arg instanceof Uint8Array) arg.fill(0);
      data.args.length = 0;
      self.close();
    }
  };
});
