import { loadVaultOtp } from '../src/vault-otp';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ args: [string] }>) => {
    try {
      (await loadVaultOtp()).wasm_validate_totp(data.args[0]);
      self.postMessage({ ok: true, value: null });
    } catch (error) {
      self.postMessage({ ok: false, error: typeof error === 'string' ? error : '无法检查验证码，请重试。' });
    } finally {
      data.args[0] = '';
      self.close();
    }
  };
});
