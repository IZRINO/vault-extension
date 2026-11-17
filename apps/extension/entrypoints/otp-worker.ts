import { loadVaultOtp } from '../src/vault-otp';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: [string, number?] }>) => {
    try {
      const otp = await loadVaultOtp();
      const value = data.operation === 'generate-hotp' || data.operation === 'generate-otp' ? otp.wasm_otp_at(data.args[0], data.args[1] ?? 0, 0)
        : otp.wasm_validate_totp(data.args[0]);
      self.postMessage({ ok: true, value: value ?? null });
    } catch (error) {
      self.postMessage({ ok: false, error: typeof error === 'string' ? error : '无法检查验证码，请重试。' });
    } finally {
      data.args[0] = '';
      self.close();
    }
  };
});
