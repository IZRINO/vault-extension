import init, { wasm_scan_otp } from '../../../crates/vault-qr/pkg/vault_qr.js';

export default defineUnlistedScript(() => {
  const ready = init();
  void ready.catch(() => undefined);
  self.onmessage = async ({ data }: MessageEvent<{ bytes: Uint8Array; width: number; height: number }>) => {
    try {
      await ready;
      self.postMessage({ ok: true, value: JSON.parse(wasm_scan_otp(data.bytes, data.width, data.height)) });
    } catch {
      self.postMessage({ ok: false, error: '无法读取截图中的验证码。请把完整二维码显示在屏幕内，或手动粘贴密钥。' });
    } finally { data.bytes.fill(0); self.close(); }
  };
});
