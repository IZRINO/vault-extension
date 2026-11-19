import init, { wasm_scan_migration, wasm_scan_otp } from '../../../crates/vault-qr/pkg/vault_qr.js';

function grayscale(bitmap: ImageBitmap, width: number, height: number) {
  const canvas = new OffscreenCanvas(width, height);
  const context = canvas.getContext('2d', { willReadFrequently: true })!;
  context.drawImage(bitmap, 0, 0, width, height);
  const { data } = context.getImageData(0, 0, width, height);
  const bytes = new Uint8Array(width * height);
  for (let i = 0, j = 0; i < bytes.length; i++, j += 4) bytes[i] = (data[j]! * 77 + data[j + 1]! * 150 + data[j + 2]! * 29) >> 8;
  data.fill(0);
  context.clearRect(0, 0, width, height);
  return bytes;
}

export default defineUnlistedScript(() => {
  const ready = init();
  void ready.catch(() => undefined);
  self.onmessage = async ({ data }: MessageEvent<string | { url: string; migration: true }>) => {
    let bitmap: ImageBitmap | undefined;
    try {
      const start = performance.now();
      const migration = typeof data !== 'string';
      const response = await fetch(typeof data === 'string' ? data : data.url);
      if (!response.ok) throw new Error('无法读取图像');
      bitmap = await createImageBitmap(await response.blob());
      const imageMs = performance.now() - start;
      const { width, height } = bitmap;
      if (width > 8192 || height > 8192 || width * height > 16_777_216) throw new Error('截图过大。');
      const scale = Math.min(1, (migration ? 1024 : 384) / Math.max(width, height));
      let grayscaleMs = 0, decodeMs = 0;
      async function scan(w: number, h: number) {
        const beforeGrayscale = performance.now();
        const bytes = grayscale(bitmap!, w, h);
        grayscaleMs += performance.now() - beforeGrayscale;
        try {
          await ready;
          const beforeDecode = performance.now();
          try { return JSON.parse((migration ? wasm_scan_migration : wasm_scan_otp)(bytes, w, h)) as string[]; }
          finally { decodeMs += performance.now() - beforeDecode; }
        } finally { bytes.fill(0); }
      }
      const beforeWasm = performance.now();
      // A small working image is enough for the normal large setup QR.
      let values = await scan(Math.max(1, Math.round(width * scale)), Math.max(1, Math.round(height * scale)));
      const wasmWaitMs = Math.max(0, performance.now() - beforeWasm - grayscaleMs - decodeMs);
      if (!values.length && scale < 1) values = await scan(width, height);
      self.postMessage({ ok: true, value: { values, timings: { imageMs, grayscaleMs, wasmWaitMs, decodeMs } } });
    } catch {
      self.postMessage({ ok: false, error: '无法读取截图中的验证码。请把完整二维码显示在屏幕内，或手动粘贴密钥。' });
    } finally { bitmap?.close(); self.close(); }
  };
});
