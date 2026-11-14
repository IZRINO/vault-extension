import init, { wasm_parse_browser_csv } from '../../../crates/vault-importers/pkg/vault_importers.js';
import { prepareBrowserCsv } from '../src/browser-csv';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ args: [Uint8Array] }>) => {
    const [bytes] = data.args;
    try {
      await init();
      self.postMessage({ ok: true, value: prepareBrowserCsv(wasm_parse_browser_csv(bytes)) });
    } catch (error) {
      const message = typeof error === 'string' && error.startsWith('CSV: ') ? error.slice(5) : '无法读取 CSV，请重试。';
      self.postMessage({ ok: false, error: message });
    } finally {
      bytes.fill(0);
      self.close();
    }
  };
});
