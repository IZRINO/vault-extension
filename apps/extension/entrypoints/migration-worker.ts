import init, { wasm_csv_headers, wasm_export_bitwarden, wasm_export_login_csv, wasm_parse_bitwarden, wasm_parse_mapped_csv } from '../../../crates/vault-importers/pkg/vault_importers.js';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: unknown[] }>) => {
    try {
      await init();
      const [first, second, third] = data.args;
      let value: string;
      switch (data.operation) {
        case 'csv-headers': value = wasm_csv_headers(first as Uint8Array); break;
        case 'parse-mapped-csv': value = wasm_parse_mapped_csv(first as Uint8Array, second as string); break;
        case 'parse-bitwarden': value = wasm_parse_bitwarden(first as Uint8Array, second as string); break;
        case 'export-bitwarden': value = wasm_export_bitwarden(first as string, second as string, third as Uint8Array); break;
        case 'export-login-csv': value = wasm_export_login_csv(first as string); break;
        default: throw new Error('不支持的迁移格式。');
      }
      self.postMessage({ ok: true, value });
    } catch (error) {
      self.postMessage({ ok: false, error: typeof error === 'string' ? error : '无法读取迁移文件，请检查文件格式和密码。' });
    } finally {
      for (const arg of data.args) if (arg instanceof Uint8Array) arg.fill(0);
      data.args = []; self.close();
    }
  };
});
