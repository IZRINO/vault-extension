import init, { wasm_csv_headers, wasm_export_login_csv, wasm_parse_mapped_csv, wasm_parse_authenticator_backup, wasm_portable_import, wasm_portable_export } from '../../../crates/vault-importers/pkg/vault_importers.js';
import { VENDOR_JSON_FORMATS, type Reply } from '../src/vault-messages';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: unknown[] }>) => {
    let memory: WebAssembly.Memory | undefined;
    let reply: Reply;
    try {
      memory = (await init()).memory;
      const [first, second, third] = data.args;
      let value: unknown;
      switch (data.operation) {
        case 'csv-headers': value = wasm_csv_headers(first as Uint8Array); break;
        case 'parse-mapped-csv': value = wasm_parse_mapped_csv(first as Uint8Array, second as string); break;
        case 'parse-authenticator-backup': value = wasm_parse_authenticator_backup(first as string, second as Uint8Array, third as string); break;
        case 'portable-import': {
          const result = wasm_portable_import(...data.args as Parameters<typeof wasm_portable_import>);
          try { value = { report: result.report, head: Array.from(result.head), snap: Array.from(result.snap), count: result.count }; }
          finally { result.free(); }
          break;
        }
        case 'portable-export':
          value = wasm_portable_export(...data.args as Parameters<typeof wasm_portable_export>);
          break;
        case 'export-login-csv': value = wasm_export_login_csv(first as string); break;
        default: throw new Error('不支持的迁移格式。');
      }
      reply = { ok: true, value };
    } catch (error) {
      reply = { ok: false, error: typeof error === 'string' ? error : '无法读取迁移文件，请检查文件格式和密码。' };
    } finally {
      // Clear parser scratch buffers (including freed pages) before replying to the parent.
      const format = data.args[0];
      if (memory && ((data.operation === 'portable-import'
        && (format === 'bitwarden' || format === 'proton' || format === 'dashlane-zip' || (VENDOR_JSON_FORMATS as readonly unknown[]).includes(format)))
        || (data.operation === 'portable-export' && format === 'bitwarden')
        || (data.operation === 'parse-authenticator-backup' && (format === 'stratum' || format === 'andotp')))) {
        new Uint8Array(memory.buffer).fill(0);
      }
      for (const arg of data.args) if (arg instanceof Uint8Array) arg.fill(0);
      data.args = [];
    }
    self.postMessage(reply);
    self.close();
  };
});
