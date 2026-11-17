import init, { wasm_export_ente_auth, wasm_parse_ente_auth } from '../../../crates/vault-importers/pkg/vault_importers.js';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: [Uint8Array | string, string] }>) => {
    try {
      await init();
      const value = data.operation === 'parse-ente'
        ? wasm_parse_ente_auth(data.args[0] as Uint8Array, data.args[1])
        : wasm_export_ente_auth(data.args[0] as string);
      self.postMessage({ ok: true, value });
    } catch (error) {
      self.postMessage({ ok: false, error: typeof error === 'string' ? error : '无法处理验证器文件，请重试。' });
    } finally {
      if (data.args[0] instanceof Uint8Array) data.args[0].fill(0);
      data.args = ['', ''];
      self.close();
    }
  };
});
