import init, { wasm_export_ente_auth, wasm_parse_ente_auth } from '../../../crates/vault-ente-auth/pkg/vault_ente_auth.js';

type EnteJob = { operation: 'parse-ente'; args: [Uint8Array, string, string?] }
  | { operation: 'export-ente'; args: [string] };

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<EnteJob>) => {
    try {
      await init();
      let value: string;
      if (data.operation === 'parse-ente') value = wasm_parse_ente_auth(...data.args);
      else if (data.operation === 'export-ente') value = wasm_export_ente_auth(...data.args);
      else throw new Error('Invalid Ente Auth operation');
      self.postMessage({ ok: true, value });
    } catch (error) {
      self.postMessage({ ok: false, error: typeof error === 'string' ? error : '无法处理验证器文件，请重试。' });
    } finally {
      if (data.args[0] instanceof Uint8Array) data.args[0].fill(0);
      data.args.fill('');
      self.close();
    }
  };
});
