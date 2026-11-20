import init, { wasm_audit_snapshot } from '../../../crates/vault-audit/pkg/vault_audit.js';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: Parameters<typeof wasm_audit_snapshot> }>) => {
    let reply;
    try {
      if (data.operation !== 'audit-snapshot') throw new Error();
      await init();
      reply = { ok: true, value: wasm_audit_snapshot(...data.args) };
    } catch {
      reply = { ok: false, error: '无法完成本地体检，请重新解锁后重试。' };
    } finally {
      for (const arg of data.args) arg.fill(0);
    }
    self.postMessage(reply);
    self.close();
  };
});
