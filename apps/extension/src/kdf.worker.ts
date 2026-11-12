import { loadVaultCore } from './vault-core';

self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: unknown[] }>) => {
  try {
    const core = await loadVaultCore();
    const fn = core[data.operation as keyof typeof core];
    if (typeof fn !== 'function' || !data.operation.startsWith('wasm_')) throw new Error('无效的密钥操作');
    const result = (fn as (...args: unknown[]) => unknown)(...data.args);
    let value: unknown = result;
    if (result instanceof core.WasmInitVaultOutput) {
      value = { head: Array.from(result.head_bytes), snap: Array.from(result.snap_bytes), recoveryCode: result.recovery_code,
        wrap: Array.from(result.session_wrap_bytes), vaultId: result.vault_id, keyEpoch: Number(result.key_epoch) };
      result.free();
    } else if (result instanceof core.WasmHeadRotationOutput) {
      value = { head: Array.from(result.head_bytes), wrap: Array.from(result.session_wrap_bytes), keyEpoch: Number(result.key_epoch) };
      result.free();
    } else if (result instanceof core.WasmImportVaultpackOutput) {
      value = { head: Array.from(result.head_bytes), snap: Array.from(result.snap_bytes), count: result.imported_count };
      result.free();
    } else if (result instanceof Uint8Array) value = Array.from(result);
    self.postMessage({ ok: true, value });
  } catch {
    self.postMessage({ ok: false, error: '验证失败或数据损坏，请检查输入。' });
  } finally {
    for (const arg of data.args) if (arg instanceof Uint8Array) arg.fill(0);
    data.args.length = 0;
    self.close();
  }
};
