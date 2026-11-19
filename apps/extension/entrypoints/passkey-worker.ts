import init, { wasm_passkey_candidates, wasm_passkey_perform } from '../../../crates/vault-passkeys/pkg/vault_passkeys.js';

export default defineUnlistedScript(() => {
  self.onmessage = async ({ data }: MessageEvent<{ operation: string; args: unknown[] }>) => {
    try {
      await init();
      let value: unknown;
      if (data.operation === 'passkey:candidates') {
        value = wasm_passkey_candidates(...data.args as Parameters<typeof wasm_passkey_candidates>);
      } else if (data.operation === 'passkey:perform') {
        const result = wasm_passkey_perform(...data.args as Parameters<typeof wasm_passkey_perform>);
        try { value = { reply: result.reply, head: Array.from(result.head), snap: Array.from(result.snap) }; }
        finally { result.free(); }
      } else throw new Error('Unknown passkey operation');
      self.postMessage({ ok: true, value });
    } catch (error) {
      const text = typeof error === 'string' ? error : '';
      self.postMessage({ ok: false, error: text.startsWith('Passkey counter is unverified')
        ? '无法确认这枚通行密钥的计数。请同步较新的副本，或在网站重新登记。'
        : text.includes('already registered') ? '此站点已登记这枚通行密钥。' : '无法完成通行密钥请求，请确认网站和所选条目。' });
    } finally {
      for (const arg of data.args) if (arg instanceof Uint8Array) arg.fill(0);
      data.args.length = 0;
      self.close();
    }
  };
});
