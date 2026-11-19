import {
  initSync, WasmVaultEngine, wasm_create_prf_wrap, wasm_evaluate_password_strength,
  wasm_generate_passphrase, wasm_generate_password, wasm_hibp_match_range, wasm_hibp_prefix,
  wasm_unlock_with_prf_wrap,
} from '../../../crates/vault-core/pkg/vault_core.js';
import coreUrl from '../../../crates/vault-core/pkg/vault_core_bg.wasm?url&no-inline';

const core = { WasmVaultEngine, wasm_create_prf_wrap, wasm_evaluate_password_strength,
  wasm_generate_passphrase, wasm_generate_password, wasm_hibp_match_range, wasm_hibp_prefix, wasm_unlock_with_prf_wrap };
let initialized: Promise<typeof core> | undefined;

export function loadVaultCore(): Promise<typeof core> {
  initialized ??= WebAssembly.compileStreaming(fetch(coreUrl)).then(module => {
    initSync({ module });
    performance.mark('vault:wasm-loaded');
    return core;
  }).catch(error => {
    initialized = undefined;
    throw error;
  });
  return initialized;
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function nowMs(): number {
  return Date.now();
}
