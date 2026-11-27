import * as wasm from '../../../../crates/vault-preferences/pkg/vault_preferences.js';
import wasmUrl from '../../../../crates/vault-preferences/pkg/vault_preferences_bg.wasm?url&no-inline';

let initialized: Promise<typeof wasm> | undefined;

async function compilePackCrypto(): Promise<WebAssembly.Module> {
  if (import.meta.env.MODE === 'test') {
    const specifier = 'node:fs/promises';
    const { readFile } = await import(/* @vite-ignore */ specifier) as typeof import('node:fs/promises');
    const bytes = await readFile(new URL('../../../../crates/vault-preferences/pkg/vault_preferences_bg.wasm', import.meta.url));
    return WebAssembly.compile(bytes);
  }
  return WebAssembly.compileStreaming(fetch(wasmUrl));
}

export function loadPackCrypto(): Promise<typeof wasm> {
  initialized ??= compilePackCrypto().then(module => {
    wasm.initSync({ module });
    return wasm;
  }).catch(error => {
    initialized = undefined;
    throw error;
  });
  return initialized;
}
