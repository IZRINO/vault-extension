import initWasm, * as core from '../../../crates/vault-core/pkg/vault_core.js';

let initialized: Promise<typeof core> | undefined;

export async function loadVaultCore(): Promise<typeof core> {
  initialized ??= initWasm().then(() => core);
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
