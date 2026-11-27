import { loadPackCrypto } from './pack-crypto';

export const PACK_CONTENT_LIMIT = 16 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const headerBytes = 4 * 5;

export interface PackContent {
  head: Uint8Array;
  snap: Uint8Array;
  conflicts: Uint8Array;
  rules: Uint8Array;
}

interface PackIdentity { vaultId: string; id: string }
const invalid = () => new Error('无法验证加密整包，或整包格式不受支持。本机编辑仍保留。');

function identity({ vaultId, id }: PackIdentity) {
  if (!/^[0-9a-f]{32}$/.test(id) || !vaultId || vaultId.length > 128) throw invalid();
  return encoder.encode(JSON.stringify([vaultId, id]));
}

/** Only the interrupted local setup can read this code. Never include it in a package. */
export async function sealSetupRecovery(material: Uint8Array<ArrayBuffer>, version: PackIdentity, recoveryCode: string) {
  const plain = encoder.encode(recoveryCode);
  try {
    const wasm = await loadPackCrypto();
    return new Uint8Array(wasm.wasm_sync_pack_seal(material, version.vaultId, version.id, plain, true));
  } catch { throw invalid(); }
  finally { plain.fill(0); }
}

export async function openSetupRecovery(material: Uint8Array<ArrayBuffer>, version: PackIdentity, recovery: Uint8Array<ArrayBuffer>) {
  let plain: Uint8Array | undefined;
  try {
    const wasm = await loadPackCrypto();
    plain = wasm.wasm_sync_pack_open(material, version.vaultId, version.id, recovery, true);
    return decoder.decode(plain);
  } catch { throw invalid(); }
  finally { plain?.fill(0); }
}

export async function sealPackContent(material: Uint8Array<ArrayBuffer>, version: PackIdentity, content: PackContent) {
  const binding = identity(version);
  const sections = [binding, content.head, content.snap, content.conflicts, content.rules];
  const length = headerBytes + sections.reduce((sum, section) => sum + section.length, 0);
  if (!content.head.length || !content.snap.length || !content.rules.length || length > PACK_CONTENT_LIMIT) throw invalid();
  const plain = new Uint8Array(length);
  const lengths = new DataView(plain.buffer);
  let offset = headerBytes;
  for (const [index, section] of sections.entries()) {
    lengths.setUint32(index * 4, section.length);
    plain.set(section, offset);
    offset += section.length;
  }
  try {
    const wasm = await loadPackCrypto();
    return new Uint8Array(wasm.wasm_sync_pack_seal(material, version.vaultId, version.id, plain, false));
  } catch { throw invalid(); }
  finally { plain.fill(0); }
}

export async function openPackContent(material: Uint8Array<ArrayBuffer>, version: PackIdentity, cipher: Uint8Array<ArrayBuffer>): Promise<PackContent> {
  const binding = identity(version);
  let plain: Uint8Array | undefined;
  try {
    if (cipher.length > PACK_CONTENT_LIMIT) throw invalid();
    const wasm = await loadPackCrypto();
    plain = wasm.wasm_sync_pack_open(material, version.vaultId, version.id, cipher, false);
    const lengths = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
    const sections: Uint8Array[] = [];
    let offset = headerBytes;
    for (let index = 0; index < 5; index++) {
      const length = lengths.getUint32(index * 4);
      if (offset + length > plain.length || (index !== 3 && !length)) throw invalid();
      sections.push(plain.slice(offset, offset + length));
      offset += length;
    }
    if (decoder.decode(sections[0]) !== decoder.decode(binding) || offset !== plain.length) throw invalid();
    const [, head, snap, conflicts, rules] = sections;
    return { head: head!, snap: snap!, conflicts: conflicts!, rules: rules! };
  } catch { throw invalid(); }
  finally { plain?.fill(0); }
}
