import { describe, expect, it } from 'vitest';
import { openPackContent, sealPackContent } from './pack-content';

describe('encrypted whole-vault package', () => {
  it('round-trips all encrypted sections and rejects substitution across versions', async () => {
    const material = crypto.getRandomValues(new Uint8Array(32));
    const version = { vaultId: 'vault-fixture', id: 'd'.repeat(32) };
    const content = {
      head: new Uint8Array([12, 35, 99]),
      snap: new Uint8Array([9, 3, 5]),
      conflicts: new Uint8Array([5, 2, 8]),
      rules: new TextEncoder().encode('only-for-pack-fixture.example'),
    };
    const sealed = await sealPackContent(material, version, content);
    expect(new TextDecoder().decode(sealed)).not.toContain('only-for-pack-fixture.example');
    expect(await openPackContent(material, version, sealed)).toEqual(content);
    await expect(openPackContent(material, { ...version, id: 'e'.repeat(32) }, sealed)).rejects.toThrow();
    sealed[sealed.length - 1]! ^= 1;
    await expect(openPackContent(material, version, sealed)).rejects.toThrow();
  });
});
