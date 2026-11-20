const fs = require('node:fs');
const assert = require('node:assert/strict');
for (const name of ['vault-core', 'vault-importers', 'vault-ente-auth', 'vault-otp', 'vault-qr', 'vault-preferences', 'vault-sync', 'vault-passkeys']) {
  const file = 'crates/' + name + '/pkg/' + name.replaceAll('-', '_') + '_bg.wasm';
  const bytes = fs.readFileSync(file);
  assert(WebAssembly.validate(bytes), file + ' cannot load in the current JS runtime');
  if (name === 'vault-core') assert(bytes.length <= 250 * 1024, 'vault-core exceeds the 250 KiB budget: ' + bytes.length);
  console.log(name + ': valid WASM, ' + bytes.length + ' bytes');
}
