# Vendored RustCrypto `crypto_secretstream`

Source: crates.io `0.2.0` (`9a6419214057ad50a13efccb3ad7714b86b848e3a5aa7b6cf5a3ff07edf387eb`),
from [RustCrypto/nacl-compat](https://github.com/RustCrypto/nacl-compat/tree/a7a59e39101ed6fe1891c2e26476bcf880a460a7/crypto_secretstream).
Original MIT and Apache-2.0 notices are retained.

Local patch: enable primitive zeroization, wipe the library's owned key and
stream subkey on drop, and wrap per-frame MAC keys and tag keystream in
`Zeroizing`. Borrow the tag block for authentication instead of copying it.
No framing, wire-format, cipher, or authentication rule is changed.

Validate compatibility with `node scripts/test-authenticator-fixtures.cjs --ente`
after building the production WASM.
