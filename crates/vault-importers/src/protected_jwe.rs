use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use aes_kw::KekAes256;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use vault_core::crypto::csprng_fill;
use zeroize::Zeroizing;

const ALG: &str = "PBES2-HS512+A256KW";
const ENC: &str = "A256GCM";
const ITERATIONS: u32 = 210_000;
const INVALID: &str = "不支持或已损坏的 CXF JWE 文件。";
const AUTH: &str = "文件密码错误或 CXF JWE 认证失败。";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header { alg: String, enc: String, p2s: String, p2c: u32, #[serde(default)] cty: Option<String> }

fn derive(salt: &[u8], iterations: u32, password: &str) -> Zeroizing<[u8; 32]> {
    let salt = [ALG.as_bytes(), &[0], salt].concat();
    let mut key = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt, iterations, key.as_mut());
    key
}

pub(crate) fn seal(plain: &[u8], password: &str) -> Result<String, &'static str> {
    if !(12..=1024).contains(&password.len()) { return Err("文件密码需要 12 至 1024 字节。"); }
    let mut entropy = Zeroizing::new([0; 60]);
    csprng_fill(entropy.as_mut()).map_err(|_| INVALID)?;
    let header = Header { alg: ALG.into(), enc: ENC.into(), p2s: B64.encode(&entropy[..16]), p2c: ITERATIONS, cty: Some("application/json".into()) };
    let header = B64.encode(serde_json::to_vec(&header).map_err(|_| INVALID)?);
    let key = derive(&entropy[..16], ITERATIONS, password);
    let mut wrapped = [0; 40];
    KekAes256::try_from(key.as_slice()).map_err(|_| INVALID)?.wrap(&entropy[16..48], &mut wrapped).map_err(|_| INVALID)?;
    let mut ciphertext = Zeroizing::new(plain.to_vec());
    let nonce = &entropy[48..];
    let tag = Aes256Gcm::new_from_slice(&entropy[16..48]).map_err(|_| INVALID)?
        .encrypt_in_place_detached(Nonce::from_slice(nonce), header.as_bytes(), &mut ciphertext).map_err(|_| INVALID)?;
    Ok([header, B64.encode(wrapped), B64.encode(nonce), B64.encode(&*ciphertext), B64.encode(tag)].join("."))
}

pub(crate) fn open(input: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if password.is_empty() { return Err("请输入 CXF JWE 文件密码。"); }
    if password.len() > 4096 { return Err(INVALID); }
    let text = std::str::from_utf8(input).map_err(|_| INVALID)?.trim();
    let fields = text.split('.').collect::<Vec<_>>();
    let [header, wrapped, nonce, ciphertext, tag] = fields.as_slice() else { return Err(INVALID); };
    if header.len() > 512 || wrapped.len() != 54 || nonce.len() != 16 || tag.len() != 22 { return Err(INVALID); }
    let config: Header = serde_json::from_slice(&B64.decode(header).map_err(|_| INVALID)?).map_err(|_| INVALID)?;
    if config.alg != ALG || config.enc != ENC || !(10_000..=1_000_000).contains(&config.p2c) { return Err(INVALID); }
    let salt = B64.decode(config.p2s).map_err(|_| INVALID)?;
    if !(8..=64).contains(&salt.len()) { return Err(INVALID); }
    let key = derive(&salt, config.p2c, password);
    let mut cek = Zeroizing::new([0; 32]);
    KekAes256::try_from(key.as_slice()).map_err(|_| INVALID)?.unwrap(&B64.decode(wrapped).map_err(|_| INVALID)?, cek.as_mut()).map_err(|_| AUTH)?;
    let (nonce, tag) = (B64.decode(nonce).map_err(|_| INVALID)?, B64.decode(tag).map_err(|_| INVALID)?);
    if nonce.len() != 12 || tag.len() != 16 { return Err(INVALID); }
    let mut raw = Zeroizing::new(B64.decode(ciphertext).map_err(|_| INVALID)?);
    Aes256Gcm::new_from_slice(cek.as_slice()).map_err(|_| INVALID)?
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), header.as_bytes(), &mut raw, Tag::from_slice(&tag)).map_err(|_| AUTH)?;
    Ok(raw)
}
