use vault_core::crypto::{FileRole, SCHEMA_VERSION, SealedEnvelope, SecretKey};
use vault_core::error::VaultError;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const PACK_LIMIT: usize = 16 * 1024 * 1024;
const RECOVERY_LIMIT: usize = 1024;

fn pack_context(
    material: &[u8], vault: &str, version: &str, setup: bool,
) -> Result<(String, SecretKey, usize), VaultError> {
    if material.len() != 32 || vault.is_empty() || vault.len() > 128 || !vault.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') ||
        version.len() != 32 || !version.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(VaultError::CryptoAuthFailed);
    }
    let purpose = if setup { "setup" } else { "package" };
    let object = format!("vault:whole-sync:{purpose}:v1:{vault}:{version}");
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, material)
        .expand(object.as_bytes(), key.as_mut()).map_err(|_| VaultError::CryptoAuthFailed)?;
    Ok((object, SecretKey::from_slice(key.as_ref())?, if setup { RECOVERY_LIMIT } else { PACK_LIMIT }))
}

#[wasm_bindgen]
pub fn wasm_sync_pack_seal(
    material: Vec<u8>, vault: &str, version: &str, payload: Vec<u8>, setup: bool,
) -> Result<Vec<u8>, JsValue> {
    let (material, payload) = (Zeroizing::new(material), Zeroizing::new(payload));
    let (object, key, limit) = pack_context(&material, vault, version, setup)?;
    if payload.is_empty() || payload.len() > limit { return Err(VaultError::CryptoAuthFailed.into()); }
    let bytes = SealedEnvelope::seal_bucketed(&key, FileRole::Snap, object, 1, &payload)?.to_bytes()?;
    if bytes.len() > limit { return Err(VaultError::CryptoAuthFailed.into()); }
    Ok(bytes)
}

#[wasm_bindgen]
pub fn wasm_sync_pack_open(
    material: Vec<u8>, vault: &str, version: &str, ciphertext: Vec<u8>, setup: bool,
) -> Result<Vec<u8>, JsValue> {
    let material = Zeroizing::new(material);
    let (object, key, limit) = pack_context(&material, vault, version, setup)?;
    if ciphertext.len() > limit { return Err(VaultError::CryptoAuthFailed.into()); }
    let envelope = SealedEnvelope::from_bytes(&ciphertext)?;
    if envelope.schema_version != SCHEMA_VERSION || envelope.hlc_epoch != 1 { return Err(VaultError::CryptoAuthFailed.into()); }
    Ok(envelope.open_bucketed(&key, FileRole::Snap, Some(&object))?.0.clone())
}
