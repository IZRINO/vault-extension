use vault_core::crypto::{FileRole, SCHEMA_VERSION, SealedEnvelope, SecretKey};
use vault_core::error::VaultError;
use vault_core::session::SessionWrappedDekBlob;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const LIMIT: usize = 256 * 1024;

fn context(session_key: &[u8], session_wrap: &[u8]) -> Result<(String, SecretKey), VaultError> {
    let (vault, _, dek) = SessionWrappedDekBlob::unwrap(session_wrap, &SecretKey::from_slice(session_key)?)?;
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, dek.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"vault:local-autofill-preferences:aead:v1", &mut *key)
        .map_err(|_| VaultError::CryptoAuthFailed)?;
    Ok((format!("{vault}:local-autofill-preferences:v1"), SecretKey::from_slice(&*key)?))
}
fn seal(session_key: &[u8], session_wrap: &[u8], plain: &str) -> Result<Vec<u8>, VaultError> {
    if plain.len() > LIMIT { return Err(VaultError::InvalidInput("website preferences exceed 256 KiB".into())); }
    let (object, key) = context(session_key, session_wrap)?;
    // The dedicated key and object domain separate this local envelope from every vault file.
    SealedEnvelope::seal_bucketed(&key, FileRole::Head, object, 0, plain.as_bytes())?.to_bytes()
}
fn open(session_key: &[u8], session_wrap: &[u8], sealed: &[u8]) -> Result<String, VaultError> {
    if sealed.len() > LIMIT + 1024 { return Err(VaultError::CryptoAuthFailed); }
    let (object, key) = context(session_key, session_wrap)?;
    let envelope = SealedEnvelope::from_bytes(sealed)?;
    if envelope.schema_version != SCHEMA_VERSION || envelope.hlc_epoch != 0 { return Err(VaultError::CryptoAuthFailed); }
    let plain = envelope.open_bucketed(&key, FileRole::Head, Some(&object))?;
    String::from_utf8(plain.0.clone()).map_err(|_| VaultError::CryptoAuthFailed)
}

#[wasm_bindgen]
pub fn wasm_seal_preferences(session_key: Vec<u8>, session_wrap: Vec<u8>, plain: String) -> Result<Vec<u8>, JsValue> {
    let (key, wrap, plain) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap), Zeroizing::new(plain));
    seal(&key, &wrap, &plain).map_err(Into::into)
}
#[wasm_bindgen]
pub fn wasm_open_preferences(session_key: Vec<u8>, session_wrap: Vec<u8>, sealed: Vec<u8>) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap));
    open(&key, &wrap, &sealed).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_preferences_hide_domains_and_survive_session_and_password_rotation() {
        let dek = SecretKey::random().unwrap();
        let first = SecretKey::random().unwrap();
        let wrap = SessionWrappedDekBlob::wrap("vault-a", 1, &dek, &first).unwrap();
        let plain = r#"{"sites":{"https://private.example":{"saveDisabled":true}}}"#;
        let sealed = seal(first.as_bytes(), &wrap, plain).unwrap();
        assert!(!sealed.windows(b"private.example".len()).any(|w| w == b"private.example"));
        assert_eq!(SealedEnvelope::from_bytes(&sealed).unwrap().ciphertext.len() % 256, 0);
        let next = SecretKey::random().unwrap();
        let rotated = SessionWrappedDekBlob::wrap("vault-a", 2, &dek, &next).unwrap();
        assert_eq!(open(next.as_bytes(), &rotated, &sealed).unwrap(), plain);
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(next.as_bytes(), &rotated, &tampered).is_err());
        let foreign = SessionWrappedDekBlob::wrap("vault-b", 2, &dek, &next).unwrap();
        assert!(open(next.as_bytes(), &foreign, &sealed).is_err());
        assert!(open(first.as_bytes(), &rotated, &sealed).is_err());
    }
}
