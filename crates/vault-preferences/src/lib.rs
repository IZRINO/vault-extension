use hmac::{Hmac, Mac};
use vault_core::crypto::{FileRole, SCHEMA_VERSION, SealedEnvelope, SecretKey};
use vault_core::error::VaultError;
use vault_core::session::SessionWrappedDekBlob;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum Domain { Autofill, WebDav }
impl Domain {
    fn name(self) -> &'static str {
        match self {
            Self::Autofill => "local-autofill-preferences",
            Self::WebDav => "local-webdav-credentials",
        }
    }
    fn limit(self) -> usize {
        match self { Self::Autofill => 256 * 1024, Self::WebDav => 8192 }
    }
}

fn context(session_key: &[u8], session_wrap: &[u8], domain: Domain) -> Result<(String, SecretKey), VaultError> {
    let (vault, _, dek) = SessionWrappedDekBlob::unwrap(session_wrap, &SecretKey::from_slice(session_key)?)?;
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, dek.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(format!("vault:{}:aead:v1", domain.name()).as_bytes(), &mut *key)
        .map_err(|_| VaultError::CryptoAuthFailed)?;
    Ok((format!("{vault}:{}:v1", domain.name()), SecretKey::from_slice(&*key)?))
}
fn seal(session_key: &[u8], session_wrap: &[u8], plain: &str, domain: Domain) -> Result<Vec<u8>, VaultError> {
    if plain.len() > domain.limit() { return Err(VaultError::InvalidInput("local settings exceed byte limit".into())); }
    let (object, key) = context(session_key, session_wrap, domain)?;
    // The dedicated key and object domain separate this local envelope from every vault file.
    SealedEnvelope::seal_bucketed(&key, FileRole::Head, object, 0, plain.as_bytes())?.to_bytes()
}
fn open(session_key: &[u8], session_wrap: &[u8], sealed: &[u8], domain: Domain) -> Result<String, VaultError> {
    if sealed.len() > domain.limit() + 1024 { return Err(VaultError::CryptoAuthFailed); }
    let (object, key) = context(session_key, session_wrap, domain)?;
    let envelope = SealedEnvelope::from_bytes(sealed)?;
    if envelope.schema_version != SCHEMA_VERSION || envelope.hlc_epoch != 0 { return Err(VaultError::CryptoAuthFailed); }
    let plain = envelope.open_bucketed(&key, FileRole::Head, Some(&object))?;
    String::from_utf8(plain.0.clone()).map_err(|_| VaultError::CryptoAuthFailed)
}

fn authorization(key: &[u8], scope: &str, payload: &[u8]) -> Result<Hmac<sha2::Sha256>, VaultError> {
    if key.len() != 32 || payload.len() > 64 * 1024 || !matches!(scope, "item:edit:v1" | "otp:read:v1" | "vaultpack:receipt:v1") {
        return Err(VaultError::CryptoAuthFailed);
    }
    let mut derived = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, key).expand(scope.as_bytes(), derived.as_mut())
        .map_err(|_| VaultError::CryptoAuthFailed)?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(derived.as_ref()).map_err(|_| VaultError::CryptoAuthFailed)?;
    mac.update(payload);
    Ok(mac)
}

#[wasm_bindgen]
pub fn wasm_sign_authorization(key: Vec<u8>, scope: &str, payload: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let (key, payload) = (Zeroizing::new(key), Zeroizing::new(payload));
    Ok(authorization(&key, scope, &payload)?.finalize().into_bytes().to_vec())
}

#[wasm_bindgen]
pub fn wasm_verify_authorization(key: Vec<u8>, scope: &str, payload: Vec<u8>, tag: &[u8]) -> Result<bool, JsValue> {
    let (key, payload) = (Zeroizing::new(key), Zeroizing::new(payload));
    Ok(authorization(&key, scope, &payload)?.verify_slice(tag).is_ok())
}

#[wasm_bindgen]
pub fn wasm_seal_preferences(session_key: Vec<u8>, session_wrap: Vec<u8>, plain: String) -> Result<Vec<u8>, JsValue> {
    let (key, wrap, plain) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap), Zeroizing::new(plain));
    seal(&key, &wrap, &plain, Domain::Autofill).map_err(Into::into)
}
#[wasm_bindgen]
pub fn wasm_open_preferences(session_key: Vec<u8>, session_wrap: Vec<u8>, sealed: Vec<u8>) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap));
    open(&key, &wrap, &sealed, Domain::Autofill).map_err(Into::into)
}
#[wasm_bindgen]
pub fn wasm_seal_webdav(session_key: Vec<u8>, session_wrap: Vec<u8>, plain: String) -> Result<Vec<u8>, JsValue> {
    let (key, wrap, plain) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap), Zeroizing::new(plain));
    seal(&key, &wrap, &plain, Domain::WebDav).map_err(Into::into)
}
#[wasm_bindgen]
pub fn wasm_open_webdav(session_key: Vec<u8>, session_wrap: Vec<u8>, sealed: Vec<u8>) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap));
    open(&key, &wrap, &sealed, Domain::WebDav).map_err(Into::into)
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
        let sealed = seal(first.as_bytes(), &wrap, plain, Domain::Autofill).unwrap();
        assert!(!sealed.windows(b"private.example".len()).any(|w| w == b"private.example"));
        assert_eq!(SealedEnvelope::from_bytes(&sealed).unwrap().ciphertext.len() % 256, 0);
        let next = SecretKey::random().unwrap();
        let rotated = SessionWrappedDekBlob::wrap("vault-a", 2, &dek, &next).unwrap();
        assert_eq!(open(next.as_bytes(), &rotated, &sealed, Domain::Autofill).unwrap(), plain);
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(next.as_bytes(), &rotated, &tampered, Domain::Autofill).is_err());
        let foreign = SessionWrappedDekBlob::wrap("vault-b", 2, &dek, &next).unwrap();
        assert!(open(next.as_bytes(), &foreign, &sealed, Domain::Autofill).is_err());
        assert!(open(first.as_bytes(), &rotated, &sealed, Domain::Autofill).is_err());
    }
    #[test]
    fn webdav_and_autofill_envelopes_are_not_interchangeable() {
        let dek = SecretKey::random().unwrap();
        let key = SecretKey::random().unwrap();
        let wrap = SessionWrappedDekBlob::wrap("vault-a", 1, &dek, &key).unwrap();
        let plain = r#"{"username":"private-account","password":"private-app-password"}"#;
        let sealed = seal(key.as_bytes(), &wrap, plain, Domain::WebDav).unwrap();
        assert!(!sealed.windows(7).any(|w| w == b"private"));
        assert!(open(key.as_bytes(), &wrap, &sealed, Domain::Autofill).is_err());
        assert_eq!(open(key.as_bytes(), &wrap, &sealed, Domain::WebDav).unwrap(), plain);
    }
}
