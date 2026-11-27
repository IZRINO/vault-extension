use hmac::{Hmac, Mac};
use sha2::Sha256;
use vault_core::error::VaultError;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const MAX_RECORD_BYTES: usize = 16 * 1024;
const RECORD_DOMAIN: &[u8] = b"vault:webdav-pack:version-record:v1";

fn record_mac(material: &[u8], vault_id: &str, message: &[u8]) -> Result<Hmac<Sha256>, VaultError> {
    let id = vault_id.as_bytes();
    if material.len() != 32
        || message.is_empty()
        || message.len() > MAX_RECORD_BYTES
        || id.len() != 36
        || id.iter().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte != b'-',
            _ => !matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
    {
        return Err(VaultError::CryptoAuthFailed);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(id), material)
        .expand(RECORD_DOMAIN, key.as_mut())
        .map_err(|_| VaultError::CryptoAuthFailed)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_ref()).map_err(|_| VaultError::CryptoAuthFailed)?;
    mac.update(message);
    Ok(mac)
}

#[wasm_bindgen]
pub fn wasm_sync_pack_record_sign(
    material: Vec<u8>,
    vault_id: &str,
    message: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let material = Zeroizing::new(material);
    Ok(record_mac(&material, vault_id, &message)?
        .finalize()
        .into_bytes()
        .to_vec())
}

#[wasm_bindgen]
pub fn wasm_sync_pack_record_verify(
    material: Vec<u8>,
    vault_id: &str,
    message: Vec<u8>,
    tag: Vec<u8>,
) -> Result<bool, JsValue> {
    let material = Zeroizing::new(material);
    Ok(record_mac(&material, vault_id, &message)?
        .verify_slice(&tag)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_mac_matches_webcrypto_wire_vector_and_is_vault_specific() {
        let seed = vec![7; 32];
        let vault = "12121212-1212-4121-8121-121212121212";
        let different_vault = "12121212-1212-4121-8121-121212121213";
        let message = b"vault-version-wire-fixture";
        let tag = wasm_sync_pack_record_sign(seed.clone(), vault, message.to_vec()).unwrap();
        assert_eq!(
            tag,
            [
                0xec, 0x31, 0x4f, 0x02, 0x97, 0x31, 0xd1, 0x77, 0x05, 0x54, 0x51, 0x73, 0xfa, 0xcc,
                0xfd, 0xe6, 0x7c, 0xe3, 0xdd, 0x09, 0x75, 0x07, 0x99, 0xf2, 0xe2, 0xe2, 0xbe, 0x54,
                0x5e, 0x0b, 0x2c, 0xff,
            ],
        );
        assert!(
            wasm_sync_pack_record_verify(seed.clone(), vault, message.to_vec(), tag.clone())
                .unwrap()
        );
        assert!(
            !wasm_sync_pack_record_verify(
                seed.clone(),
                different_vault,
                message.to_vec(),
                tag.clone()
            )
            .unwrap()
        );
        assert!(
            !wasm_sync_pack_record_verify(seed, vault, b"altered-version".to_vec(), tag).unwrap()
        );
    }
}
