mod batch;
#[cfg(test)]
mod bench;
mod conflict;
mod device;
mod journal;
mod merge;
mod reconcile;
mod remote;
pub use reconcile::*;
pub use remote::*;
pub use conflict::*;
pub use device::*;

use vault_core::crypto::{SecretKey, VaultKeyHierarchy};
use vault_core::error::VaultError;
use vault_core::model::VaultSnapshot;
use vault_core::session::SessionWrappedDekBlob;
use vault_core::sync_codec::{VaultHead, open_snapshot};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn keys(session_key: &[u8], session_wrap: &[u8]) -> Result<(String, u64, VaultKeyHierarchy), VaultError> {
    let (id, epoch, dek) = SessionWrappedDekBlob::unwrap(session_wrap, &SecretKey::from_slice(session_key)?)?;
    Ok((id, epoch, VaultKeyHierarchy::from_master_dek(dek)?))
}

fn verified_snapshot(
    keys: &VaultKeyHierarchy, vault_id: &str, key_epoch: u64, head: &[u8], snap: &[u8],
) -> Result<VaultSnapshot, VaultError> {
    let head = VaultHead::from_bytes(head)?;
    if head.vault_id != vault_id || head.key_epoch != key_epoch { return Err(VaultError::CryptoAuthFailed); }
    let pointer = head.decrypt_pointer(keys)?;
    let snapshot = open_snapshot(keys, Some(&pointer.latest_snapshot_id), snap)?;
    if snapshot.snapshot_epoch != pointer.snapshot_epoch || snapshot.vault_id != vault_id ||
        snapshot.snapshot_id != pointer.latest_snapshot_id || snapshot.state_mac != pointer.state_root_mac {
        return Err(VaultError::CryptoAuthFailed);
    }
    Ok(snapshot)
}

#[wasm_bindgen]
pub fn wasm_make_local_wal(
    session_key: Vec<u8>, session_wrap: Vec<u8>, id: &str, device_id: &str,
    before_head: &[u8], before_snap: &[u8], after_head: &[u8], after_snap: &[u8], checkpoint: bool,
) -> Result<Vec<u8>, JsValue> {
    let (session_key, session_wrap) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap));
    let (vault_id, epoch, keys) = keys(&session_key, &session_wrap)?;
    let before = verified_snapshot(&keys, &vault_id, epoch, before_head, before_snap)?;
    let after = verified_snapshot(&keys, &vault_id, epoch, after_head, after_snap)?;
    journal::seal_delta(&keys, id, device_id, &before, &after, checkpoint).map_err(Into::into)
}

#[wasm_bindgen]
pub fn wasm_verify_local_wal(
    session_key: Vec<u8>, session_wrap: Vec<u8>, id: &str, ciphertext: &[u8],
) -> Result<bool, JsValue> {
    let (session_key, session_wrap) = (Zeroizing::new(session_key), Zeroizing::new(session_wrap));
    let (vault_id, _, keys) = keys(&session_key, &session_wrap)?;
    Ok(journal::open_delta(&keys, &vault_id, id, ciphertext).is_ok())
}
