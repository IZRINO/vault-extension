use vault_core::{
    crypto::{SecretKey, VaultKeyHierarchy},
    error::VaultError,
    model::VaultSnapshot,
    session::SessionWrappedDekBlob,
    sync_codec::{VaultHead, open_snapshot, seal_snapshot},
};

pub fn open_vault(key: &[u8], wrap: &[u8], head: &[u8], snap: &[u8]) -> Result<(VaultKeyHierarchy, VaultHead, VaultSnapshot), VaultError> {
    let session = SecretKey::from_slice(key)?;
    let (id, epoch, dek) = SessionWrappedDekBlob::unwrap(wrap, &session)?;
    let keys = VaultKeyHierarchy::from_master_dek(dek)?;
    let head = VaultHead::from_bytes(head)?;
    if head.vault_id != id || head.key_epoch != epoch { return Err(VaultError::CryptoAuthFailed); }
    let pointer = head.decrypt_pointer(&keys)?;
    let contents = open_snapshot(&keys, Some(&pointer.latest_snapshot_id), snap)?;
    if contents.vault_id != id || contents.snapshot_epoch != pointer.snapshot_epoch ||
       contents.state_mac != pointer.state_root_mac || contents.snapshot_id != pointer.latest_snapshot_id {
        return Err(VaultError::CryptoAuthFailed);
    }
    Ok((keys, head, contents))
}

pub fn seal_vault(keys: &VaultKeyHierarchy, mut head: VaultHead, mut snap: VaultSnapshot, now: u64) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    snap.hlc_timestamp = snap.hlc_timestamp.max(now).saturating_add(1);
    let encrypted = seal_snapshot(keys, &mut snap)?;
    let mut pointer = head.decrypt_pointer(keys)?;
    pointer.state_root_mac = snap.state_mac;
    pointer.updated_at_ms = now;
    head.update_pointer(keys, &pointer)?;
    Ok((head.to_bytes()?, encrypted))
}
