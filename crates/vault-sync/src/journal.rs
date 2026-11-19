use std::collections::{BTreeMap, BTreeSet};
use vault_core::crypto::{FileRole, SCHEMA_VERSION, SealedEnvelope, VaultKeyHierarchy};
use vault_core::error::VaultError;
use vault_core::model::{VaultItem, VaultSnapshot};
use vault_core::sync_codec::{
    MpReader, MsgPackWire, mp_write_array_len, mp_write_bin, mp_write_bool, mp_write_opt_u64,
    mp_write_str, mp_write_uint, open_compact_object, seal_compact_object,
};

const WAL_VERSION: u64 = 1;
const MAX_CHANGES: u32 = 16_384;

#[derive(PartialEq, Eq)]
pub(crate) struct Change {
    id: String,
    base_rev: Option<u64>,
    after: Option<VaultItem>,
}

#[derive(PartialEq, Eq)]
pub(crate) struct Journal {
    vault: String,
    device: String,
    base_epoch: u64,
    base_root: [u8; 32],
    next_root: [u8; 32],
    checkpoint: bool,
    changes: Vec<Change>,
}

fn bad() -> VaultError { VaultError::InvalidFormat("invalid or unsupported WAL".into()) }

pub(crate) fn time_of_id(id: &str) -> Result<u64, VaultError> {
    let parts: Vec<_> = id.split('_').collect();
    if id.len() != 38 || parts.len() != 3 || parts[0].len() != 14 || parts[1].len() != 8 || parts[2].len() != 14 ||
        parts.iter().any(|part| !part.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))) {
        return Err(bad());
    }
    u64::from_str_radix(parts[0], 16).map_err(|_| bad())
}

pub(crate) fn valid_device(id: &str) -> bool {
    id.len() == 36 && id.bytes().enumerate().all(|(i, byte)| {
        if matches!(i, 8 | 13 | 18 | 23) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    })
}

impl MsgPackWire for Journal {
    fn encode_msgpack(&self, wr: &mut Vec<u8>) {
        mp_write_array_len(wr, 8);
        mp_write_uint(wr, WAL_VERSION);
        mp_write_str(wr, &self.vault);
        mp_write_str(wr, &self.device);
        mp_write_uint(wr, self.base_epoch);
        mp_write_bin(wr, &self.base_root);
        mp_write_bin(wr, &self.next_root);
        mp_write_bool(wr, self.checkpoint);
        mp_write_array_len(wr, self.changes.len());
        for change in &self.changes {
            // The item already contains the ID. A deleted row stores only its ID.
            mp_write_array_len(wr, if change.after.is_some() { 2 } else { 3 });
            mp_write_opt_u64(wr, change.base_rev);
            if let Some(item) = &change.after {
                item.encode_msgpack(wr);
            } else {
                mp_write_str(wr, &change.id);
                mp_write_bool(wr, true);
            }
        }
    }

    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        if rd.read_array_len() != 8 || rd.read_u64() != WAL_VERSION { return Err(bad()); }
        let vault = rd.read_string();
        let device = rd.read_string();
        if !valid_device(&device) { return Err(bad()); }
        let base_epoch = rd.read_u64();
        let base_root = rd.read_bin_vec().try_into().map_err(|_| bad())?;
        let next_root = rd.read_bin_vec().try_into().map_err(|_| bad())?;
        let checkpoint = rd.read_bool();
        let count = rd.read_array_len();
        if count > MAX_CHANGES { return Err(bad()); }
        let mut changes = Vec::with_capacity(count as usize);
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let len = rd.read_array_len();
            let base_rev = rd.read_opt_u64();
            let (id, after) = match len {
                2 => {
                    let item = VaultItem::decode_msgpack(rd)?;
                    (item.id.clone(), Some(item))
                }
                3 if base_rev.is_some() => {
                    let id = rd.read_string();
                    if !rd.read_bool() || checkpoint { return Err(bad()); }
                    (id, None)
                }
                _ => return Err(bad()),
            };
            if id.is_empty() || !seen.insert(id.clone()) { return Err(bad()); }
            changes.push(Change { id, base_rev, after });
        }
        rd.finish()?;
        Ok(Self { vault, device, base_epoch, base_root, next_root, checkpoint, changes })
    }
}

pub(crate) fn seal_delta(
    keys: &VaultKeyHierarchy, id: &str, device: &str, before: &VaultSnapshot, after: &VaultSnapshot, checkpoint: bool,
) -> Result<Vec<u8>, VaultError> {
    let time = time_of_id(id)?;
    if !valid_device(device) || before.vault_id != after.vault_id { return Err(bad()); }
    let old: BTreeMap<_, _> = before.items.iter().map(|item| (item.id.as_str(), item)).collect();
    let new: BTreeMap<_, _> = after.items.iter().map(|item| (item.id.as_str(), item)).collect();
    if old.len() != before.items.len() || new.len() != after.items.len() { return Err(bad()); }
    let mut changes = Vec::new();
    for (id, item) in &new {
        let prior = old.get(id).copied();
        if checkpoint || prior != Some(*item) {
            changes.push(Change { id: id.to_string(), base_rev: prior.map(|x| x.revision), after: Some((*item).clone()) });
        }
    }
    if !checkpoint {
        for (id, item) in old {
            if !new.contains_key(id) { changes.push(Change { id: id.to_string(), base_rev: Some(item.revision), after: None }); }
        }
    }
    if changes.len() > MAX_CHANGES as usize { return Err(VaultError::CompactObjectTooLarge); }
    let wal = Journal { vault: before.vault_id.clone(), device: device.into(), base_epoch: before.snapshot_epoch,
        base_root: before.state_mac, next_root: after.state_mac, checkpoint, changes };
    let object_id = format!("local:{id}");
    seal_compact_object(keys.wal_key(), FileRole::Wal, &object_id, time, &wal)
}

pub(crate) fn open_delta(keys: &VaultKeyHierarchy, vault: &str, id: &str, ciphertext: &[u8]) -> Result<Journal, VaultError> {
    let time = time_of_id(id)?;
    let envelope = SealedEnvelope::from_bytes(ciphertext)?;
    if envelope.schema_version != SCHEMA_VERSION || envelope.hlc_epoch != time { return Err(VaultError::CryptoAuthFailed); }
    let decoded: Journal = open_compact_object(keys.wal_key(), FileRole::Wal, Some(&format!("local:{id}")), ciphertext)?;
    if decoded.vault != vault { return Err(VaultError::CryptoAuthFailed); }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::crypto::SecretKey;
    use vault_core::sync_codec::seal_snapshot;

    #[test]
    fn roundtrip_local_journal_binds_ancestor_item_role_and_vault() {
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::from_bytes([17; 32])).unwrap();
        let mut before = VaultSnapshot::new_empty("my-vault".into(), "initial".into(), 100);
        seal_snapshot(&keys, &mut before).unwrap();
        let mut after = before.clone();
        let item = VaultItem::from_json_str(r#"{"id":"23262a46-a88d-42fd-8ad7-d99162d39ab1","title":"Fixture","data":{"kind":"login","password":"local-only-secret"}} "#).unwrap();
        after.items.push(item);
        let snap = seal_snapshot(&keys, &mut after).unwrap();
        let id = "00000000001000_09abcd11_00000000000001";
        let device = "9bba890e-b0ca-4882-a562-4e86c9b66a15";
        let mut sealed = seal_delta(&keys, id, device, &before, &after, false).unwrap();
        assert!(sealed.len() <= 600, "single simple WAL: {} bytes", sealed.len());
        assert!(!sealed.windows(17).any(|w| w == b"local-only-secret"));
        assert!(!sealed.windows(device.len()).any(|w| w == device.as_bytes()));
        let opened = open_delta(&keys, &before.vault_id, id, &sealed).unwrap();
        assert_eq!(opened.base_root, before.state_mac);
        assert_eq!(opened.next_root, after.state_mac);
        assert_eq!(opened.device, device);
        assert_eq!(opened.changes.len(), 1);
        assert_eq!(opened.changes[0].base_rev, None);
        assert_eq!(opened.changes[0].after.as_ref(), Some(&after.items[0]));
        assert!(open_delta(&keys, "other-vault", id, &sealed).is_err());
        assert!(open_delta(&keys, &before.vault_id, id, &snap).is_err());
        assert!(open_delta(&VaultKeyHierarchy::from_master_dek(SecretKey::from_bytes([90; 32])).unwrap(), &before.vault_id, id, &sealed).is_err());
        *sealed.last_mut().unwrap() ^= 1;
        assert!(open_delta(&keys, &before.vault_id, id, &sealed).is_err());
        let deleted = seal_delta(&keys, id, device, &after, &before, false).unwrap();
        let opened = open_delta(&keys, &before.vault_id, id, &deleted).unwrap();
        assert_eq!(opened.changes[0].base_rev, Some(0));
        assert!(opened.changes[0].after.is_none());
    }
}
