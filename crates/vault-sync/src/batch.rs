use std::collections::{BTreeMap, BTreeSet};
use vault_core::crypto::{FileRole, SCHEMA_VERSION, SealedEnvelope, VaultKeyHierarchy};
use vault_core::error::VaultError;
use vault_core::model::{DeviceMetadata, VaultItem, VaultSnapshot};
use vault_core::sync_codec::{
    MpReader, MsgPackWire, mp_write_array_len, mp_write_bin, mp_write_str, mp_write_uint,
    open_compact_object, seal_compact_object,
};
use zeroize::Zeroizing;
use crate::conflict::{Conflict, Staged};
use crate::reconcile::{different_secrets, login_scopes};

const MAX_CHANGES: u32 = 16_384;
const MAX_FRAME_COUNT: usize = 750;
const MAX_DEFERRED_EDITS: usize = 16_384;

pub(crate) struct Edit {
    pub(crate) id: String,
    pub(crate) before: Option<VaultItem>,
    pub(crate) after: Option<VaultItem>,
}

pub(crate) struct Batch {
    vault: String,
    pub(crate) device: String,
    pub(crate) base_epoch: u64,
    pub(crate) base_root: [u8; 32],
    pub(crate) edits: Vec<Edit>,
    devices: Vec<(Option<DeviceMetadata>, Option<DeviceMetadata>)>,
    resolutions: BTreeSet<[u8; 32]>,
}

pub(crate) fn invalid() -> VaultError {
    VaultError::InvalidFormat("unknown or inconsistent WebDAV history".into())
}

pub(crate) fn read_item(reader: &mut MpReader<'_>) -> Result<Option<VaultItem>, VaultError> {
    match reader.read_array_len() {
        0 => Ok(None),
        1 => {
            let start = reader.position();
            let item = VaultItem::decode_msgpack(reader)?;
            let mut canonical = Zeroizing::new(Vec::new());
            item.encode_msgpack(&mut canonical);
            if canonical.as_slice() != reader.consumed_since(start) { return Err(invalid()); }
            Ok(Some(item))
        }
        _ => Err(invalid()),
    }
}

pub(crate) fn write_item(bytes: &mut Vec<u8>, item: Option<&VaultItem>) {
    mp_write_array_len(bytes, usize::from(item.is_some()));
    if let Some(item) = item { item.encode_msgpack(bytes); }
}

fn read_device(reader: &mut MpReader<'_>) -> Result<Option<DeviceMetadata>, VaultError> {
    match reader.read_array_len() {
        0 => Ok(None),
        1 => {
            let start = reader.position();
            let device = DeviceMetadata::decode_msgpack(reader)?;
            crate::device::indexed(std::slice::from_ref(&device))?;
            let mut canonical = Zeroizing::new(Vec::new());
            device.encode_msgpack(&mut canonical);
            if canonical.as_slice() != reader.consumed_since(start) { return Err(invalid()); }
            Ok(Some(device))
        }
        _ => Err(invalid()),
    }
}

impl MsgPackWire for Batch {
    fn encode_msgpack(&self, bytes: &mut Vec<u8>) {
        let receipts = !self.resolutions.is_empty();
        mp_write_array_len(bytes, if receipts { 8 } else { 7 });
        mp_write_uint(bytes, if receipts { 3 } else { 2 });
        mp_write_str(bytes, &self.vault);
        mp_write_str(bytes, &self.device);
        mp_write_uint(bytes, self.base_epoch);
        mp_write_bin(bytes, &self.base_root);
        mp_write_array_len(bytes, self.edits.len());
        for edit in &self.edits {
            // The ID is already present in whichever version is available.
            mp_write_array_len(bytes, 2);
            write_item(bytes, edit.before.as_ref());
            write_item(bytes, edit.after.as_ref());
        }
        mp_write_array_len(bytes, self.devices.len());
        for (before, after) in &self.devices {
            mp_write_array_len(bytes, 2);
            for device in [before, after] {
                mp_write_array_len(bytes, usize::from(device.is_some()));
                if let Some(device) = device { device.encode_msgpack(bytes); }
            }
        }
        if receipts {
            mp_write_array_len(bytes, self.resolutions.len());
            for receipt in &self.resolutions { mp_write_bin(bytes, receipt); }
        }
    }

    fn decode_msgpack(reader: &mut MpReader<'_>) -> Result<Self, VaultError> {
        let format = (reader.read_array_len(), reader.read_u64());
        if !matches!(format, (6, 1) | (7, 2) | (8, 3)) { return Err(invalid()); }
        let vault = reader.read_string();
        let device = reader.read_string();
        if !crate::journal::valid_device(&device) { return Err(invalid()); }
        let base_epoch = reader.read_u64();
        let base_root = reader.read_bin_vec().try_into().map_err(|_| invalid())?;
        let len = reader.read_array_len();
        if len > MAX_CHANGES { return Err(invalid()); }
        let mut edits = Vec::with_capacity(len as usize);
        let mut prior = String::new();
        for _ in 0..len {
            if reader.read_array_len() != 2 { return Err(invalid()); }
            let before = read_item(reader)?;
            let after = read_item(reader)?;
            let id = before.as_ref().or(after.as_ref()).ok_or_else(invalid)?.id.clone();
            if id <= prior || after.as_ref().is_some_and(|item| item.id != id) || before == after { return Err(invalid()); }
            prior.clone_from(&id);
            edits.push(Edit { id, before, after });
        }
        let mut devices = Vec::new();
        if format.1 >= 2 {
            let len = reader.read_array_len() as usize;
            if len > crate::device::MAX_DEVICES { return Err(invalid()); }
            let mut ids = BTreeSet::new();
            for _ in 0..len {
                if reader.read_array_len() != 2 { return Err(invalid()); }
                let before = read_device(reader)?;
                let after = read_device(reader)?;
                let id = &before.as_ref().or(after.as_ref()).ok_or_else(invalid)?.device_id;
                if !ids.insert(id.clone()) || after.as_ref().is_some_and(|device| &device.device_id != id) || before == after { return Err(invalid()); }
                devices.push((before, after));
            }
        }
        let mut resolutions = BTreeSet::new();
        if format.1 == 3 {
            let len = reader.read_array_len();
            if !(1..=MAX_CHANGES).contains(&len) { return Err(invalid()); }
            for _ in 0..len {
                if !resolutions.insert(reader.read_bin_vec().try_into().map_err(|_| invalid())?) { return Err(invalid()); }
            }
        }
        if edits.is_empty() && devices.is_empty() && resolutions.is_empty() { return Err(invalid()); }
        reader.finish()?;
        Ok(Self { vault, device, base_epoch, base_root, edits, devices, resolutions })
    }
}

pub(crate) fn indexed(snap: &VaultSnapshot) -> Result<BTreeMap<&str, &VaultItem>, VaultError> {
    let map: BTreeMap<_, _> = snap.items.iter().map(|item| (item.id.as_str(), item)).collect();
    if map.len() != snap.items.len() || map.contains_key("") { return Err(invalid()); }
    Ok(map)
}

#[derive(Default)]
struct LoginIndex(BTreeMap<(String, String), BTreeSet<String>>);

impl LoginIndex {
    fn add(&mut self, item: &VaultItem) {
        for (domain, user) in login_scopes(item) {
            self.0.entry((domain, user.to_owned())).or_default().insert(item.id.clone());
        }
    }

    fn remove(&mut self, item: &VaultItem) {
        for (domain, user) in login_scopes(item) {
            let key = (domain, user.to_owned());
            if let Some(ids) = self.0.get_mut(&key) {
                ids.remove(&item.id);
                if ids.is_empty() { self.0.remove(&key); }
            }
        }
    }

    fn matches(&self, item: &VaultItem) -> BTreeSet<&str> {
        login_scopes(item).into_iter().flat_map(|(domain, user)| self.0.get(&(domain, user.to_owned())))
            .flatten().map(String::as_str).collect()
    }
}

fn duplicate_proof(keys: &VaultKeyHierarchy, scope: &str, new: &VaultItem, known: &VaultItem) -> [u8; 32] {
    let mut proof = Zeroizing::new(b"webdav:login-pair:v1\0".to_vec());
    mp_write_str(&mut proof, scope);
    write_item(&mut proof, Some(new));
    write_item(&mut proof, Some(known));
    keys.compute_state_mac(&proof)
}

pub(crate) fn seal_batch(
    keys: &VaultKeyHierarchy, id: &str, device: &str, base: &VaultSnapshot, before: &VaultSnapshot, after: &VaultSnapshot,
    receipts: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let time = crate::journal::time_of_id(id)?;
    if !crate::journal::valid_device(device) || base.vault_id != before.vault_id || base.vault_id != after.vault_id { return Err(invalid()); }
    let (old_items, new_items) = (indexed(before)?, indexed(after)?);
    let ids: BTreeSet<_> = old_items.keys().chain(new_items.keys()).copied().collect();
    let mut edits = Vec::new();
    for id in ids {
        if old_items.get(id) != new_items.get(id) {
            edits.push(Edit { id: id.into(), before: old_items.get(id).map(|v| (*v).clone()), after: new_items.get(id).map(|v| (*v).clone()) });
        }
    }
    let (old, new) = (crate::device::indexed(&before.device_registry)?, crate::device::indexed(&after.device_registry)?);
    let ids: BTreeSet<_> = old.keys().chain(new.keys()).copied().collect();
    let devices: Vec<_> = ids.into_iter().filter_map(|id| {
        let (before, after) = (old.get(id).copied(), new.get(id).copied());
        (before != after).then(|| (before.cloned(), after.cloned()))
    }).collect();
    if receipts.len() % 32 != 0 || receipts.len() / 32 > MAX_CHANGES as usize { return Err(invalid()); }
    let mut resolutions: BTreeSet<_> = receipts.chunks_exact(32).map(|bytes| bytes.try_into().unwrap()).collect();
    if edits.iter().any(|edit| edit.before.is_none()) {
        let mut logins = LoginIndex::default();
        for &item in old_items.values() { logins.add(item); }
        for item in edits.iter().filter(|edit| edit.before.is_none()).filter_map(|edit| edit.after.as_ref()) {
            for candidate in logins.matches(item) {
                let known = old_items[candidate];
                if different_secrets(item, known) { resolutions.insert(duplicate_proof(keys, "previously-seen", item, known)); }
                if resolutions.len() > MAX_CHANGES as usize { return Err(VaultError::CompactObjectTooLarge); }
            }
        }
    }
    if edits.is_empty() && devices.is_empty() && resolutions.is_empty() { return Ok(Vec::new()); }
    if edits.len() > MAX_CHANGES as usize { return Err(VaultError::CompactObjectTooLarge); }
    // The leading HLC is already authenticated by the envelope epoch.
    seal_compact_object(keys.wal_key(), FileRole::Wal, &format!("r:{}", &id[15..]), time,
        &Batch { vault: base.vault_id.clone(), device: device.into(), base_epoch: base.snapshot_epoch, base_root: base.state_mac, edits, devices, resolutions })
}

pub(crate) fn open_batch(keys: &VaultKeyHierarchy, vault: &str, id: &str, bytes: &[u8]) -> Result<Batch, VaultError> {
    let time = crate::journal::time_of_id(id)?;
    let envelope = SealedEnvelope::from_bytes(bytes)?;
    if envelope.schema_version != SCHEMA_VERSION || envelope.hlc_epoch != time { return Err(invalid()); }
    let batch: Batch = open_compact_object(keys.wal_key(), FileRole::Wal, Some(&format!("r:{}", &id[15..])), bytes)?;
    if batch.vault != vault { return Err(invalid()); }
    Ok(batch)
}

pub(crate) fn frames(mut packed: &[u8]) -> Result<BTreeMap<&str, &[u8]>, VaultError> {
    let mut result = BTreeMap::new();
    while !packed.is_empty() {
        let (name, next) = packed.split_at_checked(38).ok_or_else(invalid)?;
        let (len, next) = next.split_at_checked(4).ok_or_else(invalid)?;
        let (bytes, rest) = next.split_at_checked(u32::from_le_bytes(len.try_into().unwrap()) as usize).ok_or_else(invalid)?;
        let name = std::str::from_utf8(name).map_err(|_| invalid())?;
        crate::journal::time_of_id(name)?;
        if bytes.is_empty() || result.len() >= MAX_FRAME_COUNT || result.insert(name, bytes).is_some() { return Err(invalid()); }
        packed = rest;
    }
    Ok(result)
}

pub(crate) fn check_snapshot(keys: &VaultKeyHierarchy, snapshot: &VaultSnapshot) -> Result<(), VaultError> {
    let mut copy = snapshot.clone();
    copy.state_mac = [0; 32];
    let mut bytes = Zeroizing::new(Vec::new());
    copy.encode_msgpack(&mut bytes);
    if keys.compute_state_mac(&bytes) != snapshot.state_mac { return Err(invalid()); }
    Ok(())
}

pub(crate) fn replay(
    keys: &VaultKeyHierarchy, base: &VaultSnapshot, packed: &[u8], ancestors: &[(u64, [u8; 32])],
) -> Result<(VaultSnapshot, Staged), VaultError> {
    let mut snapshot = base.clone();
    let mut items: BTreeMap<_, _> = indexed(base)?.into_iter().map(|(id, item)| (id.to_string(), item.clone())).collect();
    let mut consumed: BTreeSet<_> = base.included_wal_ids.iter().cloned().collect();
    let mut writers = BTreeMap::<String, String>::new();
    let mut new_logins = LoginIndex::default();
    let base_ids: BTreeSet<_> = base.items.iter().map(|item| item.id.as_str()).collect();
    let mut blocked = BTreeMap::<String, Conflict>::new();
    let mut waiting = BTreeMap::<String, String>::new();
    let mut deferred = BTreeMap::<String, Vec<(Edit, String, String)>>::new();
    let mut deferred_count = 0;
    for (id, bytes) in frames(packed)? {
        if consumed.contains(id) { continue; }
        let batch = open_batch(keys, &base.vault_id, id, bytes)?;
        if (batch.base_epoch, batch.base_root) != (base.snapshot_epoch, base.state_mac) &&
           !ancestors.contains(&(batch.base_epoch, batch.base_root)) {
            return Err(VaultError::InvalidInput("SyncAncestorRequired".into()));
        }
        for (before, after) in batch.devices {
            let name = &before.as_ref().or(after.as_ref()).ok_or_else(invalid)?.device_id;
            let local: Vec<_> = snapshot.device_registry.extract_if(.., |device| &device.device_id == name).collect();
            snapshot.device_registry.extend(crate::device::merge(before.as_slice(), after.as_slice(), &local)?);
        }
        let released: Vec<_> = blocked.iter().filter_map(|(id, conflict)| {
            conflict.receipt.filter(|receipt| batch.resolutions.contains(receipt)).map(|_| id.clone())
        }).collect();
        let mut approved = BTreeSet::new();
        for id in &released {
            if let Some(row) = blocked.remove(id)
                && let Some(other) = row.theirs.as_ref().filter(|other| other.id != *id)
            {
                approved.insert((id.clone(), other.id.clone()));
            }
        }
        if !released.is_empty() { waiting.retain(|_, owner| !released.contains(owner)); }
        let mut released_edits = Vec::new();
        for id in released {
            if let Some(mut queue) = deferred.remove(&id) {
                deferred_count -= queue.len();
                released_edits.append(&mut queue);
            }
        }
        for (edit, wal, device) in batch.edits.into_iter().map(|edit| (edit, id.to_string(), batch.device.clone())).chain(released_edits) {
            if let Some(owner) = waiting.get(&edit.id) {
                deferred_count += 1;
                if deferred_count > MAX_DEFERRED_EDITS { return Err(VaultError::CompactObjectTooLarge); }
                deferred.entry(owner.clone()).or_default().push((edit, wal, device));
                continue;
            }
            let current = items.get(&edit.id);
            if current == edit.after.as_ref() { continue; }
            let source = |device: Option<&str>| -> String {
                let Some(device) = device else { return "网盘快照".into(); };
                snapshot.device_registry.iter().find(|row| row.device_id == device && !row.device_name.trim().is_empty())
                    .map_or_else(|| format!("设备 {}", &device[..8]), |row| row.device_name.clone())
            };
            if current.is_none() && edit.before.is_none() && !base_ids.contains(edit.id.as_str()) && let Some(new) = &edit.after {
                let candidates = new_logins.matches(new);
                let other = candidates.into_iter().filter_map(|id| items.get(id)).find(|known| {
                    writers.get(&known.id).is_some_and(|writer| *writer != device) && different_secrets(new, known) &&
                        !approved.contains(&(edit.id.clone(), known.id.clone())) &&
                        !batch.resolutions.contains(&duplicate_proof(keys, "previously-seen", new, known))
                });
                if let Some(other) = other {
                    if let Some(owner) = waiting.get(&other.id).cloned() {
                        deferred_count += 1;
                        if deferred_count > MAX_DEFERRED_EDITS { return Err(VaultError::CompactObjectTooLarge); }
                        waiting.insert(edit.id.clone(), owner.clone());
                        deferred.entry(owner).or_default().push((edit, wal, device));
                    } else {
                        waiting.insert(edit.id.clone(), edit.id.clone());
                        waiting.insert(other.id.clone(), edit.id.clone());
                        blocked.insert(edit.id.clone(), Conflict { id: edit.id.clone(), base: None, fields: vec!["$duplicate".into()],
                            receipt: Some(duplicate_proof(keys, &wal, new, other)), theirs: Some(other.clone()),
                            sources: Some((source(Some(&device)), source(writers.get(&other.id).map(String::as_str)))),
                            ours: edit.after });
                    }
                    continue;
                }
            }
            let value = if current == edit.before.as_ref() { edit.after }
            else {
                let merged = crate::merge::item(edit.before.as_ref(), edit.after.as_ref(), current,
                    &crate::merge::Choices::new(), ("另一设备", "网盘"))?;
                if !merged.contested.is_empty() {
                    let mut proof = Zeroizing::new(b"webdav:resolve-wal:v1\0".to_vec());
                    mp_write_str(&mut proof, &wal);
                    mp_write_str(&mut proof, &edit.id);
                    write_item(&mut proof, current);
                    waiting.insert(edit.id.clone(), edit.id.clone());
                    blocked.insert(edit.id.clone(), Conflict { id: edit.id.clone(), fields: merged.contested, base: edit.before,
                        ours: edit.after, theirs: merged.item.clone(), receipt: Some(keys.compute_state_mac(&proof)),
                        sources: Some((source(Some(&device)), source(writers.get(&edit.id).map(String::as_str)))) });
                }
                merged.item
            };
            if !base_ids.contains(edit.id.as_str()) {
                if let Some(old) = current { new_logins.remove(old); }
                if let Some(new) = &value { new_logins.add(new); }
            }
            writers.insert(edit.id.clone(), device);
            if let Some(item) = value { items.insert(edit.id, item); }
            else { items.remove(&edit.id); }
        }
        snapshot.hlc_timestamp = snapshot.hlc_timestamp.max(crate::journal::time_of_id(id)?);
        consumed.insert(id.to_string());
    }
    snapshot.items = items.into_values().collect();
    snapshot.device_registry.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    crate::device::indexed(&snapshot.device_registry)?;
    snapshot.included_wal_ids = consumed.into_iter().collect();
    Ok((snapshot, Staged(blocked.into_values().collect())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::crypto::SecretKey;
    use vault_core::sync_codec::seal_snapshot;

    #[test]
    fn append_is_immutable_idempotent_and_requires_a_common_snapshot() {
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::from_bytes([27; 32])).unwrap();
        let mut base = VaultSnapshot::new_empty("test-vault".into(), "base".into(), 1);
        seal_snapshot(&keys, &mut base).unwrap();
        let mut next = base.clone();
        next.items.push(VaultItem::from_json_str(r#"{"title":"Offline","id":"23262a46-a88d-42fd-8ad7-d99162d39ab1","data":{"kind":"login","password":"example"}}"#).unwrap());
        let id = "00000000001000_09abcd11_00000000000001";
        let device = "9bba890e-b0ca-4882-a562-4e86c9b66a15";
        let bytes = seal_batch(&keys, id, device, &base, &base, &next, &[]).unwrap();
        let batch = open_batch(&keys, "test-vault", id, &bytes).unwrap();
        assert_eq!(batch.device, device);
        assert!(bytes.len() <= 600, "simple append {} B", bytes.len());
        let frame = [id.as_bytes(), &(bytes.len() as u32).to_le_bytes(), &bytes].concat();
        let (replayed, staged) = replay(&keys, &base, &frame, &[]).unwrap();
        assert!(staged.0.is_empty());
        assert_eq!(replayed.items, next.items);
        assert_eq!(replayed.included_wal_ids, vec![id.to_string()]);
        assert_eq!(replay(&keys, &replayed, &frame, &[]).unwrap().0.items, next.items);
        let mut different = base.clone();
        different.state_mac = [99; 32];
        assert!(replay(&keys, &different, &frame, &[]).is_err());
        assert!(open_batch(&keys, "other-vault", id, &bytes).is_err());
    }

    #[test]
    fn divergent_published_batches_keep_both_versions_until_the_exact_resolution() {
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::from_bytes([42; 32])).unwrap();
        let mut base = VaultSnapshot::new_empty("vault".into(), "base".into(), 1);
        let row = |value: &str, note: &str| VaultItem::from_json_str(&format!(
            r#"{{"title":"Login","id":"login1","data":{{"kind":"login","password":"{value}"}},"note":"{note}"}}"#)).unwrap();
        base.items.push(row("original", ""));
        seal_snapshot(&keys, &mut base).unwrap();
        let device = "9bba890e-b0ca-4882-a562-4e86c9b66a15";
        let frame = |index: u64, before: &VaultSnapshot, after: &VaultSnapshot, receipts: &[u8]| {
            let id = format!("{index:014}_09abcd11_{index:014}");
            let bytes = seal_batch(&keys, &id, device, &base, before, after, receipts).unwrap();
            [id.as_bytes(), &(bytes.len() as u32).to_le_bytes(), &bytes].concat()
        };
        let mut a = base.clone();
        a.items[0] = row("value A", "");
        let mut b = base.clone();
        b.items[0] = row("value B", "independent note");
        let mut packed = [frame(2, &base, &a, &[]), frame(3, &base, &b, &[])].concat();
        let (visible, staged) = replay(&keys, &base, &packed, &[]).unwrap();
        assert_eq!(staged.0.len(), 1);
        assert_eq!(staged.0[0].fields, ["data.password"]);
        assert_eq!(staged.0[0].ours.as_ref().unwrap().to_json_value().get_field("data").unwrap().get_str("password"), "value B");
        assert_eq!(visible.items[0].note, "independent note");
        let mut chosen = visible.clone();
        chosen.items[0] = b.items[0].clone();
        packed.extend(frame(4, &visible, &visible, &[9; 32]));
        assert_eq!(replay(&keys, &base, &packed, &[]).unwrap().1.0.len(), 1);
        packed.extend(frame(5, &visible, &chosen, &staged.0[0].receipt.unwrap()));
        let (finished, resolved) = replay(&keys, &base, &packed, &[]).unwrap();
        assert!(resolved.0.is_empty());
        assert_eq!(finished.items, chosen.items);
        assert_eq!(finished.included_wal_ids.len(), 4);
    }

    #[test]
    fn two_published_creates_for_the_same_login_are_staged_until_explicitly_kept() {
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::from_bytes([90; 32])).unwrap();
        let mut base = VaultSnapshot::new_empty("vault".into(), "base".into(), 1);
        seal_snapshot(&keys, &mut base).unwrap();
        let row = |id: &str, host: &str, password: &str| VaultItem::from_json_str(&format!(
            r#"{{"id":"{id}","title":"Login {id}","data":{{"kind":"login","username":"alice","password":"{password}","uris":[{{"uri":"https://{host}"}}]}}}}"#
        )).unwrap();
        let frame = |n: u64, device: &str, before: &VaultSnapshot, after: &VaultSnapshot, receipts: &[u8]| {
            let id = format!("{n:014}_09abcd11_{n:014}");
            let bytes = seal_batch(&keys, &id, device, &base, before, after, receipts).unwrap();
            [id.as_bytes(), &(bytes.len() as u32).to_le_bytes(), &bytes].concat()
        };
        let a = "9bba890e-b0ca-4882-a562-4e86c9b66a15";
        let b = "99ba890e-b0ca-4882-a562-4e86c9b66a16";
        let mut left = base.clone();
        left.items.push(row("a", "team.example.net", "first"));
        let mut right = base.clone();
        right.items.push(row("b", "accounts.example.net", "second"));
        right.items.push(row("c", "unrelated.example.org", "third"));
        let mut packed = [frame(2, a, &base, &left, &[]), frame(3, b, &base, &right, &[])].concat();
        let (visible, staged) = replay(&keys, &base, &packed, &[]).unwrap();
        assert_eq!(visible.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["a", "c"]);
        let [pending] = &staged.0[..] else { panic!("Expected exactly one duplicate") };
        assert_eq!(pending.fields, ["$duplicate"]);
        assert_eq!(pending.ours.as_ref().unwrap().id, "b");
        let mut both = visible.clone();
        both.items.push(pending.ours.as_ref().unwrap().clone());
        packed.extend(frame(4, a, &visible, &both, &pending.receipt.unwrap()));
        let (chosen, remaining) = replay(&keys, &base, &packed, &[]).unwrap();
        assert_eq!(chosen.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
        assert!(remaining.0.is_empty());
    }
}
