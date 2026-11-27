use std::collections::{BTreeMap, BTreeSet};

use crate::{batch, conflict, device::Provenance, journal::valid_device, merge, remote};
use vault_core::model::{VaultItem, VaultSnapshot};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

type Authors<'a> = (&'a BTreeMap<&'a str, &'a VaultItem>, &'a Provenance);

#[wasm_bindgen]
pub fn wasm_sync_pack_edit(
    key: Vec<u8>, wrap: Vec<u8>, before_head: &[u8], before_snap: &[u8], after_head: &[u8], after_snap: &[u8],
    device: &str, guard: &[u8],
) -> Result<Option<remote::Replayed>, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    if !valid_device(device) { return Err(batch::invalid().into()); }
    let (vault, epoch, keys) = crate::keys(&key, &wrap)?;
    let before = crate::verified_snapshot(&keys, &vault, epoch, before_head, before_snap)?;
    let mut after = crate::verified_snapshot(&keys, &vault, epoch, after_head, after_snap)?;
    batch::check_snapshot(&keys, &before)?;
    batch::check_snapshot(&keys, &after)?;
    let mut authors = Provenance::read(&before.sync_provenance)?;
    let old = batch::indexed(&before)?;
    let new = batch::indexed(&after)?;
    let staged = conflict::Staged::open(&keys, &vault, guard)?;
    conflict::guard_staged(&old, &new, &staged)?;
    let mut changed = old.keys().filter(|id| !new.contains_key(**id)).count();
    for (&id, &item) in &new {
        if !merge::same(old.get(id).copied(), Some(item)) {
            authors.writers.insert(id.into(), device.into());
            changed += 1;
        }
    }
    if changed > 0 { authors.last_edits.insert(device.into(), u32::try_from(changed).map_err(|_| batch::invalid())?); }
    let proposed = std::mem::take(&mut after.sync_provenance);
    authors.store(&mut after);
    if after.sync_provenance == proposed { return Ok(None); }
    Ok(Some(remote::materialize(&keys, after_head, after)?))
}

pub(crate) fn merge_authors(base: &Provenance, ours: Authors, theirs: Authors, output: &mut VaultSnapshot) {
    let mut result = Provenance::default();
    for item in &output.items {
        let id = item.id.as_str();
        let ours_auth = ours.1.writers.get(id);
        let theirs_auth = theirs.1.writers.get(id);
        let author = match (merge::same(Some(item), ours.0.get(id).copied()), merge::same(Some(item), theirs.0.get(id).copied())) {
            (true, false) => ours_auth,
            (false, true) => theirs_auth,
            (true, true) if ours_auth.is_none() || theirs_auth.is_none() => ours_auth.or(theirs_auth),
            _ if ours_auth == theirs_auth => ours_auth,
            _ => None, // An item composed from different writers has no single author.
        };
        if let Some(author) = author { result.writers.insert(id.into(), author.clone()); }
    }
    let devices: BTreeSet<_> = ours.1.last_edits.keys().chain(theirs.1.last_edits.keys()).collect();
    for device in devices {
        let (old, our_count, their_count) = (base.last_edits.get(device), ours.1.last_edits.get(device), theirs.1.last_edits.get(device));
        let count = if our_count == their_count || our_count == old { their_count } else if their_count == old { our_count } else { None };
        if let Some(count) = count { result.last_edits.insert(device.clone(), *count); }
    }
    result.store(output);
}
