use std::collections::{BTreeMap, BTreeSet};
use vault_core::error::VaultError;
use vault_core::model::{CredentialData, VaultItem, VaultSnapshot};
use vault_core::sync_codec::MsgPackWire;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{batch, conflict::{Conflict, Staged}, merge, remote};

pub(crate) fn login_scopes(item: &VaultItem) -> Vec<(String, &str)> {
    let CredentialData::Login(login) = &item.data else { return Vec::new(); };
    if item.trashed || login.username.is_empty() { return Vec::new(); }
    login.uris.iter().filter_map(|entry| {
        let url = url::Url::parse(&entry.uri).ok()?;
        if !matches!(url.scheme(), "http" | "https") { return None; }
        let domain = psl::domain_str(url.domain()?)?.to_string();
        Some((domain, login.username.as_str()))
    }).collect()
}

pub(crate) fn different_secrets(a: &VaultItem, b: &VaultItem) -> bool {
    let (CredentialData::Login(a), CredentialData::Login(b)) = (&a.data, &b.data) else { return false; };
    if a.password != b.password { return true; }
    let identity = |uri: &str| vault_otp::parse(uri).ok().map(|otp| otp.identity());
    match (&a.totp_uri, &b.totp_uri) {
        (Some(a), Some(b)) if a != b => {
            let (a, b) = (identity(a), identity(b));
            a.is_none() || b.is_none() || a != b
        }
        (a, b) => a.is_some() != b.is_some(),
    }
}

fn reconcile(
    base: &VaultSnapshot, ours: &VaultSnapshot, theirs: &VaultSnapshot, staged: Staged, shared: Staged, receipts: &[u8],
) -> Result<(VaultSnapshot, Staged), VaultError> {
    let (base_items, local_items, remote_items) = (batch::indexed(base)?, batch::indexed(ours)?, batch::indexed(theirs)?);
    let (duplicates, regular): (Vec<_>, Vec<_>) = staged.0.into_iter().filter(|row| row.receipt.is_none())
        .partition(|row| row.fields.iter().any(|field| field == "$duplicate"));
    let mut pending: BTreeMap<_, _> = regular.into_iter().map(|row| (row.id.clone(), row)).collect();
    let mut shared: BTreeMap<_, _> = shared.0.into_iter().filter(|row| {
        row.receipt.is_some_and(|key| !receipts.chunks_exact(32).any(|receipt| receipt == key))
    }).map(|row| (row.id.clone(), row)).collect();
    let ids: BTreeSet<_> = base_items.keys().chain(local_items.keys()).chain(remote_items.keys()).map(|id| (*id).to_string())
        .chain(pending.keys().cloned()).chain(shared.keys().cloned()).collect();
    let mut result = theirs.clone();
    result.items.clear();
    let mut conflicts = Vec::new();
    for id in ids {
        let old = pending.remove(&id);
        let base = base_items.get(id.as_str()).copied();
        let ours = local_items.get(id.as_str()).copied();
        let theirs = remote_items.get(id.as_str()).copied();
        if let Some(row) = shared.remove(&id) {
            let local = old.as_ref().map_or(ours, |row| row.ours.as_ref());
            if !merge::same(local, base) && !merge::same(local, theirs) && !merge::same(local, row.ours.as_ref()) {
                return Err(VaultError::InvalidInput("本机待上传编辑与网盘中的待裁决项重叠，请先在没有该本机草稿的设备上裁决。未修改任何凭证。".into()));
            }
            if let Some(item) = theirs { result.items.push(item.clone()); }
            conflicts.push(row);
            continue;
        }
        let (base, ours) = if let Some(prior) = &old {
            if !merge::same(ours, prior.theirs.as_ref()) { return Err(batch::invalid()); }
            (prior.base.as_ref(), prior.ours.as_ref())
        } else { (base, ours) };
        let merged = merge::item(base, ours, theirs, &merge::Choices::new(), ("本机", "网盘"))?;
        if merged.contested.is_empty() {
            if let Some(item) = merged.item { result.items.push(item); }
        } else {
            if let Some(item) = theirs { result.items.push(item.clone()); }
            conflicts.push(Conflict { id, base: base.cloned(), ours: ours.cloned(), theirs: theirs.cloned(), fields: merged.contested,
                receipt: None, sources: old.and_then(|row| row.sources) });
        }
    }
    let mut paired = conflicts.iter().flat_map(|row| std::iter::once(row.id.as_str()).chain(row.theirs.iter().map(|item| item.id.as_str())))
        .map(str::to_string).collect::<BTreeSet<_>>();
    let mut hidden = BTreeSet::new();
    for mut row in duplicates {
        let Some(local) = row.ours.as_ref() else { return Err(batch::invalid()); };
        let other = row.theirs.as_ref().and_then(|prior| remote_items.get(prior.id.as_str())).copied();
        if other.is_some_and(|other| !other.trashed && different_secrets(local, other)) {
            let other = other.unwrap();
            if !paired.insert(other.id.clone()) { return Err(batch::invalid()); }
            hidden.insert(row.id.clone());
            row.theirs = Some(other.clone());
            conflicts.push(row);
        } else if other.is_none() && !result.items.iter().any(|item| item.id == local.id) {
            result.items.push(local.clone());
        }
    }
    let mut incoming = BTreeMap::<_, BTreeSet<_>>::new();
    for (&id, &row) in &remote_items {
        if base_items.contains_key(id) || local_items.contains_key(id) { continue; }
        for scope in login_scopes(row) { incoming.entry(scope).or_default().insert(id); }
    }
    for (&id, &row) in &local_items {
        if base_items.contains_key(id) || remote_items.contains_key(id) || paired.contains(id) || hidden.contains(id) { continue; }
        let candidates = login_scopes(row).into_iter().flat_map(|scope| incoming.get(&scope).into_iter().flatten().copied())
            .filter(|id| different_secrets(row, remote_items[*id])).collect::<BTreeSet<_>>();
        if let Some(&other) = candidates.first() {
            if candidates.len() > 1 || !paired.insert(other.into()) {
                return Err(VaultError::InvalidInput("同站点同账号匹配到多个待裁决条目；已保留本机编辑，未上传。".into()));
            }
            hidden.insert(id.into());
            conflicts.push(Conflict { id: id.into(), base: None, ours: Some(row.clone()), theirs: Some(remote_items[other].clone()),
                fields: vec!["$duplicate".into()], receipt: None, sources: None });
        }
    }
    result.items.retain(|row| !hidden.contains(&row.id));
    result.items.sort_by(|a, b| a.id.cmp(&b.id));
    result.hlc_timestamp = result.hlc_timestamp.max(ours.hlc_timestamp);
    result.device_registry = crate::device::merge(&base.device_registry, &ours.device_registry, &theirs.device_registry)?;
    Ok((result, Staged(conflicts)))
}

#[wasm_bindgen]
pub fn wasm_sync_reconcile(
    key: Vec<u8>, wrap: Vec<u8>, base_head: &[u8], base: &[u8], our_head: &[u8], ours: &[u8],
    remote_head: &[u8], theirs: &[u8], staged: &[u8], shared: Option<Vec<u8>>, receipts: Option<Vec<u8>>,
) -> Result<remote::Replayed, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let base = super::verified_snapshot(&keys, &vault, epoch, base_head, base)?;
    let ours = super::verified_snapshot(&keys, &vault, epoch, our_head, ours)?;
    let theirs = super::verified_snapshot(&keys, &vault, epoch, remote_head, theirs)?;
    let (after, conflicts) = reconcile(&base, &ours, &theirs, Staged::open(&keys, &vault, staged)?,
        Staged::open(&keys, &vault, shared.as_deref().unwrap_or_default())?, receipts.as_deref().unwrap_or_default())?;
    let mut result = remote::materialize(&keys, remote_head, after)?;
    result.set_conflicts(conflicts.seal(&keys, &vault)?, conflicts.0.len());
    Ok(result)
}

#[wasm_bindgen]
pub fn wasm_sync_adopt(
    source_key: Vec<u8>, source_wrap: Vec<u8>, source_head: &[u8], source: &[u8],
    target_key: Vec<u8>, target_wrap: Vec<u8>, target_head: &[u8], target: &[u8], staged: &[u8],
) -> Result<remote::Replayed, JsValue> {
    let (source_key, source_wrap, target_key, target_wrap) = (Zeroizing::new(source_key), Zeroizing::new(source_wrap),
        Zeroizing::new(target_key), Zeroizing::new(target_wrap));
    let (source_id, source_epoch, source_keys) = super::keys(&source_key, &source_wrap)?;
    let (target_id, target_epoch, target_keys) = super::keys(&target_key, &target_wrap)?;
    if source_id == target_id { return Err(batch::invalid().into()); }
    let mut source = super::verified_snapshot(&source_keys, &source_id, source_epoch, source_head, source)?;
    let target = super::verified_snapshot(&target_keys, &target_id, target_epoch, target_head, target)?;
    // A different key hierarchy has no common ancestor. Never transfer device IDs, wrapping
    // slots, synchronization state or file identities from the source.
    source.device_registry.clear();
    let base = VaultSnapshot::new_empty(target_id.clone(), target.snapshot_id.clone(), 0);
    let (after, conflicts) = reconcile(&base, &source, &target, Staged(Vec::new()),
        Staged::open(&target_keys, &target_id, staged)?, &[])?;
    let mut out = remote::materialize(&target_keys, target_head, after)?;
    out.set_conflicts(conflicts.seal(&target_keys, &target_id)?, conflicts.0.len());
    Ok(out)
}

#[wasm_bindgen]
pub struct WriteGuard {
    stamp: String,
    before: u32,
    after: u32,
    removed: u32,
    blocked: bool,
}

#[wasm_bindgen]
impl WriteGuard {
    #[wasm_bindgen(getter)]
    pub fn stamp(&self) -> String { self.stamp.clone() }
    #[wasm_bindgen(getter)]
    pub fn before(&self) -> u32 { self.before }
    #[wasm_bindgen(getter)]
    pub fn after(&self) -> u32 { self.after }
    #[wasm_bindgen(getter)]
    pub fn removed(&self) -> u32 { self.removed }
    #[wasm_bindgen(getter)]
    pub fn blocked(&self) -> bool { self.blocked }
}

fn guard(keys: &vault_core::crypto::VaultKeyHierarchy, before: &VaultSnapshot, after: &VaultSnapshot, had_records: bool) -> WriteGuard {
    let before_count = before.items.iter().filter(|item| !item.trashed).count() as u32;
    let after_count = after.items.iter().filter(|item| !item.trashed).count() as u32;
    let latest: BTreeSet<_> = after.items.iter().filter(|item| !item.trashed).map(|item| item.id.as_str()).collect();
    let removed = before.items.iter().filter(|item| !item.trashed && !latest.contains(item.id.as_str())).count() as u32;
    let blocked = after_count == 0 && (before_count > 0 || had_records);
    let mut stamp = String::new();
    let decrease = before_count.saturating_sub(after_count);
    if !blocked && decrease >= 5 && u64::from(decrease) * 2 >= u64::from(before_count) {
        use std::fmt::Write;
        let mut payload = Zeroizing::new(b"webdav:confirm-removals:v1\0".to_vec());
        before.encode_msgpack(&mut payload);
        after.encode_msgpack(&mut payload);
        for byte in keys.compute_state_mac(&payload) { let _ = write!(&mut stamp, "{byte:02x}"); }
    }
    WriteGuard { stamp, before: before_count, after: after_count, removed, blocked }
}

#[wasm_bindgen]
pub fn wasm_sync_write_guard(
    key: Vec<u8>, wrap: Vec<u8>, before_head: &[u8], before: &[u8], after_head: &[u8], after: &[u8], had_records: bool,
) -> Result<WriteGuard, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let before = super::verified_snapshot(&keys, &vault, epoch, before_head, before)?;
    let after = super::verified_snapshot(&keys, &vault, epoch, after_head, after)?;
    Ok(guard(&keys, &before, &after, had_records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{crypto::{SecretKey, VaultKeyHierarchy}, model::VaultItem};

    fn vault(count: usize) -> VaultSnapshot {
        let mut snap = VaultSnapshot::new_empty("v".into(), "s".into(), 0);
        for i in 1..=count {
            snap.items.push(VaultItem::from_json_str(&format!(
                r#"{{"title":"Fixture {i}","id":"23262a46-a88d-42fd-8ad7-{i:012}","data":{{"kind":"login","password":"example"}}}}"#
            )).unwrap());
        }
        snap
    }

    #[test]
    fn guards_empty_and_exact_joint_threshold_and_binds_the_decision() {
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::from_bytes([101; 32])).unwrap();
        assert!(guard(&keys, &vault(10), &vault(0), false).blocked);
        assert!(guard(&keys, &vault(0), &vault(0), true).blocked);
        assert!(!guard(&keys, &vault(0), &vault(0), false).blocked);
        assert!(guard(&keys, &vault(11), &vault(6), true).stamp.is_empty()); // 5, below half
        assert!(guard(&keys, &vault(8), &vault(4), true).stamp.is_empty()); // half, below 5
        let stamp = guard(&keys, &vault(10), &vault(5), true).stamp;
        assert_eq!(stamp.len(), 64);
        let mut other = vault(5);
        other.items[4].title = "changed after confirmation".into();
        assert_ne!(guard(&keys, &vault(10), &other, true).stamp, stamp);
        assert_ne!(guard(&keys, &vault(10), &vault(4), true).stamp, stamp);
    }

    #[test]
    fn distinct_offline_login_ids_are_not_uploaded_on_same_domain_and_account_conflict() {
        let row = |id: &str, uri: &str, password: &str| VaultItem::from_json_str(&format!(
            r#"{{"title":"Fixture","id":"{id}","data":{{"kind":"login","username":"tester","password":"{password}","uris":[{{"uri":"{uri}"}}]}}}}"#)).unwrap();
        let base = vault(0);
        let mut local = base.clone();
        local.items = vec![row("a", "https://login.example.com", "local"), row("c", "https://user.github.io", "local")];
        let mut remote = base.clone();
        remote.items = vec![row("b", "https://accounts.example.com", "remote"), row("d", "https://different.github.io", "remote")];
        let (current, stages) = reconcile(&base, &local, &remote, Staged(Vec::new()), Staged(Vec::new()), &[]).unwrap();
        assert_eq!(stages.0.len(), 1);
        assert_eq!(stages.0[0].id, "a");
        assert_eq!(stages.0[0].fields, ["$duplicate"]);
        assert_eq!(current.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["b", "c", "d"]);
        let (_, known) = reconcile(&remote, &current, &remote, stages, Staged(Vec::new()), &[]).unwrap();
        assert_eq!(known.0.len(), 1);
    }
}
