use std::collections::{BTreeMap, BTreeSet};
use vault_core::error::VaultError;
use vault_core::model::{CredentialData, VaultItem, VaultSnapshot};
use vault_core::sync_codec::MsgPackWire;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{batch, conflict::{Conflict, Draft, Staged}, device::{self, Provenance}, merge, remote};

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
    release_drafts: bool, local_device: Option<&str>,
) -> Result<(VaultSnapshot, Staged), VaultError> {
    let (base_items, local_items, remote_items) = (batch::indexed(base)?, batch::indexed(ours)?, batch::indexed(theirs)?);
    let provenance = Provenance::read(&theirs.sync_provenance)?;
    let local_source = device::source(&ours.device_registry, local_device, "本机");
    let remote_source = |id: &str| device::source(&theirs.device_registry, provenance.writers.get(id).map(String::as_str), "网盘快照（来源未知）");
    let mut drafts = staged.drafts;
    let (duplicates, regular): (Vec<_>, Vec<_>) = staged.rows.into_iter().filter(|row| row.receipt.is_none())
        .partition(|row| row.fields.iter().any(|field| field == "$duplicate"));
    let mut pending: BTreeMap<_, _> = regular.into_iter().map(|row| (row.id.clone(), row)).collect();
    let held: BTreeSet<_> = shared.rows.iter().flat_map(Conflict::affected_ids).map(str::to_owned).collect();
    let shared: Vec<_> = shared.rows.into_iter().filter(|row| {
        row.receipt.is_some_and(|key| !receipts.chunks_exact(32).any(|receipt| receipt == key))
    }).collect();
    let active: BTreeMap<_, _> = shared.iter().flat_map(|row| row.affected_ids().map(move |id| (id, row))).collect();
    let ids: BTreeSet<_> = base_items.keys().chain(local_items.keys()).chain(remote_items.keys()).map(|id| (*id).to_string())
        .chain(pending.keys().cloned()).chain(active.keys().map(|&id| id.to_owned())).chain(drafts.keys().cloned()).collect();
    let mut result = theirs.clone();
    result.items.clear();
    let mut conflicts = Vec::new();
    let mut recovered = BTreeSet::new();
    for id in ids {
        let old = pending.remove(&id);
        let base = base_items.get(id.as_str()).copied();
        let ours = local_items.get(id.as_str()).copied();
        let theirs = remote_items.get(id.as_str()).copied();
        if let Some(row) = active.get(id.as_str()) {
            let (start, local) = old.as_ref().map_or((base, ours), |row| (row.base.as_ref(), row.ours.as_ref()));
            if !merge::same(local, start) && !merge::same(local, theirs) &&
                !(row.id == id && merge::same(local, row.ours.as_ref()))
            {
                let queue = drafts.entry(id).or_default();
                if !queue.iter().any(|draft| merge::same(draft.base.as_ref(), start) && merge::same(draft.ours.as_ref(), local)) {
                    queue.push(Draft { base: start.cloned(), ours: local.cloned() });
                }
            }
            if let Some(item) = theirs { result.items.push(item.clone()); }
            continue;
        }
        let restored = if release_drafts && old.is_none() && !held.contains(&id) &&
            (merge::same(ours, base) || merge::same(ours, theirs))
        {
            drafts.get_mut(&id).and_then(|queue| (!queue.is_empty()).then(|| queue.remove(0)))
        } else { None };
        let (base, ours) = if let Some(prior) = &old {
            if !merge::same(ours, prior.theirs.as_ref()) { return Err(batch::invalid()); }
            (prior.base.as_ref(), prior.ours.as_ref())
        } else if let Some(draft) = &restored {
            (draft.base.as_ref(), draft.ours.as_ref())
        } else { (base, ours) };
        let theirs_source = remote_source(&id);
        let ours_source = old.as_ref().and_then(|row| row.sources.as_ref()).map_or(local_source.as_str(), |(name, _)| name);
        let merged = merge::item(base, ours, theirs, &merge::Choices::new(), (ours_source, &theirs_source))?;
        if merged.contested.is_empty() {
            if restored.is_some() && base.is_none() && theirs.is_none() && ours.is_some() { recovered.insert(id); }
            if let Some(item) = merged.item { result.items.push(item); }
        } else {
            if let Some(item) = theirs { result.items.push(item.clone()); }
            conflicts.push(Conflict { id, base: base.cloned(), ours: ours.cloned(), theirs: theirs.cloned(), fields: merged.contested,
                receipt: None, sources: Some((ours_source.to_owned(), theirs_source)), additional: Vec::new() });
        }
    }
    conflicts.extend(shared);
    let mut paired = conflicts.iter().flat_map(Conflict::affected_ids).map(str::to_owned).collect::<BTreeSet<_>>();
    let mut hidden = BTreeSet::<String>::new();
    let mut prior_sources = BTreeMap::new();
    // Recheck earlier matches as a group, including new versions of the same login.
    // If any overlap is already being reviewed, keep the local draft off the wire.
    let mut revisit = Vec::new();
    {
        let visible = batch::indexed(&result)?;
        for row in duplicates {
            let Some(local) = row.ours.as_ref() else { return Err(batch::invalid()); };
            let scopes = login_scopes(local);
            let has_match = row.matches().filter_map(|(item, _)| visible.get(item.id.as_str())).any(|item|
                different_secrets(local, item) && login_scopes(item).iter().any(|scope| scopes.contains(scope)));
            if paired.contains(&row.id) || held.contains(&row.id) || visible.contains_key(row.id.as_str()) || (!release_drafts && !has_match)
            {
                drafts.entry(row.id).or_default().insert(0, Draft { base: None, ours: row.ours });
            } else {
                prior_sources.insert(row.id.clone(), (row.labels().0.to_owned(),
                    row.matches().map(|(item, label)| (item.id.clone(), label.to_owned())).collect::<BTreeMap<_, _>>()));
                recovered.insert(row.id);
                revisit.push(row.ours.unwrap());
            }
        }
    }
    result.items.extend(revisit);
    let visible = batch::indexed(&result)?;
    let mut incoming = BTreeMap::<_, BTreeSet<_>>::new();
    for (&id, &row) in &visible {
        if !remote_items.contains_key(id) { continue; }
        for scope in login_scopes(row) { incoming.entry(scope).or_default().insert(id); }
    }
    for row in &result.items {
        let id = row.id.as_str();
        let is_recovered = recovered.contains(id);
        if (!is_recovered && (base_items.contains_key(id) || !local_items.contains_key(id))) ||
            remote_items.contains_key(id) || paired.contains(id) { continue; }
        let candidates = login_scopes(row).into_iter().flat_map(|scope| incoming.get(&scope).into_iter().flatten().copied())
            .filter(|other| (is_recovered || (remote_items.contains_key(other) && !base_items.contains_key(other) &&
                !local_items.contains_key(other))) && *other != id && different_secrets(row, visible[*other])).collect::<BTreeSet<_>>();
        if !candidates.is_empty() && candidates.iter().all(|&other| !paired.contains(other) && !held.contains(other)) {
            let (ours_source, prior) = prior_sources.remove(id).unwrap_or_else(|| (local_source.clone(), BTreeMap::new()));
            let source = |id: &str| if provenance.writers.contains_key(id) { remote_source(id) }
                else { prior.get(id).cloned().unwrap_or_else(|| remote_source(id)) };
            let mut matches = candidates.iter().map(|&id| (visible[id].clone(), source(id)));
            let (theirs, their_source) = matches.next().unwrap();
            paired.insert(id.into());
            paired.extend(candidates.iter().copied().map(str::to_owned));
            hidden.insert(id.into());
            conflicts.push(Conflict { id: id.into(), base: None, ours: Some(row.clone()), theirs: Some(theirs),
                fields: vec!["$duplicate".into()], receipt: None, sources: Some((ours_source, their_source)), additional: matches.collect() });
        } else if !candidates.is_empty() || (is_recovered && !release_drafts) {
            hidden.insert(id.into());
            drafts.entry(id.into()).or_default().insert(0, Draft { base: None, ours: Some(row.clone()) });
        }
    }
    drafts.retain(|_, queue| !queue.is_empty());
    result.items.retain(|row| !hidden.contains(&row.id));
    result.items.sort_by(|a, b| a.id.cmp(&b.id));
    result.hlc_timestamp = result.hlc_timestamp.max(ours.hlc_timestamp);
    result.device_registry = crate::device::merge(&base.device_registry, &ours.device_registry, &theirs.device_registry)?;
    provenance.store(&mut result);
    Ok((result, Staged { rows: conflicts, drafts }))
}

#[wasm_bindgen]
pub fn wasm_sync_reconcile(
    key: Vec<u8>, wrap: Vec<u8>, base_head: &[u8], base: &[u8], our_head: &[u8], ours: &[u8],
    remote_head: &[u8], theirs: &[u8], staged: &[u8], shared: Option<Vec<u8>>, receipts: Option<Vec<u8>>, release_drafts: Option<bool>,
    local_device: Option<String>,
) -> Result<remote::Replayed, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let base = super::verified_snapshot(&keys, &vault, epoch, base_head, base)?;
    let ours = super::verified_snapshot(&keys, &vault, epoch, our_head, ours)?;
    let theirs = super::verified_snapshot(&keys, &vault, epoch, remote_head, theirs)?;
    let (after, conflicts) = reconcile(&base, &ours, &theirs, Staged::open(&keys, &vault, staged)?,
        Staged::open(&keys, &vault, shared.as_deref().unwrap_or_default())?, receipts.as_deref().unwrap_or_default(),
        release_drafts.unwrap_or(true), local_device.as_deref())?;
    let mut result = remote::materialize(&keys, remote_head, after)?;
    result.set_conflicts(&conflicts, &keys, &vault)?;
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
    source.sync_provenance.clear();
    let base = VaultSnapshot::new_empty(target_id.clone(), target.snapshot_id.clone(), 0);
    let (after, conflicts) = reconcile(&base, &source, &target, Staged::default(),
        Staged::open(&target_keys, &target_id, staged)?, &[], true, None)?;
    let mut out = remote::materialize(&target_keys, target_head, after)?;
    out.set_conflicts(&conflicts, &target_keys, &target_id)?;
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
        let (current, stages) = reconcile(&base, &local, &remote, Staged::default(), Staged::default(), &[], true, None).unwrap();
        assert_eq!(stages.rows.len(), 1);
        assert_eq!(stages.rows[0].id, "a");
        assert_eq!(stages.rows[0].fields, ["$duplicate"]);
        assert_eq!(current.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["b", "c", "d"]);
        let (_, known) = reconcile(&remote, &current, &remote, stages, Staged::default(), &[], true, None).unwrap();
        assert_eq!(known.rows.len(), 1);
    }
}
