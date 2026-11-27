use std::collections::{BTreeMap, BTreeSet};
use crate::{batch, conflict::{self, Conflict, Draft, Staged}, device, merge, remote::{self, Replayed}};
use vault_core::crypto::VaultKeyHierarchy;
use vault_core::error::VaultError;
use vault_core::model::{VaultItem, VaultSnapshot};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

struct PackState<'a> {
    items: BTreeMap<&'a str, &'a VaultItem>,
    conflicts: BTreeMap<&'a str, &'a Conflict>,
    staged: &'a Staged,
}

impl<'a> PackState<'a> {
    fn new((snapshot, staged): (&'a VaultSnapshot, &'a Staged)) -> Result<Self, VaultError> {
        let items = batch::indexed(snapshot)?;
        if staged.tombstones.iter().any(|id| items.contains_key(id.as_str())) {
            return Err(batch::invalid());
        }
        let mut conflicts = BTreeMap::new();
        for row in &staged.rows {
            if row.receipt.is_some() || !row.additional.is_empty() ||
                row.base.iter().chain(&row.ours).chain(&row.theirs).any(|item| item.id != row.id) ||
                !merge::same(items.get(row.id.as_str()).copied(), row.theirs.as_ref()) ||
                conflicts.insert(row.id.as_str(), row).is_some()
            {
                return Err(batch::invalid());
            }
        }
        if staged.drafts.keys().any(|id| !conflicts.contains_key(id.as_str())) {
            return Err(batch::invalid());
        }
        Ok(Self { items, conflicts, staged })
    }

    fn row(&self, id: &str) -> Entry<'a> {
        Entry {
            item: self.items.get(id).copied(),
            conflict: self.conflicts.get(id).copied(),
            drafts: self.staged.drafts.get(id).map_or(&[], Vec::as_slice),
            deleted: self.staged.tombstones.contains(id),
        }
    }
}

#[derive(Clone, Copy)]
struct Entry<'a> {
    item: Option<&'a VaultItem>,
    conflict: Option<&'a Conflict>,
    drafts: &'a [Draft],
    deleted: bool,
}

fn same_pending(left: Option<&Conflict>, right: Option<&Conflict>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.fields == right.fields &&
            merge::same(left.base.as_ref(), right.base.as_ref()) &&
            merge::same(left.ours.as_ref(), right.ours.as_ref()) &&
            merge::same(left.theirs.as_ref(), right.theirs.as_ref()),
        (None, None) => true,
        _ => false,
    }
}

fn same_draft(left: &Draft, right: &Draft) -> bool {
    merge::same(left.base.as_ref(), right.base.as_ref()) && merge::same(left.ours.as_ref(), right.ours.as_ref())
}

fn merged_drafts(base: &[Draft], ours: &[Draft], theirs: &[Draft]) -> Vec<Draft> {
    let contains = |drafts: &[Draft], draft: &Draft| drafts.iter().any(|other| same_draft(draft, other));
    let mut output = Vec::new();
    for (side, other) in [(ours, theirs), (theirs, ours)] {
        for draft in side {
            if (!contains(base, draft) || contains(other, draft)) && !contains(&output, draft) {
                output.push(draft.clone());
            }
        }
    }
    output
}

fn hold_edit(drafts: &mut Vec<Draft>, shown: &Conflict, base: Option<&VaultItem>, item: Option<&VaultItem>) {
    if [base, shown.ours.as_ref(), shown.theirs.as_ref()].into_iter().any(|known| merge::same(known, item)) {
        return;
    }
    let draft = Draft { base: base.cloned(), ours: item.cloned() };
    if !drafts.iter().any(|other| same_draft(&draft, other)) { drafts.push(draft); }
}

fn conflict_row(
    id: &str, base: Option<&VaultItem>, ours: Option<&VaultItem>, theirs: Option<&VaultItem>,
    fields: Vec<String>, sources: (&str, &str),
) -> Conflict {
    Conflict { id: id.into(), fields, base: base.cloned(), ours: ours.cloned(), theirs: theirs.cloned(),
        receipt: None, sources: Some((sources.0.into(), sources.1.into())), additional: Vec::new() }
}

fn revisit_drafts(
    id: &str, item: &mut Option<VaultItem>, stage: &mut Staged, drafts: Vec<Draft>,
) -> Result<(), VaultError> {
    let sources = ("待合并设备", "已合并版本");
    let mut drafts = drafts.into_iter();
    while let Some(draft) = drafts.next() {
        let (base, ours, theirs) = (draft.base.as_ref(), draft.ours.as_ref(), item.as_ref());
        let merged = merge::item(base, ours, theirs, &merge::Choices::new(), sources)?;
        if !merged.contested.is_empty() {
            stage.rows.push(conflict_row(id, base, ours, theirs, merged.contested, sources));
            if drafts.len() > 0 { stage.drafts.insert(id.into(), drafts.collect()); }
            return Ok(());
        }
        *item = merged.item;
    }
    Ok(())
}

fn staged_versions(staged: &Staged) -> impl Iterator<Item = &VaultItem> {
    staged.rows.iter().flat_map(|row| row.base.iter().chain(&row.ours).chain(&row.theirs))
        .chain(staged.drafts.values().flatten().flat_map(|draft| draft.base.iter().chain(&draft.ours)))
}

fn apply_counters(ledger: &merge::CounterLedger, snapshot: &mut VaultSnapshot, staged: &mut Staged) -> Result<(), VaultError> {
    let preferred = merge::CounterLedger::collect(snapshot.items.iter())?;
    ledger.apply(&mut snapshot.items, Some(&preferred))?;
    let visible = batch::indexed(snapshot)?;
    for row in &mut staged.rows {
        row.theirs = visible.get(row.id.as_str()).map(|item| (*item).clone());
    }
    Ok(())
}

impl Entry<'_> {
    fn same(self, other: Self) -> bool {
        self.deleted == other.deleted && merge::same(self.item, other.item) && same_pending(self.conflict, other.conflict) &&
            self.drafts.len() == other.drafts.len() && self.drafts.iter().zip(other.drafts).all(|(a, b)| same_draft(a, b))
    }

    fn with_history(mut self, base: Self) -> Self {
        self.deleted |= self.item.is_none() && (base.item.is_some() || base.deleted);
        self
    }

    fn save(self, id: &str, output: &mut VaultSnapshot, stage: &mut Staged) {
        output.items.extend(self.item.cloned());
        stage.rows.extend(self.conflict.cloned());
        if !self.drafts.is_empty() { stage.drafts.insert(id.into(), self.drafts.to_vec()); }
        if self.deleted { stage.tombstones.insert(id.into()); }
    }
}

fn merge_packs(
    base: (&VaultSnapshot, &Staged),
    ours: (&VaultSnapshot, &Staged),
    theirs: (&VaultSnapshot, &Staged),
    sources: (&str, &str),
) -> Result<(VaultSnapshot, Staged), VaultError> {
    let (base_state, our_state, their_state) = (PackState::new(base)?, PackState::new(ours)?, PackState::new(theirs)?);
    let ids: BTreeSet<_> = [&base_state, &our_state, &their_state].into_iter().flat_map(|view|
        view.items.keys().copied().chain(view.conflicts.keys().copied())
            .chain(view.staged.drafts.keys().map(String::as_str)).chain(view.staged.tombstones.iter().map(String::as_str))
    ).collect();
    let mut output = ours.0.clone();
    output.items.clear();
    output.included_wal_ids.clear();
    output.hlc_timestamp = output.hlc_timestamp.max(theirs.0.hlc_timestamp);
    output.device_registry = device::merge(&base.0.device_registry, &ours.0.device_registry, &theirs.0.device_registry)?;
    let mut staged = Staged::default();
    for id in ids {
        let base = base_state.row(id);
        let ours = our_state.row(id).with_history(base);
        let theirs = their_state.row(id).with_history(base);
        if ours.same(theirs) || ours.same(base) {
            theirs.save(id, &mut output, &mut staged);
            continue;
        }
        if theirs.same(base) {
            ours.save(id, &mut output, &mut staged);
            continue;
        }
        let mut drafts = merged_drafts(base.drafts, ours.drafts, theirs.drafts);
        let keep_conflict = match (ours.conflict, theirs.conflict) {
            (_, Some(row)) if ours.conflict.is_some() || !same_pending(Some(row), base.conflict) => Some((row, theirs, ours)),
            (Some(row), _) if !same_pending(Some(row), base.conflict) => Some((row, ours, theirs)),
            _ => None,
        };
        if let Some((active, display, alternate)) = keep_conflict {
            if let Some(other) = alternate.conflict {
                hold_edit(&mut drafts, active, other.base.as_ref(), other.ours.as_ref());
                hold_edit(&mut drafts, active, other.base.as_ref(), other.theirs.as_ref());
            } else {
                hold_edit(&mut drafts, active, base.item, alternate.item);
            }
            display.save(id, &mut output, &mut staged);
            if drafts.is_empty() { staged.drafts.remove(id); } else { staged.drafts.insert(id.into(), drafts); }
            continue;
        }
        if ours.conflict.is_some() || theirs.conflict.is_some() {
            // One branch resolved the shared conflict. Revisit concurrent edits held by the other.
            let resolved = if ours.conflict.is_some() { theirs } else { ours };
            let mut item = resolved.item.cloned();
            revisit_drafts(id, &mut item, &mut staged, drafts)?;
            if item.is_none() && (resolved.deleted || base.item.is_some()) { staged.tombstones.insert(id.into()); }
            output.items.extend(item);
            continue;
        }
        // If both branches chose a resolution, compare their decisions against the original base.
        let ancestor = base.conflict.map_or(base.item, |row| row.base.as_ref());
        let mut merged = merge::item(ancestor, ours.item, theirs.item, &merge::Choices::new(), sources)?;
        if (ours.deleted && theirs.item.is_some()) || (theirs.deleted && ours.item.is_some()) {
            merged.contested = vec!["$item".into()];
        }
        if merged.contested.is_empty() {
            if merged.item.is_none() && (ours.deleted || theirs.deleted) { staged.tombstones.insert(id.into()); }
            output.items.extend(merged.item);
        } else {
            output.items.extend(theirs.item.cloned());
            if theirs.deleted { staged.tombstones.insert(id.into()); }
            staged.rows.push(conflict_row(id, ancestor, ours.item, theirs.item, merged.contested, sources));
        }
    }
    let counter_versions = [base, ours, theirs].into_iter().flat_map(|(snapshot, staged)| snapshot.items.iter().chain(staged_versions(staged)));
    let counters = merge::CounterLedger::collect(counter_versions)?;
    apply_counters(&counters, &mut output, &mut staged)?;
    device::Provenance::read(&output.sync_provenance)?.store(&mut output);
    Ok((output, staged))
}

fn read_snapshot(keys: &VaultKeyHierarchy, vault: &str, epoch: u64, head: &[u8], bytes: &[u8]) -> Result<VaultSnapshot, VaultError> {
    let snapshot = crate::verified_snapshot(keys, vault, epoch, head, bytes)?;
    // This format cannot safely reserialize a snapshot containing fields it cannot read.
    batch::check_snapshot(keys, &snapshot)?;
    device::Provenance::read(&snapshot.sync_provenance)?;
    Ok(snapshot)
}

#[wasm_bindgen]
pub struct PackInspection {
    count: u32,
    conflict_count: u32,
    draft_count: u32,
}

#[wasm_bindgen]
impl PackInspection {
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> u32 { self.count }
    #[wasm_bindgen(getter)]
    pub fn conflict_count(&self) -> u32 { self.conflict_count }
    #[wasm_bindgen(getter)]
    pub fn draft_count(&self) -> u32 { self.draft_count }
}

#[wasm_bindgen]
pub fn wasm_sync_pack_inspect(key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], staged: &[u8]) -> Result<PackInspection, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = crate::keys(&key, &wrap)?;
    let snapshot = read_snapshot(&keys, &vault, epoch, head, snap)?;
    let staged = Staged::open(&keys, &vault, staged)?;
    PackState::new((&snapshot, &staged))?;
    Ok(PackInspection { count: snapshot.items.iter().filter(|item| !item.trashed).count() as u32,
        conflict_count: staged.rows.len() as u32, draft_count: staged.draft_count() as u32 })
}

fn materialize(keys: &VaultKeyHierarchy, vault: &str, template: &[u8], snapshot: VaultSnapshot, staged: &Staged) -> Result<Replayed, VaultError> {
    PackState::new((&snapshot, staged))?;
    let mut result = remote::materialize(keys, template, snapshot)?;
    result.set_conflicts(staged, keys, vault)?;
    Ok(result)
}

#[wasm_bindgen]
pub fn wasm_sync_pack_merge(
    key: Vec<u8>, wrap: Vec<u8>,
    base_head: &[u8], base: &[u8], our_head: &[u8], ours: &[u8], their_head: &[u8], theirs: &[u8],
    base_staged: &[u8], our_staged: &[u8], their_staged: &[u8], local_device: Option<String>, remote_device: Option<String>,
) -> Result<Replayed, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = crate::keys(&key, &wrap)?;
    let base = read_snapshot(&keys, &vault, epoch, base_head, base)?;
    let ours = read_snapshot(&keys, &vault, epoch, our_head, ours)?;
    let theirs = read_snapshot(&keys, &vault, epoch, their_head, theirs)?;
    let (base_staged, our_staged, their_staged) = (Staged::open(&keys, &vault, base_staged)?,
        Staged::open(&keys, &vault, our_staged)?, Staged::open(&keys, &vault, their_staged)?);
    let local_name = device::source(&ours.device_registry, local_device.as_deref(), "本机");
    let remote_name = device::source(&theirs.device_registry, remote_device.as_deref(), "网盘");
    let (snapshot, staged) = merge_packs((&base, &base_staged), (&ours, &our_staged), (&theirs, &their_staged), (&local_name, &remote_name))?;
    Ok(materialize(&keys, &vault, our_head, snapshot, &staged)?)
}

fn update_tombstones(staged: &mut Staged, before: impl IntoIterator<Item = String>, after: &[VaultItem]) {
    let current: BTreeSet<_> = after.iter().map(|item| item.id.as_str()).collect();
    staged.tombstones.extend(before.into_iter().filter(|id| !current.contains(id.as_str())));
    staged.tombstones.retain(|id| !current.contains(id.as_str()));
}

fn restore_pack(
    mut current: VaultSnapshot, mut history: VaultSnapshot, mut staged: Staged, history_stage: &Staged,
) -> Result<(VaultSnapshot, Staged), VaultError> {
    let view = PackState::new((&current, &staged))?;
    PackState::new((&history, history_stage))?;
    if !history_stage.rows.is_empty() || !history_stage.drafts.is_empty() {
        return Err(VaultError::InvalidInput("SyncUnresolvedHistory".into()));
    }
    remote::restore_counters(&current, &mut history, false)?;
    // Retain every row that still awaits review, including a deletion shown in place of an item.
    let held: BTreeSet<_> = view.conflicts.keys().map(|id| (*id).to_owned()).chain(staged.drafts.keys().cloned()).collect();
    history.items.retain(|item| !held.contains(item.id.as_str()));
    let before = current.items.iter().map(|item| item.id.clone()).collect::<Vec<_>>();
    history.items.extend(current.items.drain(..).filter(|item| held.contains(item.id.as_str())));
    current.items = std::mem::take(&mut history.items);
    current.items.sort_by(|a, b| a.id.cmp(&b.id));
    current.hlc_timestamp = current.hlc_timestamp.max(history.hlc_timestamp);
    device::Provenance::read(&current.sync_provenance)?.store(&mut current);
    update_tombstones(&mut staged, before, &current.items);
    Ok((current, staged))
}

#[wasm_bindgen]
pub fn wasm_sync_pack_restore(
    key: Vec<u8>, wrap: Vec<u8>, current_head: &[u8], current: &[u8], history_head: &[u8], history: &[u8],
    current_staged: &[u8], history_staged: &[u8],
) -> Result<Replayed, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = crate::keys(&key, &wrap)?;
    let current = read_snapshot(&keys, &vault, epoch, current_head, current)?;
    let history = read_snapshot(&keys, &vault, epoch, history_head, history)?;
    let (staged, history_staged) = (Staged::open(&keys, &vault, current_staged)?, Staged::open(&keys, &vault, history_staged)?);
    let (snapshot, staged) = restore_pack(current, history, staged, &history_staged)?;
    Ok(materialize(&keys, &vault, current_head, snapshot, &staged)?)
}

fn resolve_pack(
    current: VaultSnapshot, staged: Staged, rules: &str, time: u64,
) -> Result<(VaultSnapshot, Staged), VaultError> {
    PackState::new((&current, &staged))?;
    let counters = merge::CounterLedger::collect(current.items.iter().chain(staged_versions(&staged)))?;
    let before = current.items.iter().map(|item| item.id.clone()).collect::<Vec<_>>();
    let (mut snapshot, mut staged, _) = conflict::resolve_staged(current, staged, rules, time)?;
    let mut items: BTreeMap<_, _> = snapshot.items.drain(..).map(|item| (item.id.clone(), item)).collect();
    let active: BTreeSet<_> = staged.rows.iter().map(|row| row.id.clone()).collect();
    for (id, drafts) in std::mem::take(&mut staged.drafts) {
        if active.contains(&id) {
            staged.drafts.insert(id, drafts);
        } else {
            let mut item = items.remove(&id);
            revisit_drafts(&id, &mut item, &mut staged, drafts)?;
            if let Some(item) = item { items.insert(id, item); }
        }
    }
    snapshot.items = items.into_values().collect();
    apply_counters(&counters, &mut snapshot, &mut staged)?;
    staged.rows.sort_by(|a, b| a.id.cmp(&b.id));
    update_tombstones(&mut staged, before, &snapshot.items);
    Ok((snapshot, staged))
}

#[wasm_bindgen]
pub fn wasm_sync_pack_resolve(
    key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], staged: &[u8], rules: String, time: f64,
) -> Result<Replayed, JsValue> {
    let (key, wrap, rules) = (Zeroizing::new(key), Zeroizing::new(wrap), Zeroizing::new(rules));
    let (vault, epoch, keys) = crate::keys(&key, &wrap)?;
    let snapshot = read_snapshot(&keys, &vault, epoch, head, snap)?;
    let staged = Staged::open(&keys, &vault, staged)?;
    let (snapshot, staged) = resolve_pack(snapshot, staged, &rules, time as u64)?;
    Ok(materialize(&keys, &vault, head, snapshot, &staged)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::model::{CredentialData, LoginCredential};
    use vault_passkeys::{Passkey, bundle};

    fn row(id: &str, title: &str, note: &str) -> VaultItem {
        VaultItem::from_json_str(&format!(
            r#"{{"id":"{id}","title":"{title}","note":"{note}","data":{{"kind":"login","password":"fixture"}}}}"#,
        )).unwrap()
    }

    fn pack(items: Vec<VaultItem>) -> VaultSnapshot {
        let mut snapshot = VaultSnapshot::new_empty("test-vault".into(), "test-snapshot".into(), 0);
        snapshot.items = items;
        snapshot
    }

    fn with_counters(mut item: VaultItem, hotp_count: u64, passkey_count: u32) -> VaultItem {
        let CredentialData::Login(login) = &mut item.data else { panic!() };
        login.totp_uri = Some(format!("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter={hotp_count}"));
        let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        der.extend_from_slice(&[17; 32]);
        let mut key = Passkey::from_pkcs8(vec![3; 32], "example.com".into(), vec![5], "fixture".into(), &der,
            true, true, Some(passkey_count)).unwrap();
        key.count_unverified = false;
        login.passkey_data = bundle::write(&[key]).unwrap();
        item
    }

    fn login(item: &VaultItem) -> &LoginCredential {
        let CredentialData::Login(data) = &item.data else { panic!() };
        data
    }

    #[test]
    fn simultaneous_edits_to_separate_items_and_fields_survive_in_the_same_pack() {
        let base = pack(vec![row("a", "Original", "original-note")]);
        let ours = pack(vec![row("a", "Local title", "original-note"), row("b", "New on A", "")]);
        let theirs = pack(vec![row("a", "Original", "remote-note"), row("c", "New on B", "")]);
        let empty = Staged::default();
        let (merged, staged) = merge_packs((&base, &empty), (&ours, &empty), (&theirs, &empty), ("A", "B")).unwrap();
        let items = crate::batch::indexed(&merged).unwrap();
        assert_eq!(items.keys().copied().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(items["a"].title, "Local title");
        assert_eq!(items["a"].note, "remote-note");
        assert!(staged.rows.is_empty());
    }

    #[test]
    fn third_device_pulls_the_conflict_without_losing_unrelated_edits() {
        use vault_core::crypto::SecretKey;

        let base = pack(vec![row("a", "Original", "")]);
        let ours = pack(vec![row("a", "Title A", ""), row("b", "New on A", "")]);
        let theirs = pack(vec![row("a", "Title B", ""), row("c", "New on B", "")]);
        let empty = Staged::default();
        let (merged, staged) = merge_packs((&base, &empty), (&ours, &empty), (&theirs, &empty), ("A", "B")).unwrap();
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::from_slice(&[7; 32]).unwrap()).unwrap();
        let wire = staged.seal(&keys, &base.vault_id).unwrap();
        let received = Staged::open(&keys, &base.vault_id, &wire).unwrap();
        let (pulled, staged) = merge_packs((&base, &empty), (&base, &empty), (&merged, &received), ("C", "B")).unwrap();
        let shown = crate::batch::indexed(&pulled).unwrap();
        assert_eq!(shown.keys().copied().collect::<Vec<_>>(), ["a", "b", "c"]);
        let [conflict] = staged.rows.as_slice() else { panic!("exactly one row awaits resolution"); };
        assert_eq!(conflict.fields, ["title"]);
        assert_eq!(conflict.ours.as_ref().unwrap().title, "Title A");
        assert_eq!(conflict.theirs.as_ref().unwrap().title, "Title B");
    }

    #[test]
    fn a_permanent_deletion_survives_another_pack_and_contests_an_unseen_edit() {
        let base = pack(vec![row("a", "Original", ""), row("b", "Keep", "")]);
        let deleted = pack(vec![row("b", "Keep", "")]);
        let unseen = pack(vec![row("a", "Changed off-line", ""), row("b", "Keep", "")]);
        let empty = Staged::default();
        let (removed, marker) = merge_packs((&base, &empty), (&deleted, &empty), (&base, &empty), ("A", "B")).unwrap();
        let (carried, marker) = merge_packs((&removed, &marker), (&removed, &marker), (&removed, &marker), ("A", "B")).unwrap();
        let (output, staged) = merge_packs((&deleted, &empty), (&unseen, &empty), (&carried, &marker), ("C", "A")).unwrap();
        let [conflict] = staged.rows.as_slice() else { panic!("an independently deleted identity cannot silently reappear"); };
        assert_eq!(conflict.fields, ["$item"]);
        assert_eq!(conflict.ours.as_ref().unwrap().title, "Changed off-line");
        assert!(conflict.theirs.is_none());
        assert_eq!(output.items[0].title, "Keep");
    }

    #[test]
    fn an_offline_edit_in_a_third_branch_is_still_reviewable_after_the_first_resolution() {
        let base = pack(vec![row("a", "Original", "")]);
        let ours = pack(vec![row("a", "Title A", "")]);
        let theirs = pack(vec![row("a", "Title B", "")]);
        let third = pack(vec![row("a", "Title C", "Note on C"), row("c", "New on C", "")]);
        let empty = Staged::default();
        let (merged, staged) = merge_packs((&base, &empty), (&ours, &empty), (&theirs, &empty), ("A", "B")).unwrap();
        let (combined, pending) = merge_packs((&base, &empty), (&third, &empty), (&merged, &staged), ("C", "B")).unwrap();
        assert_eq!(pending.rows[0].ours.as_ref().unwrap().title, "Title A");
        assert_eq!(pending.draft_count(), 1);
        let rules = r#"[{"id":"a","mode":"ours"}]"#;
        let (reviewed, pending) = resolve_pack(combined, pending, rules, 10).unwrap();
        assert_eq!(pending.rows[0].ours.as_ref().unwrap().title, "Title C");
        assert_eq!(pending.rows[0].theirs.as_ref().unwrap().title, "Title A");
        let (resolved, pending) = resolve_pack(reviewed, pending, rules, 11).unwrap();
        assert!(pending.rows.is_empty());
        assert_eq!(resolved.items[0].title, "Title C");
        assert_eq!(resolved.items[0].note, "Note on C");
        assert_eq!(resolved.items[1].title, "New on C");
    }

    #[test]
    fn waiting_for_a_field_resolution_preserves_the_highest_hotp_and_passkey_counters() {
        let base = pack(vec![with_counters(row("a", "Original", ""), 7, 3)]);
        let ours = pack(vec![with_counters(row("a", "Local title", ""), 12, 9)]);
        let theirs = pack(vec![with_counters(row("a", "Remote title", ""), 10, 7)]);
        let empty = Staged::default();
        let (merged, staged) = merge_packs((&base, &empty), (&ours, &empty), (&theirs, &empty), ("A", "B")).unwrap();
        assert_eq!(staged.rows[0].fields, ["title"]);
        for item in [&merged.items[0], staged.rows[0].theirs.as_ref().unwrap()] {
            let login = login(item);
            assert_eq!(vault_otp::parse(login.totp_uri.as_deref().unwrap()).unwrap().counter, 12);
            assert_eq!(bundle::read(&login.passkey_data).unwrap()[0].count, 9);
        }
        let (resolved, staged) = resolve_pack(merged, staged, r#"[{"id":"a","mode":"theirs"}]"#, 11).unwrap();
        assert!(staged.rows.is_empty());
        assert_eq!(resolved.items[0].title, "Remote title");
        let login = login(&resolved.items[0]);
        assert_eq!(vault_otp::parse(login.totp_uri.as_deref().unwrap()).unwrap().counter, 12);
        assert_eq!(bundle::read(&login.passkey_data).unwrap()[0].count, 9);
    }

    #[test]
    fn history_restores_content_and_keeps_current_counters() {
        let current = pack(vec![with_counters(row("a", "Current title", ""), 12, 9)]);
        let history = pack(vec![with_counters(row("a", "Earlier title", ""), 7, 3)]);
        let (restored, staged) = restore_pack(current, history, Staged::default(), &Staged::default()).unwrap();
        assert!(staged.rows.is_empty());
        assert_eq!(restored.items[0].title, "Earlier title");
        let login = login(&restored.items[0]);
        let otp = vault_otp::parse(login.totp_uri.as_deref().unwrap()).unwrap();
        assert_eq!(otp.counter, 12);
        assert!(!otp.counter_unverified);
        let mut keys = bundle::read(&login.passkey_data).unwrap();
        let key = keys.pop().unwrap();
        assert_eq!(key.count, 9);
        assert!(!key.count_unverified);
    }
}
