use super::*;
use std::sync::OnceLock;
use vault_core::{crypto::KdfParams, session::initialize_new_vault};

struct Fixture {
    key: Vec<u8>,
    wrap: Vec<u8>,
    head: Vec<u8>,
    empty: VaultSnapshot,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        let key = vec![seed; 32];
        let params = KdfParams { m_cost_kib: 32768, t_cost: 2, p_cost: 1, salt: [seed; 32] };
        let (head, snap, _, wrap, id, epoch) = initialize_new_vault(b"test-only-master", params, &key, 10).unwrap();
        let (_, _, keys) = crate::keys(&key, &wrap).unwrap();
        let empty = crate::verified_snapshot(&keys, &id, epoch, &head, &snap).unwrap();
        Self { key, wrap, head, empty }
    }

    fn with(&self, items: Vec<VaultItem>) -> Replayed {
        let (_, _, keys) = crate::keys(&self.key, &self.wrap).unwrap();
        let mut snapshot = self.empty.clone();
        snapshot.items = items;
        remote::materialize(&keys, &self.head, snapshot).unwrap()
    }

    fn merge(&self, base: &Replayed, ours: &Replayed, theirs: &Replayed) -> Replayed {
        wasm_sync_pack_merge(self.key.clone(), self.wrap.clone(), &base.head(), &base.snap(),
            &ours.head(), &ours.snap(), &theirs.head(), &theirs.snap(),
            &base.conflicts(), &ours.conflicts(), &theirs.conflicts(), None, None).unwrap()
    }

    fn stamp(&self, result: &Replayed) -> String {
        crate::wasm_sync_conflict_stamp(self.key.clone(), self.wrap.clone(), &result.conflicts()).unwrap()
    }

    fn adopt(&self, source: &Fixture, local: &Replayed, target: &Replayed) -> Replayed {
        wasm_sync_pack_adopt(source.key.clone(), source.wrap.clone(), &local.head(), &local.snap(),
            self.key.clone(), self.wrap.clone(), &target.head(), &target.snap(), &target.conflicts()).unwrap()
    }

    fn inspect(&self, state: &Replayed) -> PackInspection {
        wasm_sync_pack_inspect(self.key.clone(), self.wrap.clone(), &state.head(), &state.snap(), &state.conflicts()).unwrap()
    }

    fn resolve(&self, state: &Replayed, id: &str, mode: &str) -> Replayed {
        let rules = format!(r#"[{{"id":"{id}","mode":"{mode}"}}]"#);
        crate::wasm_sync_preview_resolutions(self.key.clone(), self.wrap.clone(), &state.conflicts(), rules.clone(), false).unwrap();
        wasm_sync_pack_resolve(self.key.clone(), self.wrap.clone(), &state.head(), &state.snap(), &state.conflicts(), rules, 20.).unwrap()
    }

    fn snapshot(&self, state: &Replayed) -> VaultSnapshot {
        let (vault, epoch, keys) = crate::keys(&self.key, &self.wrap).unwrap();
        crate::verified_snapshot(&keys, &vault, epoch, &state.head(), &state.snap()).unwrap()
    }
}

fn vaults() -> (&'static Fixture, &'static Fixture) {
    static SOURCE: OnceLock<Fixture> = OnceLock::new();
    static TARGET: OnceLock<Fixture> = OnceLock::new();
    (SOURCE.get_or_init(|| Fixture::new(74)), TARGET.get_or_init(|| Fixture::new(75)))
}

fn item(id: &str, title: &str) -> VaultItem {
    VaultItem::from_json_str(&format!(r#"{{"id":"{id}","title":"{title}","data":{{"kind":"login"}}}}"#)).unwrap()
}

fn login(id: &str, password: &str) -> VaultItem {
    VaultItem::from_json_str(&format!(r#"{{"id":"{id}","title":"Login {id}","data":{{"kind":"login","username":"test-user",
        "uris":[{{"uri":"https://{id}.example.com"}}],"password":"{password}"}}}}"#)).unwrap()
}

#[test]
fn adopting_into_an_existing_pack_preserves_its_unreviewed_edits_drafts_and_deletions() {
    let (source, target) = vaults();
    let base = target.with(vec![item("edited", "Original"), item("deleted", "Removed later")]);
    let first = target.with(vec![item("edited", "First change")]);
    let second = target.with(vec![item("edited", "Second change"), item("deleted", "Removed later")]);
    let third = target.with(vec![item("edited", "Third change"), item("deleted", "Removed later")]);
    let fork = target.merge(&base, &first, &second);
    let pending = target.merge(&base, &third, &fork);
    assert_eq!((pending.conflict_count(), pending.draft_count()), (1, 1));
    let joined = target.adopt(source, &source.with(vec![item("new", "Separate credential")]), &pending);
    assert_eq!((joined.count(), joined.conflict_count(), joined.draft_count()), (2, 1, 1));
    assert_eq!(target.stamp(&joined), target.stamp(&pending));
}

#[test]
fn adopting_duplicate_logins_previews_all_candidates_and_keeps_the_selected_versions() {
    let (source, target) = vaults();
    let local = source.with(vec![login("ours", "local-fixture")]);
    let remote = target.with(vec![login("a", "remote-fixture-a"), login("b", "remote-fixture-b"), item("keep", "Keep")]);
    let joined = target.adopt(source, &local, &remote);
    assert_eq!(joined.conflict_count(), 1);
    assert_eq!(target.inspect(&joined).count(), 3);
    let preview = crate::wasm_sync_conflicts(target.key.clone(), target.wrap.clone(), &joined.conflicts(), false).unwrap();
    assert!(preview.contains("$duplicate") && preview.contains("Login a") && preview.contains("Login b"));
    assert!(!preview.contains("local-fixture") && !preview.contains("remote-fixture"));
    for (mode, expected) in [("ours", vec!["keep", "ours"]), ("theirs", vec!["a", "b", "keep"]),
                             ("both", vec!["a", "b", "keep", "ours"])] {
        let chosen = target.resolve(&joined, "ours", mode);
        assert_eq!(target.inspect(&chosen).conflict_count(), 0);
        let snap = target.snapshot(&chosen);
        assert_eq!(snap.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), expected);
        let retained = snap.items.iter().find(|item| item.id == if mode == "theirs" { "a" } else { "ours" }).unwrap();
        let vault_core::model::CredentialData::Login(login) = &retained.data else { panic!() };
        assert_eq!(login.password_history.len(), if mode == "theirs" { 1 } else { 2 });
        let repeated = target.merge(&joined, &joined, &chosen);
        assert_eq!(target.inspect(&repeated).conflict_count(), 0);
        assert_eq!(repeated.count(), chosen.count());
    }
}

#[test]
fn offline_duplicate_logins_preserve_a_third_devices_edit_to_the_displayed_candidate() {
    let (_, target) = vaults();
    let base = target.with(vec![item("initial", "Original")]);
    let a = target.with(vec![item("initial", "Original"), login("a", "first-fixture")]);
    let b = target.with(vec![item("initial", "Original"), login("b", "second-fixture")]);
    let pending = target.merge(&base, &a, &b);
    assert_eq!(target.inspect(&pending).conflict_count(), 1);
    let mut edited_b = login("b", "newer-offline-fixture");
    edited_b.note = "Independent offline edit".into();
    let third = target.with(vec![item("initial", "Original"), edited_b, item("extra", "Separate credential")]);
    let pulled = target.merge(&b, &third, &pending);
    assert_eq!((target.inspect(&pulled).conflict_count(), pulled.draft_count()), (1, 1));
    let preview = crate::wasm_sync_conflicts(target.key.clone(), target.wrap.clone(), &pulled.conflicts(), true).unwrap();
    assert!(preview.contains("second-fixture"));
    let reviewed = target.resolve(&pulled, "a", "ours");
    assert_eq!(target.inspect(&reviewed).conflict_count(), 1);
    let complete = target.resolve(&reviewed, "b", "ours");
    let snap = target.snapshot(&complete);
    assert_eq!(snap.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["a", "b", "extra", "initial"]);
    assert_eq!(snap.items[1].note, "Independent offline edit");
    assert_eq!(target.inspect(&complete).conflict_count(), 0);
}

#[test]
fn every_incoming_login_with_an_overlapping_candidate_can_be_reviewed_in_turn() {
    let (source, target) = vaults();
    let local = source.with(vec![login("a", "first"), login("c", "other")]);
    let remote = target.with(vec![login("b", "target")]);
    let joined = target.adopt(source, &local, &remote);
    let counts = target.inspect(&joined);
    assert_eq!((counts.count(), counts.conflict_count(), counts.draft_count()), (1, 1, 1));
    let base = target.with(vec![]);
    let elsewhere = target.merge(&base, &base, &joined);
    let next = target.resolve(&elsewhere, "a", "theirs");
    assert_eq!((target.inspect(&next).conflict_count(), next.draft_count()), (1, 0));
    let reviewed = target.resolve(&next, "c", "both");
    let snap = target.snapshot(&reviewed);
    assert_eq!(snap.items.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(), ["b", "c"]);
    assert_eq!(target.inspect(&reviewed).conflict_count(), 0);
}

#[test]
fn separately_reviewed_forks_that_share_a_candidate_keep_both_decisions_available() {
    let (_, target) = vaults();
    let empty = target.with(vec![]);
    let b = target.with(vec![login("b", "target")]);
    let ab = target.merge(&empty, &target.with(vec![login("a", "first")]), &b);
    let cb = target.merge(&empty, &target.with(vec![login("c", "other")]), &b);
    let (vault, _, keys) = crate::keys(&target.key, &target.wrap).unwrap();
    let open = |wire: &Replayed| (target.snapshot(wire), Staged::open(&keys, &vault, &wire.conflicts()).unwrap());
    let (base, left, right) = (open(&b), open(&ab), open(&cb));
    let (snapshot, stage) = merge_packs((&base.0, &base.1), (&left.0, &left.1), (&right.0, &right.1), ("A", "C")).unwrap();
    let joined = materialize(&keys, &vault, &b.head(), snapshot, &stage).unwrap();
    assert_eq!((target.inspect(&joined).conflict_count(), joined.draft_count()), (1, 1));
    let next = target.resolve(&joined, "c", "theirs");
    let chosen = target.resolve(&next, "a", "ours");
    assert_eq!(target.inspect(&chosen).count(), 1);
    assert_eq!(target.snapshot(&chosen).items[0].id, "a");
}

#[test]
fn a_duplicate_decision_that_arrives_before_an_unseen_draft_still_preserves_that_edit() {
    let (_, target) = vaults();
    let empty = target.with(vec![]);
    let a = target.with(vec![login("a", "first")]);
    let b = target.with(vec![login("b", "target")]);
    let pending = target.merge(&empty, &a, &b);
    let reviewed = target.resolve(&pending, "a", "ours");
    let draft = target.merge(&b, &target.with(vec![login("b", "new-offline-value")]), &pending);
    let combined = target.merge(&pending, &reviewed, &draft);
    let details = crate::wasm_sync_conflicts(target.key.clone(), target.wrap.clone(), &combined.conflicts(), true).unwrap();
    let final_state = target.resolve(&combined, "b", "ours");
    let snapshot = target.snapshot(&final_state);
    let restored = snapshot.items.iter().find(|item| item.id == "b").expect("offline version remains available");
    let vault_core::model::CredentialData::Login(login) = &restored.data else { panic!() };
    assert_eq!(login.password, "new-offline-value");
    assert!(!details.contains("$duplicate"));
}

#[test]
fn adoption_checks_a_hidden_target_candidate_even_when_the_displayed_password_matches() {
    let (source, target) = vaults();
    let base = target.with(vec![]);
    let pending = target.merge(&base, &target.with(vec![login("a", "hidden")]), &target.with(vec![login("b", "shown")]));
    let adopted = target.adopt(source, &source.with(vec![login("c", "shown")]), &pending);
    assert_eq!((target.inspect(&adopted).count(), adopted.draft_count()), (1, 1));
    let first = target.resolve(&adopted, "a", "ours");
    assert_eq!(target.inspect(&first).conflict_count(), 1);
    let second = target.resolve(&first, "c", "both");
    assert_eq!(target.inspect(&second).count(), 2);
}

#[test]
fn duplicate_preview_names_the_actual_device_of_each_candidate() {
    let (_, target) = vaults();
    let base = target.with(vec![]);
    let add = |before: &Replayed, id: &str, device: &str, label: &str| {
        let mut snapshot = target.snapshot(before);
        snapshot.items.push(login(id, id));
        let (_, _, keys) = crate::keys(&target.key, &target.wrap).unwrap();
        let after = remote::materialize(&keys, &before.head(), snapshot).unwrap();
        let tracked = crate::wasm_sync_device_change(target.key.clone(), target.wrap.clone(), &after.head(), &after.snap(),
            format!(r#"{{"action":"track","id":"{device}","tag":"12ab34cd","name":"{label}","time":10}}"#)).unwrap();
        crate::wasm_sync_pack_edit(target.key.clone(), target.wrap.clone(), &before.head(), &before.snap(),
            &tracked.head(), &tracked.snap(), device, &[]).unwrap().unwrap()
    };
    let left = add(&base, "a", "00000000-0000-0000-0000-000000000001", "Office");
    let right = add(&base, "b", "00000000-0000-0000-0000-000000000002", "Home");
    let right = add(&right, "c", "00000000-0000-0000-0000-000000000003", "Travel");
    let pending = target.merge(&base, &left, &right);
    let details = crate::wasm_sync_conflicts(target.key.clone(), target.wrap.clone(), &pending.conflicts(), false).unwrap();
    let json = vault_core::json_lite::JVal::parse(&details).unwrap();
    let row = &json.as_array().unwrap()[0];
    assert_eq!(row.get_field("ours").unwrap().get_str("source"), "Office");
    assert_eq!(row.get_field("theirs").unwrap().get_str("source"), "Home");
    assert_eq!(row.get_field("otherMatches").unwrap().as_array().unwrap()[0].get_str("source"), "Travel");
}

#[test]
fn authenticated_legacy_duplicate_groups_are_reviewable_and_mismatched_candidate_snapshots_are_rejected() {
    let (source, target) = vaults();
    let ours = source.with(vec![login("local", "local-fixture")]);
    let theirs = target.with(vec![login("a", "remote-a"), login("b", "remote-b")]);
    let old = crate::wasm_sync_adopt(source.key.clone(), source.wrap.clone(), &ours.head(), &ours.snap(),
        target.key.clone(), target.wrap.clone(), &theirs.head(), &theirs.snap(), &[]).unwrap();
    assert_eq!(target.inspect(&old).conflict_count(), 1);
    assert_eq!(target.resolve(&old, "local", "both").count(), 3);
    let (vault, _, keys) = crate::keys(&target.key, &target.wrap).unwrap();
    let stage = Staged::open(&keys, &vault, &old.conflicts()).unwrap();
    for changed in [vec![login("a", "remote-a")], vec![login("a", "remote-a"), login("b", "different")],
                    vec![login("a", "remote-a"), login("b", "remote-b"), login("local", "local-fixture")]] {
        let snapshot = target.snapshot(&target.with(changed));
        assert!(materialize(&keys, &vault, &old.head(), snapshot, &stage).is_err());
    }
}

#[test]
fn an_incoming_offline_login_waits_when_the_existing_review_is_on_the_local_branch() {
    let (_, target) = vaults();
    let base = target.with(vec![]);
    let local = target.merge(&base, &target.with(vec![login("a", "hidden")]), &target.with(vec![login("b", "shown")]));
    let remote = target.with(vec![login("c", "shown")]);
    let combined = target.merge(&base, &local, &remote);
    assert_eq!((target.inspect(&combined).count(), combined.draft_count()), (1, 1));
    let first = target.resolve(&combined, "a", "ours");
    assert_eq!(target.inspect(&first).conflict_count(), 1);
    assert_eq!(target.resolve(&first, "c", "ours").count(), 1);
}
