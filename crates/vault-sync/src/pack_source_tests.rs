use crate::{device::Provenance, remote::{self, Replayed}, wasm_sync_conflicts, wasm_sync_pack_merge, wasm_sync_pack_resolve};
use vault_core::{WasmVaultEngine, crypto::KdfParams, json_lite::JVal, model::{DeviceMetadata, VaultItem}, session::initialize_new_vault};

const DESK: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const LAPTOP: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const PHONE: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";

#[test]
fn reconfirming_an_older_clients_unpublished_restore_repairs_only_that_backup_and_keeps_a_pending_review() {
    use crate::conflict::{Conflict, Staged};
    let key = vec![7; 32];
    let params = || KdfParams { m_cost_kib: 32768, t_cost: 2, p_cost: 1, salt: [17; 32] };
    let (head, snap, _, wrap, vault, epoch) = initialize_new_vault(b"fixture-master", params(), &key, 100).unwrap();
    let (_, _, keys) = crate::keys(&key, &wrap).unwrap();
    let mut original = crate::verified_snapshot(&keys, &vault, epoch, &head, &snap).unwrap();
    let login = |id: &str, password: &str| VaultItem::from_json_str(&format!(
        r#"{{"id":"{id}","title":"{id}","data":{{"kind":"login","password":"{password}"}}}}"#)).unwrap();
    original.items = vec![login("from-backup", "restored")];
    let backup = vault_core::sync_codec::export_vaultpack(&original, b"fixture-file-secret", params(), 100).unwrap();
    original.items.push(login("needs-review", "remote"));
    let local = remote::materialize(&keys, &head, original).unwrap();
    let mut staged = Staged::default();
    staged.tombstones.extend(["from-backup".into(), "stay-deleted".into()]);
    staged.rows.push(Conflict { id: "needs-review".into(), fields: vec!["data.password".into()],
        base: Some(login("needs-review", "original")), ours: Some(login("needs-review", "local")), theirs: Some(login("needs-review", "remote")),
        sources: Some(("Desk".into(), "Phone".into())), additional: vec![], receipt: None });
    let saved = staged.seal(&keys, &vault).unwrap();
    let stamp = |wire: &[u8]| crate::wasm_sync_conflicts(key.clone(), wrap.clone(), wire, false).unwrap();
    let import = |head: &[u8], snap: &[u8], staged: &[u8], confirm| crate::wasm_sync_import_pack(key.clone(), wrap.clone(), head, snap,
        backup.clone(), "fixture-file-secret".into(), 200., confirm, Some(staged.to_vec())).unwrap();
    let preview = import(&local.head(), &local.snap(), &saved, false);
    assert_eq!((preview.added(), preview.updated(), preview.skipped()), (0, 1, 0));
    assert!(preview.head().is_empty() && preview.snap().is_empty() && preview.conflicts().is_empty());
    let confirmed = import(&local.head(), &local.snap(), &saved, true);
    let inspection = crate::wasm_sync_pack_inspect(key.clone(), wrap.clone(), &confirmed.head(), &confirmed.snap(), &confirmed.conflicts()).unwrap();
    assert_eq!((inspection.count(), inspection.conflict_count()), (2, 1));
    assert_eq!(stamp(&confirmed.conflicts()), stamp(&saved));
    let repeated = import(&confirmed.head(), &confirmed.snap(), &confirmed.conflicts(), false);
    assert_eq!((repeated.added(), repeated.updated(), repeated.skipped()), (0, 0, 1));
}

#[test]
fn two_remote_authors_in_one_pack_appear_in_review_and_in_the_displaced_password_history() {
    let key = vec![7; 32];
    let (head, snap, _, wrap, vault, epoch) = initialize_new_vault(b"fixture-master",
        KdfParams { m_cost_kib: 32768, t_cost: 2, p_cost: 1, salt: [11; 32] }, &key, 100).unwrap();
    let (_, _, keys) = crate::keys(&key, &wrap).unwrap();
    let mut template = crate::verified_snapshot(&keys, &vault, epoch, &head, &snap).unwrap();
    for (id, label) in [(DESK, "Desk"), (LAPTOP, "Travel laptop"), (PHONE, "Work phone")] {
        template.device_registry.push(DeviceMetadata { device_id: id.into(), device_name: label.into(), dev_tag: id[..8].into(),
            os_arch: String::new(), browser: String::new(), ext_version: String::new(), created_at_ms: 1, last_seen_at_ms: 2 });
    }
    let branch = |rows: [(&str, &str); 2]| {
        let mut snapshot = template.clone();
        let mut provenance = Provenance::default();
        for (id, (password, author)) in ["first", "second"].into_iter().zip(rows) {
            snapshot.items.push(VaultItem::from_json_str(&format!(
                r#"{{"id":"{id}","title":"{id}","data":{{"kind":"login","password":"{password}"}}}}"#)).unwrap());
            provenance.writers.insert(id.into(), author.into());
        }
        provenance.store(&mut snapshot);
        remote::materialize(&keys, &head, snapshot).unwrap()
    };
    let base = branch([("original-1", DESK), ("original-2", DESK)]);
    let local = branch([("desk-1", DESK), ("desk-2", DESK)]);
    let laptop = branch([("laptop-1", LAPTOP), ("original-2", DESK)]);
    let phone = branch([("original-1", DESK), ("phone-2", PHONE)]);
    let merge = |base: &Replayed, local: &Replayed, remote: &Replayed| wasm_sync_pack_merge(key.clone(), wrap.clone(),
        &base.head(), &base.snap(), &local.head(), &local.snap(), &remote.head(), &remote.snap(),
        &base.conflicts(), &local.conflicts(), &remote.conflicts(), None, None).unwrap();
    let combined = merge(&base, &laptop, &phone);
    let fork = merge(&base, &local, &combined);
    let JVal::Arr(ref conflicts) = JVal::parse(&wasm_sync_conflicts(key.clone(), wrap.clone(), &fork.conflicts(), false).unwrap()).unwrap()
        else { panic!("expected conflict summaries"); };
    assert_eq!(conflicts.iter().map(|row| (row.get_str("id"), row.get_field("theirs").unwrap().get_str("source"))).collect::<Vec<_>>(),
        [("first".into(), "Travel laptop".into()), ("second".into(), "Work phone".into())]);
    let resolved = wasm_sync_pack_resolve(key.clone(), wrap.clone(), &fork.head(), &fork.snap(), &fork.conflicts(),
        r#"[{"id":"first","mode":"ours"},{"id":"second","mode":"ours"}]"#.into(), 200.).unwrap();
    let mut engine = WasmVaultEngine::new();
    engine.restore_from_session(&key, &wrap, &resolved.head(), &resolved.snap()).unwrap();
    for (id, password, author) in [("first", "laptop-1", "Travel laptop"), ("second", "phone-2", "Work phone")] {
        let item = VaultItem::from_json_str(&engine.get_item_json(id, true).unwrap()).unwrap();
        let vault_core::model::CredentialData::Login(data) = &item.data else { panic!("expected a login") };
        assert_eq!(data.password_history.iter().map(|entry| (entry.password.as_str(), entry.source_device.as_deref())).collect::<Vec<_>>(),
            [(password, Some(author))]);
    }
    let review_source = |fork: Replayed, id: &str| {
        let rows = JVal::parse(&wasm_sync_conflicts(key.clone(), wrap.clone(), &fork.conflicts(), false).unwrap()).unwrap();
        rows.as_array().unwrap().iter().find(|row| row.get_str("id") == id).unwrap().get_field("theirs").unwrap().get_str("source")
    };
    // The device making a new decision becomes the author of the resulting change.
    let marked = crate::wasm_sync_pack_edit(key.clone(), wrap.clone(), &fork.head(), &fork.snap(),
        &resolved.head(), &resolved.snap(), PHONE, &[]).unwrap().unwrap();
    assert_eq!(review_source(merge(&base, &laptop, &marked), "first"), "Work phone");
    // An explicit historical restore takes the author of the restored value.
    let historical = crate::wasm_sync_pack_restore(key.clone(), wrap.clone(), &laptop.head(), &laptop.snap(),
        &phone.head(), &phone.snap(), &[], &[]).unwrap();
    assert_eq!(review_source(merge(&base, &local, &historical), "second"), "Work phone");
}
