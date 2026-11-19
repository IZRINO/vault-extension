use crate::batch;
use vault_core::{
    crypto::{SecretKey, VaultKeyHierarchy},
    model::{CustomField, VaultItem, VaultSnapshot},
    sync_codec::{open_snapshot, seal_snapshot},
};

fn text(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    let (mut acc, mut bits) = (0u16, 0u8);
    for &byte in bytes {
        acc = (acc << 8) | u16::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            result.push(ALPHABET[((acc >> bits) & 63) as usize] as char);
        }
    }
    if bits != 0 { result.push(ALPHABET[((acc << (6 - bits)) & 63) as usize] as char); }
    result
}

#[test]
fn one_thousand_complete_records_and_one_changed_wal_size() {
    let keys = VaultKeyHierarchy::from_master_dek(SecretKey::from_bytes([167; 32])).unwrap();
    let mut snap = VaultSnapshot::new_empty("size-fixture".into(), "snap_00000000001000_09abcd11_00000000000001".into(), 0);
    for index in 0..1_000u32 {
        let pseudorandom = keys.compute_state_mac(&index.to_be_bytes());
        let old = keys.compute_state_mac(&[b"old:".as_slice(), &index.to_be_bytes()].concat());
        let otp = pseudorandom[..16].iter().map(|byte| b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(byte & 31) as usize] as char).collect::<String>();
        let mut item = VaultItem::from_json_str(&format!(
            r#"{{"id":"768d7906-32d7-4696-92be-{index:012x}","title":"Test account {index}","data":{{"kind":"login","username":"employee{index}@example.test","password":"{}","uris":[{{"uri":"https://portal{}.example.test/login"}}],"totpUri":"otpauth://totp/Example:employee{index}?secret={otp}&issuer=Example","passwordHistory":[{{"password":"{}","changedAtMs":1700720000000,"sourceDevice":"Fixture Edge"}}]}},"note":"Synthetic account for device sync with a recovery contact.","tags":["work","example"],"updatedAtMs":1700700000000,"revision":2}}"#,
            text(&pseudorandom[..18]), index % 50, text(&old[..18])
        )).unwrap();
        item.custom_fields.push(CustomField { name: "fixture-key-32".into(), value: text(&old), hidden: true });
        snap.items.push(item);
    }
    let encrypted = seal_snapshot(&keys, &mut snap).unwrap();
    let mut edited = snap.clone();
    edited.items[593].note = "Local note changed on one fixture".into();
    edited.items[593].revision += 1;
    let id = "00000000002000_09abcd11_00000000000002";
    let wal = batch::seal_batch(&keys, id, "9bba890e-b0ca-4882-a562-4e86c9b66a15", &snap, &snap, &edited, &[]).unwrap();
    println!("1,000 credentials encrypted snapshot: {} B; 1 changed credential encrypted WAL: {} B", encrypted.len(), wal.len());
    assert!(encrypted.len() <= 240_000);
    assert!(wal.len() <= 600);
    assert_eq!(open_snapshot(&keys, Some(&snap.snapshot_id), &encrypted).unwrap().items, snap.items);
    assert_eq!(batch::open_batch(&keys, &snap.vault_id, id, &wal).unwrap().edits[0].after, Some(edited.items[593].clone()));
}
