use std::collections::{BTreeMap, BTreeSet};
use vault_core::crypto::{FileRole, VaultKeyHierarchy};
use vault_core::error::VaultError;
use vault_core::json_lite::JVal;
use vault_core::model::{VaultItem, generate_uuid_v4};
use vault_core::sync_codec::{MpReader, MsgPackWire, mp_write_array_len, mp_write_bin, mp_write_str, open_compact_object, seal_compact_object};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{batch::{invalid, read_item, write_item}, merge, remote};

pub(crate) struct Conflict {
    pub(crate) id: String,
    pub(crate) fields: Vec<String>,
    pub(crate) base: Option<VaultItem>,
    pub(crate) ours: Option<VaultItem>,
    pub(crate) theirs: Option<VaultItem>,
    pub(crate) receipt: Option<[u8; 32]>,
    pub(crate) sources: Option<(String, String)>,
    pub(crate) additional: Vec<(VaultItem, String)>,
}

pub(crate) struct Draft {
    pub(crate) base: Option<VaultItem>,
    pub(crate) ours: Option<VaultItem>,
}

#[derive(Default)]
pub(crate) struct Staged {
    pub(crate) rows: Vec<Conflict>,
    pub(crate) drafts: BTreeMap<String, Vec<Draft>>,
}

impl MsgPackWire for Staged {
    fn encode_msgpack(&self, out: &mut Vec<u8>) {
        mp_write_array_len(out, self.rows.len() + self.draft_count());
        for row in &self.rows {
            mp_write_array_len(out, if row.additional.is_empty() { 7 } else { 8 });
            mp_write_str(out, &row.id);
            mp_write_array_len(out, row.fields.len());
            for field in &row.fields { mp_write_str(out, field); }
            write_item(out, row.base.as_ref());
            write_item(out, row.ours.as_ref());
            write_item(out, row.theirs.as_ref());
            mp_write_bin(out, row.receipt.as_ref().map_or(&[][..], |bytes| &bytes[..]));
            if let Some((ours, theirs)) = &row.sources {
                mp_write_array_len(out, 2);
                mp_write_str(out, ours);
                mp_write_str(out, theirs);
            } else { mp_write_array_len(out, 0); }
            if !row.additional.is_empty() {
                mp_write_array_len(out, row.additional.len());
                for (item, source) in &row.additional {
                    mp_write_array_len(out, 2);
                    write_item(out, Some(item));
                    mp_write_str(out, source);
                }
            }
        }
        for (id, drafts) in &self.drafts {
            for draft in drafts {
                mp_write_array_len(out, 3);
                mp_write_str(out, id);
                write_item(out, draft.base.as_ref());
                write_item(out, draft.ours.as_ref());
            }
        }
    }
    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        let len = rd.read_array_len();
        if len > 16_384 { return Err(invalid()); }
        let mut rows = Vec::with_capacity(len as usize);
        let mut seen = BTreeSet::new();
        let mut drafts = BTreeMap::<String, Vec<Draft>>::new();
        for _ in 0..len {
            let version = rd.read_array_len();
            if !matches!(version, 3 | 5 | 7 | 8) { return Err(invalid()); }
            let id = rd.read_string();
            if id.is_empty() { return Err(invalid()); }
            if version == 3 {
                let base = read_item(rd)?;
                let ours = read_item(rd)?;
                if merge::same(base.as_ref(), ours.as_ref()) ||
                    base.iter().chain(&ours).any(|item| item.id != id)
                {
                    return Err(invalid());
                }
                drafts.entry(id).or_default().push(Draft { base, ours });
                continue;
            }
            let count = rd.read_array_len();
            if count == 0 || count > 64 || !seen.insert(id.clone()) { return Err(invalid()); }
            let fields: Vec<_> = (0..count).map(|_| rd.read_string()).collect();
            let base = read_item(rd)?;
            let ours = read_item(rd)?;
            let theirs = read_item(rd)?;
            if base.is_none() && ours.is_none() && theirs.is_none() { return Err(invalid()); }
            let (receipt, sources) = if version >= 7 {
                let receipt = rd.read_bin_vec();
                let receipt = if receipt.is_empty() { None } else { Some(receipt.try_into().map_err(|_| invalid())?) };
                let sources = match rd.read_array_len() {
                    0 => None,
                    2 => Some((rd.read_string(), rd.read_string())),
                    _ => return Err(invalid()),
                };
                (receipt, sources)
            } else { (None, None) };
            let mut additional = Vec::new();
            if version == 8 {
                let count = rd.read_array_len();
                let primary = theirs.as_ref().ok_or_else(invalid)?;
                if count == 0 || count > 16_384 || primary.id == id || base.is_some() ||
                    !ours.as_ref().is_some_and(|item| item.id == id) || fields != ["$duplicate"] {
                    return Err(invalid());
                }
                let mut matches = BTreeSet::from([id.clone(), primary.id.clone()]);
                for _ in 0..count {
                    if rd.read_array_len() != 2 { return Err(invalid()); }
                    let item = read_item(rd)?.ok_or_else(invalid)?;
                    let source = rd.read_string();
                    if !matches.insert(item.id.clone()) || source.len() > 240 { return Err(invalid()); }
                    additional.push((item, source));
                }
            }
            rows.push(Conflict { id, fields, base, ours, theirs, receipt, sources, additional });
        }
        rd.finish()?;
        Ok(Self { rows, drafts })
    }
}

impl Staged {
    pub(crate) fn draft_count(&self) -> usize { self.drafts.values().map(Vec::len).sum() }

    pub(crate) fn open(keys: &VaultKeyHierarchy, vault_id: &str, bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.is_empty() { return Ok(Self::default()); }
        open_compact_object(keys.manifest_key(), FileRole::Wal, Some(&format!("conflicts:{vault_id}")), bytes)
    }
    pub(crate) fn seal(&self, keys: &VaultKeyHierarchy, vault_id: &str) -> Result<Vec<u8>, VaultError> {
        if self.rows.is_empty() && self.drafts.is_empty() { return Ok(Vec::new()); }
        if self.rows.len() + self.draft_count() > 16_384 {
            return Err(VaultError::CompactObjectTooLarge);
        }
        seal_compact_object(keys.manifest_key(), FileRole::Wal, &format!("conflicts:{vault_id}"), 1, self)
    }
}

impl Conflict {
    pub(crate) fn labels(&self) -> (&str, &str) {
        self.sources.as_ref().map_or(("本机", "网盘"), |(a, b)| (a.as_str(), b.as_str()))
    }

    pub(crate) fn matches(&self) -> impl Iterator<Item = (&VaultItem, &str)> {
        self.theirs.iter().map(|item| (item, self.labels().1))
            .chain(self.additional.iter().map(|(item, label)| (item, label.as_str())))
    }

    pub(crate) fn affected_ids(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.id.as_str()).chain(self.matches().map(|(item, _)| item.id.as_str()))
    }

    fn sensitive(&self) -> bool {
        self.base.iter().chain(&self.ours).chain(self.matches().map(|(item, _)| item)).any(|item| item.require_reprompt)
    }
    fn json(&self, revealed: bool) -> JVal {
        let permit = !self.sensitive() || revealed;
        let group_fields = ["data.username", "data.uris", "data.password", "data.totpUri"];
        let fields: Vec<&str> = if self.fields == ["$duplicate"] { group_fields.to_vec() }
            else { self.fields.iter().map(String::as_str).collect() };
        let render = |side: Option<&VaultItem>, source: &str| {
            let Some(item) = side else { return JVal::Null; };
            let value = item.to_json_value();
            let field = |name: &str| {
                if !permit || matches!(name, "data.totpUri" | "data.passkeys" | "data.privateKey") {
                    return JVal::Str("未显示".into());
                }
                if matches!(name, "$item" | "$duplicate" | "data") { return JVal::Str(item.title.clone()); }
                if let Some(field) = name.strip_prefix("data.") {
                    if !revealed && matches!(field, "password" | "cvv" | "cardNumber" | "cardPin" | "tokenOrLicense" | "nationalIdOrPassport") {
                        return JVal::Str("••••••••".into());
                    }
                    return value.get_field("data").and_then(|data| data.get_field(field)).cloned().unwrap_or(JVal::Null);
                }
                if name == "customFields" && !revealed { return JVal::Str("未显示".into()); }
                value.get_field(name).cloned().unwrap_or(JVal::Null)
            };
            JVal::Obj(vec![("title", JVal::Str(item.title.clone())), ("time", JVal::Uint(item.updated_at_ms)), ("source", JVal::Str(source.into())),
                ("trashed", JVal::Bool(item.trashed)), ("values", JVal::ParsedObj(fields.iter().map(|&name| (name.into(), field(name))).collect()))])
        };
        JVal::Obj(vec![("id", JVal::Str(self.id.clone())), ("fields", JVal::Arr(self.fields.iter().cloned().map(JVal::Str).collect())),
            ("protected", JVal::Bool(self.sensitive())), ("base", render(self.base.as_ref(), "")), ("ours", render(self.ours.as_ref(), self.labels().0)),
            ("theirs", render(self.theirs.as_ref(), self.labels().1)),
            ("otherMatches", JVal::Arr(self.additional.iter().map(|(item, source)| render(Some(item), source)).collect()))])
    }
}

#[wasm_bindgen]
pub fn wasm_sync_conflicts(key: Vec<u8>, wrap: Vec<u8>, staged: &[u8], revealed: bool) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, _, keys) = super::keys(&key, &wrap)?;
    let staged = Staged::open(&keys, &vault, staged)?;
    Ok(JVal::Arr(staged.rows.iter().map(|row| row.json(revealed)).collect()).stringify())
}

#[wasm_bindgen]
pub fn wasm_sync_conflict_stamp(key: Vec<u8>, wrap: Vec<u8>, staged: &[u8]) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, _, keys) = super::keys(&key, &wrap)?;
    let staged = Staged::open(&keys, &vault, staged)?;
    if staged.rows.is_empty() { return Ok(String::new()); }
    // The encrypted envelope can be resealed without any version changing.
    let mut content = Zeroizing::new(b"webdav:review-stamp:v1\0".to_vec());
    staged.encode_msgpack(&mut content);
    Ok(keys.compute_state_mac(&content).iter().map(|byte| format!("{byte:02x}")).collect())
}

#[wasm_bindgen]
pub fn wasm_sync_guard_staged(
    key: Vec<u8>, wrap: Vec<u8>, current_head: &[u8], current: &[u8], proposed_head: &[u8], proposed: &[u8], staged: &[u8],
) -> Result<(), JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let before = super::verified_snapshot(&keys, &vault, epoch, current_head, current)?;
    let after = super::verified_snapshot(&keys, &vault, epoch, proposed_head, proposed)?;
    let (before, after) = (crate::batch::indexed(&before)?, crate::batch::indexed(&after)?);
    let staged = Staged::open(&keys, &vault, staged)?;
    let ids = staged.drafts.keys().map(String::as_str).chain(staged.rows.iter().flat_map(Conflict::affected_ids));
    for id in ids {
        if !merge::same(before.get(id).copied(), after.get(id).copied()) {
            return Err(VaultError::InvalidInput("SyncConflict".into()).into());
        }
    }
    Ok(())
}

fn suffixed_title(item: &mut VaultItem, source: &str) {
    let suffix = format!("（{}）", &source[..source.floor_char_boundary(240)]);
    let keep = item.title.floor_char_boundary(1024 - suffix.len());
    item.title.truncate(keep);
    item.title.push_str(&suffix);
}

fn resolve_versions(conflict: &Conflict, mode: &str) -> Result<Vec<VaultItem>, VaultError> {
    let local = conflict.ours.as_ref().ok_or_else(invalid)?;
    let versions: Vec<_> = std::iter::once((local, conflict.labels().0)).chain(conflict.matches()).collect();
    if versions.len() < 2 { return Err(invalid()); }
    let mut chosen = Vec::with_capacity(versions.len());
    let protected = conflict.sensitive();
    for (index, &(item, source)) in versions.iter().enumerate() {
        if (mode == "ours" && index != 0) || (mode == "theirs" && index == 0) { continue; }
        let mut item = item.clone();
        if mode == "both" && index != 0 {
            if item.id == local.id { item.id = generate_uuid_v4()?; }
            suffixed_title(&mut item, source);
        }
        let losing: Vec<_> = versions.iter().enumerate().filter_map(|(i, &other)| {
            (index != i && (index == 0 || i == 0)).then_some(other)
        }).collect();
        merge::archive_resolution(&mut item, &losing);
        item.require_reprompt |= protected;
        chosen.push(item);
    }
    merge::preserve_resolution_counters(&mut chosen, versions.iter().map(|(item, _)| *item).chain(&conflict.base))?;
    Ok(chosen)
}

fn resolve_one(conflict: &Conflict, rule: &JVal) -> Result<Vec<VaultItem>, VaultError> {
    let mode = rule.get_str("mode");
    let (base, ours, theirs) = (conflict.base.as_ref(), conflict.ours.as_ref(), conflict.theirs.as_ref());
    let sources = conflict.labels();
    let mut result = if mode == "both" || (matches!(mode.as_str(), "ours" | "theirs") && conflict.fields == ["$duplicate"]) {
        resolve_versions(conflict, &mode)?
    } else {
        let mut choices = merge::Choices::new();
        for field in &conflict.fields {
            let selection = match mode.as_str() {
                "ours" | "theirs" => mode.as_str(),
                "fields" if !field.starts_with('$') =>
                    rule.get_field("fields").and_then(|map| map.get_field(field)).and_then(JVal::as_str).ok_or_else(invalid)?,
                _ => return Err(invalid()),
            };
            if selection != "ours" && selection != "theirs" { return Err(invalid()); }
            choices.insert(field.clone(), selection.to_string());
        }
        merge::item(base, ours, theirs, &choices, sources)?.item.into_iter().collect()
    };
    if let [item] = result.as_mut_slice() {
        if let Some(title) = rule.get_field("title").and_then(JVal::as_str) {
            if title.trim().is_empty() || title.len() > 1024 { return Err(invalid()); }
            item.title = title.to_string();
        }
        if let Some(note) = rule.get_field("note").and_then(JVal::as_str) {
            if note.len() > 65_536 { return Err(invalid()); }
            drop(Zeroizing::new(std::mem::replace(&mut item.note, note.to_string())));
        }
    }
    Ok(result)
}

#[wasm_bindgen]
pub fn wasm_sync_resolve(
    key: Vec<u8>, wrap: Vec<u8>, current_head: &[u8], current: &[u8], staged: &[u8], rules: String, time: f64,
) -> Result<remote::Replayed, JsValue> {
    let (key, wrap, rules) = (Zeroizing::new(key), Zeroizing::new(wrap), Zeroizing::new(rules));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let mut snapshot = super::verified_snapshot(&keys, &vault, epoch, current_head, current)?;
    let staged = Staged::open(&keys, &vault, staged)?;
    let mut items: BTreeMap<_, _> = snapshot.items.drain(..).map(|item| (item.id.clone(), item)).collect();
    let rules = JVal::parse(&rules)?;
    let rules = rules.as_array().filter(|rules| !rules.is_empty() && rules.len() <= staged.rows.len()).ok_or_else(invalid)?;
    let mut selections = BTreeMap::new();
    for rule in rules {
        if selections.insert(rule.get_str("id"), rule).is_some() { return Err(invalid().into()); }
    }
    let mut remaining = Vec::new();
    let mut receipts = Vec::new();
    for row in staged.rows {
        let Some(rule) = selections.remove(&row.id) else { remaining.push(row); continue; };
        let shown_id = row.theirs.as_ref().map_or(row.id.as_str(), |item| &item.id);
        if !merge::same(items.get(shown_id), row.theirs.as_ref()) { return Err(invalid().into()); }
        for (item, _) in &row.additional {
            if !merge::same(items.get(&item.id), Some(item)) { return Err(invalid().into()); }
            items.remove(&item.id);
        }
        if let Some(receipt) = row.receipt { receipts.extend(receipt); }
        items.remove(shown_id);
        items.remove(&row.id);
        for mut item in resolve_one(&row, rule)? {
            item.updated_at_ms = (time as u64).max(item.updated_at_ms);
            item.revision = item.revision.saturating_add(1);
            if items.insert(item.id.clone(), item).is_some() { return Err(invalid().into()); }
        }
    }
    if !selections.is_empty() { return Err(invalid().into()); }
    snapshot.items = items.into_values().collect();
    let pending = Staged { rows: remaining, drafts: staged.drafts };
    let mut result = remote::materialize(&keys, current_head, snapshot)?;
    result.set_conflicts(&pending, &keys, &vault)?;
    result.set_receipts(receipts);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::model::CredentialData;
    use vault_passkeys::{Passkey, bundle};

    #[test]
    fn split_keeps_latest_counter_on_original_and_suspends_the_duplicate() {
        fn version(counter: u64) -> VaultItem {
            let mut item = VaultItem::from_json_str(&format!(
                r#"{{"id":"same","title":"Counter fixture","data":{{"kind":"login","totpUri":"otpauth://hotp/Fixture?secret=JBSWY3DPEHPK3PXP&counter={counter}"}}}}"#
            )).unwrap();
            let CredentialData::Login(login) = &mut item.data else { panic!() };
            let mut key_der = vec![0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
            key_der.extend_from_slice(&[18; 32]);
            let mut key = Passkey::from_pkcs8(vec![2; 32], "example.net".into(), vec![1], "test".into(), &key_der, true, true, None).unwrap();
            key.increment = true;
            key.count = counter as u32;
            login.passkey_data = bundle::write(&[key]).unwrap();
            item
        }
        let row = Conflict { id: "same".into(), base: Some(version(9)), ours: Some(version(12)), theirs: Some(version(29)),
            fields: vec!["data.totpUri".into(), "data.passkeys".into()], receipt: None, sources: None, additional: Vec::new() };
        let split = resolve_one(&row, &JVal::parse(r#"{"mode":"both"}"#).unwrap()).unwrap();
        for (item, paused) in split.iter().zip([false, true]) {
            let CredentialData::Login(login) = &item.data else { panic!() };
            let otp = vault_otp::parse(login.totp_uri.as_deref().unwrap()).unwrap();
            let keys = bundle::read(&login.passkey_data).unwrap();
            assert_eq!((otp.counter, otp.counter_unverified), (29, paused));
            assert_eq!((keys[0].count, keys[0].count_unverified), (29, paused));
        }
        assert_eq!(split[0].id, "same");
    }
}
