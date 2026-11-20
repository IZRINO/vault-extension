use std::collections::{BTreeMap, BTreeSet};
use vault_core::crypto::{FileRole, VaultKeyHierarchy};
use vault_core::error::VaultError;
use vault_core::json_lite::JVal;
use vault_core::model::{CredentialData, VaultItem, generate_uuid_v4};
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

    fn version_json(item: &VaultItem, source: &str, fields: &[&str], permit: bool, revealed: bool) -> JVal {
        let value = item.to_json_value();
        let field = |name: &str| {
            if !permit || matches!(name, "data.totpUri" | "data.passkeys" | "data.privateKey" | "data.passwordHistory") {
                return JVal::Str("未显示".into());
            }
            if matches!(name, "$item" | "$duplicate" | "data") { return JVal::Str(item.title.clone()); }
            if let Some(field) = name.strip_prefix("data.") {
                if !revealed && matches!(field, "password" | "cvv" | "cardNumber" | "cardPin" | "tokenOrLicense" | "nationalIdOrPassport" | "taxId") {
                    return JVal::Str("••••••••".into());
                }
                return value.get_field("data").and_then(|data| data.get_field(field)).cloned().unwrap_or(JVal::Null);
            }
            if name == "customFields" && !revealed { return JVal::Str("未显示".into()); }
            value.get_field(name).cloned().unwrap_or(JVal::Null)
        };
        JVal::Obj(vec![("title", JVal::Str(item.title.clone())), ("time", JVal::Uint(item.updated_at_ms)), ("source", JVal::Str(source.into())),
            ("trashed", JVal::Bool(item.trashed)), ("values", JVal::ParsedObj(fields.iter().map(|&name| (name.into(), field(name))).collect()))])
    }

    fn json(&self, revealed: bool) -> JVal {
        let permit = revealed || !self.sensitive();
        let fields: Vec<&str> = if self.fields == ["$duplicate"] {
            vec!["data.username", "data.uris", "data.password", "data.totpUri"]
        } else { self.fields.iter().map(String::as_str).collect() };
        let render = |side: Option<&VaultItem>, source: &str| {
            side.map_or(JVal::Null, |item| Self::version_json(item, source, &fields, permit, revealed))
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
    let adjustment = |name: &str, limit: usize| {
        rule.get_field(name).map(|value| {
            value.as_str().filter(|value| value.len() <= limit)
                .ok_or_else(|| VaultError::InvalidInput("InvalidResolutionAdjustment".into()))
        }).transpose()
    };
    let title = adjustment("title", 1024)?;
    let note = adjustment("note", 65_536)?;
    let password = adjustment("password", 16_384)?;
    if let [item] = result.as_mut_slice() {
        if let Some(title) = title {
            if title.trim().is_empty() { return Err(VaultError::InvalidInput("InvalidResolutionAdjustment".into())); }
            item.title = title.to_string();
        }
        if let Some(note) = note {
            drop(Zeroizing::new(std::mem::replace(&mut item.note, note.to_string())));
        }
        if let Some(password) = password {
            let CredentialData::Login(login) = &mut item.data else { return Err(invalid()); };
            if item.trashed || password.is_empty() { return Err(invalid()); }
            if login.password != password {
                drop(Zeroizing::new(std::mem::replace(&mut login.password, password.to_string())));
                // Rebuild from the source histories against the final password.
                // The first merge may have archived the value that now wins.
                login.password_history.clear();
                let displaced: Vec<_> = ours.into_iter().map(|item| (item, sources.0))
                    .chain(conflict.matches()).collect();
                merge::archive_resolution(item, &displaced);
            }
        }
    } else if title.is_some() || note.is_some() || password.is_some() {
        return Err(invalid());
    }
    Ok(result)
}

fn selected_rules(rules: &JVal, count: usize) -> Result<BTreeMap<String, &JVal>, VaultError> {
    let rules = rules.as_array().filter(|rules| !rules.is_empty() && rules.len() <= count).ok_or_else(invalid)?;
    let mut selected = BTreeMap::new();
    for rule in rules {
        if selected.insert(rule.get_str("id"), rule).is_some() { return Err(invalid()); }
    }
    Ok(selected)
}

fn preview_resolutions(rows: &[Conflict], rules: &str, revealed: bool) -> Result<JVal, VaultError> {
    let rules = JVal::parse(rules)?;
    let mut selected = selected_rules(&rules, rows.len())?;
    let mut planned = Vec::new();
    for row in rows {
        let Some(rule) = selected.remove(&row.id) else { continue; };
        let items = resolve_one(row, rule)?;
        let can_replace_password = matches!(items.as_slice(), [item] if !item.trashed && matches!(item.data, CredentialData::Login(_)));
        let permit = revealed || !row.sensitive();
        let has_replacement = rule.get_field("password").is_some();
        let collect_item = |item: &VaultItem| {
            let mut fields = vec!["note", "tags"];
            let summary: &[_] = match item.data {
                CredentialData::Login(_) => &["data.username", "data.uris", "data.password"],
                CredentialData::PaymentCard(_) => &["data.cardholderName", "data.cardNumber", "data.brand", "data.expMonth", "data.expYear"],
                CredentialData::Identity(_) => &["data.fullName", "data.email"],
                CredentialData::Developer(_) => &["data.serviceOrProduct"],
            };
            fields.extend(summary);
            for field in &row.fields {
                let field = field.as_str();
                if !matches!(field, "$item" | "$duplicate" | "data" | "title" | "trashed") && !fields.contains(&field) {
                    fields.push(field);
                }
            }
            // The replacement already has a masked input in the review UI.
            fields.retain(|field| *field != "customFields" && (!has_replacement || *field != "data.password"));
            Conflict::version_json(item, "", &fields, permit, revealed)
        };
        planned.push(JVal::Obj(vec![("id", JVal::Str(row.id.clone())), ("canReplacePassword", JVal::Bool(can_replace_password)),
            ("items", JVal::Arr(items.iter().map(collect_item).collect()))]));
    }
    if !selected.is_empty() { return Err(invalid()); }
    Ok(JVal::Arr(planned))
}

#[wasm_bindgen]
pub fn wasm_sync_preview_resolutions(key: Vec<u8>, wrap: Vec<u8>, staged: &[u8], rules: String, revealed: bool) -> Result<String, JsValue> {
    let (key, wrap, rules) = (Zeroizing::new(key), Zeroizing::new(wrap), Zeroizing::new(rules));
    let (vault, _, keys) = super::keys(&key, &wrap)?;
    let staged = Staged::open(&keys, &vault, staged)?;
    Ok(preview_resolutions(&staged.rows, &rules, revealed)?.stringify())
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
    let mut selections = selected_rules(&rules, staged.rows.len())?;
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
    use vault_passkeys::{Passkey, bundle};

    #[test]
    fn preview_shows_automatic_merges_and_redacts_secrets() {
        let mut row = preview_fixture();
        let rules = r#"[{"id":"same","mode":"fields","fields":{"data.password":"ours"}}]"#;
        let preview = preview_resolutions(std::slice::from_ref(&row), rules, false).unwrap().stringify();
        assert!(preview.contains("local-note") && preview.contains("remote-label"));
        assert!(!preview.contains("fixture-password") && !preview.contains("otpauth"));
        row.theirs.as_mut().unwrap().require_reprompt = true;
        let masked = preview_resolutions(std::slice::from_ref(&row), rules, false).unwrap().stringify();
        assert!(!masked.contains("local-note") && !masked.contains("remote-label"));
        let revealed = preview_resolutions(std::slice::from_ref(&row), rules, true).unwrap().stringify();
        assert!(revealed.contains("local-note") && revealed.contains("fixture-password-A"));
        let replaced = preview_resolutions(&[row], r#"[{"id":"same","mode":"ours","password":"replacement-fixture"}]"#, true).unwrap().stringify();
        assert!(!replaced.contains("replacement-fixture") && !replaced.contains("fixture-password"));
    }

    #[test]
    fn manual_password_preserves_both_displaced_versions() {
        let row = preview_fixture();
        let rule = JVal::parse(r#"{"mode":"ours","title":"Edited","note":"","password":" typed verbatim "}"#).unwrap();
        let items = resolve_one(&row, &rule).unwrap();
        let item = &items[0];
        assert_eq!(item.title, "Edited");
        assert!(item.note.is_empty());
        let CredentialData::Login(ref login) = item.data else { panic!() };
        assert_eq!(login.password, " typed verbatim ");
        assert_eq!(login.password_history.iter().map(|entry| {
            (entry.password.as_str(), entry.changed_at_ms, entry.source_device.as_deref())
        }).collect::<Vec<_>>(), vec![
            ("fixture-password-B", 30, Some("Remote")),
            ("fixture-password-A", 20, Some("Local")),
        ]);
    }

    #[test]
    fn manual_password_equal_to_one_side_archives_only_the_other() {
        let row = preview_fixture();
        let rule = JVal::parse(r#"{"mode":"ours","password":"fixture-password-B"}"#).unwrap();
        let items = resolve_one(&row, &rule).unwrap();
        let CredentialData::Login(ref login) = items[0].data else { panic!() };
        assert_eq!(login.password, "fixture-password-B");
        assert_eq!(login.password_history.len(), 1);
        assert_eq!(login.password_history[0].password, "fixture-password-A");
    }

    fn preview_fixture() -> Conflict {
        let version = |password: &str, note: &str, tags: &str, time| VaultItem::from_json_str(&format!(
            r#"{{"id":"same","title":"Fixture","note":"{note}","tags":[{tags}],"updatedAtMs":{time},
                "data":{{"kind":"login","password":"{password}","totpUri":"otpauth://totp/Fixture?secret=JBSWY3DPEHPK3PXP"}}}}"#
        )).unwrap();
        Conflict {
            id: "same".into(), fields: vec!["data.password".into()], receipt: None, additional: Vec::new(),
            base: Some(version("fixture-password-Base", "base-note", "", 10)),
            ours: Some(version("fixture-password-A", "local-note", "", 20)),
            theirs: Some(version("fixture-password-B", "base-note", r#""remote-label""#, 30)),
            sources: Some(("Local".into(), "Remote".into())),
        }
    }

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
