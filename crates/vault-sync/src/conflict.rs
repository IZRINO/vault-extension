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
}

pub(crate) struct Staged(pub(crate) Vec<Conflict>);

impl MsgPackWire for Staged {
    fn encode_msgpack(&self, out: &mut Vec<u8>) {
        mp_write_array_len(out, self.0.len());
        for row in &self.0 {
            mp_write_array_len(out, 7);
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
        }
    }
    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        let len = rd.read_array_len();
        if len > 16_384 { return Err(invalid()); }
        let mut rows = Vec::with_capacity(len as usize);
        let mut seen = BTreeSet::new();
        for _ in 0..len {
            let version = rd.read_array_len();
            if !matches!(version, 5 | 7) { return Err(invalid()); }
            let id = rd.read_string();
            let count = rd.read_array_len();
            if count == 0 || count > 64 || !seen.insert(id.clone()) { return Err(invalid()); }
            let fields = (0..count).map(|_| rd.read_string()).collect();
            let base = read_item(rd)?;
            let ours = read_item(rd)?;
            let theirs = read_item(rd)?;
            if base.is_none() && ours.is_none() && theirs.is_none() { return Err(invalid()); }
            let (receipt, sources) = if version == 7 {
                let receipt = rd.read_bin_vec();
                let receipt = if receipt.is_empty() { None } else { Some(receipt.try_into().map_err(|_| invalid())?) };
                let sources = match rd.read_array_len() {
                    0 => None,
                    2 => Some((rd.read_string(), rd.read_string())),
                    _ => return Err(invalid()),
                };
                (receipt, sources)
            } else { (None, None) };
            rows.push(Conflict { id, fields, base, ours, theirs, receipt, sources });
        }
        rd.finish()?;
        Ok(Self(rows))
    }
}

impl Staged {
    pub(crate) fn open(keys: &VaultKeyHierarchy, vault_id: &str, bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.is_empty() { return Ok(Self(Vec::new())); }
        open_compact_object(keys.manifest_key(), FileRole::Wal, Some(&format!("conflicts:{vault_id}")), bytes)
    }
    pub(crate) fn seal(&self, keys: &VaultKeyHierarchy, vault_id: &str) -> Result<Vec<u8>, VaultError> {
        if self.0.is_empty() { return Ok(Vec::new()); }
        seal_compact_object(keys.manifest_key(), FileRole::Wal, &format!("conflicts:{vault_id}"), 1, self)
    }
}

impl Conflict {
    pub(crate) fn labels(&self) -> (&str, &str) {
        self.sources.as_ref().map_or(("本机", "网盘"), |(a, b)| (a.as_str(), b.as_str()))
    }

    fn sensitive(&self) -> bool {
        [&self.base, &self.ours, &self.theirs].into_iter().flatten().any(|item| item.require_reprompt)
    }
    fn json(&self, revealed: bool) -> JVal {
        let permit = !self.sensitive() || revealed;
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
                ("trashed", JVal::Bool(item.trashed)), ("values", JVal::ParsedObj(self.fields.iter().map(|name| (name.clone(), field(name))).collect()))])
        };
        JVal::Obj(vec![("id", JVal::Str(self.id.clone())), ("fields", JVal::Arr(self.fields.iter().cloned().map(JVal::Str).collect())),
            ("protected", JVal::Bool(self.sensitive())), ("base", render(self.base.as_ref(), "")), ("ours", render(self.ours.as_ref(), self.labels().0)),
            ("theirs", render(self.theirs.as_ref(), self.labels().1))])
    }
}

#[wasm_bindgen]
pub fn wasm_sync_conflicts(key: Vec<u8>, wrap: Vec<u8>, staged: &[u8], revealed: bool) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, _, keys) = super::keys(&key, &wrap)?;
    let staged = Staged::open(&keys, &vault, staged)?;
    Ok(JVal::Arr(staged.0.iter().map(|row| row.json(revealed)).collect()).stringify())
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
    for row in Staged::open(&keys, &vault, staged)?.0 {
        for id in std::iter::once(&row.id).chain(row.theirs.iter().map(|item| &item.id)) {
            if !merge::same(before.get(id.as_str()).copied(), after.get(id.as_str()).copied()) {
                return Err(VaultError::InvalidInput("SyncConflict".into()).into());
            }
        }
    }
    Ok(())
}

fn resolve_one(conflict: &Conflict, rule: &JVal) -> Result<Vec<VaultItem>, VaultError> {
    let mode = rule.get_str("mode");
    let (base, ours, theirs) = (conflict.base.as_ref(), conflict.ours.as_ref(), conflict.theirs.as_ref());
    let sources = conflict.labels();
    if mode == "both" {
        let (Some(mut o), Some(mut t)) = (ours.cloned(), theirs.cloned()) else { return Err(invalid()); };
        if o.id == t.id { o.id = generate_uuid_v4()?; }
        merge::archive_losing(&mut o, &mut t, sources);
        return Ok(vec![o, t]);
    }
    let mut choices = merge::Choices::new();
    for field in &conflict.fields {
        let selection = match mode.as_str() {
            "ours" | "theirs" => mode.as_str(),
            "fields" => rule.get_field("fields").and_then(|map| map.get_field(field)).and_then(JVal::as_str).ok_or_else(invalid)?,
            _ => return Err(invalid()),
        };
        if selection != "ours" && selection != "theirs" { return Err(invalid()); }
        choices.insert(field.clone(), selection.to_string());
    }
    let chosen = if let Some(side) = choices.get("$duplicate") {
        let (Some(mut o), Some(mut t)) = (ours.cloned(), theirs.cloned()) else { return Err(invalid()); };
        merge::archive_losing(&mut o, &mut t, sources);
        if side == "ours" { Some(o) } else { Some(t) }
    } else {
        merge::item(base, ours, theirs, &choices, sources)?.item
    };
    let mut result = Vec::new();
    if let Some(mut item) = chosen {
        if let Some(title) = rule.get_field("title").and_then(JVal::as_str) {
            if title.trim().is_empty() || title.len() > 1024 { return Err(invalid()); }
            item.title = title.to_string();
        }
        if let Some(note) = rule.get_field("note").and_then(JVal::as_str) {
            if note.len() > 65_536 { return Err(invalid()); }
            drop(Zeroizing::new(std::mem::replace(&mut item.note, note.to_string())));
        }
        result.push(item);
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
    let rules = rules.as_array().filter(|rules| !rules.is_empty() && rules.len() <= staged.0.len()).ok_or_else(invalid)?;
    let mut selections = BTreeMap::new();
    for rule in rules {
        if selections.insert(rule.get_str("id"), rule).is_some() { return Err(invalid().into()); }
    }
    let mut remaining = Vec::new();
    let mut receipts = Vec::new();
    for row in staged.0 {
        let Some(rule) = selections.remove(&row.id) else { remaining.push(row); continue; };
        let shown_id = row.theirs.as_ref().map_or(row.id.as_str(), |item| &item.id);
        if !merge::same(items.get(shown_id), row.theirs.as_ref()) { return Err(invalid().into()); }
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
    let pending = Staged(remaining);
    let mut result = remote::materialize(&keys, current_head, snapshot)?;
    result.set_conflicts(pending.seal(&keys, &vault)?, pending.0.len());
    result.set_receipts(receipts);
    Ok(result)
}
