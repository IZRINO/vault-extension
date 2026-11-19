use crate::bitwarden::{self, META, SecretJson, text};
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64}};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use vault_core::{crypto::csprng_fill, model::{CredentialData, CustomField, VaultItem, VaultSnapshot, generate_uuid_v4}};
use vault_passkeys::{Passkey, bundle, sealed::{open_vault, seal_vault}};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

pub(crate) type MappingError = &'static str;
type Result<T> = std::result::Result<T, MappingError>;
pub(crate) const INVALID: MappingError = "来源文件无效、损坏或超过处理限制。";
pub(crate) const LIMIT: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 5000;
const SOURCE: &str = "Vault 迁移来源";

#[derive(Default)]
pub(crate) struct Batch {
    records: Vec<VaultItem>,
    pub(crate) invalid: usize,
    pub(crate) unsupported: usize,
    pub(crate) ignored_otp: usize,
    pub(crate) ignored_passkeys: usize,
}

pub(crate) fn json_from_bytes(bytes: &[u8]) -> Result<SecretJson> {
    if bytes.is_empty() || bytes.len() > LIMIT { return Err(INVALID); }
    serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes)).map(SecretJson).map_err(|_| INVALID)
}
pub(crate) fn rows(value: &Value) -> Result<&[Value]> {
    value.as_array().map(Vec::as_slice).filter(|rows| rows.len() <= MAX_ROWS).ok_or(INVALID)
}
pub(crate) fn valid_web_url(url: &str) -> bool {
    url.len() <= 4096 && url.split_once("://").is_some_and(|(scheme, rest)| matches!(scheme, "https" | "http") &&
        !rest.is_empty() && !rest.contains(|ch: char| ch.is_control()))
}
pub(crate) fn secret_bytes(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    if raw.len() > 4096 { return Err(INVALID); }
    let pem = Zeroizing::new(raw.lines().filter(|s| !s.starts_with("-----")).collect::<String>());
    let raw = raw.strip_prefix("b64.").unwrap_or(&pem);
    B64.decode(raw).or_else(|_| STANDARD.decode(raw)).map(Zeroizing::new).map_err(|_| INVALID)
}
pub(crate) fn id_bytes(value: &str) -> Result<Vec<u8>> {
    let compact = value.replace('-', "");
    if value.len() == 36 && compact.len() == 32 && compact.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        hex::decode(compact).map_err(|_| INVALID)
    } else { secret_bytes(value).map(|mut bytes| std::mem::take(&mut *bytes)) }
}
pub(crate) fn add_record(batch: &mut Batch, value: &Value, keys: Vec<Passkey>, kind: &str, source: &str) -> Result<()> {
    if batch.records.len() >= MAX_ROWS { return Err(INVALID); }
    if text(value, "title").trim().is_empty() || text(value, "title").len() > 2048 || value["note"].as_str().is_some_and(|note| note.len() > 128 * 1024) {
        batch.invalid += 1;
        return Ok(());
    }
    let mut row = match VaultItem::from_json_str(&Zeroizing::new(value.to_string())) {
        Ok(record) => record,
        Err(_) => { batch.invalid += 1; return Ok(()); },
    };
    row.normalize_derived_fields();
    if let CredentialData::Login(login) = &mut row.data {
        if keys.len() > bundle::MAX_KEYS { return Err(INVALID); }
        login.passkey_data = bundle::write(&keys)?;
    }
    if !source.is_empty() {
        row.custom_fields.push(CustomField { name: SOURCE.to_owned(), value: format!("{kind}:{}", hex::encode(Sha256::digest(source))), hidden: true });
    }
    batch.records.push(row);
    Ok(())
}

fn metadata(row: &VaultItem) -> Result<SecretJson> {
    match row.custom_fields.iter().find(|field| field.name == META) {
        Some(field) => serde_json::from_str(&field.value).map(SecretJson).map_err(|_| INVALID),
        None => Ok(SecretJson(Value::Null)),
    }
}
fn bitwarden_key(record: &Value) -> Result<Passkey> {
    if !matches!(text(record, "keyType"), "" | "public-key") { return Err(INVALID); }
    let der = secret_bytes(text(record, "keyValue"))?;
    let count = record["counter"].as_u64().or_else(|| text(record, "counter").parse().ok()).unwrap_or(0);
    let counter = if count > 0 { Some(u32::try_from(count).map_err(|_| INVALID)?) } else { None };
    let key = Passkey::from_pkcs8(id_bytes(text(record, "credentialId"))?, text(record, "rpId").into(),
        id_bytes(text(record, "userHandle"))?, text(record, "userName").into(), &der,
        record["discoverable"].as_bool().unwrap_or(text(record, "discoverable") != "false"), true, counter)?;
    let declared = text(record, "keyAlgorithm");
    if declared.eq_ignore_ascii_case("ECDSA") && key.algorithm != -7 || declared.eq_ignore_ascii_case("EdDSA") && key.algorithm != -8 { return Err(INVALID); }
    Ok(key)
}
fn enrich_bitwarden(row: &mut VaultItem, batch: &mut Batch, clear_mapped: bool) -> Result<()> {
    let mut meta = metadata(row)?;
    let Some(raw_keys) = meta.0["extra"]["login"]["fido2Credentials"].as_array_mut() else { return Ok(()); };
    let CredentialData::Login(login) = &mut row.data else { return Ok(()); };
    let mut keys = bundle::read(&login.passkey_data)?;
    raw_keys.retain(|raw| {
        match bitwarden_key(raw) {
            Ok(key) if keys.len() < bundle::MAX_KEYS => {
                if !keys.iter().any(|old| old.rp_id == key.rp_id && old.credential_id == key.credential_id) { keys.push(key); }
                !clear_mapped
            }
            _ => { batch.ignored_passkeys += 1; true },
        }
    });
    drop(Zeroizing::new(std::mem::replace(&mut login.passkey_data, bundle::write(&keys)?)));
    if let Some(field) = row.custom_fields.iter_mut().find(|field| field.name == META) {
        drop(Zeroizing::new(std::mem::replace(&mut field.value, meta.0.to_string())));
    }
    Ok(())
}
fn read_bitwarden(bytes: &[u8], password: &str) -> Result<Batch> {
    let raw = Zeroizing::new(bitwarden::import(bytes, password)?);
    let json = json_from_bytes(raw.as_bytes())?;
    let mut batch = Batch {
        invalid: json.0["invalid"].as_u64().unwrap_or(0) as usize,
        unsupported: json.0["unsupported"].as_u64().unwrap_or(0) as usize,
        ignored_otp: json.0["ignoredOtp"].as_u64().unwrap_or(0) as usize, ..Default::default()
    };
    for input in rows(&json.0["rows"])? {
        let mut row = VaultItem::from_json_str(&Zeroizing::new(input.to_string())).map_err(|_| INVALID)?;
        enrich_bitwarden(&mut row, &mut batch, true)?;
        batch.records.push(row);
    }
    Ok(batch)
}
fn retained_bitwarden(vault: &VaultSnapshot) -> Result<Batch> {
    let mut batch = Batch::default();
    for existing in &vault.items {
        if !existing.custom_fields.iter().any(|field| field.name == META) { continue; }
        let mut row = existing.clone();
        enrich_bitwarden(&mut row, &mut batch, true)?;
        if row.data != existing.data { batch.records.push(row); }
    }
    Ok(batch)
}
fn source_key(row: &VaultItem) -> Option<String> {
    if let Some(field) = row.custom_fields.iter().find(|field| field.name == SOURCE) { return Some(field.value.clone()); }
    let meta = metadata(row).ok()?;
    let id = text(&meta.0, "sourceId");
    (!id.is_empty()).then(|| format!("bitwarden:{id}"))
}
fn signature(row: &VaultItem) -> [u8; 32] {
    let json = row.to_json_value();
    let data = Zeroizing::new(json.get_field("data").map(|value| value.stringify()).unwrap_or_default());
    let mut hash = Sha256::new();
    for value in [&*data, &row.title, &row.note] {
        hash.update(value.len().to_le_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Preview { ready: usize, skipped: usize, invalid: usize, unsupported: usize, ignored_otp: usize, passkeys: usize,
    suspended_passkeys: usize, ignored_passkeys: usize, sample: Vec<Sample> }
#[derive(Serialize)]
struct Sample { title: String, kind: &'static str, account: String }

fn apply(vault: &mut VaultSnapshot, mut batch: Batch, now: u64) -> Result<Preview> {
    let mut report = Preview { invalid: batch.invalid, unsupported: batch.unsupported, ignored_otp: batch.ignored_otp, ignored_passkeys: batch.ignored_passkeys, ..Default::default() };
    let mut sources = BTreeMap::new();
    let mut signatures = BTreeMap::new();
    let mut ids = BTreeMap::new();
    let mut known_keys = BTreeSet::new();
    let mut hotp = BTreeSet::new();
    for (index, row) in vault.items.iter().enumerate() {
        if let Some(id) = source_key(row) { sources.insert(id, index); }
        signatures.insert(signature(row), index);
        ids.insert(row.id.clone(), index);
        if let CredentialData::Login(login) = &row.data {
            for key in bundle::read(&login.passkey_data)? { known_keys.insert((key.rp_id.clone(), key.credential_id.clone())); }
            let otp = login.totp_uri.as_deref().and_then(|uri| vault_otp::parse(uri).ok()).filter(|otp| otp.kind == vault_otp::Kind::Hotp);
            if let Some(otp) = otp { hotp.insert(otp.identity()); }
        }
    }
    for mut row in batch.records.drain(..) {
        let index = ids.get(&row.id).copied().or_else(|| source_key(&row).and_then(|id| sources.get(&id).copied()))
            .or_else(|| signatures.get(&signature(&row)).copied());
        let mut incoming = match &row.data {
            CredentialData::Login(login) => bundle::read(&login.passkey_data)?,
            _ => Vec::new(),
        };
        incoming.retain(|key| !known_keys.contains(&(key.rp_id.clone(), key.credential_id.clone())));
        if let Some(index) = index {
            if incoming.is_empty() { report.skipped += 1; continue; }
            let existing = &mut vault.items[index];
            let CredentialData::Login(login) = &mut existing.data else { report.ignored_passkeys += incoming.len(); continue; };
            let mut keys = bundle::read(&login.passkey_data)?;
            if keys.len() + incoming.len() > bundle::MAX_KEYS { return Err(INVALID); }
            count_keys(&mut report, &incoming);
            for key in &incoming { known_keys.insert((key.rp_id.clone(), key.credential_id.clone())); }
            keys.append(&mut incoming);
            drop(Zeroizing::new(std::mem::replace(&mut login.passkey_data, bundle::write(&keys)?)));
            if row.id == existing.id {
                if let Some(updated) = row.custom_fields.iter().find(|field| field.name == META) {
                    if let Some(field) = existing.custom_fields.iter_mut().find(|field| field.name == META) {
                        drop(Zeroizing::new(std::mem::replace(&mut field.value, updated.value.clone())));
                    }
                }
            }
            existing.updated_at_ms = existing.updated_at_ms.max(now);
            existing.revision = existing.revision.saturating_add(1);
            record_sample(&mut report, existing);
            continue;
        }
        if let CredentialData::Login(login) = &mut row.data {
            let otp = login.totp_uri.as_deref().and_then(|uri| vault_otp::parse(uri).ok()).filter(|otp| otp.kind == vault_otp::Kind::Hotp);
            if let Some(otp) = otp { if !hotp.insert(otp.identity()) { report.skipped += 1; continue; } }
            if incoming.is_empty() && login.password.is_empty() && login.totp_uri.is_none() && !login.passkey_data.is_empty() {
                report.skipped += 1; continue;
            }
            drop(Zeroizing::new(std::mem::replace(&mut login.passkey_data, bundle::write(&incoming)?)));
        }
        count_keys(&mut report, &incoming);
        for key in incoming { known_keys.insert((key.rp_id.clone(), key.credential_id.clone())); }
        row.id = generate_uuid_v4().map_err(|_| INVALID)?;
        if row.created_at_ms == 0 { row.created_at_ms = now; }
        if row.updated_at_ms == 0 { row.updated_at_ms = now; }
        if let Some(id) = source_key(&row) { sources.insert(id, vault.items.len()); }
        signatures.insert(signature(&row), vault.items.len());
        record_sample(&mut report, &row);
        vault.items.push(row);
    }
    Ok(report)
}
fn count_keys(report: &mut Preview, keys: &[Passkey]) {
    let suspended = keys.iter().filter(|key| key.count_unverified).count();
    report.passkeys += keys.len() - suspended;
    report.suspended_passkeys += suspended;
}
fn record_sample(report: &mut Preview, row: &VaultItem) {
    report.ready += 1;
    if report.sample.len() < 5 {
        let account = match &row.data { CredentialData::Login(data) => data.username.clone(), _ => String::new() };
        report.sample.push(Sample { title: row.title.clone(), kind: row.data.kind_name(), account });
    }
}

#[wasm_bindgen]
pub struct PortableImport { report: String, head: Vec<u8>, snap: Vec<u8>, count: u32 }
#[wasm_bindgen]
impl PortableImport {
    #[wasm_bindgen(getter)] pub fn report(&self) -> String { self.report.clone() }
    #[wasm_bindgen(getter)] pub fn head(&self) -> Vec<u8> { self.head.clone() }
    #[wasm_bindgen(getter)] pub fn snap(&self) -> Vec<u8> { self.snap.clone() }
    #[wasm_bindgen(getter)] pub fn count(&self) -> u32 { self.count }
}

#[wasm_bindgen]
pub fn wasm_portable_import(format: &str, key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], bytes: Vec<u8>, password: String,
    now: f64, commit: bool) -> std::result::Result<PortableImport, JsValue> {
    let (key, wrap, bytes, password) = (Zeroizing::new(key), Zeroizing::new(wrap), Zeroizing::new(bytes), Zeroizing::new(password));
    if bytes.len() > LIMIT || password.len() > 4096 { return Err(JsValue::from_str(INVALID)); }
    let (keys, head, mut vault) = open_vault(&key, &wrap, head, snap)?;
    let batch = match format {
        "cxf" => crate::cxf::read(&bytes, &password),
        "bitwarden" => read_bitwarden(&bytes, &password),
        "bitwarden-retained" if bytes.is_empty() => retained_bitwarden(&vault),
        "keepass" => crate::keepass_kdbx::read(&bytes, &password),
        "onepassword" => crate::vendor_archives::onepassword(&bytes),
        "proton" => crate::vendor_archives::proton(&bytes),
        _ => Err(INVALID),
    }.map_err(JsValue::from_str)?;
    let preview = apply(&mut vault, batch, now as u64).map_err(JsValue::from_str)?;
    let report = serde_json::to_string(&preview).map_err(|_| JsValue::from_str(INVALID))?;
    let count = preview.ready as u32;
    let (head, snap) = if commit && count != 0 { seal_vault(&keys, head, vault, now as u64)? }
        else { (Vec::new(), Vec::new()) };
    Ok(PortableImport { report, head, snap, count })
}

fn write_bitwarden(vault: &VaultSnapshot, password: &str) -> Result<(String, usize)> {
    let mut rows = SecretJson(json!([]));
    let mut skipped_keys = 0;
    for item in &vault.items {
        let mut row = SecretJson(serde_json::from_str(&Zeroizing::new(item.to_json_value().stringify())).map_err(|_| INVALID)?);
        if let CredentialData::Login(login) = &item.data {
            let mut records = SecretJson(json!([]));
            for key in bundle::read(&login.passkey_data)? {
                if key.algorithm != -7 || !key.eligible || key.count_unverified { skipped_keys += 1; continue; }
                let der = key.to_pkcs8()?;
                records.0.as_array_mut().unwrap().push(json!({ "credentialId": bw_id(&key.credential_id), "keyType": "public-key",
                    "keyAlgorithm": "ECDSA", "keyCurve":"P-256", "keyValue":B64.encode(&*der), "rpId":key.rp_id, "rpName":key.rp_id,
                    "userHandle":B64.encode(&key.user_handle), "userName":key.account, "userDisplayName":key.account,
                    "counter":key.count.to_string(), "discoverable":key.discoverable.to_string(), "creationDate":bitwarden::date(&json!(item.created_at_ms)) }));
            }
            row.0["_vaultFido2"] = records.0.clone();
        }
        rows.0.as_array_mut().unwrap().push(row.0.clone());
    }
    let mut entropy = Zeroizing::new([0; 64]);
    csprng_fill(entropy.as_mut()).map_err(|_| INVALID)?;
    Ok((bitwarden::export(&Zeroizing::new(rows.0.to_string()), password, entropy.as_ref())?, skipped_keys))
}

fn bw_id(id: &[u8]) -> String {
    if id.len() != 16 { return format!("b64.{}", B64.encode(id)); }
    let hex = hex::encode(id);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

#[wasm_bindgen]
pub fn wasm_portable_export(format: &str, key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], password: String, now: f64) -> std::result::Result<String, JsValue> {
    let (key, wrap, password) = (Zeroizing::new(key), Zeroizing::new(wrap), Zeroizing::new(password));
    let (_, _, vault) = open_vault(&key, &wrap, head, snap)?;
    let encode = || -> Result<String> {
        let (text, count, skipped, skipped_keys) = match format {
            "cxf" => {
                let (plain, count, skipped, skipped_keys) = crate::cxf::write(&vault, now as u64)?;
                let data = if password.is_empty() { plain.to_string() } else { crate::protected_jwe::seal(plain.as_bytes(), &password)? };
                (data, count, skipped, skipped_keys)
            }
            "bitwarden" => {
                let (encoded, skipped_keys) = write_bitwarden(&vault, &password)?;
                (encoded, vault.items.len(), 0, skipped_keys)
            }
            _ => return Err(INVALID),
        };
        let text = Zeroizing::new(text);
        if text.len() > LIMIT { return Err("导出内容超过 16 MiB，请使用 .vaultpack。"); }
        let response = SecretJson(json!({ "text": &*text, "count":count, "skipped":skipped, "skippedPasskeys":skipped_keys }));
        Ok(response.0.to_string())
    };
    encode().map_err(JsValue::from_str)
}
