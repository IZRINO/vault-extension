use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD}};
use chrono::{DateTime, SecondsFormat};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const META: &str = "Bitwarden 保留字段";
const EXT: &str = "Vault 扩展字段 v1";
const INVALID: &str = "Bitwarden 文件格式无效，请选择官方导出的 JSON 文件。";
const CRYPTO_ERROR: &str = "文件密码错误，或加密文件已损坏。";
const RULES: [&str; 6] = ["base_domain", "host", "starts_with", "exact", "regex", "never"];

pub struct SecretJson(pub Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(rows) => rows.iter_mut().for_each(wipe),
                Value::Object(rows) => rows.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
pub fn text<'a>(value: &'a Value, key: &str) -> &'a str { value[key].as_str().unwrap_or("") }
pub fn millis(value: &Value) -> Option<i64> {
    value.as_str().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|d| d.timestamp_millis()).filter(|t| *t >= 0)
}
pub(crate) fn date(value: &Value) -> Value {
    value.as_i64().and_then(DateTime::from_timestamp_millis).map(|d| json!(d.to_rfc3339_opts(SecondsFormat::Millis, true))).unwrap_or(Value::Null)
}
fn key(doc: &Value, password: &str) -> Result<Zeroizing<[u8; 64]>, &'static str> {
    if password.is_empty() || password.len() > 4096 { return Err(CRYPTO_ERROR); }
    let salt = text(doc, "salt");
    if !(16..=1024).contains(&salt.len()) { return Err(INVALID); }
    // Salt is the UTF-8 base64 *text*, not its decoded bytes (Bitwarden export contract).
    let mut material = Zeroizing::new([0u8; 32]);
    let iterations = doc["kdfIterations"].as_u64().ok_or(INVALID)?;
    match doc["kdfType"].as_u64() {
        Some(0) if (5000..=2_000_000).contains(&iterations) => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations as u32, &mut *material);
        }
        Some(1) => {
            let memory = doc["kdfMemory"].as_u64().ok_or(INVALID)?;
            let lanes = doc["kdfParallelism"].as_u64().ok_or(INVALID)?;
            if !(2..=10).contains(&iterations) || !(16..=256).contains(&memory) || !(1..=16).contains(&lanes) || memory * iterations > 1024 {
                return Err("加密文件的 KDF 参数超出本机导入上限（Argon2id 16–256 MiB、2–10 轮、1–16 路）。");
            }
            let params = argon2::Params::new(memory as u32 * 1024, iterations as u32, lanes as u32, Some(32)).map_err(|_| INVALID)?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &Sha256::digest(salt.as_bytes()), &mut *material).map_err(|_| CRYPTO_ERROR)?;
        }
        _ => return Err("不支持此加密文件的 KDF 参数。PBKDF2 需为 5,000–2,000,000 轮。"),
    }
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&*material).map_err(|_| CRYPTO_ERROR)?;
    let mut result = Zeroizing::new([0u8; 64]);
    hkdf.expand(b"enc", &mut result[..32]).map_err(|_| CRYPTO_ERROR)?;
    hkdf.expand(b"mac", &mut result[32..]).map_err(|_| CRYPTO_ERROR)?;
    Ok(result)
}
fn decrypt(enc: &str, key: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let parts: Vec<_> = enc.strip_prefix("2.").ok_or(CRYPTO_ERROR)?.split('|').collect();
    if parts.len() != 3 { return Err(CRYPTO_ERROR); }
    let iv = B64.decode(parts[0]).map_err(|_| CRYPTO_ERROR)?;
    let ciphertext = Zeroizing::new(B64.decode(parts[1]).map_err(|_| CRYPTO_ERROR)?);
    let tag = B64.decode(parts[2]).map_err(|_| CRYPTO_ERROR)?;
    if key.len() != 64 || iv.len() != 16 || tag.len() != 32 || ciphertext.is_empty() || ciphertext.len() > MAX_BYTES { return Err(CRYPTO_ERROR); }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[32..]).map_err(|_| CRYPTO_ERROR)?;
    mac.update(&iv); mac.update(&ciphertext); mac.verify_slice(&tag).map_err(|_| CRYPTO_ERROR)?;
    let result = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key[..32], &iv).map_err(|_| CRYPTO_ERROR)?
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext).map_err(|_| CRYPTO_ERROR)?;
    Ok(Zeroizing::new(result))
}
fn encrypt(plain: &[u8], key: &[u8], iv: &[u8]) -> Result<String, &'static str> {
    let ciphertext = Zeroizing::new(cbc::Encryptor::<aes::Aes256>::new_from_slices(&key[..32], iv).map_err(|_| CRYPTO_ERROR)?
        .encrypt_padded_vec_mut::<Pkcs7>(plain));
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[32..]).map_err(|_| CRYPTO_ERROR)?;
    mac.update(iv); mac.update(&ciphertext);
    Ok(format!("2.{}|{}|{}", B64.encode(iv), B64.encode(&*ciphertext), B64.encode(mac.finalize().into_bytes())))
}
fn open(bytes: &[u8], password: &str) -> Result<SecretJson, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES { return Err("迁移文件不能超过 16 MiB。"); }
    let input = std::str::from_utf8(bytes).map_err(|_| INVALID)?.trim_start_matches('\u{feff}');
    let doc = SecretJson(serde_json::from_str(input).map_err(|_| INVALID)?);
    if doc.0["encrypted"] == true {
        if doc.0["passwordProtected"] != true {
            return Err("这是绑定 Bitwarden 账号的加密导出，主密码无法直接解密。请在 Bitwarden 中改选「密码保护」或未加密 JSON 再导出。");
        }
        let key = key(&doc.0, password)?;
        let _validation = decrypt(text(&doc.0, "encKeyValidation_DO_NOT_EDIT"), &*key)?;
        let decoded = decrypt(text(&doc.0, "data"), &*key)?;
        let plain = SecretJson(serde_json::from_slice(&decoded).map_err(|_| INVALID)?);
        if plain.0["encrypted"] == true { return Err(INVALID); }
        Ok(plain)
    } else { Ok(doc) }
}
fn take(value: &mut Value, key: &str) -> Value {
    value.as_object_mut().and_then(|v| v.remove(key)).unwrap_or(Value::Null)
}
fn strings(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| text(value, k)).filter(|s| !s.is_empty()).map(str::to_string).collect()
}
fn ssh_pair_hash(data: &Value) -> String {
    let public = text(data, "publicKey");
    let mut hash = Sha256::new();
    hash.update((public.len() as u64).to_le_bytes());
    hash.update(public.as_bytes());
    hash.update(text(data, "privateKey").as_bytes());
    STANDARD_NO_PAD.encode(hash.finalize())
}
fn ssh_fingerprint(public_key: &str) -> Option<String> {
    let mut fields = public_key.split_ascii_whitespace();
    let algorithm = fields.next()?;
    let encoded = fields.next()?;
    let blob = B64.decode(encoded).or_else(|_| STANDARD_NO_PAD.decode(encoded)).ok()?;
    let length = u32::try_from(algorithm.len()).ok()?.to_be_bytes();
    let payload = blob.strip_prefix(length.as_slice())?.strip_prefix(algorithm.as_bytes())?;
    if payload.is_empty() { return None; }
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))))
}
fn compatibility_field(field: &Value, kind: u64) -> Option<SecretJson> {
    if text(field, "name") != EXT || field["type"] != 1 { return None; }
    let parsed = SecretJson(serde_json::from_str(text(field, "value")).ok()?);
    let expected = match kind { 1 => "login", 3 => "payment_card", 4 => "identity", _ => "developer" };
    (parsed.0["version"] == 1 && parsed.0["data"]["kind"] == expected &&
        (kind != 5 || parsed.0["data"]["subtype"] == "ssh_key")).then_some(parsed)
}

pub fn import(bytes: &[u8], password: &str) -> Result<String, &'static str> {
    let doc = open(bytes, password)?;
    let items = doc.0["items"].as_array().ok_or(INVALID)?;
    if items.len() > 5000 { return Err("单次最多导入 5,000 条，请分批导出。"); }
    let folders = doc.0["folders"].as_array();
    let mut rows = SecretJson(json!([]));
    let (mut invalid, mut unsupported, mut ignored_otp) = (0, 0, 0);
    for source in items {
        let kind = source["type"].as_u64().unwrap_or(0);
        if !(1..=5).contains(&kind) { unsupported += 1; continue; }
        if text(source, "name").trim().is_empty() { invalid += 1; continue; }
        let mut extra = SecretJson(source.clone());
        let mut fields = SecretJson(json!([]));
        let mut colliding_fields = SecretJson(json!([]));
        let mut templates = Vec::new();
        let compatibility = source["fields"].as_array().and_then(|fields| fields.iter().enumerate().rev()
            .find_map(|(index, field)| compatibility_field(field, kind).map(|value| (index, value))));
        if let Some(raw_fields) = source["fields"].as_array() {
            for (index, field) in raw_fields.iter().enumerate() {
                if compatibility.as_ref().is_some_and(|(selected, _)| *selected == index) { continue; }
                let name = text(field, "name");
                if matches!(name, EXT | META | crate::portable::SOURCE) {
                    colliding_fields.0.as_array_mut().unwrap().push(field.clone());
                    continue;
                }
                let mut template = field.clone();
                drop(SecretJson(take(&mut template, "value")));
                templates.push(template);
                fields.0.as_array_mut().unwrap().push(json!({
                    "name": name, "value": field["value"].as_str().map(str::to_string).unwrap_or_else(|| if field["value"].is_null() { String::new() } else { field["value"].to_string() }),
                    "hidden": field["type"] == 1 || field["type"] == 3
                }));
            }
        }
        let extension = compatibility.map(|(_, value)| value).unwrap_or(SecretJson(Value::Null));
        let mut data = SecretJson(match kind {
            1 => {
                let login = &source["login"];
                if !login.is_object() { invalid += 1; continue; }
                let otp = text(login, "totp");
                let otp = if otp.is_empty() { Value::Null } else {
                    let parsed = if let Some(seed) = otp.strip_prefix("steam://") {
                        vault_otp::parse(&format!("otpauth://steam/Steam?secret={seed}"))
                    } else { vault_otp::parse(otp) };
                    match parsed {
                        Ok(parsed) => json!(&*parsed.canonical_uri()),
                        Err(_) => {
                            ignored_otp += 1;
                            fields.0.as_array_mut().unwrap().push(json!({ "name": "Bitwarden 未识别的验证码设置", "value": otp, "hidden": true }));
                            Value::Null
                        }
                    }
                };
                let uris = login["uris"].as_array().map(|uris| uris.iter().filter(|u| !text(u, "uri").is_empty()).map(|u|
                    json!({ "uri": text(u, "uri"), "matchRule": u["match"].as_u64().and_then(|m| RULES.get(m as usize)).unwrap_or(&"base_domain") })
                ).collect::<Vec<_>>()).unwrap_or_default();
                let history = source["passwordHistory"].as_array().map(|history| history.iter().take(20).map(|entry|
                    json!({ "password": text(entry, "password"), "changedAtMs": millis(&entry["lastUsedDate"]).unwrap_or(0), "sourceDevice": "Bitwarden" })
                ).collect::<Vec<_>>()).unwrap_or_default();
                json!({ "kind": "login", "username": text(login, "username"), "password": text(login, "password"), "uris": uris, "totpUri": otp, "passwordHistory": history })
            }
            3 => {
                let card = &source["card"];
                if !card.is_object() { invalid += 1; continue; }
                json!({ "kind": "payment_card", "cardholderName": text(card, "cardholderName"), "cardNumber": text(card, "number"),
                    "brand": text(card, "brand").to_ascii_lowercase().replace("unionpay", "union_pay"),
                    "expMonth": text(card, "expMonth"), "expYear": text(card, "expYear"), "cvv": text(card, "code") })
            }
            4 => {
                let id = &source["identity"];
                if !id.is_object() { invalid += 1; continue; }
                json!({ "kind": "identity", "fullName": strings(id, &["firstName", "middleName", "lastName"]).join(" "),
                    "phone": text(id, "phone"), "email": text(id, "email"), "nationalIdOrPassport": strings(id, &["passportNumber", "ssn", "licenseNumber"]).join(" / "),
                    "country": text(id, "country"), "province": text(id, "state"), "city": text(id, "city"),
                    "addressLine": strings(id, &["address1", "address2", "address3"]).join("\n"), "postalCode": text(id, "postalCode"), "company": text(id, "company") })
            }
            5 => {
                let ssh = &source["sshKey"];
                let private = text(ssh, "privateKey");
                if private.trim().is_empty() || private.len() > 128 * 1024 ||
                    [("publicKey", 128 * 1024), ("keyFingerprint", 512)].iter().any(|(name, limit)|
                        !ssh[*name].is_null() && !ssh[*name].as_str().is_some_and(|value| value.len() <= *limit)) {
                    invalid += 1; continue;
                }
                json!({ "kind": "developer", "subtype": "ssh_key", "privateKey": private, "publicKey": text(ssh, "publicKey") })
            }
            _ => json!({ "kind": "developer", "subtype": "secure_note" }),
        });
        // Our own compatibility field restores data without making imported source IDs authoritative.
        if extension.0["version"] == 1 && extension.0["data"]["kind"] == data.0["kind"] {
            if kind == 2 { data = SecretJson(extension.0["data"].clone()); }
            else if let Some(values) = extension.0["data"].as_object() {
                for (key, value) in values { if data.0.get(key).is_none() { data.0[key] = value.clone(); } }
            }
        }
        let mut tags = extension.0["tags"].as_array().cloned().unwrap_or_default();
        if let Some(folder) = folders.and_then(|folders| folders.iter().find(|f| f["id"] == source["folderId"])) {
            if !text(folder, "name").is_empty() && !tags.contains(&folder["name"]) { tags.push(folder["name"].clone()); }
        }
        // Keep only unmapped source fields. Avoid retaining stale copies of edited passwords.
        for name in ["name", "notes", "favorite", "reprompt", "deletedDate", "creationDate", "revisionDate", "passwordHistory", "folderId", "collectionIds", "organizationId", "id"] { take(&mut extra.0, name); }
        extra.0["fields"] = json!(templates);
        for (parent, keys) in [
            ("login", &["username", "password", "uris", "totp"][..]),
            ("card", &["cardholderName", "number", "brand", "expMonth", "expYear", "code"][..]),
            ("identity", &["phone", "email", "country", "state", "city", "postalCode", "company"][..]),
        ] { for key in keys { take(&mut extra.0[parent], key); } }
        let mut fingerprint = Value::Null;
        if kind == 5 {
            let source_fingerprint = text(&source["sshKey"], "keyFingerprint");
            if !source_fingerprint.is_empty() {
                fingerprint = json!({"value":source_fingerprint,"pairHash":ssh_pair_hash(&data.0)});
            }
            for field in ["privateKey", "publicKey", "keyFingerprint"] { drop(SecretJson(take(&mut extra.0["sshKey"], field))); }
        }
        let mut metadata = SecretJson(json!({ "version": 1, "sourceId": source["id"], "originalType": kind, "extra": extra.0 }));
        if !fingerprint.is_null() { metadata.0["sshFingerprint"] = fingerprint; }
        if let Some(fields) = colliding_fields.0.as_array().filter(|fields| !fields.is_empty()) {
            metadata.0["collidingFields"] = json!(fields);
        }
        fields.0.as_array_mut().unwrap().push(json!({ "name": META, "hidden": true, "value": metadata.0.to_string() }));
        rows.0.as_array_mut().unwrap().push(json!({
            "id": "", "title": text(source, "name"), "data": data.0, "note": text(source, "notes"), "customFields": fields.0,
            "tags": tags, "pinned": source["favorite"] == true, "requireReprompt": source["reprompt"] == 1,
            "trashed": !source["deletedDate"].is_null(), "trashedAtMs": millis(&source["deletedDate"]),
            "createdAtMs": millis(&source["creationDate"]), "updatedAtMs": millis(&source["revisionDate"])
        }));
    }
    serde_json::to_string(&SecretJson(json!({ "rows": rows.0, "invalid": invalid, "unsupported": unsupported, "ignoredOtp": ignored_otp })).0).map_err(|_| INVALID)
}
pub fn export(items_json: &str, password: &str, entropy: &[u8]) -> Result<String, &'static str> {
    let items = SecretJson(serde_json::from_str(items_json).map_err(|_| INVALID)?);
    let items = items.0.as_array().filter(|v| v.len() <= 5000).ok_or(INVALID)?;
    let mut rows = SecretJson(json!([]));
    for item in items {
        let data = &item["data"];
        let custom = item["customFields"].as_array();
        let meta = SecretJson(custom.and_then(|fs| fs.iter().find(|f| text(f, "name") == META))
            .and_then(|f| serde_json::from_str(text(f, "value")).ok()).unwrap_or(Value::Null));
        let mut row = SecretJson(if meta.0["version"] == 1 && meta.0["extra"].is_object() { meta.0["extra"].clone() } else { json!({}) });
        let native_ssh = text(data, "kind") == "developer" && text(data, "subtype") == "ssh_key" && !text(data, "privateKey").trim().is_empty();
        if meta.0["originalType"] == 5 && !native_ssh { drop(SecretJson(take(&mut row.0, "sshKey"))); }
        row.0["id"] = item["id"].clone(); row.0["organizationId"] = Value::Null; row.0["folderId"] = Value::Null;
        row.0["name"] = item["title"].clone(); row.0["notes"] = item["note"].clone();
        row.0["favorite"] = json!(item["pinned"] == true); row.0["reprompt"] = json!(if item["requireReprompt"] == true { 1 } else { 0 });
        row.0["creationDate"] = date(&item["createdAtMs"]); row.0["revisionDate"] = date(&item["updatedAtMs"]);
        row.0["deletedDate"] = if item["trashed"] == true { date(&item["trashedAtMs"]).as_str().map(|s| json!(s)).unwrap_or_else(|| json!("1970-01-01T00:00:00.000Z")) } else { Value::Null };
        let mut fields = SecretJson(json!([]));
        if let Some(custom) = custom {
            for field in custom.iter().filter(|f| text(f, "name") != META) {
                let template = meta.0["extra"]["fields"].as_array().and_then(|fs| fs.iter().find(|f| f["name"] == field["name"]));
                let mut mapped = template.cloned().unwrap_or_else(|| json!({}));
                mapped["name"] = field["name"].clone(); mapped["value"] = field["value"].clone();
                mapped["type"] = template.map(|f| f["type"].clone()).unwrap_or_else(|| json!(if field["hidden"] == true { 1 } else { 0 }));
                fields.0.as_array_mut().unwrap().push(mapped);
            }
        }
        if let Some(retained) = meta.0["collidingFields"].as_array() {
            fields.0.as_array_mut().unwrap().extend(retained.iter().filter(|field|
                matches!(text(field, "name"), EXT | META | crate::portable::SOURCE)).cloned());
        }
        let mut extension = SecretJson(json!({ "version": 1, "data": data, "tags": item["tags"] }));
        if native_ssh {
            for field in ["privateKey", "publicKey"] { drop(SecretJson(take(&mut extension.0["data"], field))); }
        }
        fields.0.as_array_mut().unwrap().push(json!({ "name": EXT, "type": 1, "value": extension.0.to_string() }));
        row.0["fields"] = fields.0.clone();
        match text(data, "kind") {
            "login" => {
                row.0["type"] = json!(1);
                if !row.0["login"].is_object() { row.0["login"] = json!({}); }
                for (target, source) in [("username", "username"), ("password", "password"), ("totp", "totpUri")] { row.0["login"][target] = data[source].clone(); }
                if let Ok(otp) = vault_otp::parse(text(data, "totpUri")) {
                    if otp.kind == vault_otp::Kind::Steam {
                        let uri = otp.canonical_uri();
                        if let Some(secret) = uri.split_once('?').and_then(|(_, params)| params.split('&').find_map(|p| p.strip_prefix("secret="))) {
                            row.0["login"]["totp"] = json!(format!("steam://{secret}"));
                        }
                    }
                }
                if let Some(records) = item["_vaultFido2"].as_array() {
                    drop(SecretJson(std::mem::replace(&mut row.0["login"]["fido2Credentials"], json!(records))));
                }
                row.0["login"]["uris"] = json!(data["uris"].as_array().map(|uris| uris.iter().map(|uri|
                    json!({ "uri": uri["uri"], "match": RULES.iter().position(|r| *r == text(uri, "matchRule")) })
                ).collect::<Vec<_>>()).unwrap_or_default());
                row.0["passwordHistory"] = json!(data["passwordHistory"].as_array().map(|h| h.iter().map(|h|
                    json!({ "password": h["password"], "lastUsedDate": date(&h["changedAtMs"]) })
                ).collect::<Vec<_>>()).unwrap_or_default());
            }
            "payment_card" => {
                row.0["type"] = json!(3); if !row.0["card"].is_object() { row.0["card"] = json!({}); }
                for (target, source) in [("cardholderName", "cardholderName"), ("number", "cardNumber"), ("code", "cvv"), ("expMonth", "expMonth"), ("expYear", "expYear")] { row.0["card"][target] = data[source].clone(); }
                row.0["card"]["brand"] = json!(match text(data, "brand") { "union_pay" => "UnionPay", "visa" => "Visa", "mastercard" => "Mastercard", "amex" => "Amex", "jcb" => "JCB", "discover" => "Discover", _ => "Other" });
            }
            "identity" => {
                row.0["type"] = json!(4); if !row.0["identity"].is_object() { row.0["identity"] = json!({}); }
                if strings(&row.0["identity"], &["firstName", "middleName", "lastName"]).join(" ") != text(data, "fullName") {
                    row.0["identity"]["firstName"] = data["fullName"].clone(); row.0["identity"]["middleName"] = Value::Null; row.0["identity"]["lastName"] = Value::Null;
                }
                if strings(&row.0["identity"], &["address1", "address2", "address3"]).join("\n") != text(data, "addressLine") {
                    row.0["identity"]["address1"] = data["addressLine"].clone(); row.0["identity"]["address2"] = Value::Null; row.0["identity"]["address3"] = Value::Null;
                }
                if strings(&row.0["identity"], &["passportNumber", "ssn", "licenseNumber"]).join(" / ") != text(data, "nationalIdOrPassport") {
                    row.0["identity"]["passportNumber"] = data["nationalIdOrPassport"].clone(); row.0["identity"]["ssn"] = Value::Null; row.0["identity"]["licenseNumber"] = Value::Null;
                }
                for (target, source) in [("phone", "phone"), ("email", "email"), ("country", "country"), ("state", "province"), ("city", "city"), ("postalCode", "postalCode"), ("company", "company")] { row.0["identity"][target] = data[source].clone(); }
            }
            "developer" if native_ssh => {
                let public = text(data, "publicKey");
                let retained = &meta.0["sshFingerprint"];
                let fingerprint = ssh_fingerprint(public).unwrap_or_else(|| {
                    if text(retained, "pairHash") == ssh_pair_hash(data) {
                        text(retained, "value").to_owned()
                    } else { String::new() }
                });
                row.0["type"] = json!(5);
                if !row.0["sshKey"].is_object() { row.0["sshKey"] = json!({}); }
                row.0["sshKey"]["privateKey"] = data["privateKey"].clone();
                row.0["sshKey"]["publicKey"] = json!(public);
                row.0["sshKey"]["keyFingerprint"] = json!(fingerprint);
            }
            _ => { row.0["type"] = json!(2); row.0["secureNote"] = json!({ "type": 0 }); }
        }
        rows.0.as_array_mut().unwrap().push(row.0.clone());
    }
    let plain = Zeroizing::new(SecretJson(json!({ "encrypted": false, "folders": [], "items": rows.0 })).0.to_string());
    if plain.len() > MAX_BYTES - 1024 { return Err("导出内容超过 16 MiB，请改用加密备份。"); }
    if password.is_empty() { return Ok(plain.to_string()); }
    if entropy.len() != 64 || password.len() < 12 || password.len() > 1024 { return Err("导出密码需要 12–1024 个字符。"); }
    let mut doc = json!({ "encrypted": true, "passwordProtected": true, "salt": B64.encode(&entropy[..16]), "kdfType": 0, "kdfIterations": 600000 });
    let key = key(&doc, password)?;
    doc["encKeyValidation_DO_NOT_EDIT"] = json!(encrypt(&entropy[48..], &*key, &entropy[16..32])?);
    doc["data"] = json!(encrypt(plain.as_bytes(), &*key, &entropy[32..48])?);
    let result = doc.to_string();
    if result.len() > MAX_BYTES { return Err("加密导出超过 16 MiB，请改用密码库备份。"); }
    Ok(result)
}

#[wasm_bindgen]
pub fn wasm_parse_bitwarden(bytes: Vec<u8>, password: String) -> Result<String, JsValue> {
    let (bytes, password) = (Zeroizing::new(bytes), Zeroizing::new(password));
    import(&bytes, &password).map_err(JsValue::from_str)
}
#[wasm_bindgen]
pub fn wasm_export_bitwarden(items: String, password: String, entropy: Vec<u8>) -> Result<String, JsValue> {
    let (items, password, entropy) = (Zeroizing::new(items), Zeroizing::new(password), Zeroizing::new(entropy));
    export(&items, &password, &entropy).map_err(JsValue::from_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bitwarden_ssh_without_retaining_duplicate_keys() {
        let private = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nsynthetic-old-key\r\n-----END OPENSSH PRIVATE KEY-----\r\n";
        let public = "ssh-ed25519 fixture-pub synthetic@example.test";
        let source = json!({"encrypted":false,"folders":[{"id":"work","name":"Work"}],"items":[{
            "id":"synthetic-ssh","type":5,"name":"Fixture SSH","notes":"Fixture note","folderId":"work",
            "favorite":true,"reprompt":1,"sshKey":{"privateKey":private,"publicKey":public,"keyFingerprint":"SHA256:fixture","fixtureExtra":"retained"}
        }]});
        let imported: Value = serde_json::from_str(&import(source.to_string().as_bytes(), "").unwrap()).unwrap();
        assert_eq!((imported["invalid"].as_u64(), imported["unsupported"].as_u64()), (Some(0), Some(0)));
        let row = &imported["rows"][0];
        assert_eq!(row["data"], json!({"kind":"developer","subtype":"ssh_key","privateKey":private,"publicKey":public}));
        assert_eq!(row["note"], "Fixture note");
        assert_eq!(row["tags"], json!(["Work"]));
        assert_eq!(row["pinned"], true);
        assert_eq!(row["requireReprompt"], true);
        let metadata = row["customFields"][0]["value"].as_str().unwrap();
        assert!(!metadata.contains("synthetic-old-key") && !metadata.contains("fixture-pub"));

        let emit = |item: &Value| -> Value {
            let doc: Value = serde_json::from_str(&export(&json!([item]).to_string(), "", &[]).unwrap()).unwrap();
            doc["items"][0].clone()
        };
        let exported = emit(row);
        assert_eq!(exported["type"], 5);
        assert_eq!(exported["sshKey"], source["items"][0]["sshKey"]);
        assert!(!exported["fields"].to_string().contains("synthetic-old-key"));

        let mut edited = row.clone();
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend([0x42; 32]); // Binary layout of a synthetic public key fixture.
        let new_public = format!("ssh-ed25519 {} fresh-public-key", B64.encode(blob));
        edited["data"]["privateKey"] = json!("synthetic-replacement-private");
        edited["data"]["publicKey"] = json!(new_public);
        let exported = emit(&edited);
        assert_eq!(exported["sshKey"], json!({"privateKey":"synthetic-replacement-private","publicKey":new_public,
            "keyFingerprint":"SHA256:LgZpRzWEAbVvBimxTv69/UB88PD8jyOSDqfozr+iNX0","fixtureExtra":"retained"}));
        assert!(!exported.to_string().contains("synthetic-old-key"));
        assert!(!exported.to_string().contains("SHA256:fixture"));
    }

    #[test]
    fn distinguishes_invalid_ssh_from_unsupported_bitwarden_types() {
        let source = json!({"items":[
            {"type":5,"name":"Absent key"},
            {"type":5,"name":"Blank key","sshKey":{"privateKey":" \r\n "}},
            {"type":5,"name":"Non-string public key","sshKey":{"privateKey":"synthetic","publicKey":17}},
            {"type":5,"name":"Private only","sshKey":{"privateKey":"synthetic","publicKey":null}},
            {"type":42,"name":"Unsupported"},
        ]});
        let result: Value = serde_json::from_str(&import(source.to_string().as_bytes(), "").unwrap()).unwrap();
        assert_eq!(result["invalid"], 3);
        assert_eq!(result["unsupported"], 1);
        assert_eq!(result["rows"].as_array().unwrap().len(), 1);
        assert_eq!(result["rows"][0]["data"]["privateKey"], "synthetic");
        assert_eq!(result["rows"][0]["data"]["publicKey"], "");
    }

    #[test]
    fn keeps_source_custom_fields_separate_from_vault_metadata() {
        let fields = json!([
            {"name":META,"value":"ordinary source field","type":1},
            {"name":"Vault 迁移来源","value":"ordinary source label","type":0},
            {"name":EXT,"value":"ordinary compatibility name","type":1},
            {"name":EXT,"value":"{\"version\":1,\"data\":\"ordinary JSON\"}","type":1}
        ]);
        let doc = json!({"items":[{"id":"source-id","type":5,"name":"Fixture","fields":fields,
            "sshKey":{"privateKey":"synthetic"}}]});
        let imported: Value = serde_json::from_str(&import(doc.to_string().as_bytes(), "").unwrap()).unwrap();
        let item = &imported["rows"][0];
        let only_internal_metadata = item["customFields"].as_array().unwrap();
        assert_eq!(only_internal_metadata.len(), 1);
        assert_eq!(only_internal_metadata[0]["name"], META);
        let meta: Value = serde_json::from_str(only_internal_metadata[0]["value"].as_str().unwrap()).unwrap();
        assert_eq!(meta["sourceId"], "source-id");
        let exported: Value = serde_json::from_str(&export(&json!([item]).to_string(), "", &[]).unwrap()).unwrap();
        assert_eq!(&exported["items"][0]["fields"].as_array().unwrap()[..4], fields.as_array().unwrap());
        let round_trip: Value = serde_json::from_str(&import(exported.to_string().as_bytes(), "").unwrap()).unwrap();
        let retained: Value = serde_json::from_str(round_trip["rows"][0]["customFields"][0]["value"].as_str().unwrap()).unwrap();
        assert_eq!(retained["collidingFields"], fields);
    }

    #[test]
    fn does_not_export_an_old_fingerprint_after_editing_a_private_only_key() {
        let doc = json!({"items":[{"type":5,"name":"Fixture","sshKey":{"privateKey":"synthetic",
            "keyFingerprint":"SHA256:unverified-original"}}]});
        let mut imported: Value = serde_json::from_str(&import(doc.to_string().as_bytes(), "").unwrap()).unwrap();
        let item = &mut imported["rows"][0];
        let fingerprint = |row: &Value| {
            let out: Value = serde_json::from_str(&export(&json!([row]).to_string(), "", &[]).unwrap()).unwrap();
            out["items"][0]["sshKey"]["keyFingerprint"].clone()
        };
        assert_eq!(fingerprint(item), "SHA256:unverified-original");
        item["data"]["privateKey"] = json!("new synthetic key");
        assert_eq!(fingerprint(item), "");
    }

    #[test]
    fn encryption_authentication_and_kdf_limits() {
        let config = json!({ "salt": "dGVzdC1leHBvcnQtc2FsdA==", "kdfType": 0, "kdfIterations": 10000 });
        let derived = key(&config, "fixture password").unwrap();
        let encrypted = encrypt(b"secret fixture", &*derived, &[7; 16]).unwrap();
        assert_eq!(&*decrypt(&encrypted, &*derived).unwrap(), b"secret fixture");
        assert!(decrypt(&encrypted.replace("2.", "0."), &*derived).is_err());
        assert!(decrypt(&encrypted, &[0; 64]).is_err());
        let mut bad = config.clone(); bad["kdfIterations"] = json!(u32::MAX);
        assert!(key(&bad, "fixture").is_err());
        bad["kdfType"] = json!(1); bad["kdfMemory"] = json!(u32::MAX);
        assert!(key(&bad, "fixture").is_err());
    }
    #[test]
    fn maps_all_four_types_and_preserves_unmapped_data() {
        let source = json!({ "encrypted": false, "folders": [{ "id": "f1", "name": "Work" }], "items": [
            { "id": "a", "type": 1, "name": "Login", "folderId": "f1", "notes": "note", "favorite": true, "reprompt": 1,
              "login": { "username": "a", "password": "p", "totp": "JBSWY3DPEHPK3PXP", "uris": [{ "uri": "https://example.com", "match": 3 }], "fido2Credentials": [{ "keyValue": "preserved" }] },
              "fields": [{ "name": "hidden", "value": "value", "type": 1 }] },
            { "id": "b", "type": 2, "name": "Note", "notes": "private note", "secureNote": { "type": 0 } },
            { "id": "c", "type": 3, "name": "Card", "card": { "number": "4111111111111111", "code": "123", "brand": "Visa" } },
            { "id": "d", "type": 4, "name": "Identity", "identity": { "firstName": "Ada", "lastName": "Lovelace", "address1": "Line1", "address2": "Line2", "passportNumber": "passport", "ssn": "ssn" } }
        ] });
        let decoded: Value = serde_json::from_str(&import(source.to_string().as_bytes(), "").unwrap()).unwrap();
        assert_eq!(decoded["rows"].as_array().unwrap().len(), 4);
        assert_eq!(decoded["rows"][0]["tags"], json!(["Work"]));
        assert_eq!(decoded["rows"][0]["requireReprompt"], true);
        let encoded: Value = serde_json::from_str(&export(&decoded["rows"].to_string(), "", &[]).unwrap()).unwrap();
        assert_eq!(encoded["items"][0]["login"]["fido2Credentials"][0]["keyValue"], "preserved");
        assert_eq!(encoded["items"][0]["login"]["password"], "p");
        assert_eq!(encoded["items"][1]["type"], 2);
        assert_eq!(encoded["items"][2]["card"]["code"], "123");
        assert_eq!(encoded["items"][3]["identity"]["address2"], "Line2");
        let mut edited = decoded["rows"].clone(); edited[0]["data"]["password"] = json!("new password");
        let encoded: Value = serde_json::from_str(&export(&edited.to_string(), "", &[]).unwrap()).unwrap();
        assert_eq!(encoded["items"][0]["login"]["password"], "new password");
        assert!(!text(&decoded["rows"][0]["customFields"][1], "value").contains("\"password\":\"p\""));
    }
}
