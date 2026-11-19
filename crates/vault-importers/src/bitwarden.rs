use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
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
pub fn import(bytes: &[u8], password: &str) -> Result<String, &'static str> {
    let doc = open(bytes, password)?;
    let items = doc.0["items"].as_array().ok_or(INVALID)?;
    if items.len() > 5000 { return Err("单次最多导入 5,000 条，请分批导出。"); }
    let folders = doc.0["folders"].as_array();
    let mut rows = SecretJson(json!([]));
    let (mut invalid, mut unsupported, mut ignored_otp) = (0, 0, 0);
    for source in items {
        let kind = source["type"].as_u64().unwrap_or(0);
        if !(1..=4).contains(&kind) { unsupported += 1; continue; }
        if text(source, "name").trim().is_empty() { invalid += 1; continue; }
        let mut extra = SecretJson(source.clone());
        let mut fields = SecretJson(json!([]));
        let mut extension = SecretJson(Value::Null);
        if let Some(raw_fields) = source["fields"].as_array() {
            for field in raw_fields {
                if text(field, "name") == EXT {
                    if let Ok(value) = serde_json::from_str::<Value>(text(field, "value")) { extension.0 = value; }
                    continue;
                }
                fields.0.as_array_mut().unwrap().push(json!({
                    "name": text(field, "name"), "value": field["value"].as_str().map(str::to_string).unwrap_or_else(|| if field["value"].is_null() { String::new() } else { field["value"].to_string() }),
                    "hidden": field["type"] == 1 || field["type"] == 3
                }));
            }
        }
        let mut data = match kind {
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
            _ => json!({ "kind": "developer", "subtype": "api_token", "serviceOrProduct": "安全备注" }),
        };
        // Our own compatibility field restores data without making imported source IDs authoritative.
        if extension.0["version"] == 1 && extension.0["data"]["kind"] == data["kind"] {
            if kind == 2 { data = extension.0["data"].clone(); }
            else if let Some(values) = extension.0["data"].as_object() {
                for (key, value) in values { if data.get(key).is_none() { data[key] = value.clone(); } }
            }
        }
        let mut tags = extension.0["tags"].as_array().cloned().unwrap_or_default();
        if let Some(folder) = folders.and_then(|folders| folders.iter().find(|f| f["id"] == source["folderId"])) {
            if !text(folder, "name").is_empty() && !tags.contains(&folder["name"]) { tags.push(folder["name"].clone()); }
        }
        // Keep only unmapped source fields. Avoid retaining stale copies of edited passwords.
        for name in ["name", "notes", "favorite", "reprompt", "deletedDate", "creationDate", "revisionDate", "passwordHistory", "folderId", "collectionIds", "organizationId", "id"] { take(&mut extra.0, name); }
        let templates: Vec<_> = source["fields"].as_array().map(|fs| fs.iter().filter(|f| text(f, "name") != EXT).map(|f| {
            let mut template = f.clone(); take(&mut template, "value"); template
        }).collect()).unwrap_or_default();
        extra.0["fields"] = json!(templates);
        for (parent, keys) in [
            ("login", &["username", "password", "uris", "totp"][..]),
            ("card", &["cardholderName", "number", "brand", "expMonth", "expYear", "code"][..]),
            ("identity", &["phone", "email", "country", "state", "city", "postalCode", "company"][..]),
        ] { for key in keys { take(&mut extra.0[parent], key); } }
        fields.0.as_array_mut().unwrap().push(json!({ "name": META, "hidden": true,
            "value": json!({ "version": 1, "sourceId": source["id"], "originalType": kind, "extra": extra.0 }).to_string() }));
        rows.0.as_array_mut().unwrap().push(json!({
            "id": "", "title": text(source, "name"), "data": data, "note": text(source, "notes"), "customFields": fields.0,
            "tags": tags, "pinned": source["favorite"] == true, "requireReprompt": source["reprompt"] == 1,
            "trashed": !source["deletedDate"].is_null(), "trashedAtMs": millis(&source["deletedDate"]),
            "createdAtMs": millis(&source["creationDate"]), "updatedAtMs": millis(&source["revisionDate"])
        }));
    }
    serde_json::to_string(&json!({ "rows": rows.0, "invalid": invalid, "unsupported": unsupported, "ignoredOtp": ignored_otp })).map_err(|_| INVALID)
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
        fields.0.as_array_mut().unwrap().push(json!({ "name": EXT, "type": 1,
            "value": json!({ "version": 1, "data": data, "tags": item["tags"] }).to_string() }));
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
                if let Some(added) = item["_vaultFido2"].as_array().filter(|values| !values.is_empty()) {
                    let mut records = row.0["login"]["fido2Credentials"].as_array().cloned().unwrap_or_default();
                    for key in added {
                        if !records.iter().any(|old| old["credentialId"] == key["credentialId"]) { records.push(key.clone()); }
                    }
                    row.0["login"]["fido2Credentials"] = json!(records);
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
            _ => { row.0["type"] = json!(2); row.0["secureNote"] = json!({ "type": 0 }); }
        }
        rows.0.as_array_mut().unwrap().push(row.0.clone());
    }
    let plain = Zeroizing::new(json!({ "encrypted": false, "folders": [], "items": rows.0 }).to_string());
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
