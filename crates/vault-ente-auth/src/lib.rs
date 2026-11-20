use std::collections::BTreeSet;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_secretstream::{Header, Key, PullStream, Stream, Tag};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vault_otp::{Otp, parse, uri_decode, uri_encode};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_BACKUP_BYTES: usize = 3 * 1024 * 1024;
const MAX_ROWS: usize = 5000;
const INVALID: &str = "无法读取验证器文件，请选择 Ente Auth 导出的文本或加密 JSON。";
const INVALID_BACKUP: &str = "Ente Auth 加密备份格式无效。";
const BACKUP_AUTH: &str = "Ente Auth 文件密码错误，或加密备份已损坏。";
const MAX_KDF_MEMORY: u64 = 1024 * 1024 * 1024;
const MAX_KDF_WORK: u64 = 4 * MAX_KDF_MEMORY;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Backup {
    version: u32,
    kdf_params: KdfParams,
    encrypted_data: String,
    encryption_nonce: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KdfParams {
    mem_limit: u64,
    ops_limit: u32,
    salt: String,
}

fn decrypt_backup(backup: Backup, password: Option<&str>) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if backup.version != 1 { return Err("此 Ente Auth 加密备份版本不受支持。"); }
    let KdfParams { mem_limit, ops_limit, salt } = backup.kdf_params;
    // Accept the native 1 GiB / 4 profile and its lower-memory fallbacks, not
    // arbitrary work requested by a file. Never substitute different parameters.
    if !(8192..=MAX_KDF_MEMORY).contains(&mem_limit) || !mem_limit.is_multiple_of(1024) ||
        ops_limit == 0 || u64::from(ops_limit) > MAX_KDF_WORK / mem_limit {
        return Err("Ente Auth 备份的密钥派生参数超出本机导入上限。");
    }
    let password = password.filter(|s| !s.is_empty()).ok_or("请输入 Ente Auth 文件密码。")?;
    if password.len() > 4096 { return Err("Ente Auth 文件密码太长。"); }
    let salt = STANDARD.decode(salt).map_err(|_| INVALID_BACKUP)?;
    if salt.len() != 16 { return Err(INVALID_BACKUP); }
    // This is a secretstream header, despite the historical JSON field name.
    let header = STANDARD.decode(backup.encryption_nonce).map_err(|_| INVALID_BACKUP)?;
    let header = Header::try_from(header.as_slice()).map_err(|_| INVALID_BACKUP)?;
    let mut buffer = Zeroizing::new(STANDARD.decode(backup.encrypted_data).map_err(|_| INVALID_BACKUP)?);
    if !(Stream::ABYTES..=MAX_BYTES + Stream::ABYTES).contains(&buffer.len()) {
        return Err(INVALID_BACKUP);
    }

    let params = Params::new((mem_limit / 1024) as u32, ops_limit, 1, Some(Key::BYTES))
        .map_err(|_| INVALID_BACKUP)?;
    let mut key = Zeroizing::new([0; Key::BYTES]);
    {
        let mut blocks = Zeroizing::new(Vec::new());
        blocks.try_reserve_exact(params.block_count()).map_err(|_| "本机内存不足，无法解密 Ente Auth 备份。")?;
        blocks.resize(params.block_count(), Block::default());
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(password.as_bytes(), &salt, &mut *key, &mut *blocks)
            .map_err(|_| BACKUP_AUTH)?;
    }
    // Ente Auth uses one authenticated secretstream message with empty AAD.
    // Older readers/writers allow a MESSAGE tag as well as this format's FINAL.
    let stream_key = Key::try_from(key.as_slice()).map_err(|_| INVALID_BACKUP)?;
    let tag = PullStream::init(header, &stream_key).pull(&mut *buffer, &[]).map_err(|_| BACKUP_AUTH)?;
    if !matches!(tag, Tag::Final | Tag::Message) { return Err(INVALID_BACKUP); }
    Ok(buffer)
}

/// serde_json::Value has no Zeroize implementation. Scrub every string on drop.
struct SensitiveJson(Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::String(s) => s.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(wipe),
                Value::Object(values) => values.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

fn display_json(value: &str) -> Result<SensitiveJson, &'static str> {
    let mut stream = serde_json::Deserializer::from_str(value).into_iter::<Value>();
    let parsed = SensitiveJson(stream.next().ok_or(INVALID)?.map_err(|_| INVALID)?);
    let trailing = value[stream.byte_offset()..].trim();
    if !parsed.0.is_object() || (!trailing.is_empty() && !trailing.starts_with('#')) { return Err(INVALID); }
    for key in ["pinned", "trashed"] {
        if parsed.0.get(key).is_some_and(|v| !v.is_boolean() && !v.is_null()) { return Err(INVALID); }
    }
    if parsed.0.get("note").is_some_and(|v| !v.is_string() && !v.is_null()) { return Err(INVALID); }
    if let Some(tags) = parsed.0.get("tags").filter(|v| !v.is_null()) {
        if !tags.as_array().is_some_and(|tags| tags.iter().all(Value::is_string)) { return Err(INVALID); }
    }
    Ok(parsed)
}

/// Normalize only known Ente export defects; validation of the result stays strict.
fn normalize(line: &str) -> Result<Otp, &'static str> {
    let quoted;
    let line = if line.starts_with('"') {
        quoted = Zeroizing::new(serde_json::from_str::<String>(line).map_err(|_| INVALID)?);
        &*quoted
    } else { line };
    let uri = line.strip_prefix("otpauth://").ok_or(INVALID)?;
    let (kind, uri) = uri.split_once('/').ok_or(INVALID)?;
    let (label, query) = uri.split_once('?').ok_or(INVALID)?;
    let mut params = Zeroizing::new(Vec::<(String, String)>::new());
    let mut sticky_period = None;
    for field in query.split('&') {
        let (key, value) = field.split_once('=').ok_or(INVALID)?;
        if params.iter().any(|(old, _)| old == key) { return Err(INVALID); }
        let mut value = uri_decode(value, true)?;
        if key == "algorithm" {
            let algorithm = value.rsplit('.').next().unwrap_or("").to_ascii_uppercase();
            value.zeroize();
            *value = algorithm;
        }
        if key == "issuer" {
            if let Some(index) = value.find("period=") {
                sticky_period = Some(value[index + 7..].parse::<u64>().map_err(|_| INVALID)?);
                value.truncate(index);
            }
        }
        if key == "codeDisplay" {
            let display = display_json(&value)?;
            value.zeroize();
            *value = serde_json::to_string(&display.0).map_err(|_| INVALID)?;
        }
        params.push((key.into(), std::mem::take(&mut *value)));
    }
    if let Some(period) = sticky_period {
        if !params.iter().any(|(key, _)| key == "period") { params.push(("period".into(), period.to_string())); }
    }
    let mut normalized = Zeroizing::new(format!("otpauth://{kind}/{}?", uri_encode(&uri_decode(label, false)?)));
    for (index, (key, value)) in params.iter().enumerate() {
        if index != 0 { normalized.push('&'); }
        let encoded = Zeroizing::new(uri_encode(value));
        normalized.push_str(key);
        normalized.push('=');
        normalized.push_str(&encoded);
    }
    parse(&normalized)
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct Row {
    setup_key: String,
    issuer: String,
    account: String,
    note: String,
    tags: Vec<String>,
    pinned: bool,
    trashed: bool,
}

#[derive(Serialize)]
struct Batch {
    rows: Vec<Row>,
    invalid: usize,
    skipped: usize,
}

fn read(bytes: &[u8], existing: &str) -> Result<String, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES { return Err("验证器文件不能超过 2 MiB。"); }
    let text = std::str::from_utf8(bytes).map_err(|_| INVALID)?.trim_start_matches('\u{feff}');
    let existing = SensitiveJson(serde_json::from_str(existing).map_err(|_| INVALID)?);
    let mut seen = BTreeSet::new();
    for setup in existing.0.as_array().ok_or(INVALID)? {
        let value = setup.as_str().or_else(|| setup["setupKey"].as_str());
        if let Some(mut otp) = value.and_then(|s| parse(s).ok()) {
            if otp.label.is_empty() && setup.is_object() {
                otp.issuer = setup["title"].as_str().unwrap_or("Account").into();
                otp.label = format!("{}:{}", otp.issuer, setup["account"].as_str().unwrap_or(""));
            }
            seen.insert(otp.identity());
        }
    }
    let mut batch = Batch { rows: Vec::new(), invalid: 0, skipped: 0 };
    let mut count = 0;
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty()) {
        count += 1;
        if count > MAX_ROWS { return Err("单次最多导入 5,000 个验证码，请分批导入。"); }
        let otp = match normalize(line) {
            Ok(otp) => otp,
            Err(_) => { batch.invalid += 1; continue; }
        };
        if !seen.insert(otp.identity()) { batch.skipped += 1; continue; }
        let display = if otp.code_display.is_empty() { SensitiveJson(json!({})) } else { display_json(&otp.code_display)? };
        batch.rows.push(Row {
            setup_key: otp.canonical_uri().to_string(), issuer: otp.issuer.clone(), account: otp.account().into(),
            note: display.0["note"].as_str().unwrap_or("").into(),
            tags: display.0["tags"].as_array().map(|v| v.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default(),
            pinned: display.0["pinned"].as_bool().unwrap_or(false),
            trashed: display.0["trashed"].as_bool().unwrap_or(false),
        });
    }
    serde_json::to_string(&batch).map_err(|_| INVALID)
}

fn read_input(bytes: &[u8], existing: &str, password: Option<&str>) -> Result<String, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_BACKUP_BYTES {
        return Err("Ente Auth 文本不能超过 2 MiB，加密 JSON 不能超过 3 MiB。");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| INVALID)?.trim_start_matches('\u{feff}').trim_start();
    if text.starts_with('{') || password.is_some() {
        if let Ok(backup) = serde_json::from_str::<Backup>(text) {
            let plaintext = decrypt_backup(backup, password)?;
            return read(&plaintext, existing);
        }
        // Reject identifiable but corrupt JSON backups. A lone malformed text
        // line beginning with "{" must not discard other valid URI lines.
        if password.is_some() || ["\"encryptedData\"", "\"encryptionNonce\"", "\"kdfParams\""]
            .iter().any(|key| text.contains(key)) || serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok() {
            return Err(INVALID_BACKUP);
        }
    }
    read(bytes, existing)
}

fn export(items: &str) -> Result<String, &'static str> {
    let items = SensitiveJson(serde_json::from_str(items).map_err(|_| INVALID)?);
    let items = items.0.as_array().ok_or(INVALID)?;
    if items.len() > MAX_ROWS { return Err("每次最多导出 5,000 个验证码。"); }
    let mut output = Zeroizing::new(String::new());
    for item in items {
        let data = &item["data"];
        let mut otp = parse(data["totpUri"].as_str().ok_or(INVALID)?)?;
        if otp.label.is_empty() {
            otp.issuer = item["title"].as_str().unwrap_or("Account").into();
            let account = data["username"].as_str().unwrap_or("");
            otp.label = format!("{}:{account}", otp.issuer);
        }
        let mut display = if otp.code_display.is_empty() { SensitiveJson(json!({})) } else { display_json(&otp.code_display)? };
        for (key, default) in [("note", json!("")), ("tags", json!([])), ("pinned", json!(false)), ("trashed", json!(false))] {
            display.0[key] = item.get(key).cloned().unwrap_or(default);
        }
        *otp.code_display = serde_json::to_string(&display.0).map_err(|_| INVALID)?;
        output.push_str(&otp.canonical_uri());
        output.push('\n');
        if output.len() > MAX_BYTES { return Err("导出的验证器文本超过 2 MiB，请分批导出。"); }
    }
    Ok(std::mem::take(&mut *output))
}

#[wasm_bindgen]
pub fn wasm_parse_ente_auth(bytes: Vec<u8>, existing_setups: String, password: Option<String>) -> Result<String, JsValue> {
    let password = password.map(Zeroizing::new);
    read_input(&Zeroizing::new(bytes), &Zeroizing::new(existing_setups), password.as_ref().map(|s| s.as_str()))
        .map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn wasm_export_ente_auth(items: String) -> Result<String, JsValue> {
    export(&Zeroizing::new(items)).map_err(JsValue::from_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn batch(text: &str) -> Value { serde_json::from_str(&read(text.as_bytes(), "[]").unwrap()).unwrap() }

    #[test]
    fn keeps_plaintext_rows_after_a_malformed_brace_line() {
        let text = format!("{{invalid line}}\notpauth://totp/Example?secret={SECRET}");
        let result: Value = serde_json::from_str(&read_input(text.as_bytes(), "[]", None).unwrap()).unwrap();
        assert_eq!(result["invalid"], 1);
        assert_eq!(result["rows"].as_array().unwrap().len(), 1);
        assert_eq!(read_input(b"{\"kdfParams\":", "[]", None), Err(INVALID_BACKUP));
    }

    #[test]
    fn repairs_legacy_exports_and_preserves_display_metadata() {
        let display = json!({"pinned": true, "trashed": true, "note": "notes # & 中文", "tags": ["work", "中文"], "iconID": "custom", "position": 12});
        let source = format!("otpauth://totp/Acme:user#123?secret=gezd-gnbv%20gy3tqojqgezdgnbvgy3tqojq&algorithm=Algorithm.sha256&issuer=Acmeperiod=60&codeDisplay={}", uri_encode(&(display.to_string() + " #")));
        let parsed = batch(&source);
        let row = &parsed["rows"][0];
        assert_eq!(row["account"], "user#123");
        assert_eq!(row["issuer"], "Acme");
        assert_eq!(row["tags"], display["tags"]);
        assert_eq!(row["note"], display["note"]);
        assert_eq!(row["trashed"], true);
        let otp = parse(row["setupKey"].as_str().unwrap()).unwrap();
        assert!(otp.canonical_uri().contains("algorithm=SHA256"));
        assert!(otp.canonical_uri().contains("period=60"));
        assert_eq!(display_json(&otp.code_display).unwrap().0, display);
    }

    #[test]
    fn totp_hotp_steam_export_import_round_trip_is_lossless() {
        let source = ["totp", "hotp", "steam"].iter().map(|kind|
            format!("otpauth://{kind}/Issuer%3Auser?secret={SECRET}&counter=9007199254740993")
        ).collect::<Vec<_>>().join("\r\n");
        let rows = batch(&source);
        let items: Vec<Value> = rows["rows"].as_array().unwrap().iter().map(|row| json!({
            "title": row["issuer"], "data": {"kind": "login", "username": row["account"], "totpUri": row["setupKey"]},
            "note": "same note", "tags": ["one", "two"], "pinned": true, "trashed": true,
        })).collect();
        let exported = export(&serde_json::to_string(&items).unwrap()).unwrap();
        let second = batch(&exported);
        for row in second["rows"].as_array().unwrap() {
            assert_eq!(row["note"], "same note");
            assert_eq!(row["tags"], json!(["one", "two"]));
            assert_eq!(row["pinned"], true);
            assert_eq!(row["trashed"], true);
        }
        assert!(exported.contains("counter=9007199254740993"));
        assert_eq!(second["rows"].as_array().unwrap().len(), 3);
        let third = batch(&export(&serde_json::to_string(&second["rows"].as_array().unwrap().iter().map(|row| json!({
            "data": {"totpUri": row["setupKey"]}, "note": row["note"], "tags": row["tags"], "pinned": row["pinned"], "trashed": row["trashed"],
        })).collect::<Vec<_>>()).unwrap()).unwrap());
        assert_eq!(second, third);
    }

    #[test]
    fn deduplication_does_not_roll_back_hotp_counters_or_restore_trash() {
        let source = format!("otpauth://hotp/Example%3Auser?secret={SECRET}&counter=0");
        let existing = source.replace("counter=0", "counter=50");
        let parsed: Value = serde_json::from_str(&read(source.as_bytes(), &json!([existing]).to_string()).unwrap()).unwrap();
        assert_eq!(parsed["rows"], json!([]));
        assert_eq!(parsed["skipped"], 1);
        assert_eq!(batch(&(source.clone() + "\n" + &source))["skipped"], 1);
        let renamed = source.replace("Example%3Auser", "Renamed%3Aother");
        let parsed: Value = serde_json::from_str(&read(renamed.as_bytes(), &json!([existing]).to_string()).unwrap()).unwrap();
        assert_eq!(parsed["skipped"], 1);
    }

    #[test]
    fn manually_entered_seeds_do_not_duplicate_after_exporting_and_importing() {
        let item = json!({
            "title": "Personal mail", "data": {"username": "guest", "totpUri": SECRET},
            "note": "", "tags": [], "pinned": false, "trashed": false,
        });
        let exported = export(&json!([item]).to_string()).unwrap();
        let existing = json!([{"title": "Personal mail", "account": "guest", "setupKey": SECRET}]);
        let parsed: Value = serde_json::from_str(&read(exported.as_bytes(), &existing.to_string()).unwrap()).unwrap();
        assert_eq!(parsed["skipped"], 1);
        assert_eq!(parsed["rows"], json!([]));
    }

    #[test]
    fn malformed_records_are_reported_without_leaking_secrets() {
        let text = format!("not-an-otp\n otpauth://totp/Test?secret={SECRET}&secret={SECRET}\notpauth://hotp/Test?secret={SECRET}");
        assert_eq!(batch(&text)["invalid"], 3);
        assert!(read(&[0xff], "[]").is_err());
        assert!(read(&vec![b' '; MAX_BYTES + 1], "[]").is_err());
        assert!(read("invalid\n".repeat(MAX_ROWS + 1).as_bytes(), "[]").is_err());
    }

    #[test]
    fn quoted_lines_and_plus_encoded_labels_survive() {
        let source = format!("otpauth://totp/Example%3Auser%2Btag?secret={SECRET}&issuer=Example");
        let parsed = batch(&serde_json::to_string(&source).unwrap());
        assert_eq!(parsed["rows"][0]["account"], "user+tag");
        let invalid = format!("{source}&codeDisplay={}", uri_encode(r#"{"tags":123}"#));
        assert_eq!(batch(&invalid)["invalid"], 1);
    }
}
