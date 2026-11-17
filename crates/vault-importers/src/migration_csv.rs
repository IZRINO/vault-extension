use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
use crate::bitwarden::{SecretJson, text};

fn records(bytes: &[u8]) -> Result<Zeroizing<Vec<Vec<String>>>, &'static str> {
    if bytes.is_empty() || bytes.len() > crate::MAX_BYTES { return Err("CSV 需为不超过 2 MiB 的 UTF-8 文件。"); }
    let data = std::str::from_utf8(bytes).map_err(|_| "CSV 需使用 UTF-8 编码。")?;
    crate::read_csv(data.trim_start_matches('\u{feff}'))
}
fn headers(bytes: &[u8]) -> Result<String, &'static str> {
    let rows = records(bytes)?;
    let head = rows.first().ok_or("CSV 没有表头。")?;
    Ok(json!({ "headers": head, "count": rows.len() - 1 }).to_string())
}
fn import(bytes: &[u8], mapping: &str) -> Result<String, &'static str> {
    let records = records(bytes)?;
    let (head, rows) = records.split_first().ok_or("CSV 没有表头。")?;
    let mapping: Value = serde_json::from_str(mapping).map_err(|_| "字段映射无效。")?;
    if !mapping.is_object() { return Err("字段映射无效。"); }
    let mut used = Vec::new();
    for (key, index) in mapping.as_object().unwrap() {
        if !["title", "url", "username", "password", "note", "totp", "tags", "trashed"].contains(&key.as_str()) { return Err("字段映射无效。"); }
        let index = index.as_u64().filter(|n| (*n as usize) < head.len()).ok_or("请选择有效的源列。")?;
        if used.contains(&index) { return Err("同一个源列不能同时映射到多个字段。"); } used.push(index);
    }
    if mapping.get("password").is_none() || mapping.get("url").is_none() { return Err("请映射网站和密码列。"); }
    let (mut invalid, mut ignored_otp) = (0, 0);
    let mut output = SecretJson(json!([]));
    for row in rows {
        let get = |name: &str| mapping[name].as_u64().and_then(|i| row.get(i as usize)).map(String::as_str).unwrap_or("");
        if row.len() != head.len() || get("password").is_empty() || get("url").trim().is_empty() { invalid += 1; continue; }
        let otp = get("totp");
        let mut fields = Vec::new();
        let otp = if otp.is_empty() { Value::Null } else { match vault_otp::parse(otp) {
            Ok(code) => json!(&*code.canonical_uri()),
            Err(_) => {
                ignored_otp += 1; fields.push(json!({ "name": "CSV 未识别的验证码设置", "value": otp, "hidden": true }));
                Value::Null
            }
        }};
        let tags = if get("tags").is_empty() { Vec::new() } else {
            serde_json::from_str::<Vec<String>>(get("tags")).unwrap_or_else(|_| get("tags").split(';').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        };
        output.0.as_array_mut().unwrap().push(json!({ "id": "", "title": if get("title").trim().is_empty() { get("url").trim() } else { get("title").trim() },
            "data": { "kind": "login", "username": get("username"), "password": get("password"), "uris": [{ "uri": get("url").trim() }], "totpUri": otp },
            "note": get("note"), "customFields": fields, "tags": tags, "pinned": false, "requireReprompt": false,
            "trashed": (["true", "1", "yes"].contains(&get("trashed"))) }));
    }
    Ok(json!({ "rows": output.0, "invalid": invalid, "unsupported": 0, "ignoredOtp": ignored_otp }).to_string())
}
fn cell(value: &str) -> String { format!("\"{}\"", value.replace('"', "\"\"")) }
fn export(items: &str) -> Result<String, &'static str> {
    let items = SecretJson(serde_json::from_str(items).map_err(|_| "无法导出 CSV。")?);
    let rows = items.0.as_array().ok_or("无法导出 CSV。")?;
    let mut output = Zeroizing::new(String::from("\u{feff}title,url,username,password,note,totp,tags,trashed\r\n"));
    let (mut count, mut skipped) = (0, 0);
    for item in rows {
        if text(&item["data"], "kind") != "login" { skipped += 1; continue; }
        let data = &item["data"];
        let url = data["uris"].as_array().and_then(|uris| uris.first()).map(|uri| text(uri, "uri")).unwrap_or("");
        let tags = Zeroizing::new(item["tags"].to_string());
        let columns = [text(item, "title"), url, text(data, "username"), text(data, "password"), text(item, "note"), text(data, "totpUri"), &*tags,
            if item["trashed"] == true { "true" } else { "false" }];
        output.push_str(&columns.into_iter().map(cell).collect::<Vec<_>>().join(",")); output.push_str("\r\n");
        count += 1;
    }
    if output.len() > crate::MAX_BYTES { return Err("登录 CSV 超过 2 MiB，请改用 Bitwarden JSON 或加密备份。"); }
    Ok(json!({ "text": &*output, "count": count, "skipped": skipped }).to_string())
}

#[wasm_bindgen]
pub fn wasm_csv_headers(bytes: Vec<u8>) -> Result<String, JsValue> { headers(&Zeroizing::new(bytes)).map_err(JsValue::from_str) }
#[wasm_bindgen]
pub fn wasm_parse_mapped_csv(bytes: Vec<u8>, mapping: String) -> Result<String, JsValue> {
    import(&Zeroizing::new(bytes), &mapping).map_err(JsValue::from_str)
}
#[wasm_bindgen]
pub fn wasm_export_login_csv(items: String) -> Result<String, JsValue> {
    export(&Zeroizing::new(items)).map_err(JsValue::from_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manual_mapping_quotes_otp_and_roundtrip() {
        let csv = "账号,站点,口令,备注,密钥\r\nu,https://example.com,\" p,\"\"q\",\"a\r\nb\",JBSWY3DPEHPK3PXP\r\n";
        let map = json!({ "username": 0, "url": 1, "password": 2, "note": 3, "totp": 4 }).to_string();
        let batch: Value = serde_json::from_str(&import(csv.as_bytes(), &map).unwrap()).unwrap();
        assert_eq!(batch["rows"][0]["data"]["password"], " p,\"q");
        assert_eq!(batch["rows"][0]["note"], "a\r\nb");
        assert!(text(&batch["rows"][0]["data"], "totpUri").starts_with("otpauth://totp/"));
        let exported: Value = serde_json::from_str(&export(&batch["rows"].to_string()).unwrap()).unwrap();
        let map = json!({ "title": 0, "url": 1, "username": 2, "password": 3, "note": 4, "totp": 5, "tags": 6, "trashed": 7 }).to_string();
        let restored: Value = serde_json::from_str(&import(text(&exported, "text").as_bytes(), &map).unwrap()).unwrap();
        assert_eq!(restored["rows"], batch["rows"]);
        assert!(import(csv.as_bytes(), r#"{"url":1,"password":1}"#).is_err());
        let headers: Value = serde_json::from_str(&headers(csv.as_bytes()).unwrap()).unwrap();
        assert!(!headers.to_string().contains("JBSWY"));
    }
}
