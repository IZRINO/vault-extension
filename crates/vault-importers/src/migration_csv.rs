use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
use crate::bitwarden::{SecretJson, text};

pub(crate) fn records(bytes: &[u8]) -> Result<Zeroizing<Vec<Vec<String>>>, &'static str> {
    if bytes.is_empty() || bytes.len() > crate::MAX_BYTES { return Err("CSV 需为不超过 2 MiB 的 UTF-8 文件。"); }
    let data = std::str::from_utf8(bytes).map_err(|_| "CSV 需使用 UTF-8 编码。")?;
    crate::read_csv(data.trim_start_matches('\u{feff}'))
}

type Mapping = BTreeMap<&'static str, usize>;
fn detect(head: &[String]) -> Option<(&'static str, Mapping)> {
    let names = head.iter().map(|name| name.trim().to_ascii_lowercase()).collect::<Vec<_>>();
    let columns = names.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if columns.len() != head.len() || columns.contains("") { return None; }
    let has = |required: &[&str]| required.iter().all(|name| columns.contains(name));
    let candidates = [
        ("Dashlane", has(&["username","username2","title","password","note","url","category"]), [
            "title", "url", "username", "password", "note", "otpurl", "category",
        ]),
        ("NordPass", has(&["name","url","username","password","note","folder","cardholdername","cardnumber","type"]), [
            "name", "url", "username", "password", "note", "totp", "folder",
        ]),
        ("LastPass", has(&["url","username","password","extra","name","grouping","fav"]), [
            "name", "url", "username", "password", "extra", "totp", "grouping",
        ]),
    ];
    let [(vendor, _, fields)] = candidates.iter().filter(|(_, matched, _)| *matched).collect::<Vec<_>>()[..] else { return None; };
    let mut mapping = Mapping::new();
    for (key, name) in ["title","url","username","password","note","totp","tags"].into_iter().zip(fields) {
        if *vendor == "Dashlane" && key == "totp" && columns.contains("otpsecret") && columns.contains("otpurl") { return None; }
        let name = if *vendor == "Dashlane" && key == "totp" && columns.contains("otpsecret") { "otpsecret" } else { name };
        if let Some(index) = names.iter().position(|candidate| candidate == name) { mapping.insert(key, index); }
    }
    Some((vendor, mapping))
}

fn enpass(rows: &[Vec<String>]) -> bool {
    rows.first().is_some_and(|row| row[1..].chunks_exact(2).any(|pair| pair[0].trim().eq_ignore_ascii_case("*password")))
        || (rows.len() > 1 && rows[1..].iter().any(|row| {
            let labels = row[1..].chunks_exact(2).map(|pair| pair[0].trim().to_ascii_lowercase()).collect::<BTreeSet<_>>();
            labels.contains("*password") && (labels.contains("website") || labels.contains("username"))
        }) && !rows[0].iter().any(|cell| ["url", "password", "website", "密码"].contains(&cell.trim().to_ascii_lowercase().as_str())))
}

fn headers(bytes: &[u8]) -> Result<String, &'static str> {
    let rows = records(bytes)?;
    let head = rows.first().ok_or("CSV 没有表头。")?;
    if let Some(vendor) = crate::typed_csv::detect(head) {
        return Ok(json!({ "vendor":vendor.label(), "headers":[], "count":rows.len() - 1, "mapping":{} }).to_string());
    }
    if enpass(&rows) {
        return Ok(json!({ "vendor": "Enpass", "headers": [], "count": rows.len(), "mapping": {} }).to_string());
    }
    let mut result = json!({ "headers": head, "count": rows.len() - 1 });
    if let Some((vendor, mapping)) = detect(head) {
        result["vendor"] = json!(vendor);
        result["mapping"] = json!(mapping);
    }
    Ok(result.to_string())
}

#[derive(Default)]
struct Login<'a> {
    title: &'a str, username: &'a str, password: &'a str, note: &'a str, otp: &'a str,
    urls: Vec<&'a str>, tags: Vec<String>, pinned: bool, trashed: bool, dashlane: bool,
}
fn login_row(login: Login<'_>, ignored_otp: &mut usize) -> Value {
    let mut fields = SecretJson(json!([]));
    let uri = SecretJson(if login.otp.is_empty() { Value::Null } else {
        let with_label = login.dashlane.then(|| login.otp.strip_prefix("otpauth://totp/?")).flatten()
            .map(|query| Zeroizing::new(format!("otpauth://totp/Account?{query}")));
        let input = with_label.as_ref().map_or(login.otp, |uri| uri.as_str());
        match vault_otp::parse(input) {
            Ok(code) => json!(&*code.canonical_uri()),
            Err(_) => {
                *ignored_otp += 1;
                fields.0.as_array_mut().unwrap().push(json!({"name":"CSV 未识别的验证码设置","value":login.otp,"hidden":true}));
                Value::Null
            }
        }
    });
    let title = if login.title.is_empty() { login.urls.first().copied().unwrap_or("") } else { login.title };
    json!({ "id": "", "title": title, "note": login.note, "tags": login.tags,
        "data": { "kind": "login", "username": login.username, "password": login.password, "totpUri": uri.0,
            "uris": login.urls.into_iter().map(|uri| json!({"uri": uri})).collect::<Vec<_>>() },
        "customFields": fields.0, "pinned": login.pinned, "requireReprompt": false, "trashed": login.trashed })
}

fn csv_result(mut rows: SecretJson, invalid: usize, unsupported: usize, ignored_otp: usize) -> SecretJson {
    let mut result = SecretJson(json!({ "invalid": invalid, "unsupported": unsupported, "ignoredOtp": ignored_otp }));
    result.0["rows"] = std::mem::take(&mut rows.0);
    result
}

fn import_enpass(rows: &[Vec<String>]) -> SecretJson {
    let (mut invalid, mut skipped, mut ignored_otp) = (0, 0, 0);
    let mut output = SecretJson(json!([]));
    for row in rows {
        let (title, fields) = row.split_first().unwrap();
        let mut pairs = fields.chunks_exact(2);
        let note = pairs.remainder().first().map_or("", String::as_str);
        let mut row = Login { title, note, ..Default::default() };
        let mut email = "";
        let mut ambiguous = false;
        for pair in &mut pairs {
            let label = pair[0].trim_start_matches('*').trim().to_ascii_lowercase();
            let value = pair[1].as_str();
            match label.as_str() {
                "username" if row.username.is_empty() => row.username = value,
                "e-mail" | "email" if email.is_empty() => email = value,
                "password" if row.password.is_empty() => row.password = value,
                "password" if !value.is_empty() && row.password != value => ambiguous = true,
                "website" | "url" if !value.is_empty() => row.urls.push(value),
                "one-time code" if row.otp.is_empty() => row.otp = value,
                "one-time code" if !value.is_empty() && row.otp != value => ambiguous = true,
                _ => {}
            }
        }
        if ambiguous || title.is_empty() { invalid += 1; continue; }
        if row.password.is_empty() { skipped += 1; continue; }
        if row.username.is_empty() { row.username = email; }
        output.0.as_array_mut().unwrap().push(login_row(row, &mut ignored_otp));
    }
    csv_result(output, invalid, skipped, ignored_otp)
}

pub(crate) fn valid_additional_url(raw: &str) -> bool {
    let Some((scheme, _)) = raw.split_once("://") else { return false; };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") { return false; }
    if raw.len() > 8192 || raw.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) { return false; }
    let Ok(url) = url::Url::parse(raw) else { return false; };
    let valid = url.has_host() && url.username().is_empty() && url.password().is_none();
    let _serialized = Zeroizing::new(String::from(url));
    valid
}

fn add_additional_url<'a>(urls: &mut Vec<&'a str>, value: Option<&'a str>, unsupported: &mut usize) {
    if let Some(url) = value.filter(|url| urls.len() < 64 && valid_additional_url(url)) {
        urls.push(url);
    } else {
        *unsupported += 1;
    }
}

fn import(bytes: &[u8], mapping: &str) -> Result<String, &'static str> {
    let records = records(bytes)?;
    Ok(import_rows(&records, mapping, false)?.0.to_string())
}

pub(crate) fn dashlane_credentials(records: &[Vec<String>]) -> Result<SecretJson, &'static str> {
    let header = records.first().ok_or("Dashlane 登录文件没有表头。")?;
    let (_, mapping) = detect(header).filter(|(vendor, _)| *vendor == "Dashlane").ok_or("无法识别 Dashlane 登录文件表头。")?;
    import_rows(records, &json!(mapping).to_string(), true)
}

fn import_rows(records: &[Vec<String>], mapping: &str, allow_incomplete_dashlane_rows: bool) -> Result<SecretJson, &'static str> {
    let (head, rows) = records.split_first().ok_or("CSV 没有表头。")?;
    let mapping: Value = serde_json::from_str(mapping).map_err(|_| "字段映射无效。")?;
    if !mapping.is_object() { return Err("字段映射无效。"); }
    if let Some(vendor) = crate::typed_csv::detect(head) {
        if mapping.as_object().is_some_and(|fields| !fields.is_empty()) { return Err("此导出格式不接受手工字段映射。"); }
        return Ok(crate::typed_csv::import(vendor, head, rows));
    }
    if enpass(records) {
        if mapping.as_object().is_some_and(|fields| !fields.is_empty()) { return Err("Enpass 导出使用记录内的字段名，不接受表头映射。"); }
        return Ok(import_enpass(records));
    }
    let vendor = detect(head).filter(|(_, expected)| json!(expected) == mapping).map(|(vendor, _)| vendor);
    let column = |name: &str| head.iter().position(|column| column.trim().eq_ignore_ascii_case(name));
    let type_index = vendor.filter(|v| *v == "NordPass").and_then(|_| column("type"));
    let additional = vendor.filter(|v| *v == "NordPass").and_then(|_| column("additional_urls"));
    let favorite = vendor.filter(|v| *v == "LastPass").and_then(|_| column("fav"));
    let dashlane = vendor == Some("Dashlane");
    let aliases = ["username2", "username3"].into_iter().filter_map(|name| Some((name, column(name)?))).collect::<Vec<_>>();
    let mut used = Vec::new();
    for (key, index) in mapping.as_object().unwrap() {
        if !["title", "url", "username", "password", "note", "totp", "tags", "trashed"].contains(&key.as_str()) { return Err("字段映射无效。"); }
        let index = index.as_u64().and_then(|index| usize::try_from(index).ok()).filter(|n| *n < head.len()).ok_or("请选择有效的源列。")?;
        if used.contains(&index) { return Err("同一个源列不能同时映射到多个字段。"); } used.push(index);
    }
    if mapping.get("password").is_none() || mapping.get("url").is_none() { return Err("请映射网站和密码列。"); }
    let (mut invalid, mut ignored_otp, mut unsupported) = (0, 0, 0);
    let mut output = SecretJson(json!([]));
    for row in rows {
        let get = |name: &str| mapping[name].as_u64().and_then(|i| row.get(i as usize)).map(String::as_str).unwrap_or("");
        if row.len() != head.len() { invalid += 1; continue; }
        if type_index.is_some_and(|i| !row[i].eq_ignore_ascii_case("password")) || (vendor == Some("LastPass") && get("url").trim() == "http://sn") {
            unsupported += 1;
            continue;
        }
        let source_url = get("url");
        let url = source_url.trim();
        let blocked_url = dashlane && !url.is_empty() && !valid_additional_url(url);
        if !(dashlane && allow_incomplete_dashlane_rows) && (get("password").is_empty() || url.is_empty()) { invalid += 1; continue; }
        if dashlane && ["title", "username", "password", "note", "totp", "url"].iter().all(|key| get(key).is_empty())
            && aliases.iter().all(|(_, index)| row[*index].is_empty()) {
            invalid += 1;
            continue;
        }
        let tags = if get("tags").is_empty() { Vec::new() } else if vendor.is_some() { vec![get("tags").into()] } else {
            serde_json::from_str::<Vec<String>>(get("tags")).unwrap_or_else(|_| get("tags").split(';').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        };
        let extra = additional.map_or("", |index| row[index].trim());
        let is_array = extra.starts_with('[');
        let array = SecretJson(if is_array { serde_json::from_str::<Value>(extra).unwrap_or(Value::Null) } else { Value::Null });
        let mut urls: Vec<_> = (!url.is_empty() && !blocked_url).then_some(url).into_iter().collect();
        if is_array {
            match array.0.as_array() {
                Some(entries) => {
                    for entry in entries { add_additional_url(&mut urls, entry.as_str(), &mut unsupported); }
                }
                None => unsupported += 1,
            }
        } else if !extra.is_empty() {
            // A bare URL may contain commas and nested URLs. Only the JSON form denotes a list.
            add_additional_url(&mut urls, Some(extra), &mut unsupported);
        }
        let title = get("title").trim();
        let title = if dashlane && title.is_empty() { "Dashlane 登录项" } else { title };
        let mut mapped = SecretJson(login_row(Login { title, username: get("username"),
            password: get("password"), note: get("note"), otp: get("totp"), urls, tags,
            pinned: favorite.is_some_and(|i| row[i] == "1"), trashed: ["true","1","yes"].contains(&get("trashed")),
            dashlane }, &mut ignored_otp));
        if dashlane {
            let mut source_fields: BTreeMap<_, _> = aliases.iter().filter_map(|&(name, index)| {
                let value = row[index].as_str();
                (!value.is_empty()).then_some((name, value))
            }).collect();
            if blocked_url || source_url != url { source_fields.insert("url", source_url); }
            if blocked_url { unsupported += 1; }
            if !source_fields.is_empty() {
                let mut field = json!({"name":"CSV 源自定义字段", "hidden":true});
                field["value"] = Value::String(serde_json::to_string(&source_fields).unwrap());
                mapped.0["customFields"].as_array_mut().unwrap().push(field);
            }
        }
        output.0.as_array_mut().unwrap().push(std::mem::take(&mut mapped.0));
    }
    Ok(csv_result(output, invalid, unsupported, ignored_otp))
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
    fn vendor_signatures_preserve_login_fields_without_exposing_headers_from_enpass_rows() {
        let dashlane = "\u{feff}username,username2,username3,title,password,note,url,category,otpUrl\r\nu,,,Entry,\" p,\"\"x\",\"Line\r\n2\",https://example.com,Work,JBSWY3DPEHPK3PXP";
        let nordpass = "name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields\nEntry,https://example.com,https://example.org,u,p,Note,,,,,,Work,,,,,,,,,password,";
        let lastpass = "url,username,password,totp,extra,name,grouping,fav\nhttps://example.com,u,p,JBSWY3DPEHPK3PXP,\"Line\n2\",Entry,Work,1";
        let enpass = "\"Entry\",Username,u,*Password,\"p,\"\"x\",Website,https://example.com,Website,https://example.org,One-time code,JBSWY3DPEHPK3PXP,\"Line\n2\"\nNext,E-mail,other@example.com,*Password,q,Website,https://other.example";
        for (vendor, csv) in [("Dashlane", dashlane), ("NordPass", nordpass), ("LastPass", lastpass), ("Enpass", enpass)] {
            let report: Value = serde_json::from_str(&headers(csv.as_bytes()).unwrap()).unwrap();
            assert_eq!(report["vendor"], vendor);
            let batch: Value = serde_json::from_str(&import(csv.as_bytes(), &report["mapping"].to_string()).unwrap()).unwrap();
            let first = &batch["rows"][0];
            assert_eq!(first["title"], "Entry");
            assert_eq!(first["data"]["username"], "u");
            assert_eq!(first["data"]["uris"][0]["uri"], "https://example.com");
            if vendor != "NordPass" {
                assert!(text(&first["data"], "totpUri").starts_with("otpauth://totp/"));
                assert!(text(first, "note").ends_with("\n2"));
            }
            if vendor == "Enpass" {
                assert_eq!(report["headers"], json!([]));
                assert_eq!(first["data"]["password"], "p,\"x");
                assert_eq!(first["data"]["uris"][1]["uri"], "https://example.org");
                assert_eq!(batch["rows"][1]["data"]["username"], "other@example.com");
            }
            if vendor == "Dashlane" { assert_eq!(first["data"]["password"], " p,\"x"); }
        }
        for ambiguous in [
            "url,username,password,extra,name,grouping,fav,password\na,u,p,n,x,t,0,p",
            "title,url,username,password,note\na,b,c,d,e",
        ] {
            let report: Value = serde_json::from_str(&headers(ambiguous.as_bytes()).unwrap()).unwrap();
            assert!(report["vendor"].is_null());
        }
    }

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
