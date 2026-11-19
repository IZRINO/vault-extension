use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use base64::{Engine, engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD}};
use prost::Message;
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, io::{Cursor, Read}};
use vault_otp::{encode_base32, parse, uri_decode, uri_encode};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type Result<T> = std::result::Result<T, &'static str>;
const MAX_FILE: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 5000;
const INVALID: &str = "备份格式无效、损坏或超过处理上限。";
const AUTH: &str = "文件密码错误或备份认证失败；没有写入任何条目。";
const PASSWORD: &str = "请输入源备份的文件密码。";

struct Json(Value);
impl Json {
    fn read(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes)).map(Self).map_err(|_| INVALID)
    }
}
impl Drop for Json {
    fn drop(&mut self) {
        fn scrub(value: Value) {
            match value {
                Value::String(mut s) => s.zeroize(),
                Value::Array(arr) => arr.into_iter().for_each(scrub),
                Value::Object(obj) => for (mut key, value) in obj { key.zeroize(); scrub(value); },
                _ => (),
            }
        }
        scrub(std::mem::take(&mut self.0));
    }
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Record {
    title: String,
    data: Login,
    note: String,
    tags: Vec<String>,
    pinned: bool,
    #[serde(rename = "customFields")]
    custom_fields: [(); 0],
}
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Login {
    kind: String,
    username: String,
    #[serde(rename = "totpUri")]
    totp_uri: String,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Batch { rows: Vec<Record>, invalid: usize, unsupported: usize, ignored_otp: usize, repeated_parts: usize, missing_parts: usize }

fn str_at<'a>(v: &'a Value, name: &str) -> &'a str { v.get(name).and_then(Value::as_str).unwrap_or("") }
fn number(v: &Value, name: &str) -> Option<u64> { v.get(name).and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok())) }
fn first<'a>(values: &[&'a str]) -> &'a str { values.iter().copied().find(|v| !v.trim().is_empty()).unwrap_or("") }
fn array(v: &Value) -> Result<&[Value]> { v.as_array().map(Vec::as_slice).filter(|v| v.len() <= MAX_ROWS).ok_or(INVALID) }
fn b64(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    if text.len() > MAX_FILE * 2 { return Err(INVALID); }
    STANDARD.decode(text.trim()).or_else(|_| STANDARD_NO_PAD.decode(text.trim()))
        .or_else(|_| URL_SAFE.decode(text.trim())).or_else(|_| URL_SAFE_NO_PAD.decode(text.trim()))
        .map(Zeroizing::new).map_err(|_| INVALID)
}
fn hex_bytes(text: &str, size: usize) -> Result<Zeroizing<Vec<u8>>> {
    if text.len() != size * 2 { return Err(INVALID); }
    hex::decode(text).map(Zeroizing::new).map_err(|_| INVALID)
}

struct Mapping<'a> {
    kind: &'a str, account: &'a str, issuer: &'a str, title: &'a str, secret: &'a str,
    algorithm: &'a str, digits: Option<u64>, period: Option<u64>, counter: Option<u64>,
    note: &'a str, tags: Vec<String>, pinned: bool,
}
impl Batch {
    fn push(&mut self, row: Mapping) {
        let kind = match row.kind.to_ascii_lowercase().as_str() {
            "totp" | "" => "totp", "hotp" => "hotp", "steam" | "steamotp" => "steam",
            _ => { self.unsupported += 1; return; },
        };
        if row.account.len() > 1024 || row.issuer.len() > 1024 || row.title.len() > 2048 || row.note.len() > 32*1024 {
            self.invalid += 1; return;
        }
        let default_label = first(&[row.account, row.issuer, row.title, "验证码"]);
        let label = if !row.issuer.is_empty() && !row.account.is_empty() && !row.account.contains(':') { format!("{}:{}", row.issuer, row.account) } else { default_label.into() };
        let algorithm = if row.algorithm.is_empty() { "SHA1".to_owned() } else { row.algorithm.to_ascii_uppercase().replace('-', "") };
        if !matches!(algorithm.as_str(), "SHA1" | "SHA256" | "SHA512") { self.unsupported += 1; return; }
        let mut setup = Zeroizing::new(format!("otpauth://{kind}/{}?secret={}&algorithm={algorithm}&digits={}",
            uri_encode(&label), uri_encode(row.secret), if kind == "steam" { 5 } else { row.digits.unwrap_or(6) }));
        if !row.issuer.is_empty() { setup.push_str(&format!("&issuer={}", uri_encode(row.issuer))); }
        if kind == "hotp" { setup.push_str(&format!("&counter={}", row.counter.unwrap_or(0))); }
        else { setup.push_str(&format!("&period={}", if kind == "steam" { 30 } else { row.period.unwrap_or(30) })); }
        if let Ok(valid) = parse(&setup) {
            self.rows.push(Record { title: first(&[row.title, row.issuer, row.account, "验证码"]).into(), note: row.note.into(),
                tags: row.tags, pinned: row.pinned, custom_fields: [], data: Login {
                    kind: "login".into(), username: row.account.into(), totp_uri: valid.canonical_uri().to_string(),
                },
            });
        } else { self.invalid += 1; }
    }
}

#[derive(Message, Zeroize, ZeroizeOnDrop)]
struct GooglePart {
    #[prost(message, repeated, tag = "1")] items: Vec<GoogleOtp>,
    #[prost(int32, tag = "2")] version: i32,
    #[prost(int32, tag = "3")] size: i32,
    #[prost(int32, tag = "4")] index: i32,
    #[prost(int32, tag = "5")] id: i32,
}
#[derive(Message, Zeroize, ZeroizeOnDrop)]
struct GoogleOtp {
    #[prost(bytes = "vec", tag = "1")] secret: Vec<u8>,
    #[prost(string, tag = "2")] name: String,
    #[prost(string, tag = "3")] issuer: String,
    #[prost(int32, tag = "4")] algorithm: i32,
    #[prost(int32, tag = "5")] digits: i32,
    #[prost(int32, tag = "6")] kind: i32,
    #[prost(int64, tag = "7")] counter: i64,
}
fn google(bytes: &[u8]) -> Result<Batch> {
    let text = std::str::from_utf8(bytes).map_err(|_| INVALID)?.trim_start_matches('\u{feff}');
    let mut batch = Batch::default();
    let mut identity = None;
    let mut parts: BTreeMap<i32, (GooglePart, Zeroizing<Vec<u8>>)> = BTreeMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let body = line.trim().strip_prefix("otpauth-migration://offline?data=").ok_or("二维码不是 Google Authenticator 迁移码。")?;
        if body.len() > 256 * 1024 || body.contains(['&', '#']) { return Err(INVALID); }
        let raw = b64(&uri_decode(body, false).map_err(|_| INVALID)?)?;
        let part = GooglePart::decode(raw.as_slice()).map_err(|_| INVALID)?;
        if part.version != 1 || !(1..=64).contains(&part.size) || !(0..part.size).contains(&part.index) ||
            part.items.is_empty() || part.items.len() > 1000 { return Err(INVALID); }
        let id = (part.id, part.size);
        if identity.is_some_and(|old| old != id) { return Err("选中了不同批次的二维码，请一次只选同一批。"); }
        identity = Some(id);
        if let Some((_, seen)) = parts.get(&part.index) {
            if **seen != *raw { return Err("同一位置的二维码内容不一致。"); }
            batch.repeated_parts += 1;
        } else { parts.insert(part.index, (part, raw)); }
    }
    let (_, size) = identity.ok_or(INVALID)?;
    batch.missing_parts = size as usize - parts.len();
    if parts.values().map(|(part, _)| part.items.len()).sum::<usize>() > MAX_ROWS { return Err(INVALID); }
    for (part, _) in parts.values() {
        for row in &part.items {
            let kind = match row.kind { 1 => "hotp", 2 => "totp", _ => { batch.unsupported += 1; continue; } };
            let algorithm = match row.algorithm { 0 | 1 => "SHA1", 2 => "SHA256", 3 => "SHA512", _ => { batch.unsupported += 1; continue; } };
            let digits = match row.digits { 0 | 1 => 6, 2 => 8, _ => { batch.unsupported += 1; continue; } };
            if row.counter < 0 || row.secret.len() > 128 { batch.invalid += 1; continue; }
            let secret = encode_base32(&row.secret);
            let prefix = format!("{}:", row.issuer);
            let account = row.name.strip_prefix(&prefix).unwrap_or(&row.name);
            batch.push(Mapping { kind, account, issuer: &row.issuer, title: "", secret: &secret, algorithm, digits: Some(digits), period: None,
                counter: Some(row.counter as u64), tags: Vec::new(), note: "", pinned: false });
        }
    }
    Ok(batch)
}

fn gcm(key: &[u8], nonce: &[u8], mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 || nonce.len() != 12 || bytes.len() < 16 { return Err(INVALID); }
    let aes = Aes256Gcm::new_from_slice(key).map_err(|_| INVALID)?;
    aes.decrypt_in_place(Nonce::from_slice(nonce), &[], &mut *bytes).map_err(|_| AUTH)?;
    Ok(bytes)
}
fn joined_gcm(key: &[u8], params: &Value, mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    bytes.extend_from_slice(&hex_bytes(str_at(params, "tag"), 16)?);
    gcm(key, &hex_bytes(str_at(params, "nonce"), 12)?, bytes)
}

fn aegis(bytes: &[u8], password: &str) -> Result<Batch> {
    let outer = Json::read(bytes)?;
    if number(&outer.0, "version") != Some(1) { return Err("不支持该 Aegis 外层版本。"); }
    let content;
    let db = &outer.0["db"];
    let db = if let Some(encoded) = db.as_str() {
        if password.is_empty() { return Err(PASSWORD); }
        let header = &outer.0["header"];
        let slots = array(&header["slots"])?;
        if slots.len() > 16 { return Err(INVALID); }
        let pass = slots.iter().find(|slot| number(slot, "type") == Some(1))
            .ok_or("没有可解密的 Aegis 密码槽；系统生物识别槽不可迁移。")?;
        let (n, r, p) = (number(pass, "n").ok_or(INVALID)?, number(pass, "r").ok_or(INVALID)?, number(pass, "p").ok_or(INVALID)?);
        if !n.is_power_of_two() || !(1024..=65536).contains(&n) || !(1..=8).contains(&r) || !(1..=2).contains(&p) || n*r*p > 524_288 { return Err("Aegis scrypt 参数超出本机预算。"); }
        let params = scrypt::Params::new(n.trailing_zeros() as u8, r as u32, p as u32, 32).map_err(|_| INVALID)?;
        let mut key = Zeroizing::new([0; 32]);
        scrypt::scrypt(password.as_bytes(), &hex_bytes(str_at(pass, "salt"), 32)?, &params, key.as_mut()).map_err(|_| AUTH)?;
        let master = joined_gcm(key.as_ref(), &pass["key_params"], hex_bytes(str_at(pass, "key"), 32)?)?;
        let plain = joined_gcm(&master, &header["params"], b64(encoded)?)?;
        content = Json::read(&plain)?;
        &content.0
    } else { db };
    if !matches!(number(db, "version"), Some(1..=3)) { return Err("不支持该 Aegis 数据版本。"); }
    let groups: BTreeMap<&str, &str> = db["groups"].as_array().into_iter().flatten()
        .map(|group| (str_at(group, "uuid"), str_at(group, "name"))).collect();
    let mut batch = Batch::default();
    for row in array(&db["entries"])? {
        let tags = row["groups"].as_array().into_iter().flatten().filter_map(|v| groups.get(v.as_str()?)).map(|v| (*v).to_owned())
            .chain(row["group"].as_str().filter(|s| !s.is_empty()).map(str::to_owned)).take(32).collect();
        let info = &row["info"];
        batch.push(Mapping { kind: str_at(row, "type"), account: str_at(row, "name"), issuer: str_at(row, "issuer"),
            title: "", secret: str_at(info, "secret"), algorithm: str_at(info, "algo"), digits: number(info, "digits"),
            period: number(info, "period"), counter: number(info, "counter"), tags, note: str_at(row, "note"),
            pinned: row["favorite"].as_bool().unwrap_or(false) });
    }
    Ok(batch)
}

fn twofas_open(text: &str, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut iter = text.split(':');
    let (encrypted, salt, nonce) = (b64(iter.next().ok_or(INVALID)?)?, b64(iter.next().ok_or(INVALID)?)?, b64(iter.next().ok_or(INVALID)?)?);
    // The app generates 256-byte salts; continue accepting the previously supported shorter salts.
    if iter.next().is_some() || (salt.len() != 256 && !(16..=64).contains(&salt.len())) { return Err(INVALID); }
    let mut key = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, 10_000, key.as_mut());
    gcm(key.as_ref(), &nonce, encrypted)
}

fn twofas(bytes: &[u8], password: &str) -> Result<Batch> {
    let root = Json::read(bytes)?;
    if !matches!(number(&root.0, "schemaVersion"), Some(2..=4)) { return Err("不支持该 2FAS 备份版本。"); }
    let field = |name| match &root.0[name] {
        Value::String(text) => Ok(text.as_str()),
        Value::Null => Ok(""),
        _ => Err(INVALID),
    };
    let (reference, encrypted) = (field("reference")?, field("servicesEncrypted")?);
    let decrypted;
    let services = if reference.is_empty() && encrypted.is_empty() { &root.0["services"] } else {
        if reference.is_empty() || encrypted.is_empty() { return Err(INVALID); }
        if password.is_empty() { return Err(PASSWORD); }
        twofas_open(reference, password)?;
        decrypted = Json::read(&twofas_open(encrypted, password)?)?;
        &decrypted.0
    };
    let groups: BTreeMap<&str, &str> = root.0["groups"].as_array().into_iter().flatten()
        .map(|group| (str_at(group, "id"), str_at(group, "name"))).collect();
    let mut batch = Batch::default();
    for row in array(services)? {
        let Some(otp) = row.get("otp").filter(|value| value.is_object()) else {
            batch.invalid += 1;
            continue;
        };
        // The outer type describes the service, not the OTP; schema 2 may omit tokenType.
        let kind = match otp.get("tokenType") {
            None | Some(Value::Null) => "totp",
            Some(Value::String(text)) if !text.trim().is_empty() => text.as_str(),
            _ => { batch.invalid += 1; continue; },
        };
        let tag = groups.get(str_at(row, "groupId")).filter(|s| !s.is_empty()).map(|s| (*s).to_owned());
        batch.push(Mapping { kind,
            account: first(&[str_at(otp, "account"), str_at(otp, "label")]), issuer: str_at(otp, "issuer"),
            title: str_at(row, "name"), secret: str_at(row, "secret"), algorithm: str_at(otp, "algorithm"),
            digits: number(otp, "digits"), period: number(otp, "period"), counter: number(otp, "counter"),
            tags: tag.into_iter().collect(), note: "", pinned: false });
    }
    Ok(batch)
}

fn raivo_zip(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| INVALID)?;
    if archive.len() > 16 { return Err(INVALID); }
    let selected = archive.file_names().filter(|name| name.rsplit('/').next() == Some("raivo-otp-export.json")).map(str::to_owned).collect::<Vec<_>>();
    if selected.len() != 1 { return Err("Raivo ZIP 应包含一份 raivo-otp-export.json。"); }
    let entry = if password.is_empty() { archive.by_name(&selected[0]).map_err(|_| PASSWORD)? }
        else { archive.by_name_decrypt(&selected[0], password.as_bytes()).map_err(|_| AUTH)? };
    if entry.size() > MAX_FILE as u64 || !entry.is_file() { return Err(INVALID); }
    let mut out = Zeroizing::new(Vec::new());
    entry.take(MAX_FILE as u64 + 1).read_to_end(&mut out).map_err(|_| AUTH)?;
    if out.len() > MAX_FILE { return Err(INVALID); }
    Ok(out)
}

fn raivo_or_andotp(bytes: &[u8], password: &str, raivo: bool) -> Result<Batch> {
    let unzipped;
    let input = if raivo && bytes.starts_with(b"PK\x03\x04") { unzipped = raivo_zip(bytes, password)?; unzipped.as_slice() }
        else if !raivo && bytes.iter().copied().find(|c| !c.is_ascii_whitespace()).is_some_and(|c| c != b'[' && c != 0xef) {
            return Err("此路径支持 andOTP 明文 JSON；加密或 OpenPGP 备份请在原应用中先导出 JSON。");
        } else { bytes };
    let root = Json::read(input)?;
    let mut batch = Batch::default();
    for row in array(&root.0)? {
        batch.push(Mapping { kind: str_at(row, if raivo { "kind" } else { "type" }),
            account: str_at(row, if raivo { "account" } else { "label" }), issuer: str_at(row, "issuer"), title: "",
            secret: str_at(row, "secret"), algorithm: str_at(row, "algorithm"), digits: number(row, "digits"),
            period: number(row, if raivo { "timer" } else { "period" }), counter: number(row, "counter"),
            tags: row["tags"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).take(32).collect(),
            note: "", pinned: false });
    }
    Ok(batch)
}

fn field<'a>(row: &'a Value, upper: &str, lower: &str) -> &'a Value { row.get(upper).or_else(|| row.get(lower)).unwrap_or(&Value::Null) }
fn txt<'a>(row: &'a Value, upper: &str, lower: &str) -> &'a str { field(row, upper, lower).as_str().unwrap_or("") }
fn stratum(bytes: &[u8]) -> Result<Batch> {
    let root = Json::read(bytes).map_err(|_| "此路径支持 Stratum 明文备份；加密备份请在原应用中先导出。")?;
    let root = &root.0;
    let groups: BTreeMap<&str, &str> = field(root, "Categories", "categories").as_array().into_iter().flatten()
        .map(|group| (txt(group, "Id", "id"), txt(group, "Name", "name"))).collect();
    let map = field(root, "AuthenticatorCategories", "authenticatorCategories");
    let mut tags: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for category in map.as_array().into_iter().flatten() {
        if let Some(name) = groups.get(txt(category, "CategoryId", "categoryId")) {
            let entry = tags.entry(txt(category, "AuthenticatorSecret", "authenticatorSecret")).or_default();
            if entry.len() < 32 { entry.push((*name).to_owned()); }
        }
    }
    let mut batch = Batch::default();
    for row in array(field(root, "Authenticators", "authenticators"))? {
        let kind = match field(row, "Type", "type") { Value::Number(num) => match num.as_u64() {
            Some(1) => "hotp", Some(2) => "totp", Some(4) => "steam", _ => "unsupported",
        }, Value::String(s) => s.as_str(), _ => "unsupported" };
        let algorithm = match field(row, "Algorithm", "algorithm") {
            Value::Number(num) => match num.as_u64() { Some(0) => "SHA1", Some(1) => "SHA256", Some(2) => "SHA512", _ => "unsupported" },
            Value::String(s) => s.as_str(), _ => "SHA1",
        };
        let secret = txt(row, "Secret", "secret");
        batch.push(Mapping { kind, account: txt(row, "Username", "username"), issuer: txt(row, "Issuer", "issuer"),
            title: "", secret, algorithm, digits: field(row, "Digits", "digits").as_u64(), period: field(row, "Period", "period").as_u64(),
            counter: field(row, "Counter", "counter").as_u64(), tags: tags.get(secret).cloned().unwrap_or_default(), note: "", pinned: false });
    }
    Ok(batch)
}

#[wasm_bindgen]
pub fn wasm_parse_authenticator_backup(format: &str, bytes: Vec<u8>, password: String) -> std::result::Result<String, JsValue> {
    let (bytes, password) = (Zeroizing::new(bytes), Zeroizing::new(password));
    let parse = || -> Result<String> {
        if bytes.is_empty() || bytes.len() > MAX_FILE || password.len() > 4096 { return Err(INVALID); }
        let batch = match format {
            "google" => google(&bytes), "aegis" => aegis(&bytes, &password), "2fas" => twofas(&bytes, &password),
            "raivo" => raivo_or_andotp(&bytes, &password, true), "andotp" => raivo_or_andotp(&bytes, &password, false),
            "stratum" => stratum(&bytes), _ => Err(INVALID),
        }?;
        serde_json::to_string(&batch).map_err(|_| INVALID)
    };
    parse().map_err(JsValue::from_str)
}
