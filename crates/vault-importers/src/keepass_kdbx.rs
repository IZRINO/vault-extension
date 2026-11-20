use crate::{bitwarden::SecretJson, portable::{Batch, INVALID, MappingError, add_record, secret_bytes, valid_web_url}};
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}};
use keepass::{Database, DatabaseKey, db::GroupRef};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use vault_passkeys::Passkey;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, MappingError>;
const RESOURCE: &str = "KeePass 的密钥派生成本超出本机导入预算。";
const MAX_AES_ROUNDS: u64 = 5_000_000;
const PASSWORD: &str = "无法解密 KeePass 库：请检查文件密码、损坏或是否需要密钥文件。";
const MAGIC: &[u8] = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5";

fn take<'a>(data: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let (value, remaining) = data.split_at_checked(len).ok_or(INVALID)?;
    *data = remaining;
    Ok(value)
}
fn u32le(bytes: &[u8]) -> Result<u32> { Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| INVALID)?)) }
fn u64le(bytes: &[u8]) -> Result<u64> { Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| INVALID)?)) }

fn check_kdf(mut data: &[u8]) -> Result<()> {
    if take(&mut data, 2)? != b"\0\x01" { return Err(INVALID); }
    let mut fields = std::collections::BTreeMap::<&[u8], &[u8]>::new();
    for _ in 0..32 {
        let typ = take(&mut data, 1)?[0];
        if typ == 0 {
            if !data.is_empty() { return Err(INVALID); }
            let uuid: &[u8] = fields.get(b"$UUID".as_slice()).ok_or(INVALID)?;
            match hex::encode(uuid).as_str() {
                "c9d9f39a628a4460bf740d08c18a4fea" | "7c02bb8279a74ac0927d114a00648238" => {
                    let limit = u64le(fields.get(b"R".as_slice()).ok_or(INVALID)?)?;
                    return if (1..=MAX_AES_ROUNDS).contains(&limit) { Ok(()) } else { Err(RESOURCE) };
                }
                "ef636ddf8c29444b91f7a9a403e30a0c" | "9e298b1956db4773b23dfc3ec6f0a1e6" => {
                    let m = u64le(fields.get(b"M".as_slice()).ok_or(INVALID)?)?;
                    let i = u64le(fields.get(b"I".as_slice()).ok_or(INVALID)?)?;
                    let p = u32le(fields.get(b"P".as_slice()).ok_or(INVALID)?)?;
                    return if (8192..=100_663_296).contains(&m) && (1..=24).contains(&i) && (1..=16).contains(&p) &&
                        m * i <= 603_979_776 { Ok(()) } else { Err(RESOURCE) };
                }
                _ => return Err("不支持该 KeePass 密钥派生算法。"),
            }
        }
        let key_len = u32le(take(&mut data, 4)?)? as usize;
        let key = take(&mut data, key_len)?;
        let value_len = u32le(take(&mut data, 4)?)? as usize;
        let value = take(&mut data, value_len)?;
        if fields.insert(key, value).is_some() { return Err(INVALID); }
    }
    Err(INVALID)
}
fn check_header(mut data: &[u8]) -> Result<()> {
    if take(&mut data, 8)? != MAGIC { return Err("请选择 KeePass KDBX 3.1 或 4.x。"); }
    let version = u32le(take(&mut data, 4)?)?;
    let major = version >> 16;
    if !(version == 0x0003_0001 || major == 4) { return Err("请选择 KeePass KDBX 3.1 或 4.x。"); }
    let mut found = false;
    let mut seen = [false; 256];
    for _ in 0..64 {
        let kind = take(&mut data, 1)?[0] as usize;
        let len = if major == 4 { u32le(take(&mut data, 4)?)? as usize }
            else { u16::from_le_bytes(take(&mut data, 2)?.try_into().map_err(|_| INVALID)?) as usize };
        if len > 1024 * 1024 || std::mem::replace(&mut seen[kind], true) { return Err(INVALID); }
        let value = take(&mut data, len)?;
        match kind {
            0 if found => return Ok(()),
            0 => return Err(INVALID),
            6 if major == 3 => {
                if !(1..=MAX_AES_ROUNDS).contains(&u64le(value)?) { return Err(RESOURCE); }
                found = true;
            }
            11 if major == 4 => { check_kdf(value)?; found = true; }
            _ => (),
        }
    }
    Err(INVALID)
}

pub(crate) fn read(bytes: &[u8], password: &str) -> Result<Batch> {
    if !bytes.starts_with(MAGIC) { return crate::keepass_text::read(bytes, password); }
    check_header(bytes)?;
    if password.is_empty() { return Err("请输入 KeePass 库的密码。"); }
    let database = Database::open(&mut std::io::Cursor::new(bytes), DatabaseKey::new().with_password(password)).map_err(|_| PASSWORD)?;
    let recycle = database.meta.recyclebin_uuid.map(|id| id.to_string());
    let mut batch = Batch::default();
    visit(&database.root(), "", false, 0, &mut 0, recycle.as_deref(), &mut batch)?;
    Ok(batch)
}

fn visit(group: &GroupRef<'_>, prefix: &str, trashed: bool, level: usize, visited: &mut usize, recycle: Option<&str>, batch: &mut Batch) -> Result<()> {
    *visited += 1;
    if *visited > 5000 || level > 64 { return Err(INVALID); }
    let path = if prefix.is_empty() { group.name.clone() } else { format!("{prefix}/{}", group.name) };
    if path.len() > 4096 { return Err(INVALID); }
    let trashed = trashed || recycle.is_some_and(|id| id == group.id().uuid().to_string());
    collect(group, &path, trashed, batch)?;
    for child in group.groups() { visit(&child, &path, trashed, level + 1, visited, recycle, batch)?; }
    Ok(())
}

fn collect(group: &GroupRef<'_>, path: &str, trashed: bool, batch: &mut Batch) -> Result<()> {
    for entry in group.entries() {
        if batch.invalid + batch.unsupported + batch.ignored_passkeys > 10000 { return Err(INVALID); }
        let mut tags = entry.tags.clone();
        if !path.is_empty() { tags.push(path.to_string()); }
        let time = |value: Option<chrono::NaiveDateTime>| value.map(|value| value.and_utc().timestamp_millis().max(0) as u64);
        let history = entry.history.iter().flat_map(|old| old.get_entries().iter().rev().take(20))
            .filter_map(|old| Some((old.get_password()?, time(old.times.last_modification).unwrap_or(0)))).collect();
        batch.unsupported += entry.attachments_named().count();
        add_entry(batch, Entry {
            fields: entry.fields.iter().map(|(k, v)| (k.as_str(), (v.as_str(), v.is_protected()))).collect(),
            tags, history, trashed, id: &entry.id().uuid().to_string(),
            created: time(entry.times.creation), updated: time(entry.times.last_modification),
        })?;
    }
    Ok(())
}

#[derive(Default)]
pub(crate) struct Entry<'a> {
    pub fields: BTreeMap<&'a str, (&'a str, bool)>,
    pub tags: Vec<String>,
    pub history: Vec<(&'a str, u64)>,
    pub id: &'a str,
    pub trashed: bool,
    pub created: Option<u64>,
    pub updated: Option<u64>,
}

fn otp_field(name: &str) -> bool {
    name == "otp" || name.starts_with("TimeOtp-") || name.starts_with("HmacOtp-")
        || matches!(name, "TOTP Seed" | "TOTP Settings")
}

fn read_otp(fields: &BTreeMap<&str, (&str, bool)>) -> Result<Zeroizing<String>> {
    let get = |name: &str| fields.get(name).map(|value| value.0);
    let has_native = fields.iter().any(|(name, (value, _))|
        !value.is_empty() && (name.starts_with("TimeOtp-") || name.starts_with("HmacOtp-")));
    let legacy = get("TOTP Seed").filter(|value| !value.is_empty());
    let settings = get("TOTP Settings").filter(|value| !value.is_empty());
    if let Some(otp) = get("otp").filter(|value| !value.is_empty()) {
        if has_native || legacy.is_some() || settings.is_some() { return Err(INVALID); }
        if otp.starts_with("otpauth://") { return keepass_uri(otp); }
        return keeotp(otp);
    }
    if let Some(seed) = legacy {
        if has_native { return Err(INVALID); }
        let (period, mode) = settings.map_or(Ok(("30", "6")), |value| value.split_once(';').ok_or(INVALID))?;
        let period = period.parse::<u32>().map_err(|_| INVALID)?;
        let (kind, digits, period) = if mode == "S" {
            // KeePassXC legacy settings with S use the default step, irrespective of the first field.
            ("steam", 5, 30)
        } else { ("totp", mode.parse::<u32>().map_err(|_| INVALID)?, period) };
        let seed = Zeroizing::new(vault_otp::uri_encode(seed));
        let uri = Zeroizing::new(format!("otpauth://{kind}/KeePassXC?secret={}&digits={digits}&period={period}", &*seed));
        return vault_otp::parse(&uri).map(|otp| otp.canonical_uri());
    }
    if settings.is_some() { return Err(INVALID); }
    // KeePass 2.x stores native OTP in separate fields, with several encodings.
    let seeds: Vec<_> = fields.iter().filter(|(name, (value, _))| {
        !value.is_empty() && ["TimeOtp-", "HmacOtp-"].iter().any(|prefix| name.strip_prefix(prefix)
            .is_some_and(|name| matches!(name, "Secret" | "Secret-Hex" | "Secret-Base32" | "Secret-Base64")))
    }).collect();
    let [(name, (seed, _))] = seeds.as_slice() else { return Err(INVALID); };
    let (kind, encoding) = name.split_once('-').ok_or(INVALID)?;
    if fields.iter().any(|(name, (value, _))| !value.is_empty()
        && (name.starts_with("TimeOtp-") || name.starts_with("HmacOtp-")) && !name.starts_with(kind)) {
        return Err(INVALID);
    }
    let hmac = kind == "HmacOtp";
    let encoded = match encoding {
        "Secret" => vault_otp::encode_base32(seed.as_bytes()),
        "Secret-Hex" => vault_otp::encode_base32(&Zeroizing::new(hex::decode(seed.trim()).map_err(|_| INVALID)?)),
        "Secret-Base32" => Zeroizing::new(vault_otp::uri_encode(seed)),
        "Secret-Base64" => vault_otp::encode_base32(&Zeroizing::new(STANDARD.decode(seed.trim()).map_err(|_| INVALID)?)),
        _ => return Err(INVALID),
    };
    let (algorithm, digits, period) = if hmac { ("SHA1", 6, 30) } else {
        let algorithm = match get("TimeOtp-Algorithm").unwrap_or("HMAC-SHA-1") {
            "HMAC-SHA-1" => "SHA1", "HMAC-SHA-256" => "SHA256", "HMAC-SHA-512" => "SHA512", _ => return Err(INVALID),
        };
        (algorithm, get("TimeOtp-Length").unwrap_or("6").parse::<u32>().map_err(|_| INVALID)?,
            get("TimeOtp-Period").unwrap_or("30").parse::<u64>().map_err(|_| INVALID)?)
    };
    let kind = if hmac { "hotp" } else { "totp" };
    let mut uri = Zeroizing::new(format!("otpauth://{kind}/KeePass?secret={}&algorithm={algorithm}&digits={digits}&period={period}", &*encoded));
    if hmac {
        // KeePass's native HMACOTP starts at zero when the field is absent.
        let counter = get("HmacOtp-Counter").unwrap_or("0").parse::<u64>().map_err(|_| INVALID)?;
        uri.push_str(&format!("&counter={counter}"));
    }
    vault_otp::parse(&uri).map(|otp| otp.canonical_uri())
}

fn otp_params(query: &str) -> Result<BTreeMap<&str, &str>> {
    let mut params = BTreeMap::new();
    for part in query.split('&') {
        let (key, value) = part.split_once('=').ok_or(INVALID)?;
        if params.len() == 24 || key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || params.insert(key, value).is_some() {
            return Err(INVALID);
        }
    }
    Ok(params)
}

fn keepass_uri(uri: &str) -> Result<Zeroizing<String>> {
    use vault_otp::Kind;
    if uri.len() > vault_otp::MAX_SETUP_BYTES { return Err(INVALID); }
    let params = otp_params(uri.split_once('?').ok_or(INVALID)?.1)?;
    let encoder = params.get("encoder").map(|value| vault_otp::uri_decode(value, true)).transpose()?;
    let otp = match encoder.as_deref().map(String::as_str) {
        Some("steam") => {
            if params.get("digits").copied() != Some("5") || params.contains_key("counter") { return Err(INVALID); }
            let body = uri.strip_prefix("otpauth://totp/").ok_or(INVALID)?;
            vault_otp::parse(&Zeroizing::new(format!("otpauth://steam/{body}")))?
        }
        None | Some("") => {
            let otp = vault_otp::parse(uri)?;
            // KeePassXC selects Steam via its encoder, not its account's label or issuer.
            if otp.kind == Kind::Steam && !uri.starts_with("otpauth://steam/") { return Err(INVALID); }
            otp
        }
        _ => return Err(INVALID),
    };
    Ok(otp.canonical_uri())
}

fn keeotp(query: &str) -> Result<Zeroizing<String>> {
    if query.len() > vault_otp::MAX_SETUP_BYTES || query.contains('#') { return Err(INVALID); }
    let params = otp_params(query)?;
    if !params.keys().all(|&name| matches!(name, "key" | "size" | "step" | "otpHashMode")) { return Err(INVALID); }
    let get = |name| params.get(name).map(|value| vault_otp::uri_decode(value, false)).transpose();
    let seed = Zeroizing::new(vault_otp::uri_encode(&get("key")?.ok_or(INVALID)?));
    let hash = get("otpHashMode")?;
    let algorithm = match hash.as_deref().map(String::as_str) {
        None | Some("SHA1" | "HMAC-SHA-1") => "SHA1",
        Some("SHA256" | "HMAC-SHA-256") => "SHA256",
        Some("SHA512" | "HMAC-SHA-512") => "SHA512",
        _ => return Err(INVALID),
    };
    let digits = get("size")?.map_or(Ok(6), |v| v.parse::<u32>().map_err(|_| INVALID))?;
    let period = get("step")?.map_or(Ok(30), |v| v.parse::<u32>().map_err(|_| INVALID))?;
    let uri = Zeroizing::new(format!("otpauth://totp/KeePassXC?secret={}&algorithm={algorithm}&digits={digits}&period={period}", &*seed));
    vault_otp::parse(&uri).map(|otp| otp.canonical_uri())
}

pub(crate) fn add_entry(batch: &mut Batch, entry: Entry<'_>) -> Result<()> {
    let passkey_field = |name: &str| name.starts_with("KPEX_PASSKEY") || name.starts_with("KPXC_PASSKEY");
    let get = |key| entry.fields.get(key).map_or("", |value| value.0);
    let mut keys = Vec::new();
    if entry.fields.keys().any(|key| passkey_field(key)) {
        let read = || {
            let der = secret_bytes(get("KPEX_PASSKEY_PRIVATE_KEY_PEM"))?;
            let id = entry.fields.get("KPEX_PASSKEY_GENERATED_USER_ID").map_or(get("KPEX_PASSKEY_CREDENTIAL_ID"), |v| v.0);
            let account = entry.fields.get("KPXC_PASSKEY_USERNAME").map_or(get("KPEX_PASSKEY_USERNAME"), |v| v.0);
            let eligible = entry.fields.get("KPEX_PASSKEY_FLAG_BE").is_none_or(|value| matches!(value.0, "1" | "true"));
            let decode = |value: &str, max: usize| {
                if value.len() > max.div_ceil(3) * 4 { return Err(INVALID); }
                URL_SAFE_NO_PAD.decode(value).or_else(|_| URL_SAFE.decode(value)).map_err(|_| INVALID)
            };
            Passkey::from_pkcs8(decode(id, 1023)?, get("KPEX_PASSKEY_RELYING_PARTY").into(),
                decode(get("KPEX_PASSKEY_USER_HANDLE"), 64)?, account.into(), &der, true, eligible, None)
        };
        match read() { Ok(key) => keys.push(key), Err(_) => batch.ignored_passkeys += 1 }
    }
    let otp = if entry.fields.iter().any(|(k, (v, _))| otp_field(k) && !v.is_empty()) {
        match read_otp(&entry.fields) {
            Ok(uri) => Some(uri),
            Err(_) => { batch.ignored_otp += 1; None }
        }
    } else { None };
    let raw_url = get("URL");
    let url = valid_web_url(raw_url).then_some(raw_url);
    if !raw_url.is_empty() && url.is_none() { batch.unsupported += 1; }
    let title = [get("Title"), get("UserName"), url.unwrap_or("")].into_iter()
        .find(|text| !text.trim().is_empty());
    let history = SecretJson(Value::Array(entry.history.iter().filter(|(password, _)| !password.is_empty() && *password != get("Password"))
        .map(|(password, time)| json!({"password":password,"changedAtMs":time,"sourceDevice":"KeePass"})).collect()));
    let ignored = ["Title", "UserName", "Password", "URL", "Notes", "Vault 迁移来源", "Vault 扩展字段 v1", crate::bitwarden::META];
    let mut custom_fields = SecretJson(json!([]));
    for (&name, &(value, hidden)) in &entry.fields {
        if ignored.contains(&name) || passkey_field(name) || otp_field(name) { continue; }
        let fields = custom_fields.0.as_array_mut().unwrap();
        if fields.len() == 64 { batch.unsupported += 1; continue; }
        fields.push(json!({"name":name,"value":value,"hidden":hidden}));
    }
    if title.is_none() && get("Password").is_empty() && get("Notes").is_empty() && otp.is_none()
        && keys.is_empty() && custom_fields.0.as_array().is_some_and(Vec::is_empty)
        && history.0.as_array().is_some_and(Vec::is_empty)
    {
        batch.invalid += 1;
        return Ok(());
    }
    let row = SecretJson(json!({
        "title":title.unwrap_or("KeePass 条目"),"note":get("Notes"),"tags":entry.tags,"trashed":entry.trashed,
        "customFields":custom_fields.0,"createdAtMs":entry.created,"updatedAtMs":entry.updated,
        "data":{"kind":"login","username":get("UserName"),"password":get("Password"),
            "uris":url.into_iter().map(|uri| json!({"uri":uri})).collect::<Vec<_>>(),
            "totpUri":otp.as_deref(),"passwordHistory":history.0}
    }));
    add_record(batch, &row.0, keys, "keepass", entry.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_keepass_otp_dialects_without_mixing_configurations() {
        use vault_otp::Kind;
        let otp = |values: &[(&str, &str)]| {
            let fields = values.iter().map(|&(key, value)| (key, (value, true))).collect();
            read_otp(&fields).and_then(|uri| vault_otp::parse(&uri))
        };
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let steam = format!("otpauth://totp/Fixture%3Ame?secret={seed}&issuer=Fixture&digits=5&period=30&encoder=steam");
        assert!(otp(&[("otp", &steam)]).unwrap().kind == Kind::Steam);
        assert!(otp(&[("TOTP Seed", seed), ("TOTP Settings", "30;S")]).unwrap().kind == Kind::Steam);
        let keeotp = format!("key={seed}&size=7&step=60&otpHashMode=SHA256");
        let (_, hash, digits, period) = otp(&[("otp", &keeotp)]).unwrap().metadata_for_export();
        assert_eq!((hash, digits, period), ("sha256", 7, 60));
        assert_eq!(otp(&[("HmacOtp-Secret-Base32", seed)]).unwrap().counter, 0);
        let incorrect = [
            vec![("otp", steam.as_str()), ("HmacOtp-Secret-Base32", seed)],
            vec![("otp", steam.as_str()), ("TOTP Seed", seed)],
            vec![("TOTP Seed", seed), ("TOTP Settings", "30;6;7")],
            vec![("HmacOtp-Secret-Base32", seed), ("HmacOtp-Counter", "invalid")],
        ];
        for fields in incorrect { assert!(otp(&fields).is_err()); }
        let bad_steam = steam.replace("digits=5", "digits=6");
        assert!(otp(&[("otp", &bad_steam)]).is_err());
    }

    #[test]
    fn both_aes_kdf_ids_share_the_same_round_budget() {
        let budget = |id: &str, rounds: u64| {
            let mut dict = vec![0, 1];
            for (name, kind, value) in [
                (b"$UUID".as_slice(), 0x42, hex::decode(id).unwrap()),
                (b"R".as_slice(), 0x05, rounds.to_le_bytes().to_vec()),
            ] {
                dict.push(kind);
                dict.extend_from_slice(&(name.len() as u32).to_le_bytes());
                dict.extend_from_slice(name);
                dict.extend_from_slice(&(value.len() as u32).to_le_bytes());
                dict.extend_from_slice(&value);
            }
            dict.push(0);
            check_kdf(&dict)
        };
        for id in ["c9d9f39a628a4460bf740d08c18a4fea", "7c02bb8279a74ac0927d114a00648238"] {
            assert_eq!(budget(id, 5_000_000), Ok(()));
            assert_eq!(budget(id, 5_000_001), Err(RESOURCE));
            assert_eq!(budget(id, 0), Err(RESOURCE));
        }
    }
}
