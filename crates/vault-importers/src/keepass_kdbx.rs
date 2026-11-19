use crate::{bitwarden::SecretJson, portable::{Batch, INVALID, MappingError, add_record, secret_bytes, valid_web_url}};
use base64::{Engine, engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD}};
use keepass::{Database, DatabaseKey, db::GroupRef};
use serde_json::{Value, json};
use vault_passkeys::Passkey;

type Result<T> = std::result::Result<T, MappingError>;
const RESOURCE: &str = "KeePass 的密钥派生成本超出本机导入预算。";
const MAX_AES_ROUNDS: u64 = 5_000_000;
const PASSWORD: &str = "无法解密 KeePass 库：请检查文件密码、损坏或是否需要密钥文件。";

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
    if take(&mut data, 8)? != b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" { return Err("请选择 KeePass KDBX 3.1 或 4.x。"); }
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
    let passkey_field = |name: &str| name.starts_with("KPEX_PASSKEY") || name == "KPXC_PASSKEY_USERNAME";
    for entry in group.entries() {
        if batch.invalid + batch.unsupported + batch.ignored_passkeys > 10000 { return Err(INVALID); }
        let get = |key| entry.get(key).unwrap_or("");
        let mut keys = Vec::new();
        if entry.fields.keys().any(|key| passkey_field(key)) {
            let read = || {
                let der = secret_bytes(get("KPEX_PASSKEY_PRIVATE_KEY_PEM"))?;
                let id = entry.get("KPEX_PASSKEY_GENERATED_USER_ID").unwrap_or_else(|| get("KPEX_PASSKEY_CREDENTIAL_ID"));
                let account = entry.get("KPXC_PASSKEY_USERNAME").unwrap_or_else(|| get("KPEX_PASSKEY_USERNAME"));
                let eligible = entry.get("KPEX_PASSKEY_FLAG_BE").is_none_or(|value| matches!(value, "1" | "true"));
                let decode = |value: &str, max: usize| {
                    if value.len() > max.div_ceil(3) * 4 { return Err(INVALID); }
                    URL_SAFE_NO_PAD.decode(value).or_else(|_| URL_SAFE.decode(value)).map_err(|_| INVALID)
                };
                Passkey::from_pkcs8(decode(id, 1023)?, get("KPEX_PASSKEY_RELYING_PARTY").into(),
                    decode(get("KPEX_PASSKEY_USER_HANDLE"), 64)?, account.into(), &der, true, eligible, None)
            };
            match read() { Ok(key) => keys.push(key), Err(_) => batch.ignored_passkeys += 1 }
        }
        let otp = entry.get_raw_otp_value().and_then(|value| match vault_otp::parse(value) {
            Ok(otp) => Some(otp.canonical_uri()),
            Err(_) => { batch.ignored_otp += 1; None }
        });
        let url = entry.get_url().filter(|url| valid_web_url(url));
        let title = [entry.get_title(), entry.get_username(), url].into_iter().flatten()
            .find(|text| !text.trim().is_empty()).unwrap_or("KeePass 条目");
        let mut tags = entry.tags.clone();
        if !path.is_empty() { tags.push(path.to_string()); }
        let mut history = SecretJson(json!([]));
        if let Some(old) = &entry.history {
            for old in old.get_entries().iter().rev().take(20) {
                if let Some(password) = old.get_password().filter(|secret| !secret.is_empty() && Some(*secret) != entry.get_password()) {
                    history.0.as_array_mut().unwrap().push(json!({ "password": password,
                        "changedAtMs":old.times.last_modification.map(|time| time.and_utc().timestamp_millis().max(0)).unwrap_or(0), "sourceDevice":"KeePass" }));
                }
            }
        }
        let ignored = ["Title", "UserName", "Password", "URL", "Notes", "otp"];
        let custom_fields = SecretJson(Value::Array(entry.fields.iter().filter(|(name, _)| !ignored.contains(&name.as_str()) &&
            !passkey_field(name)).take(64).map(|(name, value)| json!({"name":name,"value":value.get(),"hidden":value.is_protected()})).collect()));
        batch.unsupported += entry.attachments_named().count();
        if title == "KeePass 条目" && get("Password").is_empty() && get("Notes").is_empty() && otp.is_none() &&
            keys.is_empty() && custom_fields.0.as_array().is_some_and(Vec::is_empty) &&
            history.0.as_array().is_some_and(Vec::is_empty)
        {
            batch.invalid += 1;
            continue;
        }
        let row = SecretJson(json!({ "title":title,"note":get("Notes"),"tags":tags, "trashed":trashed, "customFields":custom_fields.0,
            "createdAtMs":entry.times.creation.map(|time| time.and_utc().timestamp_millis().max(0)),
            "updatedAtMs":entry.times.last_modification.map(|time| time.and_utc().timestamp_millis().max(0)),
            "data":{"kind":"login","username":get("UserName"),"password":get("Password"),
                "uris":url.into_iter().map(|uri| json!({"uri":uri})).collect::<Vec<_>>(),"totpUri":otp.as_deref(),"passwordHistory":history.0}
        }));
        add_record(batch, &row.0, keys, "keepass", &entry.id().uuid().to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
