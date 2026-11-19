use crate::{
    bitwarden::{SecretJson, text},
    portable::{self, Batch, INVALID, LIMIT, MappingError, add_record, id_bytes, json_from_bytes, secret_bytes, valid_web_url},
};
use serde_json::{Value, json};
use std::io::{Cursor, Read};
use vault_passkeys::Passkey;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, MappingError>;
const MAX_ENTRIES: usize = 4096;

fn archive(bytes: &[u8]) -> Result<zip::ZipArchive<Cursor<&[u8]>>> {
    let zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| INVALID)?;
    if zip.len() > MAX_ENTRIES || zip.is_empty() { return Err(INVALID); }
    Ok(zip)
}
fn entry(zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = zip.by_name(name).map_err(|_| "压缩包缺少所需文件、已损坏或仍然加密。")?;
    if !file.is_file() || file.enclosed_name().is_none() || file.size() > limit as u64 { return Err(INVALID); }
    let mut out = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut out).map_err(|_| INVALID)?;
    if out.len() > limit { return Err(INVALID); }
    Ok(out)
}
fn first<'a>(options: &[&'a str]) -> &'a str { options.iter().copied().find(|s| !s.is_empty()).unwrap_or("") }
fn array(value: &Value) -> &[Value] { value.as_array().map(Vec::as_slice).unwrap_or_default() }
fn seconds(value: &Value) -> u64 { value.as_u64().and_then(|s| s.checked_mul(1000)).unwrap_or(0) }
fn otp(value: &str, batch: &mut Batch) -> Value {
    if value.is_empty() { return Value::Null; }
    match vault_otp::parse(value) {
        Ok(otp) => json!(&*otp.canonical_uri()),
        Err(_) => { batch.ignored_otp += 1; Value::Null },
    }
}
fn key(value: &Value, default_account: &str) -> Result<Passkey> {
    let private = first(&[text(value, "key"), text(value, "privateKey"), text(value, "privateKeyPem"), text(value, "keyValue")]);
    let material = secret_bytes(private)?;
    let id = id_bytes(first(&[text(value, "credentialId"), text(value, "credentialID")]))?;
    let rp = first(&[text(value, "rpId"), text(value, "relyingParty")]);
    let handle = id_bytes(first(&[text(value, "userHandle"), text(value, "userId")]))?;
    let account = first(&[text(value, "username"), text(value, "userName"), default_account]);
    let backed = value["backupEligible"].as_bool().unwrap_or(true);
    let counter = value["counter"].as_u64().or_else(|| value["signCount"].as_u64()).filter(|v| *v > 0)
        .map(u32::try_from).transpose().map_err(|_| INVALID)?;
    Passkey::from_pkcs8(id, rp.into(), handle, account.into(), &material, value["discoverable"].as_bool().unwrap_or(true), backed, counter)
}
fn collect_keys<'a>(values: impl IntoIterator<Item = &'a Value>, username: &str, batch: &mut Batch) -> Vec<Passkey> {
    let mut keys = Vec::new();
    for value in values {
        match key(value, username) {
            Ok(key) if keys.len() < 64 => {
                if !keys.iter().any(|old: &Passkey| old.credential_id == key.credential_id && old.rp_id == key.rp_id) { keys.push(key); }
            }
            _ => batch.ignored_passkeys += 1,
        }
    }
    keys
}
fn expiry(value: &Value) -> (String, String) {
    if let Some(s) = value.as_str() {
        if let Some((a, b)) = s.split_once('-').or_else(|| s.split_once('/')) {
            if a.len() == 4 { return (b.into(), a.into()); }
            if b.len() == 4 || b.len() == 2 { return (a.into(), b.into()); }
        }
    } else if let Some(value) = value.as_u64() {
        let month = value % 100;
        if (1..=12).contains(&month) && (1900..=9999).contains(&(value / 100)) {
            return (format!("{month:02}"), (value / 100).to_string());
        }
    }
    (String::new(), String::new())
}

fn one_value(field: &Value) -> &str {
    let val = &field["value"];
    val.as_str().unwrap_or_else(|| first(&["string", "concealed", "phone", "url", "menu", "creditCardNumber", "creditCardType"]
        .map(|name| text(val, name)).into_iter().chain([text(&val["email"], "email_address")]).collect::<Vec<_>>()))
}

pub(crate) fn onepassword(bytes: &[u8]) -> Result<Batch> {
    let mut zip = archive(bytes)?;
    let names = zip.file_names().collect::<Vec<_>>();
    if !names.contains(&"export.attributes") || !names.contains(&"export.data") { return Err("压缩包不是 1Password 1PUX。"); }
    let unsupported = names.into_iter().filter(|name| name.starts_with("files/") && !name.ends_with('/')).count();
    let metadata = json_from_bytes(&entry(&mut zip, "export.attributes", 16 * 1024)?)?;
    if metadata.0["version"].as_u64() != Some(3) { return Err("仅支持 1PUX 版本 3。"); }
    let json = json_from_bytes(&entry(&mut zip, "export.data", LIMIT)?)?;
    let mut batch = Batch::default();
    batch.unsupported = unsupported;
    for account in portable::rows(&json.0["accounts"])? {
        for vault in portable::rows(&account["vaults"])? {
            for item in portable::rows(&vault["items"])? {
                let details = &item["details"];
                let overview = &item["overview"];
                let mut tags = array(&overview["tags"]).iter().filter_map(Value::as_str).take(32).map(str::to_owned).collect::<Vec<_>>();
                let vault_name = text(&vault["attrs"], "name");
                if !vault_name.is_empty() { tags.push(vault_name.into()); }
                let fields = array(&details["sections"]).iter().flat_map(|section| array(&section["fields"])).take(256).collect::<Vec<_>>();
                let designated = |name| array(&details["loginFields"]).iter().find(|v| text(v, "designation") == name).map(|v| text(v, "value")).unwrap_or("");
                let get = |names: &[&str]| fields.iter().copied().find(|f| names.iter().any(|n| n.eq_ignore_ascii_case(text(f, "id"))))
                    .map(one_value).unwrap_or("");
                let category = text(item, "categoryUuid");
                let username = first(&[designated("username"), get(&["username", "email"]), text(overview, "subtitle")]);
                let mut passkey_list = array(&details["passkeys"]).iter().chain(array(&item["passkeys"])).collect::<Vec<_>>();
                for candidate in [ &details["passkey"], &item["passkey"] ].into_iter().chain(fields.iter().map(|field| &field["value"]["passkey"])) {
                    if !candidate.is_null() { passkey_list.push(candidate); }
                }
                // Public 1PUX versions need not include Passkey material; never fabricate a credential.
                let keys = collect_keys(passkey_list, username, &mut batch);
                let options = fields.iter().find_map(|field| field["value"]["totp"].as_str()).unwrap_or("");
                let mut custom = SecretJson(json!([]));
                for field in fields.iter().take(64) {
                    let value = one_value(field);
                    if !value.is_empty() && !text(field, "title").is_empty() {
                        custom.0.as_array_mut().unwrap().push(json!({ "name": text(field,"title"), "value":value,
                            "hidden":field["guarded"] == true || field["value"]["concealed"].is_string() }));
                    }
                }
                let data = SecretJson(match category {
                    "001" | "005" | "111" => {
                        let login = first(&[designated("password"), text(details,"password"), get(&["password"])]);
                        let sites = array(&overview["urls"]).iter().filter_map(|url| url["url"].as_str())
                            .chain(overview["url"].as_str()).filter(|url| valid_web_url(url)).take(64)
                            .collect::<std::collections::BTreeSet<_>>().into_iter().map(|url| json!({"uri":url})).collect::<Vec<_>>();
                        let history = array(&details["passwordHistory"]).iter().take(20).map(|h| json!({ "password":text(h,"value"),
                            "changedAtMs":seconds(&h["time"]),"sourceDevice":"1Password" })).collect::<Vec<_>>();
                        json!({ "kind":"login","username":username,"password":login,"uris":sites,"totpUri":otp(options,&mut batch),"passwordHistory":history })
                    }
                    "002" => {
                        let expire = fields.iter().find(|f| ["expiry","expirydate","expiration"].contains(&text(f,"id"))).map(|f| &f["value"]["monthYear"]).unwrap_or(&Value::Null);
                        let (month, year) = expiry(expire);
                        json!({"kind":"payment_card","cardholderName":get(&["cardholder","cardholdername"]), "cardNumber":get(&["ccnum","number"]),
                            "expMonth":month, "expYear":year, "cvv":get(&["cvv","verificationnumber"]), "cardPin":get(&["pin"])})
                    }
                    "004" => {
                        let address = fields.iter().find(|f| f["value"]["address"].is_object()).map(|f| &f["value"]["address"]).unwrap_or(&Value::Null);
                        let name = [get(&["firstname"]), get(&["initial","middlename"]), get(&["lastname"])].into_iter().filter(|v| !v.is_empty()).collect::<Vec<_>>().join(" ");
                        json!({"kind":"identity","fullName":name,"phone":get(&["phone","homephone","cellphone"]),"email":get(&["email"]),
                            "company":get(&["company"]),"addressLine":text(address,"street"),"city":text(address,"city"),
                            "province":text(address,"state"),"country":text(address,"country"),"postalCode":text(address,"zip")})
                    }
                    "003" | "100" | "102" | "110" | "112" | "114" => {
                        let ssh = fields.iter().find(|field| field["value"]["sshKey"].is_object()).map(|field| &field["value"]["sshKey"]).unwrap_or(&Value::Null);
                        let subtype = match category { "003" => "secure_note", "100" => "software_license", "114" => "ssh_key", _ => "api_key" };
                        json!({"kind":"developer","subtype":subtype,"serviceOrProduct":text(overview,"title"),
                            "tokenOrLicense":get(&["credential","licensekey","regcode","token","password"]),
                            "privateKey":first(&[text(ssh,"privateKey"),text(&ssh["metadata"],"privateKey")]),"publicKey":text(&ssh["metadata"],"publicKey")})
                    }
                    _ => { batch.unsupported += 1; continue; }
                });
                let row = SecretJson(json!({ "title":text(overview,"title"),"data":data.0,"note":text(details,"notesPlain"),"tags":tags,"customFields":custom.0,
                    "pinned":item["favIndex"].as_u64().unwrap_or(0) > 0, "trashed":text(item,"state") == "archived",
                    "createdAtMs":seconds(&item["createdAt"]), "updatedAtMs":seconds(&item["updatedAt"]) }));
                let source = format!("{}:{}:{}", text(&account["attrs"],"uuid"),text(&vault["attrs"],"uuid"),text(item,"uuid"));
                add_record(&mut batch, &row.0, keys, "onepassword", if text(item,"uuid").is_empty() { "" } else { &source })?;
            }
        }
    }
    Ok(batch)
}

pub(crate) fn proton(bytes: &[u8]) -> Result<Batch> {
    let unpacked;
    let (json, attachments) = if bytes.starts_with(b"PK\x03\x04") {
        let mut zip = archive(bytes)?;
        let files = zip.file_names().filter(|name| !name.ends_with('/')).collect::<Vec<_>>();
        let known = files.iter().filter(|name| name.rsplit('/').next() == Some("data.json") ||
            name.rsplit('/').next().is_some_and(|name| name.starts_with("proton-pass") && name.ends_with(".json"))).copied().collect::<Vec<_>>();
        let options = files.iter().filter(|name| name.ends_with(".json")).copied().collect::<Vec<_>>();
        let candidates = if known.is_empty() { &options } else { &known };
        if candidates.len() != 1 { return Err("Proton Pass ZIP 必须包含一份未加密的导出 JSON。"); }
        let count = files.len() - 1;
        let name = candidates[0].to_string();
        unpacked = entry(&mut zip, &name, LIMIT)?;
        (&unpacked[..], count)
    } else { (bytes, 0) };
    let root = json_from_bytes(json).map_err(|_| "请选择 Proton Pass 的未加密 JSON 或包含该 JSON 的 ZIP。")?;
    if root.0["encrypted"] == true { return Err("不支持 Proton Pass 的加密外层。请从原应用导出未加密的迁移文件。"); }
    let version = text(&root.0,"version");
    if version.split('.').next() != Some("1") { return Err("不支持该 Proton Pass 导出版本。"); }
    let vaults = root.0["vaults"].as_object().ok_or(INVALID)?;
    let mut batch = Batch::default();
    batch.unsupported = attachments;
    for (vault_id, vault) in vaults {
        for item in portable::rows(&vault["items"])? {
            let data = &item["data"];
            let content = &data["content"];
            let username = first(&[text(content,"itemUsername"),text(content,"itemEmail"),text(item,"aliasEmail")]);
            let keys = collect_keys(array(&content["passkeys"]), username, &mut batch);
            batch.unsupported += array(&item["files"]).len();
            let fields = SecretJson(Value::Array(array(&data["extraFields"]).iter().take(64).filter_map(|field| {
                let kind = text(field,"type");
                match kind {
                    "text" | "hidden" | "timestamp" => Some(json!({ "name":text(field,"fieldName"),
                        "value":first(&[text(&field["data"],"content"),text(&field["data"],"timestamp")]),"hidden":kind=="hidden" })),
                    "totp" => None,
                    _ => {batch.unsupported += 1; None},
                }
            }).collect()));
            let record = SecretJson(match text(data,"type") {
                "login" | "alias" => {
                    let urls = array(&content["urls"]).iter().filter_map(Value::as_str).filter(|v| valid_web_url(v)).take(64).map(|uri| json!({"uri":uri})).collect::<Vec<_>>();
                    let mut otps = content["totpUri"].as_str().filter(|s| !s.is_empty()).into_iter().chain(array(&data["extraFields"]).iter().filter_map(|f| f["data"]["totpUri"].as_str()).filter(|s| !s.is_empty()));
                    let first = otps.next().unwrap_or("");
                    batch.ignored_otp += otps.count();
                    json!({ "kind":"login","username":username,"password":text(content,"password"),"uris":urls,"totpUri":otp(first,&mut batch) })
                }
                "creditCard" => {
                    let (month,year) = expiry(&content["expirationDate"]);
                    json!({"kind":"payment_card","cardholderName":text(content,"cardholderName"),"cardNumber":text(content,"number"),
                        "expMonth":month,"expYear":year,"cvv":text(content,"verificationNumber"),"cardPin":text(content,"pin")})
                }
                "identity" => json!({"kind":"identity","fullName":text(content,"fullName"),"email":text(content,"email"),"phone":text(content,"phoneNumber"),
                    "addressLine":text(content,"streetAddress"),"city":text(content,"city"),"province":text(content,"stateOrProvince"),
                    "postalCode":text(content,"zipOrPostalCode"),"company":text(content,"organization"),"country":text(content,"countryOrRegion"),
                    "nationalIdOrPassport":text(content,"passportNumber")}),
                "note" => json!({"kind":"developer","subtype":"secure_note"}),
                "sshKey" => json!({"kind":"developer","subtype":"ssh_key","privateKey":text(content,"privateKey"),"publicKey":text(content,"publicKey")}),
                _ => { batch.unsupported += 1; continue; }
            });
            let meta = &data["metadata"];
            let row = SecretJson(json!({ "title":text(meta,"name"),"note":text(meta,"note"),"data":record.0,"tags":[text(vault,"name")],
                "customFields":fields.0,"pinned":item["pinned"] == true,"trashed":item["state"] == 2,
                "createdAtMs":seconds(&item["createTime"]),"updatedAtMs":seconds(&item["modifyTime"]) }));
            let source_id = first(&[text(item,"itemId"),text(meta,"itemUuid")]);
            let source = format!("{vault_id}:{source_id}");
            add_record(&mut batch, &row.0, keys, "proton", if source_id.is_empty() { "" } else { &source })?;
        }
    }
    Ok(batch)
}
