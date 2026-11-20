use crate::{bitwarden::{SecretJson, text}, portable::{Batch, MappingError, add_record, json_from_bytes, rows}};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use vault_core::model::{CredentialData, DeveloperCredentialSubtype, VaultSnapshot};
use vault_passkeys::{Passkey, bundle};
use zeroize::Zeroizing;

pub(crate) fn read(bytes: &[u8], password: &str) -> Result<Batch, MappingError> {
    let stripped = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let plain;
    let json = if stripped.iter().copied().find(|byte| !byte.is_ascii_whitespace()) == Some(b'{') { stripped }
        else { plain = crate::protected_jwe::open(stripped, password)?; &plain };
    let root = json_from_bytes(json)?;
    if root.0["version"]["major"].as_u64() != Some(1) || root.0["version"]["minor"].as_u64().is_none() {
        return Err("仅支持 FIDO CXF 1.x。");
    }
    let exporter = text(&root.0, "exporterRpId");
    if exporter.is_empty() { return Err("CXF 文件缺少导出方。"); }
    let mut batch = Batch::default();
    for account in rows(&root.0["accounts"])? {
        for item in rows(&account["items"])? {
            let mut login = SecretJson(json!({"kind":"login","uris":[]}));
            let mut notes = Zeroizing::new(Vec::new());
            let mut keys = Vec::new();
            if let Some(urls) = item["scope"]["urls"].as_array() {
                for url in urls.iter().filter_map(Value::as_str).take(64) {
                    if crate::portable::valid_web_url(url) { login.0["uris"].as_array_mut().unwrap().push(json!({ "uri": url })); }
                }
            }
            for cred in rows(&item["credentials"])? {
                match text(cred, "type") {
                    "basic-auth" if login.0["password"].is_null() => {
                        login.0["username"] = cred["username"]["value"].clone();
                        login.0["password"] = cred["password"]["value"].clone();
                    }
                    "passkey" => match read_key(cred) { Ok(key) => keys.push(key), Err(_) => batch.ignored_passkeys += 1 },
                    "totp" if login.0["totpUri"].is_null() => {
                        let otp = cred;
                        let username = text(otp, "username");
                        let label = if username.is_empty() { "Account" } else { username };
                        let setup = Zeroizing::new(format!("otpauth://totp/{}?secret={}&issuer={}&digits={}&algorithm={}&period={}",
                            vault_otp::uri_encode(label), vault_otp::uri_encode(text(otp, "secret")), vault_otp::uri_encode(text(otp, "issuer")),
                            otp["digits"].as_u64().unwrap_or(6), vault_otp::uri_encode(text(otp, "algorithm")), otp["period"].as_u64().unwrap_or(30)));
                        if let Ok(token) = vault_otp::parse(&setup) && token.kind == vault_otp::Kind::Totp {
                            login.0["totpUri"] = json!(&*token.canonical_uri());
                        }
                        else { batch.ignored_otp += 1; }
                    }
                    "note" => notes.push(text(&cred["content"], "value").to_owned()),
                    _ => batch.unsupported += 1,
                }
            }
            if let Some(first) = keys.first() {
                if login.0["username"].is_null() { login.0["username"] = json!(first.account); }
                if login.0["uris"].as_array().is_some_and(Vec::is_empty) {
                    login.0["uris"].as_array_mut().unwrap().push(json!({ "uri": format!("https://{}", first.rp_id) }));
                }
            }
            let login_meaningful = !text(&login.0, "username").is_empty() || !text(&login.0, "password").is_empty() ||
                login.0["totpUri"].is_string() || !keys.is_empty();
            if !login_meaningful && notes.is_empty() { batch.invalid += 1; continue; }
            if !login_meaningful { login.0 = json!({ "kind": "developer", "subtype": "api_token" }); }
            let data = SecretJson(json!({ "title": text(item, "title"), "note": notes.join("\n\n"), "data": login.0,
                "pinned": item["favorite"] == true, "tags": item["tags"], "createdAtMs": as_millis(&item["creationAt"]),
                "updatedAtMs": as_millis(&item["modifiedAt"]) }));
            let source = format!("{}:{}:{}", exporter, text(account, "id"), text(item, "id"));
            add_record(&mut batch, &data.0, keys, "cxf", &source)?;
        }
    }
    Ok(batch)
}

fn as_millis(value: &Value) -> u64 { value.as_u64().and_then(|v| v.checked_mul(1000)).unwrap_or(0) }

fn read_key(value: &Value) -> Result<Passkey, MappingError> {
    if value["fido2Extensions"].as_object().is_some_and(|ext| !ext.is_empty()) { return Err("不支持这个通行密钥的 FIDO 扩展。"); }
    let decode = |field| B64.decode(text(value, field)).map_err(|_| "通行密钥的二进制字段无效。");
    let secret = Zeroizing::new(decode("key")?);
    Passkey::from_pkcs8(decode("credentialId")?, text(value, "rpId").to_owned(), decode("userHandle")?,
        text(value, "username").to_owned(), &secret, true, true, None)
}

fn field(name: &str, value: &str) -> Value { json!({ "fieldType": name, "value": value }) }

fn has_standalone_note(item: &vault_core::model::VaultItem) -> bool {
    let CredentialData::Developer(data) = &item.data else { return false; };
    data.subtype == DeveloperCredentialSubtype::ApiToken
        && matches!(data.service_or_product.as_str(), "" | "安全备注")
        && data.token_or_license.is_empty()
        && data.private_key.is_empty()
        && data.public_key.is_empty()
        && data.expires_at_ms.is_none()
}

pub(crate) fn write(vault: &VaultSnapshot, now_ms: u64) -> Result<(Zeroizing<String>, usize, usize, usize), MappingError> {
    let mut items = SecretJson(json!([]));
    let mut skipped_items = 0;
    let mut skipped_keys = 0;
    for item in &vault.items {
        if item.trashed { skipped_items += 1; continue; }
        let mut credentials = SecretJson(json!([]));
        let values = credentials.0.as_array_mut().unwrap();
        let scope = if let CredentialData::Login(login) = &item.data {
            if !login.username.is_empty() || !login.password.is_empty() {
                values.push(json!({ "type":"basic-auth","username":field("string",&login.username),"password":field("concealed-string",&login.password) }));
            }
            if let Some(setup) = &login.totp_uri {
                if let Ok(otp) = vault_otp::parse(setup) {
                    if otp.kind == vault_otp::Kind::Totp {
                        let (secret, algorithm, digits, period) = otp.metadata_for_export();
                        values.push(json!({ "type":"totp","secret":&*secret,"algorithm":algorithm,"digits":digits,"period":period,
                            "username":otp.label, "issuer":otp.issuer }));
                    }
                }
            }
            for key in bundle::read(&login.passkey_data)? {
                if key.increment || !key.eligible || !key.discoverable { skipped_keys += 1; continue; }
                let material = key.to_pkcs8()?;
                values.push(json!({ "type":"passkey", "rpId":key.rp_id, "credentialId":B64.encode(&key.credential_id),
                    "userHandle":B64.encode(&key.user_handle), "username":key.account, "userDisplayName":key.account, "key":B64.encode(&*material) }));
            }
            Some(json!({ "urls": login.uris.iter().filter(|uri| crate::portable::valid_web_url(&uri.uri)).map(|uri| &uri.uri).collect::<Vec<_>>(), "androidApps": [] }))
        } else if has_standalone_note(item) { None }
        else { skipped_items += 1; continue; };
        if !item.note.is_empty() { values.push(json!({ "type": "note", "content": field("string", &item.note) })); }
        if values.is_empty() { skipped_items += 1; continue; }
        let mut record = json!({ "id": B64.encode(item.id.as_bytes()), "title": item.title, "favorite": item.pinned,
            "creationAt": item.created_at_ms/1000, "modifiedAt": item.updated_at_ms/1000, "credentials": credentials.0 });
        if let Some(scope) = scope { record["scope"] = scope; }
        if !item.tags.is_empty() { record["tags"] = json!(item.tags); }
        items.0.as_array_mut().unwrap().push(record);
    }
    let count = items.0.as_array().unwrap().len();
    let root = SecretJson(json!({ "version": { "major": 1, "minor": 0 }, "exporterRpId": "izrino.github.io",
        "exporterDisplayName": "Vault Extension", "timestamp": now_ms/1000, "accounts": [{ "id":B64.encode(vault.vault_id.as_bytes()),
            "username":"", "email":"", "collections":[], "items":items.0 }] }));
    Ok((Zeroizing::new(root.0.to_string()), count, skipped_items, skipped_keys))
}
