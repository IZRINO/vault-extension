use crate::bitwarden::{SecretJson, text};
use crate::migration_csv::valid_additional_url;
use crate::portable::{Batch, INVALID, MappingError, add_record, rows};
use crate::vendor_json;
use serde_json::{Value, json};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, MappingError>;

#[derive(Clone, Copy)]
pub(crate) enum Vendor { Dashlane, LastPass }

fn strings(value: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| value[*key].is_string())
}

fn url(raw: &str, exact: bool, preserve_path: bool, batch: &mut Batch) -> Vec<Value> {
    let raw = raw.trim_ascii();
    if raw.is_empty() { return vec![]; }
    if !valid_additional_url(raw) {
        batch.unsupported += 1;
        return vec![];
    }
    let exact = exact || (preserve_path && raw.split_once("://").is_some_and(|(_, rest)| {
        // Keep non-root paths and URL components within their originally supplied scope.
        rest.find(['/', '?', '#']).is_some_and(|at| &rest[at..] != "/")
    }));
    vec![json!({"uri":raw, "matchRule":if exact { "exact" } else { "host" }})]
}

fn flag(value: &Value, key: &str) -> Result<bool> {
    match value.get(key) {
        None => Ok(true),
        Some(value) => match value.as_str() {
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            _ => Err(INVALID),
        },
    }
}

fn dashlane(row: &Value, batch: &mut Batch) -> Result<()> {
    let id = text(row, "id");
    let mut title = text(row, "title");
    let tag = text(row, "category");
    let tags = (!tag.trim().is_empty()).then_some(tag).into_iter().collect::<Vec<_>>();
    let (data, note, require_reprompt, custom_fields) = if row.get("content").is_some() {
        (SecretJson(json!({"kind":"developer", "subtype":"secure_note"})), text(row, "content"),
            flag(row, "secured")?, SecretJson(json!([])))
    } else {
        let protected = flag(row, "autoProtected")?;
        let fixed = flag(row, "useFixedUrl")?;
        let subdomain_only = row.get("subdomainOnly").is_some() && flag(row, "subdomainOnly")?;
        let selected = text(row, "userSelectedUrl");
        let raw = if fixed && !selected.is_empty() { selected } else { text(row, "url") };
        let uris = url(raw, fixed || subdomain_only, true, batch);
        let (login, email, secondary) = (text(row, "login"), text(row, "email"), text(row, "secondaryLogin"));
        let username = [login, email, secondary].into_iter().find(|value| !value.is_empty()).unwrap_or("");
        let alt = [("email", email), ("secondaryLogin", secondary)].into_iter()
            .filter(|(_, value)| !value.is_empty() && *value != username).collect::<Vec<_>>();
        let fields = if alt.is_empty() { SecretJson(json!([])) }
            else { vendor_json::fields(&SecretJson(json!(alt)).0)? };
        let raw_otp = [text(row, "otpUrl"), text(row, "otpSecret")].into_iter().find(|value| !value.is_empty()).unwrap_or("");
        let mut otp = SecretJson(Value::Null);
        if !raw_otp.is_empty() {
            let labeled = raw_otp.strip_prefix("otpauth://totp/?")
                .map(|query| Zeroizing::new(format!("otpauth://totp/Account?{query}")));
            match vault_otp::parse(labeled.as_ref().map_or(raw_otp, |uri| uri.as_str())) {
                Ok(code) if code.kind == vault_otp::Kind::Totp => otp.0 = json!(&*code.canonical_uri()),
                _ => batch.ignored_otp += 1,
            };
        }
        if title.trim().is_empty() { title = "Dashlane 登录"; }
        (SecretJson(json!({"kind":"login", "username":username, "password":text(row,"password"),
            "uris":uris, "totpUri":otp.0})), text(row, "note"), protected, fields)
    };
    let item = SecretJson(json!({ "title":title, "note":note, "data":data.0, "tags":tags, "requireReprompt":require_reprompt,
        "customFields":custom_fields.0 }));
    add_record(batch, &item.0, vec![], "dashlane-cli", id)
}

fn lastpass(row: &Value, batch: &mut Batch) -> Result<()> {
    let raw = text(row, "url");
    let id = text(row, "id");
    let (group, share) = (text(row, "group"), text(row, "share"));
    let tags = [share, group].into_iter().filter(|tag| !tag.trim().is_empty()).collect::<Vec<_>>().join("/");
    let (username, password) = (text(row, "username"), text(row, "password"));
    let note = raw == "http://sn";
    let data = SecretJson(if note { json!({"kind":"developer", "subtype":"secure_note"}) }
        else { json!({"kind":"login", "username":username, "password":password,
            "uris":url(if raw == "http://" { "" } else { raw }, false, false, batch)}) });
    let fields = if note && (!username.is_empty() || !password.is_empty()) {
        vendor_json::fields(&SecretJson(json!({"username":username,"password":password})).0)?
    } else { SecretJson(json!([])) };
    let item = SecretJson(json!({ "title":text(row, "name"), "note":text(row, "note"), "data":data.0,
        "tags":(!tags.is_empty()).then_some(tags).into_iter().collect::<Vec<_>>(), "requireReprompt":true, "customFields":fields.0 }));
    let source_id = if id.bytes().all(|byte| byte == b'0') { "" } else { id };
    add_record(batch, &item.0, vec![], "lastpass-cli", source_id)
}

pub(crate) fn read(bytes: &[u8], password: &str, vendor: Vendor) -> Result<Batch> {
    if !password.is_empty() { return Err(INVALID); }
    let root = vendor_json::read(bytes)?;
    let raw = rows(&root.0)?;
    let mut recognized = raw.is_empty();
    let mut batch = Batch::default();
    for row in raw {
        let fingerprint = match vendor {
            Vendor::Dashlane => strings(row, &["id", "anonId", "lastBackupTime", "localeFormat"])
                && ((strings(row, &["password", "url"]) && row.get("content").is_none())
                    || (strings(row, &["title", "content", "secured", "type"]) && row.get("password").is_none())),
            Vendor::LastPass => strings(row, &["id", "name", "fullname", "group", "url", "username", "password", "note"])
                && (row["last_modified_gmt"].is_string() || row["last_touch"].is_string()),
        };
        if !fingerprint { batch.invalid += 1; continue; }
        recognized = true;
        let id = text(row, "id");
        if id.is_empty() || id.len() > 128 || !row.as_object().is_some_and(|fields|
            fields.len() <= 96 && fields.values().all(Value::is_string))
            || [text(row, "category"), text(row, "group"), text(row, "share")].iter().any(|tag| tag.len() > 512)
        {
            batch.invalid += 1;
            continue;
        }
        if match vendor { Vendor::Dashlane => dashlane(row, &mut batch), Vendor::LastPass => lastpass(row, &mut batch) }.is_err() {
            batch.invalid += 1;
        }
    }
    if recognized { Ok(batch) } else { Err(INVALID) }
}
