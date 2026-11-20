use crate::bitwarden::{SecretJson, text};
use crate::{migration_csv::valid_additional_url, read_csv};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Vendor { Bitwarden, Proton, RoboForm, OnePassword }

impl Vendor {
    pub(crate) fn label(self) -> &'static str {
        match self { Self::Bitwarden => "Bitwarden", Self::Proton => "Proton Pass", Self::RoboForm => "RoboForm", Self::OnePassword => "1Password" }
    }
}

pub(crate) fn detect(head: &[String]) -> Option<Vendor> {
    let names = head.iter().map(|name| name.trim().to_ascii_lowercase()).collect::<Vec<_>>();
    let names = names.iter().map(String::as_str).collect::<Vec<_>>();
    if matches!(names.as_slice(),
        ["name","url","matchurl","login","pwd","note","folder","rffieldsv2"] |
        ["name","url","login","pwd","note","folder"] |
        ["name","url","login","pwd","note","folder",""]) { return Some(Vendor::RoboForm); }
    let cols = names.iter().copied().collect::<BTreeSet<_>>();
    if cols.len() != head.len() { return None; }
    let has = |required: &[&str]| required.iter().all(|name| cols.contains(name));
    if (has(&["folder", "favorite"]) ^ cols.contains("collections"))
        && has(&["type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"])
        && cols.len() == 9 + (if cols.contains("collections") { 1 } else { 2 }) + usize::from(cols.contains("archiveddate"))
    {
        return Some(Vendor::Bitwarden);
    }
    if has(&["type","name","url","username","password","note","totp","createtime","modifytime"])
        && cols.len() == 9 + ["vault","email","autofillurls"].into_iter().filter(|column| cols.contains(column)).count()
    {
        return Some(Vendor::Proton);
    }
    if cols.len() == 9 && has(&["title","url","username","password","favorite","archived","tags"])
        && (cols.contains("note") ^ cols.contains("notes"))
        && ["otp", "otpauth", "one-time password"].into_iter().any(|column| cols.contains(column))
    {
        return Some(Vendor::OnePassword);
    }
    None
}

struct Batch {
    rows: SecretJson,
    invalid: usize,
    unsupported: usize,
    ignored_otp: usize,
}

impl Batch {
    fn new() -> Self { Self { rows: SecretJson(json!([])), invalid: 0, unsupported: 0, ignored_otp: 0 } }

    fn login(&mut self, username: &str, password: &str, uris: Vec<Value>, raw_otp: &str, fields: &mut Vec<Value>) -> Value {
        let otp = if raw_otp.is_empty() { Value::Null } else {
            match vault_otp::parse(raw_otp) {
                Ok(code) => json!(&*code.canonical_uri()),
                Err(_) => {
                    self.ignored_otp += 1;
                    fields.push(json!({"name":"CSV 未识别的验证码设置","value":raw_otp,"hidden":true}));
                    Value::Null
                }
            }
        };
        json!({"kind":"login","username":username,"password":password,"uris":uris,"totpUri":otp})
    }

    fn push(&mut self, title: &str, note: &str, data: Value, tags: &[&str], fields: Vec<Value>, pinned: bool, reprompt: bool) {
        let data = SecretJson(data);
        let fields = SecretJson(Value::Array(fields));
        let mut row = SecretJson(json!({ "id":"", "title":title, "note":note, "data":data.0, "tags":tags,
            "customFields":fields.0, "pinned":pinned, "requireReprompt":reprompt, "trashed":false }));
        if title.trim().is_empty() { self.invalid += 1; return; }
        self.rows.0.as_array_mut().unwrap().push(std::mem::take(&mut row.0));
    }

    fn result(mut self) -> SecretJson {
        let mut result = SecretJson(json!({ "invalid":self.invalid, "unsupported":self.unsupported, "ignoredOtp":self.ignored_otp }));
        result.0["rows"] = std::mem::take(&mut self.rows.0);
        result
    }
}

fn uri(value: &str, rule: Option<&str>) -> Option<Value> {
    let value = value.trim();
    if !valid_additional_url(value) { return None; }
    Some(match rule {
        Some(rule) => json!({ "uri":value, "matchRule":rule }),
        None => json!({ "uri":value }),
    })
}

fn column<'a>(head: &[String], row: &'a [String], name: &str) -> &'a str {
    head.iter().position(|h| h.trim().eq_ignore_ascii_case(name)).map_or("", |i| row[i].as_str())
}

fn field(name: &str, value: &str) -> Value { json!({ "name":name, "value":value, "hidden":true }) }
const NOTE: &str = "secure_note";

fn bitwarden(batch: &mut Batch, head: &[String], rows: &[Vec<String>]) {
    for row in rows {
        if row.len() != head.len() { batch.invalid += 1; continue; }
        let col = |name: &str| column(head, row, name);
        let reprompt = match col("reprompt") {
            "" | "0" => false,
            "1" => true,
            _ => { batch.invalid += 1; continue; }
        };
        let mut fields = Vec::new();
        let archived = col("archivedDate");
        if !archived.is_empty() { fields.push(field("CSV 源归档状态", archived)); }
        if !col("fields").is_empty() {
            // The exporter flattens field types. Retain the text as a single inert value.
            fields.push(field("CSV 源自定义字段", col("fields")));
        }
        let data = match col("type") {
            "note" => json!({"kind":"developer","subtype":NOTE}),
            "login" => {
                let raw = col("login_uri");
                let mut urls = Vec::new();
                if !raw.trim().is_empty() {
                    match read_csv(raw) {
                        Ok(records) if records.len() == 1 => {
                            for value in &records[0] {
                                if let Some(value) = uri(value, (!archived.is_empty()).then_some("never")) { urls.push(value); }
                                else if !value.is_empty() { batch.unsupported += 1; }
                            }
                        }
                        _ => batch.unsupported += 1,
                    }
                }
                batch.login(col("login_username"), col("login_password"), urls, col("login_totp"), &mut fields)
            }
            _ => { batch.unsupported += 1; continue; }
        };
        let tags = [col("folder")].into_iter().chain(col("collections").split(',').map(str::trim))
            .filter(|tag| !tag.is_empty()).collect::<Vec<_>>();
        batch.push(col("name"), col("notes"), data, &tags, fields, col("favorite") == "1", reprompt);
    }
}

pub(crate) fn proton_urls<'a>(structured: Option<&Value>, fallback: impl IntoIterator<Item = &'a str>, unsupported: &mut usize) -> Vec<Value> {
    let mut urls = Vec::new();
    let Some(structured) = structured else {
        for value in fallback {
            if urls.len() >= 64 { *unsupported += 1; break; }
            if let Some(url) = uri(value, None) { urls.push(url); }
            else if !value.is_empty() { *unsupported += 1; }
        }
        return urls;
    };
    let Some(entries) = structured.as_array().filter(|entries| entries.len() <= 64) else {
        *unsupported += 1;
        return urls;
    };
    for entry in entries {
        let rule = match entry.get("mode").and_then(Value::as_u64) {
            Some(0) => None,
            Some(1) => Some("host"),
            Some(2) => Some("never"),
            Some(3) => Some("starts_with"),
            Some(4..=6) => {
                // Pattern, regex and exact-path are not equivalent to Vault's rules.
                *unsupported += 1;
                if let Some(url) = uri(text(entry, "url"), Some("never")) { urls.push(url); }
                continue;
            }
            _ => { *unsupported += 1; return Vec::new(); }
        };
        if let Some(url) = uri(text(entry, "url"), rule) { urls.push(url); }
        else {
            *unsupported += 1;
            // Without a valid blocker, importing the positive rules could broaden access.
            if rule == Some("never") { return Vec::new(); }
        }
    }
    urls
}

fn proton(batch: &mut Batch, head: &[String], rows: &[Vec<String>]) {
    for row in rows {
        if row.len() != head.len() { batch.invalid += 1; continue; }
        let col = |name: &str| column(head, row, name);
        let mut fields = Vec::new();
        let mut note = col("note");
        let payload = SecretJson(serde_json::from_str(note).unwrap_or(Value::Null));
        let data = match col("type") {
            "login" => {
                let mail = col("email");
                let account = if col("username").is_empty() { mail } else { col("username") };
                if !mail.is_empty() && mail != account { fields.push(field("Proton Pass 邮箱", mail)); }
                let structured = SecretJson(serde_json::from_str(col("autofillUrls")).unwrap_or(Value::Null));
                let has_modes = head.iter().any(|name| name.trim().eq_ignore_ascii_case("autofillUrls"));
                let urls = if has_modes && col("autofillUrls").is_empty() && col("url").is_empty() { Vec::new() }
                    else { proton_urls(has_modes.then_some(&structured.0), col("url").split(", "), &mut batch.unsupported) };
                batch.login(account, col("password"), urls, col("totp"), &mut fields)
            }
            "note" => json!({"kind":"developer","subtype":NOTE}),
            "creditCard" | "identity" if payload.0.is_object() => {
                note = text(&payload.0, "note");
                if col("type") == "creditCard" { crate::vendor_archives::proton_card(&payload.0) }
                else { crate::vendor_archives::proton_identity(&payload.0) }
            }
            "creditCard" | "identity" => { batch.invalid += 1; continue; }
            _ => { batch.unsupported += 1; continue; }
        };
        let tags = [col("vault")].into_iter().filter(|value| !value.is_empty()).collect::<Vec<_>>();
        batch.push(col("name"), note, data, &tags, fields, false, false);
    }
}

fn roboform(batch: &mut Batch, head: &[String], rows: &[Vec<String>]) {
    let native = head[2].trim().eq_ignore_ascii_case("matchurl");
    for row in rows {
        if native && row.len() < 7 || !native && !(row.len() == 6 || row.len() == 7 && row[6].is_empty()) {
            batch.invalid += 1; continue;
        }
        let shift = usize::from(native);
        let (title, site, user, password, note, folder) = (&row[0], &row[1], &row[2 + shift], &row[3 + shift], &row[4 + shift], &row[5 + shift]);
        let match_url = if native { &row[2] } else { site };
        let mut coding = None;
        for extra in row.iter().skip(6 + shift).filter(|extra| !extra.is_empty()) {
            let seed = extra.strip_prefix("TOTP KEY$").and_then(|s| s.rsplit_once(',')).map(|(_, seed)| seed);
            match (coding, seed) {
                (None, Some(seed)) if !seed.is_empty() => coding = Some(seed),
                _ => batch.unsupported += 1,
            }
        }
        let unescape = |value: &str| if native && (value.starts_with("'@") || value.starts_with("''")) { 1 } else { 0 };
        let mut fields = Vec::new();
        let data = if site.is_empty() && match_url.is_empty() && user.is_empty() && password.is_empty() && coding.is_none() {
            json!({"kind":"developer","subtype":NOTE})
        } else {
            let mut urls = Vec::new();
            if !match_url.is_empty() {
                if let Some(url) = uri(match_url, native.then_some("exact")) { urls.push(url); }
                else { batch.unsupported += 1; }
            }
            if native && site != match_url && !site.is_empty() {
                if let Some(url) = uri(site, Some("never")) { urls.push(url); }
                else { batch.unsupported += 1; }
            }
            batch.login(&user[unescape(user)..], &password[unescape(password)..], urls, coding.unwrap_or(""), &mut fields)
        };
        let tags = (!folder.is_empty()).then_some(folder.as_str()).into_iter().collect::<Vec<_>>();
        batch.push(title, note, data, &tags, fields, false, false);
    }
}

fn flag(value: &str) -> Option<bool> {
    if value.is_empty() || value == "0" || value.eq_ignore_ascii_case("false") { Some(false) }
    else if value == "1" || value.eq_ignore_ascii_case("true") { Some(true) }
    else { None }
}

fn onepassword(batch: &mut Batch, head: &[String], rows: &[Vec<String>]) {
    for row in rows {
        if row.len() != head.len() { batch.invalid += 1; continue; }
        let col = |name: &str| column(head, row, name);
        let (Some(archived), Some(pinned)) = (flag(col("archived")), flag(col("favorite"))) else {
            batch.invalid += 1; continue;
        };
        let mut fields = Vec::new();
        if archived { fields.push(field("CSV 源归档状态", "true")); }
        let mut urls = Vec::new();
        if !col("url").is_empty() {
            if let Some(url) = uri(col("url"), archived.then_some("never")) { urls.push(url); }
            else { batch.unsupported += 1; }
        }
        let first = |values: [&str; 3]| values.iter().position(|value| !value.is_empty());
        let otps = [col("otp"), col("otpauth"), col("one-time password")];
        let tags = col("tags").split(',').map(str::trim).filter(|tag| !tag.is_empty()).collect::<Vec<_>>();
        let data = batch.login(col("username"), col("password"), urls, first(otps).map_or("", |i| otps[i]), &mut fields);
        let notes = col("notes");
        batch.push(col("title"), if notes.is_empty() { col("note") } else { notes }, data, &tags, fields, pinned, false);
    }
}

pub(crate) fn import(vendor: Vendor, head: &[String], rows: &[Vec<String>]) -> SecretJson {
    let mut batch = Batch::new();
    match vendor {
        Vendor::Bitwarden => bitwarden(&mut batch, head, rows),
        Vendor::Proton => proton(&mut batch, head, rows),
        Vendor::RoboForm => roboform(&mut batch, head, rows),
        Vendor::OnePassword => onepassword(&mut batch, head, rows),
    }
    batch.result()
}
