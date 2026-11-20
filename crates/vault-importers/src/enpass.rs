use crate::bitwarden::{SecretJson, text};
use crate::migration_csv::valid_additional_url;
use crate::portable::{Batch, INVALID, LIMIT, MappingError, add_record, rows};
use crate::vendor_json;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, MappingError>;
const MAX_FIELDS: usize = 256;
const MAX_FOLDERS_PER_ITEM: usize = 64;
const MAX_FOLDER_DEPTH: usize = 16;

fn flag(row: &Value, key: &str) -> Option<bool> {
    match row.get(key) {
        None => Some(false),
        Some(value) => match value.as_u64()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        },
    }
}

fn folder_tag<'a>(folders: &BTreeMap<&str, &'a Value>, mut id: &'a str) -> Option<String> {
    let mut names = Vec::new();
    for _ in 0..MAX_FOLDER_DEPTH {
        let row = folders.get(id)?;
        let title = text(row, "title");
        if title.trim().is_empty() || title.len() > 128 { return None; }
        names.push(title);
        id = text(row, "parent_uuid");
        if id.is_empty() {
            names.reverse();
            return Some(names.join("/"));
        }
    }
    // Refuse cycles and implausibly deep paths without following them recursively.
    None
}

fn offline_template(template: &str) -> bool {
    matches!(
        template,
        "computer.database" | "computer.emailaccount" | "computer.ftp" | "computer.messaging"
            | "computer.internetprovider" | "computer.server" | "computer.wifi"
            | "computer.hosting" | "computer.other" | "finance.bankaccount"
    )
}

pub(crate) fn read(bytes: &[u8], password: &str) -> Result<Batch> {
    if !password.is_empty() { return Err(INVALID); }
    let document = vendor_json::read(bytes)?;
    let root = &document.0;
    if !root.is_object() || root.get("encrypted").is_some() || root.get("version").is_some() {
        return Err(INVALID);
    }
    let mut folders = BTreeMap::new();
    for folder in rows(&root["folders"])? {
        let id = text(folder, "uuid");
        if id.is_empty() || id.len() > 128 || folder["title"].as_str().is_none()
            || folder.get("parent_uuid").is_some_and(|parent| !parent.is_string())
            || folders.insert(id, folder).is_some()
        {
            return Err(INVALID);
        }
    }
    let mut batch = Batch::default();
    let mut folder_paths = BTreeMap::new();
    let mut tag_bytes = 0;
    let mut source_ids = BTreeSet::new();
    'item: for row in rows(&root["items"])? {
        let id = text(row, "uuid");
        if id.trim_ascii().is_empty() || id.len() > 128 {
            batch.invalid += 1;
            continue;
        }
        if !source_ids.insert(id) { return Err(INVALID); }
        let (Some(archived), Some(trashed), Some(pinned)) =
            (flag(row, "archived"), flag(row, "trashed"), flag(row, "favorite")) else {
            batch.invalid += 1;
            continue;
        };
        if !row["template_type"].is_string() || row.get("note").is_some_and(|note| !note.is_string()) {
            batch.invalid += 1;
            continue;
        }
        let template = text(row, "template_type");
        let web_login = matches!(template, "login.default" | "password.default");
        let login = web_login || offline_template(template);
        if !login && template != "note.default" {
            batch.unsupported += 1;
            continue;
        }
        let fields = match row.get("fields") {
            None => &[][..],
            Some(value) => match value.as_array() {
                Some(fields) if fields.len() <= MAX_FIELDS => fields.as_slice(),
                _ => { batch.invalid += 1; continue; },
            },
        };
        let folder_ids = match row.get("folders") {
            None => &[][..],
            Some(value) => match value.as_array() {
                Some(ids) if ids.len() <= MAX_FOLDERS_PER_ITEM => ids.as_slice(),
                _ => { batch.invalid += 1; continue; },
            },
        };
        let mut tags = Vec::<String>::new();
        for folder in folder_ids {
            let Some(id) = folder.as_str().filter(|id| id.len() <= 128 && folders.contains_key(id)) else {
                batch.unsupported += 1;
                continue;
            };
            let Some(tag) = folder_paths.entry(id).or_insert_with(|| folder_tag(&folders, id)) else {
                batch.unsupported += 1;
                continue;
            };
            if !tags.contains(tag) {
                tag_bytes += tag.len();
                if tag_bytes > LIMIT / 4 { return Err(INVALID); }
                tags.push(tag.clone());
            }
        }

        let mut retained = SecretJson(json!({ "archived": archived, "fields": [] }));
        let extras = retained.0["fields"].as_array_mut().unwrap();
        let (mut username, mut secret) = ("", "");
        let mut email = None;
        let mut uris = Vec::new();
        let (mut otp, mut saw_otp) = (SecretJson(Value::Null), false);
        for field in fields {
            match flag(field, "deleted") {
                Some(false) => {}
                Some(true) => continue,
                None => { batch.invalid += 1; continue 'item; }
            }
            let kind = text(field, "type");
            if kind == "section" { continue; }
            let Some(value) = field["value"].as_str().filter(|_| !kind.is_empty()) else {
                batch.invalid += 1;
                continue 'item;
            };
            if value.is_empty() { continue; }
            match kind {
                "username" if login && username.is_empty() => username = value,
                "email" if login && email.is_none() => email = Some((text(field, "label"), value)),
                "password" if login && secret.is_empty() => secret = value,
                "url" if web_login => {
                    let uri = value.trim_ascii();
                    if uris.len() == 64 || !valid_additional_url(uri) {
                        batch.unsupported += 1;
                    } else {
                        uris.push(json!({ "uri":uri, "matchRule":if archived { "never" } else { "host" } }));
                    }
                }
                "totp" => {
                    if login && !saw_otp {
                        saw_otp = true;
                        if let Ok(code) = vault_otp::parse(value) && code.kind == vault_otp::Kind::Totp {
                            otp.0 = json!(&*code.canonical_uri());
                            continue;
                        }
                    }
                    batch.ignored_otp += 1;
                }
                "text" | "password" | "username" | "email" | "pin" | "numeric" | "date" | "phone" | "multiline" | "url" =>
                    extras.push(json!({ "type":kind, "label":text(field, "label"), "value":value })),
                _ => batch.unsupported += 1,
            }
        }
        if let Some((label, value)) = email {
            if username.is_empty() {
                username = value;
            } else {
                extras.push(json!({ "type":"email", "label":label, "value":value }));
            }
        }
        let note = text(row, "note");
        let data = if login && (!secret.is_empty() || !username.is_empty() || !uris.is_empty() || !otp.0.is_null()) {
            json!({ "kind":"login", "username":username, "password":secret, "uris":uris, "totpUri":otp.0 })
        } else if !note.is_empty() || !extras.is_empty() {
            json!({ "kind":"developer", "subtype":"secure_note" })
        } else {
            batch.invalid += 1;
            continue;
        };
        let data = SecretJson(data);
        let custom = if archived || !extras.is_empty() {
            match vendor_json::fields(&retained.0) {
                Ok(fields) => fields,
                Err(_) => { batch.invalid += 1; continue; },
            }
        } else { SecretJson(json!([])) };
        let item = SecretJson(json!({ "title":text(row, "title"), "data":data.0,
            "note":note, "customFields":custom.0, "tags":tags, "pinned":pinned, "trashed":trashed }));
        add_record(&mut batch, &item.0, vec![], "enpass", id)?;
    }
    Ok(batch)
}
