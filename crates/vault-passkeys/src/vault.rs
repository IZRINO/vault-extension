use crate::{Ceremony, Passkey, bundle, protocol::{decode, validate_rp, Failure, INVALID}};
use crate::sealed::{open_vault, seal_vault};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use vault_core::model::{CredentialData, LoginCredential, UriEntry, UriMatchRule, VaultItem, generate_uuid_v4};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const VERIFY: Failure = "Verification is required for this passkey operation.";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    kind: String,
    origin: String,
    rp_id: String,
    challenge: String,
    #[serde(default)]
    user: Option<User>,
    #[serde(default)]
    algorithms: Vec<i32>,
    #[serde(default)]
    credential_ids: Vec<String>,
    uv: String,
    #[serde(default)]
    conditional: bool,
    #[serde(default)]
    resident: bool,
}

#[derive(Deserialize)]
struct User { id: String, name: String, display: String }

impl Request {
    fn parse(json: &str) -> Result<Self, Failure> {
        if json.len() > 128 * 1024 { return Err(INVALID); }
        let request = serde_json::from_str::<Self>(json).map_err(|_| INVALID)?;
        if !matches!(request.kind.as_str(), "register" | "assert") || !matches!(request.uv.as_str(), "discouraged" | "preferred" | "required") ||
           request.credential_ids.len() > 64 || request.algorithms.len() > 32 { return Err(INVALID); }
        validate_rp(&request.origin, &request.rp_id)?;
        decode(&request.challenge, 16, 1024)?;
        for id in &request.credential_ids { decode(id, 1, 1023)?; }
        if request.kind == "register" {
            let user = request.user.as_ref().ok_or(INVALID)?;
            if user.name.len() > 1024 || user.display.len() > 1024 || user.name.is_empty() { return Err(INVALID); }
            decode(&user.id, 1, 64)?;
            request.algorithm()?;
        }
        Ok(request)
    }
    fn algorithm(&self) -> Result<i32, Failure> { self.algorithms.iter().copied().find(|algorithm| matches!(algorithm, -7 | -8)).ok_or(INVALID) }
    fn ceremony(&self) -> Ceremony<'_> { Ceremony::new(&self.origin, &self.rp_id, &self.challenge) }
    fn accepts(&self, key: &Passkey) -> bool {
        key.rp_id == self.rp_id && if self.credential_ids.is_empty() { key.discoverable }
        else { (!self.conditional || key.discoverable) && self.credential_ids.contains(&B64.encode(&key.credential_id)) }
    }
}

fn map_error(error: Failure) -> JsValue { JsValue::from_str(error) }

fn matching_login<'a>(item: &'a VaultItem, rp: &str) -> Option<&'a LoginCredential> {
    if item.trashed { return None; }
    let CredentialData::Login(login) = &item.data else { return None; };
    login.uris.iter().any(|uri| url::Url::parse(&uri.uri).ok()
        .is_some_and(|url| validate_rp(&url.origin().ascii_serialization(), rp).is_ok())).then_some(login)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Candidate {
    item_id: String,
    id: Option<String>,
    title: String,
    account: String,
    verify: bool,
    suspended: bool,
}

#[wasm_bindgen]
pub fn wasm_passkey_candidates(key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], request: String) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let request = Request::parse(&request).map_err(map_error)?;
    let (_, _, snap) = open_vault(&key, &wrap, head, snap)?;
    let mut result = Vec::new();
    for item in &snap.items {
        let CredentialData::Login(login) = &item.data else { continue; };
        if item.trashed { continue; }
        if request.kind == "register" {
            if matching_login(item, &request.rp_id).is_some() {
                result.push(Candidate { item_id: item.id.clone(), id: None, title: item.title.clone(),
                    account: login.username.clone(), verify: request.uv == "required" || item.require_reprompt, suspended: false });
            }
        } else {
            for credential in bundle::read(&login.passkey_data).map_err(map_error)? {
                if request.accepts(&credential) {
                    result.push(Candidate { item_id: item.id.clone(), id: Some(B64.encode(&credential.credential_id)), title: item.title.clone(),
                        account: credential.account.clone(), verify: request.uv == "required" || item.require_reprompt, suspended: credential.count_unverified });
                }
            }
        }
        if result.len() >= 128 { break; }
    }
    serde_json::to_string(&result).map_err(|_| map_error(INVALID))
}

#[wasm_bindgen]
pub struct Authenticated {
    reply: String,
    head: Vec<u8>,
    snap: Vec<u8>,
}

#[wasm_bindgen]
impl Authenticated {
    #[wasm_bindgen(getter)]
    pub fn reply(&self) -> String { self.reply.clone() }
    #[wasm_bindgen(getter)]
    pub fn head(&self) -> Vec<u8> { self.head.clone() }
    #[wasm_bindgen(getter)]
    pub fn snap(&self) -> Vec<u8> { self.snap.clone() }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection { item_id: Option<String>, credential_id: Option<String>, verified: bool, increment: bool, now: u64 }

#[wasm_bindgen]
pub fn wasm_passkey_perform(
    key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], request: String, selection: String,
    backup_head: &[u8], backup_snap: &[u8],
) -> Result<Authenticated, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let request = Request::parse(&request).map_err(map_error)?;
    if selection.len() > 4096 { return Err(map_error(INVALID)); }
    let selection = serde_json::from_str::<Selection>(&selection).map_err(|_| map_error(INVALID))?;
    if request.uv == "required" && !selection.verified { return Err(map_error(VERIFY)); }
    let (keys, head, mut snapshot) = open_vault(&key, &wrap, head, snap)?;
    let (response, modified, user_handle) = if request.kind == "register" {
        for item in &snapshot.items {
            let CredentialData::Login(login) = &item.data else { continue; };
            if bundle::read(&login.passkey_data).map_err(map_error)?.iter().any(|record| record.rp_id == request.rp_id &&
                request.credential_ids.contains(&B64.encode(&record.credential_id))) { return Err(map_error("This passkey is already registered.")); }
        }
        let user = request.user.as_ref().ok_or_else(|| map_error(INVALID))?;
        let user_id = decode(&user.id, 1, 64).map_err(map_error)?;
        let (mut credential, response) = Passkey::register(&request.ceremony(), &user_id, &user.name,
            request.algorithm().map_err(map_error)?, selection.verified, selection.increment).map_err(map_error)?;
        credential.discoverable = request.resident;
        let index = if let Some(id) = selection.item_id {
            let index = snapshot.items.iter().position(|item| item.id == id && matching_login(item, &request.rp_id).is_some()).ok_or_else(|| map_error(INVALID))?;
            if snapshot.items[index].require_reprompt && !selection.verified { return Err(map_error(VERIFY)); }
            index
        } else {
            let mut data = LoginCredential::default();
            data.username.clone_from(&user.name);
            data.uris.push(UriEntry { uri: request.origin.clone(), match_rule: UriMatchRule::BaseDomain });
            snapshot.items.push(VaultItem { id: generate_uuid_v4()?, title: format!("{} · {}", request.rp_id, user.name),
                data: CredentialData::Login(data), tags: Vec::new(), note: String::new(), custom_fields: Vec::new(), pinned: false,
                require_reprompt: false, trashed: false, trashed_at_ms: None, created_at_ms: selection.now, updated_at_ms: selection.now, revision: 0 });
            snapshot.items.len() - 1
        };
        let item = &mut snapshot.items[index];
        let CredentialData::Login(login) = &mut item.data else { return Err(map_error(INVALID)); };
        let mut entries = bundle::read(&login.passkey_data).map_err(map_error)?;
        entries.push(credential);
        drop(Zeroizing::new(std::mem::replace(&mut login.passkey_data, bundle::write(&entries).map_err(map_error)?)));
        (response, Some(item), true)
    } else {
        let id = selection.item_id.ok_or_else(|| map_error(INVALID))?;
        let credential_id = decode(&selection.credential_id.ok_or_else(|| map_error(INVALID))?, 1, 1023).map_err(map_error)?;
        let item = snapshot.items.iter_mut().find(|item| !item.trashed && item.id == id).ok_or_else(|| map_error(INVALID))?;
        if item.require_reprompt && !selection.verified { return Err(map_error(VERIFY)); }
        let CredentialData::Login(login) = &mut item.data else { return Err(map_error(INVALID)); };
        let mut entries = bundle::read(&login.passkey_data).map_err(map_error)?;
        let credential = entries.iter_mut().find(|entry| entry.credential_id == credential_id && request.accepts(entry)).ok_or_else(|| map_error(INVALID))?;
        if credential.count_unverified { return Err(map_error("Passkey counter is unverified. Sync a trusted copy or add a new passkey on the site.")); }
        let backup = if credential.eligible && credential.pack_backup_verified { true }
        else if credential.eligible && !backup_head.is_empty() && !backup_snap.is_empty() {
            open_vault(&key, &wrap, backup_head, backup_snap).ok().is_some_and(|(_, _, snapshot)| {
                snapshot.items.iter().filter(|item| !item.trashed).any(|item| match &item.data {
                    CredentialData::Login(login) => bundle::read(&login.passkey_data).ok()
                        .is_some_and(|keys| keys.iter().any(|known| known.same_key(credential) && !known.count_unverified)),
                    _ => false,
                })
            })
        } else { false };
        let count = if credential.increment { credential.count.checked_add(1).ok_or_else(|| map_error(INVALID))? } else { 0 };
        let response = credential.assert(&request.ceremony(), selection.verified, backup, count).map_err(map_error)?;
        let modified = if credential.increment {
            credential.count = count;
            drop(Zeroizing::new(std::mem::replace(&mut login.passkey_data, bundle::write(&entries).map_err(map_error)?)));
            Some(item)
        } else { None };
        (response, modified, request.credential_ids.is_empty())
    };
    let mut response = response;
    if !user_handle { response.user_handle = None; }
    let reply = serde_json::to_string(&response).map_err(|_| map_error(INVALID))?;
    let (head, snap) = if let Some(item) = modified {
        item.updated_at_ms = selection.now.max(item.updated_at_ms);
        item.revision = item.revision.saturating_add(1);
        seal_vault(&keys, head, snapshot, selection.now)?
    } else { (Vec::new(), Vec::new()) };
    Ok(Authenticated { reply, head, snap })
}
