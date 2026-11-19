use std::collections::{BTreeMap, BTreeSet};
use vault_core::error::VaultError;
use vault_core::json_lite::JVal;
use vault_core::model::{CredentialData, MAX_PASSWORD_HISTORY, PasswordHistoryEntry, VaultItem};

pub(crate) type Choices = BTreeMap<String, String>;

pub(crate) struct Merge {
    pub(crate) item: Option<VaultItem>,
    pub(crate) contested: Vec<String>,
}

pub(crate) fn same(a: Option<&VaultItem>, b: Option<&VaultItem>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => same_item_fields(a, b) && a.data == b.data,
        (None, None) => true,
        _ => false,
    }
}

fn same_item_fields(a: &VaultItem, b: &VaultItem) -> bool {
    a.id == b.id && a.title == b.title && a.note == b.note && a.custom_fields == b.custom_fields &&
        a.tags == b.tags && a.pinned == b.pinned && a.require_reprompt == b.require_reprompt && a.trashed == b.trashed
}

fn same_independent_login(a: &VaultItem, b: &VaultItem) -> Result<bool, VaultError> {
    let (CredentialData::Login(left), CredentialData::Login(right)) = (&a.data, &b.data) else { return Ok(false); };
    if !same_item_fields(a, b) || left.username != right.username || left.password != right.password ||
        left.uris != right.uris || (left.totp_uri != right.totp_uri &&
            highest_hotp(left.totp_uri.as_deref(), right.totp_uri.as_deref()).is_none())
    {
        return Ok(false);
    }
    if left.passkey_data == right.passkey_data { return Ok(true); }
    // A different credential set still needs an explicit choice. Only proof
    // and counter differences on the same credentials are monotonic.
    let mut left = vault_passkeys::bundle::read(&left.passkey_data).map_err(|_| crate::batch::invalid())?;
    let mut right = vault_passkeys::bundle::read(&right.passkey_data).map_err(|_| crate::batch::invalid())?;
    let order = |a: &vault_passkeys::Passkey, b: &vault_passkeys::Passkey|
        a.rp_id.cmp(&b.rp_id).then_with(|| a.credential_id.cmp(&b.credential_id));
    left.sort_by(order);
    right.sort_by(order);
    Ok(left.len() == right.len() && left.iter().zip(&right).all(|(a, b)|
        a.same_key(b) && a.increment == b.increment && a.account == b.account && a.discoverable == b.discoverable))
}

struct FieldMerge<'a> {
    choices: &'a Choices,
    contested: Vec<String>,
}

impl FieldMerge<'_> {
    fn fields(&mut self, base: &JVal, ours: &JVal, theirs: &JVal, prefix: &str) -> Result<JVal, VaultError> {
        let (JVal::Obj(ours_fields), JVal::Obj(theirs_fields)) = (ours, theirs) else { return Err(crate::batch::invalid()); };
        if ours_fields.len() != theirs_fields.len() { return Err(crate::batch::invalid()); }
        let mut out = Vec::with_capacity(ours_fields.len());
        for &(key, ref o) in ours_fields {
            let b = base.get_field(key).ok_or_else(crate::batch::invalid)?;
            let t = theirs.get_field(key).ok_or_else(crate::batch::invalid)?;
            if prefix.is_empty() && key == "data" {
                let kind = "kind";
                if o.get_field(kind) == t.get_field(kind) && t.get_field(kind) == b.get_field(kind) {
                    out.push((key, self.fields(b, o, t, "data.")?));
                    continue;
                }
            }
            let name = format!("{prefix}{key}");
            let value = match name.as_str() {
                "id" | "createdAtMs" => b.clone(),
                "revision" | "updatedAtMs" => JVal::Uint(o.as_u64().unwrap_or(0).max(t.as_u64().unwrap_or(0))),
                "trashedAtMs" | "data.passwordHistory" => t.clone(), // Canonicalized after field merge.
                "requireReprompt" => JVal::Bool(o.as_bool().unwrap_or(false) || t.as_bool().unwrap_or(false)),
                _ if o == b || o == t => t.clone(),
                _ if t == b => o.clone(),
                "data.totpUri" if let Some(max) = highest_hotp(o.as_str(), t.as_str()) => JVal::Str(max),
                _ => {
                    self.contested.push(name.clone());
                    if self.choices.get(&name).is_some_and(|side| side == "ours") { o.clone() } else { t.clone() }
                }
            };
            out.push((key, value));
        }
        Ok(JVal::Obj(out))
    }
}

pub(crate) fn highest_hotp(a: Option<&str>, b: Option<&str>) -> Option<String> {
    let mut a = vault_otp::parse(a?).ok()?;
    let b = vault_otp::parse(b?).ok()?;
    if a.kind != vault_otp::Kind::Hotp || b.kind != vault_otp::Kind::Hotp || a.identity() != b.identity() { return None; }
    (a.counter, a.counter_unverified) = strongest_counter((a.counter, a.counter_unverified), (b.counter, b.counter_unverified));
    Some(a.canonical_uri().to_string())
}

fn preserve_counters(item: &mut VaultItem, versions: &[&VaultItem]) -> Result<(), VaultError> {
    if let CredentialData::Login(login) = &mut item.data {
        let bundles = versions.iter().filter_map(|version| match &version.data {
            CredentialData::Login(data) => Some(data.passkey_data.as_slice()),
            _ => None,
        });
        let merged = vault_passkeys::bundle::merge(&login.passkey_data, bundles)
            .map_err(|_| VaultError::InvalidFormat("Invalid or conflicting passkey data".into()))?;
        drop(zeroize::Zeroizing::new(std::mem::replace(&mut login.passkey_data, merged)));
        for version in versions {
            if let CredentialData::Login(data) = &version.data {
                if login.totp_uri != data.totp_uri && let Some(uri) = highest_hotp(login.totp_uri.as_deref(), data.totp_uri.as_deref()) {
                    let old = login.totp_uri.replace(uri);
                    drop(zeroize::Zeroizing::new(old));
                }
            }
        }
    }
    Ok(())
}

fn history(item: &mut VaultItem, versions: &[&VaultItem], losing: &[(&VaultItem, &str)]) {
    let CredentialData::Login(login) = &mut item.data else { return; };
    let mut entries: Vec<PasswordHistoryEntry> = Vec::new();
    let mut add = |entry: PasswordHistoryEntry| {
        if !entries.iter().any(|old| old.password == entry.password && old.changed_at_ms == entry.changed_at_ms) { entries.push(entry); }
    };
    for &(old, label) in losing {
        if let CredentialData::Login(data) = &old.data {
            if !data.password.is_empty() && data.password != login.password {
                add(PasswordHistoryEntry { password: data.password.clone(), changed_at_ms: old.updated_at_ms, source_device: Some(label.into()) });
            }
        }
    }
    for entry in login.password_history.iter().take(MAX_PASSWORD_HISTORY) { add(entry.clone()); }
    for version in versions {
        if let CredentialData::Login(data) = &version.data {
            for entry in data.password_history.iter().take(MAX_PASSWORD_HISTORY) { add(entry.clone()); }
        }
    }
    entries.sort_by(|a, b| b.changed_at_ms.cmp(&a.changed_at_ms)
        .then_with(|| a.password.cmp(&b.password)).then_with(|| a.source_device.cmp(&b.source_device)));
    entries.truncate(MAX_PASSWORD_HISTORY);
    login.password_history = entries;
}

pub(crate) fn archive_resolution(item: &mut VaultItem, losing: &[(&VaultItem, &str)]) {
    item.require_reprompt |= losing.iter().any(|(old, _)| old.require_reprompt);
    history(item, &losing.iter().map(|(old, _)| *old).collect::<Vec<_>>(), losing);
}

fn strongest_counter<T: Copy + Ord>(a: (T, bool), b: (T, bool)) -> (T, bool) {
    match (a.1, b.1) {
        (false, true) => a,
        (true, false) => b,
        _ => (a.0.max(b.0), a.1),
    }
}

pub(crate) fn preserve_resolution_counters<'a>(chosen: &mut [VaultItem], versions: impl Iterator<Item = &'a VaultItem>) -> Result<(), VaultError> {
    use vault_passkeys::{Passkey, bundle};
    let hotp = |uri: Option<&str>| uri.and_then(|uri| vault_otp::parse(uri).ok()).filter(|otp| otp.kind == vault_otp::Kind::Hotp);
    let mut otp_counts = BTreeMap::new();
    let mut passkeys = BTreeMap::<_, Passkey>::new();
    for item in versions {
        let CredentialData::Login(login) = &item.data else { continue; };
        if let Some(otp) = hotp(login.totp_uri.as_deref()) {
            let counter = (otp.counter, otp.counter_unverified);
            otp_counts.entry(otp.identity()).and_modify(|known| *known = strongest_counter(*known, counter)).or_insert(counter);
        }
        for key in bundle::read(&login.passkey_data).map_err(|_| crate::batch::invalid())? {
            let id = (key.rp_id.clone(), key.credential_id.clone());
            if let Some(known) = passkeys.get_mut(&id) {
                if !known.same_key(&key) || known.increment != key.increment { return Err(crate::batch::invalid()); }
                known.pack_backup_verified |= key.pack_backup_verified;
                (known.count, known.count_unverified) = strongest_counter(
                    (known.count, known.count_unverified), (key.count, key.count_unverified));
            } else { passkeys.insert(id, key); }
        }
    }
    let mut active_hotp = BTreeSet::new();
    let mut active_passkeys = BTreeSet::new();
    for item in chosen {
        let CredentialData::Login(login) = &mut item.data else { continue; };
        if let Some(mut otp) = hotp(login.totp_uri.as_deref()) {
            let id = otp.identity();
            let (count, unverified) = otp_counts[&id];
            let paused = unverified || !active_hotp.insert(id);
            if (otp.counter, otp.counter_unverified) != (count, paused) {
                (otp.counter, otp.counter_unverified) = (count, paused);
                drop(zeroize::Zeroizing::new(login.totp_uri.replace(otp.canonical_uri().to_string())));
            }
        }
        if login.passkey_data.is_empty() { continue; }
        let mut keys = bundle::read(&login.passkey_data).map_err(|_| crate::batch::invalid())?;
        for key in &mut keys {
            let id = (key.rp_id.clone(), key.credential_id.clone());
            let known = &passkeys[&id];
            key.pack_backup_verified |= known.pack_backup_verified;
            if key.increment {
                key.count = known.count;
                key.count_unverified = known.count_unverified || !active_passkeys.insert(id);
            }
        }
        let bytes = bundle::write(&keys).map_err(|_| crate::batch::invalid())?;
        drop(zeroize::Zeroizing::new(std::mem::replace(&mut login.passkey_data, bytes)));
    }
    Ok(())
}

pub(crate) fn item(
    base: Option<&VaultItem>, ours: Option<&VaultItem>, theirs: Option<&VaultItem>,
    choices: &Choices, sources: (&str, &str),
) -> Result<Merge, VaultError> {
    let mut fields = FieldMerge { choices, contested: Vec::new() };
    let mut selected = if same(ours, theirs) || same(ours, base) {
        theirs.cloned()
    } else if same(theirs, base) {
        ours.cloned()
    } else {
        match (base, ours, theirs) {
            (None, Some(o), Some(t)) if same_independent_login(o, t)? => Some(t.clone()),
            (Some(b), Some(o), Some(t)) if o.trashed == t.trashed && o.data.kind_name() == t.data.kind_name() && o.data.kind_name() == b.data.kind_name() => {
                let value = fields.fields(&b.to_json_value(), &o.to_json_value(), &t.to_json_value(), "")?;
                let mut merged = VaultItem::from_json_value(&value)?;
                merged.trashed_at_ms = if merged.trashed { o.trashed_at_ms.max(t.trashed_at_ms) } else { None };
                Some(merged)
            }
            _ => {
                fields.contested.push("$item".into());
                if choices.get("$item").is_some_and(|side| side == "ours") { ours.cloned() } else { theirs.cloned() }
            }
        }
    };
    if let Some(item) = &mut selected {
        let versions: Vec<_> = [ours, theirs].into_iter().flatten().collect();
        let losing = if (fields.contested.iter().any(|field| field == "data.password" || field == "data" || field == "$item")) && !choices.is_empty() {
            let our_password = ours.and_then(|item| if let CredentialData::Login(data) = &item.data { Some(&data.password) } else { None });
            let selected = if let CredentialData::Login(data) = &item.data { Some(&data.password) } else { None };
            if selected == our_password { theirs.map(|row| (row, sources.1)) } else { ours.map(|row| (row, sources.0)) }
        } else { None };
        if !choices.is_empty() && versions.iter().any(|version| version.require_reprompt) {
            item.require_reprompt = true;
        }
        history(item, &versions, losing.as_slice());
        preserve_counters(item, &versions)?;
    }
    Ok(Merge { item: selected, contested: fields.contested })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(password: &str, note: &str, rev: u64, time: u64) -> VaultItem {
        VaultItem::from_json_str(&format!(r#"{{"id":"fixture","title":"Fixture","data":{{"kind":"login","password":"{password}"}},"note":"{note}","revision":{rev},"updatedAtMs":{time}}}"#)).unwrap()
    }
    #[test]
    fn independent_copy_coalesces_backup_evidence_without_hiding_a_password_conflict() {
        use vault_passkeys::{Passkey, bundle};
        let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        der.extend_from_slice(&[17; 32]);
        let mut key = Passkey::from_pkcs8(vec![3; 32], "example.com".into(), vec![5], "fixture".into(), &der, true, true, None).unwrap();
        let mut theirs = row("shared", "same note", 2, 60);
        let CredentialData::Login(target) = &mut theirs.data else { panic!() };
        target.passkey_data = bundle::write(&[key.clone()]).unwrap();
        let mut ours = theirs.clone();
        let CredentialData::Login(source) = &mut ours.data else { panic!() };
        key.pack_backup_verified = true;
        source.passkey_data = bundle::write(&[key]).unwrap();
        let both = |source: &VaultItem| item(None, Some(source), Some(&theirs), &Choices::new(), ("A", "B")).unwrap();
        let merged = both(&ours);
        assert!(merged.contested.is_empty());
        let merged = merged.item.unwrap();
        let CredentialData::Login(login) = &merged.data else { panic!() };
        assert!(bundle::read(&login.passkey_data).unwrap()[0].pack_backup_verified);
        let CredentialData::Login(source) = &mut ours.data else { panic!() };
        source.password = "local-only".into();
        assert_eq!(both(&ours).contested, ["$item"]);
    }

    #[test]
    fn non_overlapping_fields_merge_and_losing_password_is_archived_only_on_resolution() {
        let base = row("base", "old", 1, 50);
        let ours = row("current on A", "old", 2, 60);
        let theirs = row("base", "remote note", 2, 70);
        let merged = item(Some(&base), Some(&ours), Some(&theirs), &Choices::new(), ("A", "B")).unwrap();
        assert!(merged.contested.is_empty());
        let result = merged.item.unwrap();
        assert_eq!(result.note, "remote note");
        assert_eq!(result.to_json_value().get_field("data").unwrap().get_str("password"), "current on A");
        let theirs = row("current on B", "remote note", 2, 70);
        let pending = item(Some(&base), Some(&ours), Some(&theirs), &Choices::new(), ("A", "B")).unwrap();
        assert_eq!(pending.contested, vec!["data.password"]);
        let chosen = item(Some(&base), Some(&ours), Some(&theirs), &Choices::from([("data.password".into(), "ours".into())]), ("A", "B")).unwrap();
        let resolved = chosen.item.unwrap();
        let CredentialData::Login(login) = &resolved.data else { panic!() };
        assert_eq!(login.password, "current on A");
        assert_eq!(login.password_history, vec![PasswordHistoryEntry { password: "current on B".into(), changed_at_ms: 70, source_device: Some("B".into()) }]);
        assert_eq!(resolved.note, "remote note");
        assert_eq!(item(Some(&base), Some(&ours), None, &Choices::new(), ("A", "B")).unwrap().contested, vec!["$item"]);
    }
}
