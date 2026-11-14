use crate::error::VaultError;
use crate::json_lite::{JVal, compact_sort_by};
use crate::model::{CredentialData, VaultItem, extract_host_display};
use zeroize::Zeroizing;

#[inline(never)]
fn identity(uri: &str, username: &str) -> Option<(String, [u8; 16])> {
    let mut site = extract_host_display(uri);
    site.make_ascii_lowercase();
    if let Some((user_info, _)) = site.rsplit_once('@') { site.drain(..=user_info.len()); }
    let scheme = uri.split_once("://").map(|(scheme, _)| scheme).unwrap_or("");
    for (protocol, port) in [("https", ":443"), ("http", ":80")] {
        if scheme.eq_ignore_ascii_case(protocol) && site.ends_with(port) {
            site.truncate(site.len() - port.len());
        }
    }
    if site.ends_with('.') { site.pop(); }
    if site.is_empty() { return None; }
    let mut identity = Zeroizing::new(Vec::with_capacity(site.len() + 1 + username.len()));
    identity.extend_from_slice(site.as_bytes());
    identity.push(0);
    identity.extend_from_slice(username.as_bytes());
    let mut key = [0; 16];
    key.copy_from_slice(&blake3::hash(&identity).as_bytes()[..16]);
    Some((site, key))
}

pub(crate) fn plan(existing: &[VaultItem], csv: &str, now: u64) -> Result<(Vec<VaultItem>, String), VaultError> {
    let invalid_data = || VaultError::InvalidInput("invalid CSV import records".into());
    let root = JVal::parse(csv)?;
    let rows = root.get_field("rows").and_then(JVal::as_array).ok_or_else(invalid_data)?;
    if rows.len() > 5000 { return Err(invalid_data()); }
    let mut seen = Vec::new();
    for item in existing {
        if let CredentialData::Login(login) = &item.data {
            for uri in &login.uris {
                if let Some((_, key)) = identity(&uri.uri, &login.username) { seen.push(key); }
            }
        }
    }
    compact_sort_by(&mut seen, |a, b| a.cmp(b));
    seen.dedup();
    let (mut accepted, mut sample) = (Vec::new(), Vec::new());
    let mut skipped = 0;
    for row in rows {
        let mut item = VaultItem::from_json_value(row)?;
        let CredentialData::Login(login) = &item.data else { return Err(invalid_data()); };
        let (site, key) = login.uris.first().and_then(|uri| identity(&uri.uri, &login.username)).ok_or_else(invalid_data)?;
        let Err(index) = seen.binary_search(&key) else { skipped += 1; continue; };
        seen.insert(index, key);
        if sample.len() < 12 {
            sample.push(JVal::Obj(vec![
                ("title", JVal::Str(item.title.clone())),
                ("site", JVal::Str(site)),
                ("username", JVal::Str(login.username.clone())),
            ]));
        }
        item.id.clear();
        item.created_at_ms = now;
        item.updated_at_ms = now;
        item.revision = 1;
        accepted.push(item);
    }
    let details = JVal::Obj(vec![
        ("ready", JVal::Uint(accepted.len() as u64)), ("skipped", JVal::Uint(skipped)),
        ("invalid", JVal::Uint(root.get_u64("invalid"))), ("ignoredOtp", JVal::Uint(root.get_u64("ignoredOtp"))),
        ("sample", JVal::Arr(sample)),
    ]);
    Ok((accepted, details.stringify()))
}
