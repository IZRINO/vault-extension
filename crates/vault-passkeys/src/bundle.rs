use crate::{Passkey, protocol::{Failure, INVALID}};
use std::collections::BTreeMap;
use vault_core::model::{CredentialData, VaultItem};
use zeroize::Zeroizing;

pub const MAX_KEYS: usize = 64;
const MAX_BYTES: usize = 96 * 1024;

pub fn read(data: &[u8]) -> Result<Vec<Passkey>, Failure> {
    if data.is_empty() { return Ok(Vec::new()); }
    if data.len() > MAX_BYTES || data[0] != 1 { return Err(INVALID); }
    let (keys, extra) = postcard::take_from_bytes::<Vec<Passkey>>(&data[1..]).map_err(|_| INVALID)?;
    if !extra.is_empty() || keys.is_empty() || keys.len() > MAX_KEYS { return Err(INVALID); }
    Ok(keys)
}

pub fn write(keys: &[Passkey]) -> Result<Vec<u8>, Failure> {
    if keys.is_empty() { return Ok(Vec::new()); }
    if keys.len() > MAX_KEYS { return Err(INVALID); }
    let bytes = Zeroizing::new(postcard::to_allocvec(keys).map_err(|_| INVALID)?);
    if bytes.len() >= MAX_BYTES { return Err(INVALID); }
    let mut output = Vec::with_capacity(bytes.len() + 1);
    output.push(1);
    output.extend_from_slice(&bytes);
    Ok(output)
}

pub fn merge<'a>(base: &[u8], candidates: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<u8>, Failure> {
    let mut keys = read(base)?;
    for data in candidates {
        for incoming in read(data)? {
            if let Some(known) = keys.iter_mut().find(|key| key.rp_id == incoming.rp_id && key.credential_id == incoming.credential_id) {
                if !known.same_key(&incoming) || known.increment != incoming.increment { return Err(INVALID); }
                if !incoming.count_unverified { known.count = known.count.max(incoming.count); }
                known.count_unverified &= incoming.count_unverified;
                known.pack_backup_verified |= incoming.pack_backup_verified;
            } else {
                keys.push(incoming);
            }
            if keys.len() > MAX_KEYS { return Err(INVALID); }
        }
    }
    keys.sort_by(|left, right| left.rp_id.cmp(&right.rp_id).then(left.credential_id.cmp(&right.credential_id)));
    write(&keys)
}

#[derive(Default)]
pub struct CounterEvidence(BTreeMap<(String, Vec<u8>), Vec<Passkey>>);
impl CounterEvidence {
    pub fn from_items(items: &[VaultItem]) -> Result<Self, Failure> {
        let mut known = Self::default();
        for item in items {
            let CredentialData::Login(login) = &item.data else { continue; };
            for key in read(&login.passkey_data)? {
                if key.increment && !key.count_unverified {
                    known.0.entry((key.rp_id.clone(), key.credential_id.clone())).or_default().push(key);
                }
            }
        }
        Ok(known)
    }

    pub fn restore(&self, historical: &[u8], verified_pack: bool) -> Result<Vec<u8>, Failure> {
        let mut keys = read(historical)?;
        for key in &mut keys {
            key.pack_backup_verified |= verified_pack && key.eligible;
            if !key.increment { continue; }
            let latest = self.0.get(&(key.rp_id.clone(), key.credential_id.clone())).into_iter().flatten()
                .filter(|known| key.same_key(known)).map(|known| known.count).max();
            if let Some(count) = latest { key.count = key.count.max(count); key.count_unverified = false; }
            else { key.count_unverified = true; }
        }
        write(&keys)
    }
}
