use crate::batch;
use subtle::ConstantTimeEq;
use vault_core::crypto::{RecoveryCode, SecretKey, VaultKeyHierarchy};
use vault_core::error::VaultError;
use vault_core::model::{CredentialData, VaultSnapshot, generate_uuid_v4};
use vault_core::session::SessionWrappedDekBlob;
use vault_core::sync_codec::{HeadEncryptedPointer, VaultHead, open_snapshot, seal_snapshot};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"VLTR\x01\0";
const MAX_HEADER: usize = 64 * 1024;
const MAX_SAFE_EPOCH: u64 = 9_007_199_254_740_991;

fn remote_wire(core: &[u8], keys: &VaultKeyHierarchy) -> Vec<u8> {
    let mut wire = Vec::with_capacity(MAGIC.len() + core.len() + 32);
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(core);
    let mac = keys.compute_state_mac(&wire);
    wire.extend_from_slice(&mac);
    wire
}

fn remote_core(wire: &[u8]) -> Result<(&[u8], VaultHead), VaultError> {
    if wire.len() <= MAGIC.len() + 32 || wire.len() > MAX_HEADER || !wire.starts_with(MAGIC) {
        return Err(VaultError::InvalidFormat("unrecognized sync head".into()));
    }
    let core = &wire[MAGIC.len()..wire.len() - 32];
    Ok((core, VaultHead::from_bytes(core)?))
}

fn verify_wire(wire: &[u8], head: &VaultHead, keys: &VaultKeyHierarchy) -> Result<HeadEncryptedPointer, VaultError> {
    let (authenticated, mac) = wire.split_at(wire.len() - 32);
    if keys.compute_state_mac(authenticated).ct_eq(mac).unwrap_u8() != 1 { return Err(VaultError::CryptoAuthFailed); }
    let pointer = head.decrypt_pointer(keys)?;
    if head.key_epoch == 0 || head.key_epoch > MAX_SAFE_EPOCH || pointer.snapshot_epoch == 0 || pointer.snapshot_epoch > MAX_SAFE_EPOCH ||
        pointer.recent_snapshot_ids.first() != Some(&pointer.latest_snapshot_id) ||
        pointer.recent_snapshot_ids.is_empty() || pointer.recent_snapshot_ids.len() > 5 ||
        pointer.recent_snapshot_ids.iter().any(|name| !valid_snapshot_id(name)) {
        return Err(VaultError::CryptoAuthFailed);
    }
    Ok(pointer)
}

fn valid_snapshot_id(name: &str) -> bool {
    name.strip_prefix("snap_").is_some_and(|id| crate::journal::time_of_id(id).is_ok())
}

#[wasm_bindgen]
pub struct RemoteHead {
    local_head: Vec<u8>,
    session_wrap: Vec<u8>,
    vault_id: String,
    key_epoch: u64,
    pointer: HeadEncryptedPointer,
}

#[wasm_bindgen]
impl RemoteHead {
    #[wasm_bindgen(getter)]
    pub fn local_head(&self) -> Vec<u8> { self.local_head.clone() }
    #[wasm_bindgen(getter)]
    pub fn session_wrap(&self) -> Vec<u8> { self.session_wrap.clone() }
    #[wasm_bindgen(getter)]
    pub fn vault_id(&self) -> String { self.vault_id.clone() }
    #[wasm_bindgen(getter)]
    pub fn key_epoch(&self) -> f64 { self.key_epoch as f64 }
    #[wasm_bindgen(getter)]
    pub fn snapshot_id(&self) -> String { self.pointer.latest_snapshot_id.clone() }
    #[wasm_bindgen(getter)]
    pub fn snapshot_epoch(&self) -> f64 { self.pointer.snapshot_epoch as f64 }
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> { self.pointer.state_root_mac.to_vec() }
    pub fn history_id(&self, index: usize) -> Option<String> { self.pointer.recent_snapshot_ids.get(index).cloned() }
}

fn unlock_remote(wire: &[u8], session_key: &[u8], secret: &[u8], recovery: bool) -> Result<RemoteHead, VaultError> {
    let (core, head) = remote_core(wire)?;
    let key = SecretKey::from_slice(session_key)?;
    let keys = if recovery {
        let code = std::str::from_utf8(secret).map_err(|_| VaultError::CryptoAuthFailed)?;
        head.unlock_with_recovery_secret(&RecoveryCode::parse(code)?)?
    } else {
        head.unlock_with_master_password(secret)?
    };
    let pointer = verify_wire(wire, &head, &keys)?;
    let session_wrap = SessionWrappedDekBlob::wrap(&head.vault_id, head.key_epoch, keys.master_dek(), &key)?;
    Ok(RemoteHead { local_head: core.to_vec(), session_wrap, vault_id: head.vault_id, key_epoch: head.key_epoch, pointer })
}

#[wasm_bindgen]
pub fn wasm_sync_unlock_head(wire: &[u8], session_key: Vec<u8>, secret: String, recovery: bool) -> Result<RemoteHead, JsValue> {
    let (key, secret) = (Zeroizing::new(session_key), Zeroizing::new(secret));
    unlock_remote(wire, &key, secret.as_bytes(), recovery).map_err(Into::into)
}

#[wasm_bindgen]
pub fn wasm_sync_verify_recovery(local_head: &[u8], session_key: Vec<u8>, wrap: Vec<u8>, code: String) -> bool {
    let (key, wrap, code) = (Zeroizing::new(session_key), Zeroizing::new(wrap), Zeroizing::new(code));
    (|| -> Result<bool, VaultError> {
        let (vault_id, epoch, current) = super::keys(&key, &wrap)?;
        let head = VaultHead::from_bytes(local_head)?;
        if head.vault_id != vault_id || head.key_epoch != epoch { return Ok(false); }
        let recovered = head.unlock_with_recovery_secret(&RecoveryCode::parse(&code)?)?;
        Ok(recovered.master_dek().as_bytes().ct_eq(current.master_dek().as_bytes()).unwrap_u8() == 1)
    })().unwrap_or(false)
}

#[wasm_bindgen]
pub fn wasm_sync_authenticate_head(wire: &[u8], session_key: Vec<u8>, wrap: Vec<u8>) -> Result<RemoteHead, JsValue> {
    let (session_key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault_id, _, keys) = super::keys(&session_key, &wrap)?;
    let (core, head) = remote_core(wire)?;
    if head.vault_id != vault_id { return Err(VaultError::CryptoAuthFailed.into()); }
    let pointer = verify_wire(wire, &head, &keys)?;
    // An old head can be authenticated for comparison with a recorded anchor.
    // This function never grants a session at that epoch.
    Ok(RemoteHead { local_head: core.to_vec(), session_wrap: Vec::new(), vault_id, key_epoch: head.key_epoch, pointer })
}

#[wasm_bindgen]
pub fn wasm_sync_rebase_wrap(
    session_key: Vec<u8>, wrap: Vec<u8>, template: &[u8], local_head: &[u8], local_snap: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let mut template = VaultHead::from_bytes(template)?;
    let local = VaultHead::from_bytes(local_head)?;
    if template.vault_id != vault || local.vault_id != vault || template.key_epoch != epoch { return Err(batch::invalid().into()); }
    let pointer = local.decrypt_pointer(&keys)?;
    let verified = open_snapshot(&keys, Some(&pointer.latest_snapshot_id), local_snap)?;
    if verified.vault_id != vault || verified.snapshot_epoch != pointer.snapshot_epoch || verified.state_mac != pointer.state_root_mac {
        return Err(batch::invalid().into());
    }
    template.update_pointer(&keys, &pointer)?;
    template.to_bytes().map_err(Into::into)
}

#[wasm_bindgen]
pub fn wasm_sync_publish_wrap(
    session_key: Vec<u8>, wrap: Vec<u8>, wire: &[u8], rotated: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let (_, previous) = remote_core(wire)?;
    let pointer = verify_wire(wire, &previous, &keys)?;
    let mut candidate = VaultHead::from_bytes(rotated)?;
    if previous.vault_id != vault || candidate.vault_id != vault || candidate.key_epoch != epoch ||
       previous.key_epoch.checked_add(1) != Some(epoch) || previous.recovery_salt != candidate.recovery_salt {
        return Err(batch::invalid().into());
    }
    candidate.decrypt_pointer(&keys)?;
    candidate.update_pointer(&keys, &pointer)?;
    Ok(remote_wire(&candidate.to_bytes()?, &keys))
}

#[wasm_bindgen]
pub fn wasm_sync_same_wrap(session_key: Vec<u8>, wrap: Vec<u8>, wire: &[u8], local: &[u8]) -> Result<bool, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let (_, remote) = remote_core(wire)?;
    verify_wire(wire, &remote, &keys)?;
    let local = VaultHead::from_bytes(local)?;
    if remote.vault_id != vault || local.vault_id != vault || remote.key_epoch != epoch || local.key_epoch != epoch { return Ok(false); }
    Ok(remote.kdf_params.salt == local.kdf_params.salt &&
       remote.wrapped_dek_master.ciphertext == local.wrapped_dek_master.ciphertext &&
       remote.wrapped_dek_master.tag == local.wrapped_dek_master.tag &&
       remote.wrapped_dek_master.nonce == local.wrapped_dek_master.nonce)
}

#[wasm_bindgen]
pub struct Genesis {
    head: Vec<u8>,
    snap: Vec<u8>,
    root: [u8; 32],
}

#[wasm_bindgen]
impl Genesis {
    #[wasm_bindgen(getter)]
    pub fn head(&self) -> Vec<u8> { self.head.clone() }
    #[wasm_bindgen(getter)]
    pub fn snap(&self) -> Vec<u8> { self.snap.clone() }
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> { self.root.to_vec() }
}

fn create_genesis(
    keys: &VaultKeyHierarchy, local_head: &[u8], local: VaultSnapshot, opaque_id: &str, time: u64,
) -> Result<Genesis, VaultError> {
    let name = format!("snap_{opaque_id}");
    if !valid_snapshot_id(&name) { return Err(VaultError::InvalidFormat("invalid snapshot name".into())); }
    let mut head = VaultHead::from_bytes(local_head)?;
    if head.vault_id != local.vault_id { return Err(VaultError::CryptoAuthFailed); }
    let mut snapshot = local;
    snapshot.snapshot_epoch = 1;
    snapshot.hlc_timestamp = snapshot.hlc_timestamp.max(time);
    snapshot.snapshot_id = name.clone();
    snapshot.included_wal_ids.clear();
    let snap = seal_snapshot(keys, &mut snapshot)?;
    let root = snapshot.state_mac;
    head.update_pointer(keys, &HeadEncryptedPointer { latest_snapshot_id: name.clone(), recent_snapshot_ids: vec![name],
        snapshot_epoch: snapshot.snapshot_epoch, state_root_mac: root, updated_at_ms: time })?;
    let head = remote_wire(&head.to_bytes()?, keys);
    Ok(Genesis { head, snap, root })
}

#[wasm_bindgen]
pub fn wasm_sync_create_genesis(
    session_key: Vec<u8>, wrap: Vec<u8>, local_head: &[u8], local_snap: &[u8], id: &str, device: Option<String>,
) -> Result<Genesis, JsValue> {
    let (session_key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault_id, epoch, keys) = super::keys(&session_key, &wrap)?;
    let mut snapshot = super::verified_snapshot(&keys, &vault_id, epoch, local_head, local_snap)?;
    if let Some(device) = device {
        if !crate::journal::valid_device(&device) { return Err(batch::invalid().into()); }
        let mut provenance = crate::device::Provenance::read(&snapshot.sync_provenance)?;
        for item in &snapshot.items { provenance.writers.entry(item.id.clone()).or_insert_with(|| device.clone()); }
        provenance.store(&mut snapshot);
    }
    let time = crate::journal::time_of_id(id)?;
    create_genesis(&keys, local_head, snapshot, id, time).map_err(Into::into)
}

#[wasm_bindgen]
pub fn wasm_sync_verify_snapshot(
    session_key: Vec<u8>, wrap: Vec<u8>, local_head: &[u8], snap: &[u8],
) -> Result<u32, JsValue> {
    let (session_key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault_id, epoch, keys) = super::keys(&session_key, &wrap)?;
    let snapshot = super::verified_snapshot(&keys, &vault_id, epoch, local_head, snap)?;
    Ok(snapshot.items.iter().filter(|item| !item.trashed).count() as u32)
}

// Loading a prospective history object must not silently coerce it into the active snapshot.
pub(crate) fn verify_named_snapshot(keys: &VaultKeyHierarchy, vault: &str, id: &str, bytes: &[u8]) -> Result<VaultSnapshot, VaultError> {
    if !valid_snapshot_id(id) { return Err(VaultError::CryptoAuthFailed); }
    let snapshot = open_snapshot(keys, Some(id), bytes)?;
    if snapshot.vault_id != vault || snapshot.snapshot_id != id { return Err(VaultError::CryptoAuthFailed); }
    batch::check_snapshot(keys, &snapshot)?;
    Ok(snapshot)
}

#[wasm_bindgen]
pub struct Replayed {
    head: Vec<u8>,
    snap: Vec<u8>,
    included: Vec<String>,
    hlc: u64,
    count: u32,
    conflicts: Vec<u8>,
    conflict_count: u32,
    draft_count: u32,
    receipts: Vec<u8>,
    compacted: Vec<String>,
}

impl Replayed {
    pub(crate) fn set_conflicts(&mut self, staged: &crate::conflict::Staged, keys: &VaultKeyHierarchy, vault: &str) -> Result<(), VaultError> {
        self.conflicts = staged.seal(keys, vault)?;
        self.conflict_count = staged.rows.len() as u32;
        self.draft_count = staged.draft_count() as u32;
        Ok(())
    }
    pub(crate) fn set_receipts(&mut self, bytes: Vec<u8>) { self.receipts = bytes; }
}

#[wasm_bindgen]
impl Replayed {
    #[wasm_bindgen(getter)]
    pub fn head(&self) -> Vec<u8> { self.head.clone() }
    #[wasm_bindgen(getter)]
    pub fn snap(&self) -> Vec<u8> { self.snap.clone() }
    #[wasm_bindgen(getter)]
    pub fn included(&self) -> String { self.included.join("\n") }
    #[wasm_bindgen(getter)]
    pub fn hlc(&self) -> f64 { self.hlc as f64 }
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> u32 { self.count }
    #[wasm_bindgen(getter)]
    pub fn conflicts(&self) -> Vec<u8> { self.conflicts.clone() }
    #[wasm_bindgen(getter)]
    pub fn conflict_count(&self) -> u32 { self.conflict_count }
    #[wasm_bindgen(getter)]
    pub fn draft_count(&self) -> u32 { self.draft_count }
    #[wasm_bindgen(getter)]
    pub fn receipts(&self) -> Vec<u8> { self.receipts.clone() }
    #[wasm_bindgen(getter)]
    pub fn compacted(&self) -> String { self.compacted.join("\n") }
}

pub(crate) fn materialize(keys: &VaultKeyHierarchy, template: &[u8], mut snapshot: VaultSnapshot) -> Result<Replayed, VaultError> {
    if snapshot.hlc_timestamp > MAX_SAFE_EPOCH { return Err(batch::invalid()); }
    let mut head = VaultHead::from_bytes(template)?;
    let old = head.decrypt_pointer(keys)?;
    let snap = seal_snapshot(keys, &mut snapshot)?;
    head.update_pointer(keys, &HeadEncryptedPointer { latest_snapshot_id: snapshot.snapshot_id.clone(),
        recent_snapshot_ids: old.recent_snapshot_ids, snapshot_epoch: snapshot.snapshot_epoch, state_root_mac: snapshot.state_mac,
        updated_at_ms: snapshot.hlc_timestamp })?;
    Ok(Replayed { head: head.to_bytes()?, snap, included: snapshot.included_wal_ids.clone(), hlc: snapshot.hlc_timestamp, conflicts: Vec::new(), conflict_count: 0, draft_count: 0, receipts: Vec::new(), compacted: Vec::new(),
        count: snapshot.items.iter().filter(|item| !item.trashed).count() as u32 })
}

#[wasm_bindgen]
pub fn wasm_sync_replay(
    session_key: Vec<u8>, wrap: Vec<u8>, remote_head: &[u8], base: &[u8], frames: &[u8], histories: &[u8],
) -> Result<Replayed, JsValue> {
    let (session_key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&session_key, &wrap)?;
    let mut snap = super::verified_snapshot(&keys, &vault, epoch, remote_head, base)?;
    batch::check_snapshot(&keys, &snap)?;
    let pointer = VaultHead::from_bytes(remote_head)?.decrypt_pointer(&keys)?;
    let mut ancestors = Vec::new();
    for (id, bytes) in batch::frames(histories)? {
        let name = format!("snap_{id}");
        if !pointer.recent_snapshot_ids.iter().skip(1).any(|id| id == &name) { return Err(batch::invalid().into()); }
        let old = verify_named_snapshot(&keys, &vault, &name, bytes)?;
        if old.snapshot_epoch >= snap.snapshot_epoch { return Err(batch::invalid().into()); }
        ancestors.push((old.snapshot_epoch, old.state_mac));
    }
    let (applied, staged) = batch::replay(&keys, &snap, frames, &ancestors)?;
    let mut result = materialize(&keys, remote_head, applied)?;
    result.compacted = std::mem::take(&mut snap.included_wal_ids);
    result.set_conflicts(&staged, &keys, &vault)?;
    result.set_receipts(staged.rows.iter().filter_map(|row| row.receipt).flatten().collect());
    Ok(result)
}

#[wasm_bindgen]
pub fn wasm_sync_make_batch(
    session_key: Vec<u8>, wrap: Vec<u8>, remote_head: &[u8], base: &[u8], before_head: &[u8], before: &[u8],
    after_head: &[u8], after: &[u8], id: &str, device: &str, receipts: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let (session_key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&session_key, &wrap)?;
    let base = super::verified_snapshot(&keys, &vault, epoch, remote_head, base)?;
    let before = super::verified_snapshot(&keys, &vault, epoch, before_head, before)?;
    let after = super::verified_snapshot(&keys, &vault, epoch, after_head, after)?;
    batch::seal_batch(&keys, id, device, &base, &before, &after, receipts.as_deref().unwrap_or_default()).map_err(Into::into)
}

fn next_remote_snapshot(
    keys: &VaultKeyHierarchy, mut head: VaultHead, old: HeadEncryptedPointer, mut current: VaultSnapshot, id: &str,
) -> Result<Genesis, VaultError> {
    let time = crate::journal::time_of_id(id)?;
    if old.snapshot_epoch >= MAX_SAFE_EPOCH || current.vault_id != head.vault_id || current.snapshot_epoch != old.snapshot_epoch {
        return Err(batch::invalid());
    }
    let name = format!("snap_{id}");
    if old.recent_snapshot_ids.contains(&name) || time < current.hlc_timestamp { return Err(batch::invalid()); }
    current.snapshot_id = name.clone();
    current.snapshot_epoch = old.snapshot_epoch + 1;
    current.hlc_timestamp = time;
    let snap = seal_snapshot(keys, &mut current)?;
    let root = current.state_mac;
    let recent_snapshot_ids = std::iter::once(name.clone()).chain(old.recent_snapshot_ids.into_iter().take(4)).collect();
    head.update_pointer(keys, &HeadEncryptedPointer { latest_snapshot_id: name, recent_snapshot_ids,
        snapshot_epoch: current.snapshot_epoch, state_root_mac: root, updated_at_ms: time })?;
    let head = remote_wire(&head.to_bytes()?, keys);
    Ok(Genesis { head, snap, root })
}

#[wasm_bindgen]
pub fn wasm_sync_compact(
    session_key: Vec<u8>, wrap: Vec<u8>, wire: &[u8], current_head: &[u8], current: &[u8], id: &str,
    purge_before_ms: Option<f64>,
) -> Result<Genesis, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let (_, head) = remote_core(wire)?;
    if head.vault_id != vault || head.key_epoch != epoch { return Err(batch::invalid().into()); }
    let old = verify_wire(wire, &head, &keys)?;
    let mut current = super::verified_snapshot(&keys, &vault, epoch, current_head, current)?;
    if let Some(time) = purge_before_ms.filter(|time| time.is_finite() && *time > 0.0) {
        let cutoff = time as u64;
        current.items.retain(|item| !item.trashed || !item.trashed_at_ms.is_some_and(|deleted| deleted > 0 && deleted <= cutoff));
    }
    crate::device::Provenance::read(&current.sync_provenance)?.store(&mut current);
    next_remote_snapshot(&keys, head, old, current, id).map_err(Into::into)
}

fn restore_counters(current: &VaultSnapshot, restored: &mut VaultSnapshot, pack: bool) -> Result<(), VaultError> {
    use std::collections::BTreeMap;
    let passkeys = vault_passkeys::bundle::CounterEvidence::from_items(&current.items).map_err(|_| batch::invalid())?;
    let mut trusted = BTreeMap::<_, u64>::new();
    for item in &current.items {
        let CredentialData::Login(login) = &item.data else { continue; };
        let Some(otp) = login.totp_uri.as_deref().and_then(|uri| vault_otp::parse(uri).ok()) else { continue; };
        if otp.kind == vault_otp::Kind::Hotp && !otp.counter_unverified {
            trusted.entry(otp.identity()).and_modify(|n| *n = (*n).max(otp.counter)).or_insert(otp.counter);
        }
    }
    for item in &mut restored.items {
        let CredentialData::Login(login) = &mut item.data else { continue; };
        let retained = passkeys.restore(&login.passkey_data, pack && !item.trashed).map_err(|_| batch::invalid())?;
        drop(Zeroizing::new(std::mem::replace(&mut login.passkey_data, retained)));
        let Some(mut otp) = login.totp_uri.as_deref().and_then(|uri| vault_otp::parse(uri).ok()) else { continue; };
        if otp.kind != vault_otp::Kind::Hotp { continue; }
        if let Some(trusted) = trusted.get(&otp.identity()) {
            otp.counter = if otp.counter_unverified { *trusted } else { otp.counter.max(*trusted) };
            otp.counter_unverified = false;
        } else { otp.counter_unverified = true; }
        drop(Zeroizing::new(login.totp_uri.replace(otp.canonical_uri().to_string())));
    }
    if !pack {
        use crate::merge::CounterLedger;
        let history = CounterLedger::collect(restored.items.iter())?;
        let current = CounterLedger::collect_scoped(current.items.iter(), Some(&history), true)?;
        history.apply(&mut restored.items, Some(&current))?;
    }
    Ok(())
}

#[wasm_bindgen]
pub fn wasm_sync_restore_content(
    session_key: Vec<u8>, wrap: Vec<u8>, wire: &[u8], current_head: &[u8], current: &[u8], history_id: &str, history: &[u8],
) -> Result<Replayed, JsValue> {
    let (key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let (_, head) = remote_core(wire)?;
    if head.vault_id != vault || head.key_epoch != epoch { return Err(batch::invalid().into()); }
    let pointer = verify_wire(wire, &head, &keys)?;
    if !pointer.recent_snapshot_ids.contains(&history_id.to_string()) { return Err(batch::invalid().into()); }
    let mut current = super::verified_snapshot(&keys, &vault, epoch, current_head, current)?;
    let mut restored = verify_named_snapshot(&keys, &vault, history_id, history)?;
    if restored.snapshot_epoch > current.snapshot_epoch { return Err(batch::invalid().into()); }
    restore_counters(&current, &mut restored, false)?;
    std::mem::swap(&mut current.items, &mut restored.items);
    let mut provenance = crate::device::Provenance::read(&restored.sync_provenance)?;
    provenance.last_edits = crate::device::Provenance::read(&current.sync_provenance)?.last_edits;
    provenance.store(&mut current);
    materialize(&keys, current_head, current).map_err(Into::into)
}

#[wasm_bindgen]
pub struct PackImport {
    head: Vec<u8>,
    snap: Vec<u8>,
    added: u32,
    updated: u32,
    skipped: u32,
}

#[wasm_bindgen]
impl PackImport {
    #[wasm_bindgen(getter)]
    pub fn head(&self) -> Vec<u8> { self.head.clone() }
    #[wasm_bindgen(getter)]
    pub fn snap(&self) -> Vec<u8> { self.snap.clone() }
    #[wasm_bindgen(getter)]
    pub fn added(&self) -> u32 { self.added }
    #[wasm_bindgen(getter)]
    pub fn updated(&self) -> u32 { self.updated }
    #[wasm_bindgen(getter)]
    pub fn skipped(&self) -> u32 { self.skipped }
}

fn merge_pack(current: &mut VaultSnapshot, mut incoming: VaultSnapshot, now: u64) -> Result<PackImport, VaultError> {
    use crate::merge::CounterLedger;
    restore_counters(current, &mut incoming, true)?;
    // Preserve the original live owner, including when an imported row has a different item ID.
    let live_ids: std::collections::BTreeSet<_> = current.items.iter().filter(|item| !item.trashed).map(|item| item.id.as_str()).collect();
    let source = CounterLedger::collect(incoming.items.iter().filter(|item| !item.trashed || live_ids.contains(item.id.as_str())))?;
    let ledger = CounterLedger::collect_scoped(current.items.iter().chain(&incoming.items), Some(&source), false)?;
    let before: Vec<_> = current.items.iter().map(|item| match &item.data {
        CredentialData::Login(login) => Some((Zeroizing::new(login.totp_uri.clone()), Zeroizing::new(login.passkey_data.clone()))),
        _ => None,
    }).collect();
    let mut matched = std::collections::BTreeSet::new();
    let mut result = PackImport { head: Vec::new(), snap: Vec::new(), added: 0, updated: 0, skipped: 0 };
    for mut row in std::mem::take(&mut incoming.items) {
        row.normalize_derived_fields();
        if let Some((index, existing)) = current.items.iter_mut().enumerate().find(|(_, item)| !row.id.is_empty() && item.id == row.id) {
            matched.insert(index);
            if !existing.trashed && let (CredentialData::Login(old), CredentialData::Login(new)) = (&mut existing.data, &row.data) {
                if old.totp_uri != new.totp_uri
                    && let Some(uri) = crate::merge::highest_hotp(old.totp_uri.as_deref(), new.totp_uri.as_deref())
                    && old.totp_uri.as_deref() != Some(uri.as_str())
                {
                    drop(Zeroizing::new(old.totp_uri.replace(uri)));
                }
                if !row.trashed && !new.passkey_data.is_empty() {
                    let merged = Zeroizing::new(vault_passkeys::bundle::merge(&old.passkey_data, [new.passkey_data.as_slice()])
                        .map_err(|_| batch::invalid())?);
                    if old.passkey_data.as_slice() != merged.as_slice() {
                        drop(Zeroizing::new(std::mem::replace(&mut old.passkey_data, merged.to_vec())));
                    }
                }
            }
        } else if row.trashed {
            result.skipped += 1;
        } else {
            if row.id.trim_ascii().is_empty() { row.id = generate_uuid_v4()?; }
            current.items.push(row);
            result.added += 1;
        }
    }
    ledger.apply(&mut current.items, Some(&ledger))?;
    // Count only the final change; re-importing a paused duplicate does not create a write.
    for (index, (before, item)) in before.into_iter().zip(&mut current.items).enumerate() {
        let changed = match (before, &item.data) {
            (Some((otp, keys)), CredentialData::Login(login)) => *otp != login.totp_uri || *keys != login.passkey_data,
            _ => false,
        };
        if changed {
            item.updated_at_ms = item.updated_at_ms.max(now);
            item.revision = item.revision.saturating_add(1);
            result.updated += 1;
        } else if matched.contains(&index) { result.skipped += 1; }
    }
    Ok(result)
}

#[wasm_bindgen]
pub fn wasm_sync_import_pack(
    session_key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], pack: Vec<u8>, password: String, now: f64, confirm: bool,
) -> Result<PackImport, JsValue> {
    let (session_key, wrap, pack, password) = (Zeroizing::new(session_key), Zeroizing::new(wrap), Zeroizing::new(pack), Zeroizing::new(password));
    let (id, epoch, keys) = super::keys(&session_key, &wrap)?;
    let mut current = super::verified_snapshot(&keys, &id, epoch, head, snap)?;
    let incoming = vault_core::sync_codec::import_vaultpack(&pack, password.as_bytes())?;
    let mut result = merge_pack(&mut current, incoming, now as u64)?;
    if confirm && result.added + result.updated > 0 {
        current.hlc_timestamp = current.hlc_timestamp.max(now as u64).saturating_add(1);
        let output = materialize(&keys, head, current)?;
        result.head = output.head;
        result.snap = output.snap;
    }
    Ok(result)
}

#[wasm_bindgen]
pub fn wasm_sync_history_metadata(
    session_key: Vec<u8>, wrap: Vec<u8>, id: &str, snap: &[u8],
) -> Result<Vec<u32>, JsValue> {
    let (session_key, wrap) = (Zeroizing::new(session_key), Zeroizing::new(wrap));
    let (vault, _, keys) = super::keys(&session_key, &wrap)?;
    let history = verify_named_snapshot(&keys, &vault, id, snap)?;
    Ok(vec![history.snapshot_epoch.try_into().map_err(|_| VaultError::CryptoAuthFailed)?,
        history.items.iter().filter(|item| !item.trashed).count() as u32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::crypto::KdfParams;
    use vault_core::session::initialize_new_vault;
    #[test]
    fn second_install_adopts_original_identity_using_master_or_recovery() {
        let master = b"test-only-original-master";
        let session_key = [8; 32];
        let params = KdfParams { m_cost_kib: 32768, t_cost: 2, p_cost: 1, salt: [68; 32] };
        let (h, s, recovery, wrap, vault, epoch) = initialize_new_vault(master, params, &session_key, 1500).unwrap();
        let (_, _, keys) = super::super::keys(&session_key, &wrap).unwrap();
        let snap = super::super::verified_snapshot(&keys, &vault, epoch, &h, &s).unwrap();
        let mut genesis = create_genesis(&keys, &h, snap, "00000000001000_09abcd11_00000000000001", 1500).unwrap();
        assert!(unlock_remote(&genesis.head, &[3; 32], b"independent-file-password", false).is_err());
        let master_opened = unlock_remote(&genesis.head, &[3; 32], master, false).unwrap();
        let recovery_opened = unlock_remote(&genesis.head, &[5; 32], recovery.as_bytes(), true).unwrap();
        assert_eq!(master_opened.vault_id, vault);
        assert_eq!(recovery_opened.local_head, master_opened.local_head);
        let (_, e, second_keys) = super::super::keys(&[5; 32], &recovery_opened.session_wrap).unwrap();
        assert_eq!(e, epoch);
        assert!(super::super::verified_snapshot(&second_keys, &vault, e, &recovery_opened.local_head, &genesis.snap).is_ok());
        assert!(super::super::verified_snapshot(&second_keys, &vault, e, &recovery_opened.local_head, &s).is_err());
        *genesis.head.last_mut().unwrap() ^= 1;
        assert!(unlock_remote(&genesis.head, &[3; 32], master, false).is_err());
    }

    #[test]
    fn compaction_purges_only_expired_trash_and_preserves_authenticated_history() {
        use vault_core::model::VaultItem;
        let key = [9; 32];
        let now = 1_700_000_000_000u64;
        let cutoff = now - 30 * 24 * 60 * 60 * 1000;
        let params = KdfParams { m_cost_kib: 32768, t_cost: 2, p_cost: 1, salt: [69; 32] };
        let (head, snap, _, wrap, vault, epoch) = initialize_new_vault(b"test-only-master", params, &key, now).unwrap();
        let (_, _, keys) = super::super::keys(&key, &wrap).unwrap();
        let mut snap = super::super::verified_snapshot(&keys, &vault, epoch, &head, &snap).unwrap();
        let make = |id: &str, trashed: bool, deleted: u64| {
            VaultItem::from_json_str(&format!(
                r#"{{"id":"{id}","title":"Fixture","trashed":{trashed},"trashedAtMs":{deleted},"data":{{"kind":"login"}}}}"#
            )).unwrap()
        };
        snap.items = vec![make("expired", true, cutoff), make("recent", true, cutoff + 1), make("active", false, 0)];
        let old_id = format!("{now:014x}_09abcd11_00000000000001");
        let old_name = format!("snap_{old_id}");
        let old = create_genesis(&keys, &head, snap, &old_id, now).unwrap();
        let old_head = remote_core(&old.head).unwrap().0;
        let next_time = now + 1;
        let id = format!("{next_time:014x}_09abcd11_00000000000002");
        let next = wasm_sync_compact(key.to_vec(), wrap.clone(), &old.head, old_head, &old.snap, &id, Some(cutoff as f64)).unwrap();
        let (core, header) = remote_core(&next.head).unwrap();
        let pointer = verify_wire(&next.head, &header, &keys).unwrap();
        assert_eq!(pointer.recent_snapshot_ids, [format!("snap_{id}"), old_name.clone()]);
        let historic = verify_named_snapshot(&keys, &vault, &old_name, &old.snap).unwrap();
        assert!(historic.items.iter().any(|item| item.id == "expired" && item.trashed));
        let current = super::super::verified_snapshot(&keys, &vault, epoch, core, &next.snap).unwrap();
        assert!(!current.items.iter().any(|item| item.id == "expired"));
        assert!(current.items.iter().any(|item| item.id == "recent" && item.trashed));
        assert!(current.items.iter().any(|item| item.id == "active" && !item.trashed));
    }

    #[test]
    fn restore_uses_highest_counter_or_marks_the_old_token_unverified() {
        use vault_core::model::{CredentialData, VaultItem};
        let make = |counter: u64, secret: &str| {
            let mut snap = VaultSnapshot::new_empty("history".into(), "same-vault".into(), 0);
            snap.items.push(VaultItem::from_json_str(&format!(
                r#"{{"id":"old-id","title":"Fixture","data":{{"kind":"login","totpUri":"otpauth://hotp/Fixture?secret={secret}&counter={counter}"}}}}"#
            )).unwrap());
            snap
        };
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let mut yesterday = make(3, secret);
        restore_counters(&make(49, secret), &mut yesterday, false).unwrap();
        let CredentialData::Login(row) = &yesterday.items[0].data else { panic!() };
        let otp = vault_otp::parse(row.totp_uri.as_deref().unwrap()).unwrap();
        assert_eq!(otp.counter, 49);
        assert!(!otp.counter_unverified);
        let mut suspended = make(90, secret);
        let CredentialData::Login(login) = &mut suspended.items[0].data else { panic!() };
        login.totp_uri.as_mut().unwrap().push_str("&vaultCounterUnverified=1");
        restore_counters(&make(49, secret), &mut suspended, false).unwrap();
        let CredentialData::Login(row) = &suspended.items[0].data else { panic!() };
        let otp = vault_otp::parse(row.totp_uri.as_deref().unwrap()).unwrap();
        assert_eq!((otp.counter, otp.counter_unverified), (49, false));
        let mut old_only = make(2, secret);
        restore_counters(&make(500, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJR"), &mut old_only, false).unwrap();
        let CredentialData::Login(row) = &old_only.items[0].data else { panic!() };
        assert!(vault_otp::parse(row.totp_uri.as_deref().unwrap()).unwrap().counter_unverified);
    }

    #[test]
    fn pack_preserves_local_fields_but_uses_highest_known_hotp_even_from_an_older_edit() {
        use vault_core::model::VaultItem;
        let make = |password: &str, updated_at: u64, counter: u64| {
            let mut snap = VaultSnapshot::new_empty("vault".into(), "snap".into(), updated_at);
            snap.items.push(VaultItem::from_json_str(&format!(
                r#"{{"id":"shared","updatedAtMs":{updated_at},"data":{{"kind":"login","password":"{password}","totpUri":"otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter={counter}"}}}}"#
            )).unwrap());
            snap
        };
        let mut local = make("local-only", 500, 4);
        let result = merge_pack(&mut local, make("older-password", 200, 21), 600).unwrap();
        assert_eq!((result.added, result.updated, result.skipped), (0, 1, 0));
        let CredentialData::Login(login) = &local.items[0].data else { panic!() };
        assert_eq!(login.password, "local-only");
        let otp = vault_otp::parse(login.totp_uri.as_deref().unwrap()).unwrap();
        assert_eq!((otp.counter, otp.counter_unverified), (21, false));
        let repeated = merge_pack(&mut local, make("older-password", 200, 21), 700).unwrap();
        assert_eq!((repeated.updated, repeated.skipped), (0, 1));
    }

    #[test]
    fn recovery_preserves_one_active_copy_of_each_incrementing_credential() {
        use vault_core::model::VaultItem;
        use vault_passkeys::{Passkey, bundle};
        let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        der.extend_from_slice(&[17; 32]);
        let row = |id: &str, count: u32, paused: bool, trashed: bool| {
            let suffix = if paused { "&vaultCounterUnverified=1" } else { "" };
            let mut item = VaultItem::from_json_str(&format!(
                r#"{{"id":"{id}","trashed":{trashed},"title":"Fixture","data":{{"kind":"login","totpUri":"otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter={count}{suffix}"}}}}"#
            )).unwrap();
            let CredentialData::Login(login) = &mut item.data else { panic!() };
            let mut key = Passkey::from_pkcs8(vec![3; 32], "example.com".into(), vec![5], "fixture".into(), &der, true, true, Some(count)).unwrap();
            key.count_unverified = paused;
            login.passkey_data = bundle::write(&[key]).unwrap();
            item
        };
        let make = |items: Vec<VaultItem>| {
            let mut snap = VaultSnapshot::new_empty("vault".into(), "snapshot".into(), 0);
            snap.items = items;
            snap
        };
        let local = make(vec![row("live", 49, false, false)]);
        let backup = || make(vec![row("trash", 52, false, true), row("duplicate", u32::MAX, true, false), row("live", 51, false, false)]);
        let check = |snap: &VaultSnapshot, max: u32| {
            for item in &snap.items {
                let CredentialData::Login(login) = &item.data else { panic!() };
                let token = vault_otp::parse(login.totp_uri.as_deref().unwrap()).unwrap();
                let key = bundle::read(&login.passkey_data).unwrap().pop().unwrap();
                let paused = item.id != "live";
                assert_eq!((token.counter, token.counter_unverified), (u64::from(max), paused), "{}", item.id);
                assert_eq!((key.count, key.count_unverified), (max, paused), "{}", item.id);
            }
        };
        let mut restored = backup();
        restore_counters(&local, &mut restored, false).unwrap();
        check(&restored, 52);
        let mut merged = local;
        let imported = merge_pack(&mut merged, backup(), 100).unwrap();
        check(&merged, 52);
        assert_eq!((imported.added, imported.updated), (1, 1));
        let repeated = merge_pack(&mut merged, backup(), 200).unwrap();
        assert_eq!((repeated.added, repeated.updated), (0, 0));

        let mut unrelated = make(vec![row("live", 49, false, false), row("duplicate", u32::MAX, true, false)]);
        let CredentialData::Login(variant) = &mut unrelated.items[1].data else { panic!() };
        let mut variant_keys = bundle::read(&variant.passkey_data).unwrap();
        variant_keys[0].eligible = false;
        variant.passkey_data = bundle::write(&variant_keys).unwrap();
        let before = unrelated.items.clone();
        let unchanged = merge_pack(&mut unrelated, make(vec![]), 100).unwrap();
        assert_eq!((unchanged.added, unchanged.updated), (0, 0));
        assert_eq!(unrelated.items, before);

        for item in &mut unrelated.items { item.trashed = true; }
        let mut empty = make(vec![]);
        let skipped = merge_pack(&mut empty, unrelated, 100).unwrap();
        assert_eq!((skipped.added, skipped.updated, skipped.skipped), (0, 0, 2));
    }
}
