use crate::crypto::{
    derive_pin_kek, derive_prf_kek, FileRole, KdfParams, SecretKey, VaultKeyHierarchy, WrappedKey,
    DEFAULT_P_COST, MIN_M_COST_KIB,
};
use crate::error::VaultError;
use crate::json_lite::{compact_sort_by, concat2, concat3, encode_hex_lower};
use crate::model::{generate_uuid_v4, VaultItem, VaultItemSummary, VaultSnapshot};
use crate::sync_codec::{open_snapshot, seal_snapshot, HeadEncryptedPointer, VaultHead};

/// Local device PIN wrapper persisted in `chrome.storage.local` (never synced to WebDAV).
pub struct PinWrappedDekBlob;

fn encode_wrap_header(
    tag_byte: u8,
    vault_id: &str,
    key_epoch: u64,
    extra: &[u8],
    wk: &WrappedKey,
) -> Result<Vec<u8>, VaultError> {
    let vid = vault_id.as_bytes();
    if vid.len() > u16::MAX as usize {
        return Err(VaultError::InvalidInput("vault_id too long".into()));
    }
    let mut out = Vec::with_capacity(1 + 2 + vid.len() + 8 + extra.len() + 72);
    out.push(tag_byte);
    out.extend_from_slice(&(vid.len() as u16).to_le_bytes());
    out.extend_from_slice(vid);
    out.extend_from_slice(&key_epoch.to_le_bytes());
    out.extend_from_slice(extra);
    out.extend_from_slice(&wk.nonce);
    out.extend_from_slice(&wk.tag);
    out.extend_from_slice(&wk.ciphertext);
    Ok(out)
}

fn copy_exact<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&slice[..N]);
    out
}

fn decode_wrap_header(
    raw: &[u8],
    expected_tag: u8,
    extra_len: usize,
) -> Result<(String, u64, Vec<u8>, WrappedKey), VaultError> {
    if raw.len() < 1 + 2 + 8 + extra_len + 72 || raw[0] != expected_tag {
        return Err(VaultError::InvalidFormat("invalid wrapped key blob".into()));
    }
    let vid_len = u16::from_le_bytes([raw[1], raw[2]]) as usize;
    let needed = 3 + vid_len + 8 + extra_len + 72;
    if raw.len() != needed {
        return Err(VaultError::InvalidFormat("wrapped key blob length mismatch".into()));
    }
    let mut pos = 3;
    let vault_id = std::str::from_utf8(&raw[pos..pos + vid_len])
        .map_err(|_| VaultError::InvalidFormat("invalid utf8 in wrapped key".into()))?
        .to_string();
    pos += vid_len;
    let key_epoch = u64::from_le_bytes(copy_exact::<8>(&raw[pos..pos + 8]));
    pos += 8;
    let extra = raw[pos..pos + extra_len].to_vec();
    pos += extra_len;
    let wk = WrappedKey {
        nonce: copy_exact::<24>(&raw[pos..pos + 24]),
        tag: copy_exact::<16>(&raw[pos + 24..pos + 40]),
        ciphertext: copy_exact::<32>(&raw[pos + 40..pos + 72]),
    };
    Ok((vault_id, key_epoch, extra, wk))
}

impl PinWrappedDekBlob {
    pub fn create(
        vault_id: &str,
        key_epoch: u64,
        master_dek: &SecretKey,
        pin: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let mut salt = [0u8; 32];
        crate::crypto::csprng_fill(&mut salt)?;
        let params = KdfParams {
            m_cost_kib: MIN_M_COST_KIB, // 32 MiB Argon2id for fast local PIN unlock
            t_cost: 2,
            p_cost: DEFAULT_P_COST,
            salt,
        };
        let pin_kek = derive_pin_kek(pin, &params)?;
        let wrapped_dek = WrappedKey::wrap(
            &pin_kek,
            master_dek,
            FileRole::PinWrap,
            &concat2(vault_id, ":pin"),
            key_epoch,
        )?;
        let mut extra = Vec::with_capacity(44);
        extra.extend_from_slice(&params.m_cost_kib.to_le_bytes());
        extra.extend_from_slice(&params.t_cost.to_le_bytes());
        extra.extend_from_slice(&params.p_cost.to_le_bytes());
        extra.extend_from_slice(&params.salt);
        encode_wrap_header(0xA1, vault_id, key_epoch, &extra, &wrapped_dek)
    }

    pub fn unwrap_dek(raw: &[u8], pin: &[u8]) -> Result<(String, u64, SecretKey), VaultError> {
        let (vault_id, key_epoch, extra, wrapped_dek) = decode_wrap_header(raw, 0xA1, 44)?;
        let params = KdfParams {
            m_cost_kib: u32::from_le_bytes(copy_exact::<4>(&extra[0..4])),
            t_cost: u32::from_le_bytes(copy_exact::<4>(&extra[4..8])),
            p_cost: u32::from_le_bytes(copy_exact::<4>(&extra[8..12])),
            salt: copy_exact::<32>(&extra[12..44]),
        };
        let pin_kek = derive_pin_kek(pin, &params)?;
        let dek = wrapped_dek.unwrap(
            &pin_kek,
            FileRole::PinWrap,
            &concat2(&vault_id, ":pin"),
            key_epoch,
        )?;
        Ok((vault_id, key_epoch, dek))
    }
}

/// Local device WebAuthn PRF (Windows Hello) wrapper persisted in `chrome.storage.local`.
pub struct PrfWrappedDekBlob;

impl PrfWrappedDekBlob {
    pub fn create(
        vault_id: &str,
        key_epoch: u64,
        master_dek: &SecretKey,
        prf_output_32b: &[u8],
        prf_salt: &[u8; 32],
    ) -> Result<Vec<u8>, VaultError> {
        let prf_kek = derive_prf_kek(prf_output_32b, prf_salt)?;
        let wrapped_dek = WrappedKey::wrap(
            &prf_kek,
            master_dek,
            FileRole::PrfWrap,
            &concat2(vault_id, ":prf"),
            key_epoch,
        )?;
        encode_wrap_header(0xA2, vault_id, key_epoch, prf_salt, &wrapped_dek)
    }

    pub fn unwrap_dek(
        raw: &[u8],
        prf_output_32b: &[u8],
    ) -> Result<(String, u64, SecretKey), VaultError> {
        let (vault_id, key_epoch, extra, wrapped_dek) = decode_wrap_header(raw, 0xA2, 32)?;
        let prf_salt = copy_exact::<32>(&extra);
        let prf_kek = derive_prf_kek(prf_output_32b, &prf_salt)?;
        let dek = wrapped_dek.unwrap(
            &prf_kek,
            FileRole::PrfWrap,
            &concat2(&vault_id, ":prf"),
            key_epoch,
        )?;
        Ok((vault_id, key_epoch, dek))
    }
}

/// Ephemeral RAM-only session wrapper persisted in `chrome.storage.session` for `< 5ms` MV3 SW wake-up.
pub struct SessionWrappedDekBlob;

impl SessionWrappedDekBlob {
    pub fn wrap(
        vault_id: &str,
        key_epoch: u64,
        master_dek: &SecretKey,
        session_key: &SecretKey,
    ) -> Result<Vec<u8>, VaultError> {
        let wrapped_dek = WrappedKey::wrap(
            session_key,
            master_dek,
            FileRole::SessionWrap,
            &concat2(vault_id, ":session"),
            key_epoch,
        )?;
        encode_wrap_header(0xA3, vault_id, key_epoch, &[], &wrapped_dek)
    }

    pub fn unwrap(
        raw: &[u8],
        session_key: &SecretKey,
    ) -> Result<(String, u64, SecretKey), VaultError> {
        let (vault_id, key_epoch, _extra, wrapped_dek) = decode_wrap_header(raw, 0xA3, 0)?;
        let dek = wrapped_dek.unwrap(
            session_key,
            FileRole::SessionWrap,
            &concat2(&vault_id, ":session"),
            key_epoch,
        )?;
        Ok((vault_id, key_epoch, dek))
    }
}

struct UnlockedState {
    head: VaultHead,
    keys: VaultKeyHierarchy,
    snapshot: VaultSnapshot,
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        self.snapshot.zeroize_all();
    }
}

/// Stateful in-memory vault session inside WASM linear memory.
#[derive(Default)]
pub struct VaultSession {
    state: Option<UnlockedState>,
}

impl VaultSession {
    pub fn new() -> Self {
        Self { state: None }
    }

    pub fn is_unlocked(&self) -> bool {
        self.state.is_some()
    }

    pub fn lock_and_zeroize(&mut self) {
        if let Some(mut st) = self.state.take() {
            st.snapshot.zeroize_all();
        }
    }

    pub fn restore_from_session_wrap(
        &mut self,
        session_key_bytes: &[u8],
        session_wrap_bytes: &[u8],
        head_bytes: &[u8],
        snap_bytes: &[u8],
    ) -> Result<(), VaultError> {
        let session_key = SecretKey::from_slice(session_key_bytes)?;
        let (vault_id, wrapped_epoch, dek) =
            SessionWrappedDekBlob::unwrap(session_wrap_bytes, &session_key)?;
        let head = VaultHead::from_bytes(head_bytes)?;
        if head.vault_id != vault_id || head.key_epoch != wrapped_epoch {
            return Err(VaultError::CryptoAuthFailed);
        }
        let keys = VaultKeyHierarchy::from_master_dek(dek)?;
        let pointer = head.decrypt_pointer(&keys)?;
        let mut snapshot = open_snapshot(&keys, Some(&pointer.latest_snapshot_id), snap_bytes)?;
        if snapshot.vault_id != head.vault_id
            || snapshot.snapshot_id != pointer.latest_snapshot_id
            || snapshot.snapshot_epoch != pointer.snapshot_epoch
            || snapshot.state_mac != pointer.state_root_mac
        {
            snapshot.zeroize_all();
            return Err(VaultError::CryptoAuthFailed);
        }
        self.lock_and_zeroize();
        self.state = Some(UnlockedState {
            head,
            keys,
            snapshot,
        });
        Ok(())
    }

    pub fn vault_metadata(&self) -> Result<(String, u64, usize), VaultError> {
        let st = self.state.as_ref().ok_or(VaultError::VaultLocked)?;
        let active_count = st.snapshot.items.iter().filter(|i| !i.trashed).count();
        Ok((st.head.vault_id.clone(), st.head.key_epoch, active_count))
    }

    pub fn list_summaries(&self) -> Result<Vec<VaultItemSummary>, VaultError> {
        let st = self.state.as_ref().ok_or(VaultError::VaultLocked)?;
        let mut summaries: Vec<VaultItemSummary> =
            st.snapshot.items.iter().map(VaultItem::to_summary).collect();
        compact_sort_by(&mut summaries, |a, b| {
            b.pinned
                .cmp(&a.pinned)
                .then_with(|| b.updated_at_ms.cmp(&a.updated_at_ms))
        });
        Ok(summaries)
    }

    pub fn get_item(&self, item_id: &str, reprompt_verified: bool) -> Result<VaultItem, VaultError> {
        let st = self.state.as_ref().ok_or(VaultError::VaultLocked)?;
        let item = st
            .snapshot
            .items
            .iter()
            .find(|i| i.id == item_id)
            .ok_or_else(|| VaultError::ItemNotFound(item_id.to_string()))?;
        if item.require_reprompt && !reprompt_verified {
            return Err(VaultError::RepromptRequired);
        }
        Ok(item.clone())
    }

    pub fn upsert_item(
        &mut self,
        mut incoming: VaultItem,
        now_ms: u64,
        source_device: Option<String>,
    ) -> Result<(VaultItem, Vec<u8>, Vec<u8>), VaultError> {
        let st = self.state.as_mut().ok_or(VaultError::VaultLocked)?;
        let saved = if let Some(existing) = st
            .snapshot
            .items
            .iter_mut()
            .find(|i| !incoming.id.is_empty() && i.id == incoming.id)
        {
            existing.apply_update(incoming, now_ms, source_device);
            existing.clone()
        } else {
            if incoming.id.trim_ascii().is_empty() {
                incoming.id = generate_uuid_v4()?;
            }
            incoming.normalize_derived_fields();
            incoming.created_at_ms = now_ms;
            incoming.updated_at_ms = now_ms;
            incoming.revision = 1;
            if incoming.trashed && incoming.trashed_at_ms.is_none() {
                incoming.trashed_at_ms = Some(now_ms);
            }
            let cloned = incoming.clone();
            st.snapshot.items.push(incoming);
            cloned
        };
        let (head_bytes, snap_bytes) = Self::persist_unlocked(st, now_ms)?;
        Ok((saved, head_bytes, snap_bytes))
    }

    pub fn set_trashed(
        &mut self,
        item_id: &str,
        trashed: bool,
        now_ms: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        let st = self.state.as_mut().ok_or(VaultError::VaultLocked)?;
        let item = st
            .snapshot
            .items
            .iter_mut()
            .find(|i| i.id == item_id)
            .ok_or_else(|| VaultError::ItemNotFound(item_id.to_string()))?;
        item.trashed = trashed;
        item.trashed_at_ms = if trashed { Some(now_ms) } else { None };
        item.updated_at_ms = now_ms;
        item.revision = item.revision.saturating_add(1);
        Self::persist_unlocked(st, now_ms)
    }

    pub fn delete_permanently(
        &mut self,
        item_id: &str,
        now_ms: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        let st = self.state.as_mut().ok_or(VaultError::VaultLocked)?;
        let pos = st
            .snapshot
            .items
            .iter()
            .position(|i| i.id == item_id)
            .ok_or_else(|| VaultError::ItemNotFound(item_id.to_string()))?;
        let mut removed = st.snapshot.items.remove(pos);
        removed.zeroize_sensitive();
        Self::persist_unlocked(st, now_ms)
    }

    pub fn empty_trash(&mut self, now_ms: u64) -> Result<(usize, Vec<u8>, Vec<u8>), VaultError> {
        let st = self.state.as_mut().ok_or(VaultError::VaultLocked)?;
        let mut purged = 0usize;
        st.snapshot.items.retain_mut(|item| {
            if item.trashed {
                item.zeroize_sensitive();
                purged += 1;
                false
            } else {
                true
            }
        });
        let (head_bytes, snap_bytes) = Self::persist_unlocked(st, now_ms)?;
        Ok((purged, head_bytes, snap_bytes))
    }

    pub fn import_items_merge(
        &mut self,
        incoming_items: Vec<VaultItem>,
        now_ms: u64,
    ) -> Result<(usize, Vec<u8>, Vec<u8>), VaultError> {
        let st = self.state.as_mut().ok_or(VaultError::VaultLocked)?;
        let mut imported_count = 0usize;
        for mut inc in incoming_items {
            inc.normalize_derived_fields();
            if let Some(existing) = st.snapshot.items.iter_mut().find(|i| i.id == inc.id) {
                if inc.updated_at_ms >= existing.updated_at_ms {
                    existing.apply_update(inc, now_ms, Some("vaultpack".into()));
                    imported_count += 1;
                }
            } else {
                if inc.id.trim_ascii().is_empty() {
                    inc.id = generate_uuid_v4()?;
                }
                st.snapshot.items.push(inc);
                imported_count += 1;
            }
        }
        let (head_bytes, snap_bytes) = Self::persist_unlocked(st, now_ms)?;
        Ok((imported_count, head_bytes, snap_bytes))
    }

    pub fn snapshot_ref(&self) -> Result<&VaultSnapshot, VaultError> {
        let st = self.state.as_ref().ok_or(VaultError::VaultLocked)?;
        Ok(&st.snapshot)
    }

    fn persist_unlocked(st: &mut UnlockedState, now_ms: u64) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        st.snapshot.hlc_timestamp = st.snapshot.hlc_timestamp.max(now_ms).saturating_add(1);
        let snap_bytes = seal_snapshot(&st.keys, &mut st.snapshot)?;

        let mut pointer = st.head.decrypt_pointer(&st.keys)?;
        pointer.latest_snapshot_id = st.snapshot.snapshot_id.clone();
        pointer.snapshot_epoch = st.snapshot.snapshot_epoch;
        pointer.state_root_mac = st.snapshot.state_mac;
        pointer.updated_at_ms = now_ms;
        st.head.update_pointer(&st.keys, &pointer)?;
        let head_bytes = st.head.to_bytes()?;
        Ok((head_bytes, snap_bytes))
    }
}

/// Standalone helper to initialize a brand-new vault (`head.bin` + initial `snap` + 256-bit recovery code).
pub fn initialize_new_vault(
    master_password: &[u8],
    kdf_params: KdfParams,
    session_key_bytes: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, Vec<u8>, String, Vec<u8>, String, u64), VaultError> {
    kdf_params.validate()?;
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let vault_id = generate_uuid_v4()?;
    let snapshot_id = concat3("snap_", &encode_hex_lower(&now_ms.to_be_bytes()[2..]), "_init");

    let master_dek = SecretKey::random()?;
    let keys = VaultKeyHierarchy::from_master_dek(master_dek)?;
    let (recovery_code, recovery_secret) = crate::crypto::RecoveryCode::generate()?;
    let master_kek = crate::crypto::derive_master_kek(master_password, &kdf_params)?;

    let mut snapshot = VaultSnapshot::new_empty(vault_id.clone(), snapshot_id.clone(), now_ms);
    let snap_bytes = seal_snapshot(&keys, &mut snapshot)?;

    let pointer = HeadEncryptedPointer {
        latest_snapshot_id: snapshot_id.clone(),
        recent_snapshot_ids: vec![snapshot_id],
        snapshot_epoch: 1,
        state_root_mac: snapshot.state_mac,
        updated_at_ms: now_ms,
    };

    let head = VaultHead::create_new(
        vault_id.clone(),
        &master_kek,
        kdf_params,
        &recovery_secret,
        &keys,
        &pointer,
    )?;
    let head_bytes = head.to_bytes()?;
    let session_wrap =
        SessionWrappedDekBlob::wrap(&vault_id, head.key_epoch, keys.master_dek(), &session_key)?;

    Ok((
        head_bytes,
        snap_bytes,
        recovery_code.as_str().to_string(),
        session_wrap,
        vault_id,
        head.key_epoch,
    ))
}
