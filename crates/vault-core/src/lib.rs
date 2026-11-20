pub mod audit;
mod browser_csv;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod json_lite;
pub mod model;
pub mod session;
pub mod sync_codec;

use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::audit::{evaluate_password_strength, hibp_match_range_response, hibp_sha1_prefix_and_suffix};
use crate::crypto::{
    calibrate_kdf_params, csprng_fill, derive_master_kek, KdfParams, RecoveryCode, SecretKey,
    VaultKeyHierarchy, MIN_M_COST_KIB,
};
use crate::error::VaultError;
use crate::generator::{
    generate_eff_passphrase, generate_random_password, PassphraseGeneratorOptions,
    PasswordGeneratorOptions,
};
use crate::json_lite::{encode_hex_lower, JVal};
use crate::model::{infer_default_uri_match_rule, CardBrand, VaultItem};
use crate::session::{
    initialize_new_vault, PinWrappedDekBlob, PrfWrappedDekBlob, SessionWrappedDekBlob, VaultSession,
};
use crate::sync_codec::{export_vaultpack, import_vaultpack, VaultHead};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn js_date_now() -> f64;
}

#[cfg(not(target_arch = "wasm32"))]
fn js_date_now() -> f64 {
    1_700_000_000_000.0
}

#[wasm_bindgen]
pub fn wasm_calibrate_argon2id() -> Result<String, JsValue> {
    let mut probe_salt = [0u8; 32];
    csprng_fill(&mut probe_salt)?;
    let probe_params = KdfParams {
        m_cost_kib: MIN_M_COST_KIB,
        t_cost: 2,
        p_cost: 4,
        salt: probe_salt,
    };
    let t0 = js_date_now();
    let _ = crate::crypto::derive_argon2id_seed(b"vault-kdf-calibration-probe", &probe_params)?;
    let probe_ms = (js_date_now() - t0).max(1.0);
    let calibrated = calibrate_kdf_params(probe_ms)?;
    Ok(JVal::Obj(vec![
        ("probeMs", JVal::Tenths((probe_ms * 10.0) as u32)),
        ("mCostKib", JVal::Uint(calibrated.m_cost_kib as u64)),
        ("tCost", JVal::Uint(calibrated.t_cost as u64)),
        ("pCost", JVal::Uint(calibrated.p_cost as u64)),
    ])
    .stringify())
}

/// Creates a brand-new encrypted vault inside the KDF Web Worker.
#[wasm_bindgen]
pub struct WasmInitVaultOutput {
    head_bytes: Vec<u8>,
    snap_bytes: Vec<u8>,
    recovery_code: Zeroizing<String>,
    session_wrap_bytes: Vec<u8>,
    vault_id: String,
    key_epoch: u64,
}

#[wasm_bindgen]
impl WasmInitVaultOutput {
    #[wasm_bindgen(getter)]
    pub fn head_bytes(&self) -> Vec<u8> {
        self.head_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn snap_bytes(&self) -> Vec<u8> {
        self.snap_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn recovery_code(&self) -> String {
        self.recovery_code.as_str().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn session_wrap_bytes(&self) -> Vec<u8> {
        self.session_wrap_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn vault_id(&self) -> String {
        self.vault_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

#[wasm_bindgen]
pub fn wasm_create_new_vault(
    master_password: &str,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    session_key_bytes: &[u8],
    now_ms: f64,
) -> Result<WasmInitVaultOutput, JsValue> {
    let mut salt = [0u8; 32];
    csprng_fill(&mut salt)?;
    let params = KdfParams {
        m_cost_kib,
        t_cost,
        p_cost,
        salt,
    };
    let pw_bytes = Zeroizing::new(master_password.as_bytes().to_vec());
    let (head_bytes, snap_bytes, recovery_code, session_wrap_bytes, vault_id, key_epoch) =
        initialize_new_vault(&pw_bytes, params, session_key_bytes, now_ms as u64)?;
    Ok(WasmInitVaultOutput {
        head_bytes,
        snap_bytes,
        recovery_code: Zeroizing::new(recovery_code),
        session_wrap_bytes,
        vault_id,
        key_epoch,
    })
}

/// Unlocks `head.bin` with Master Password inside Web Worker and returns a `session_wrap` blob
/// encrypted under the caller-provided ephemeral `session_key_bytes`.
#[wasm_bindgen]
pub fn wasm_unlock_head_with_password(
    head_bytes: &[u8],
    master_password: &str,
    session_key_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let head = VaultHead::from_bytes(head_bytes)?;
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let pw_bytes = Zeroizing::new(master_password.as_bytes().to_vec());
    let keys = head.unlock_with_master_password(&pw_bytes)?;
    Ok(SessionWrappedDekBlob::wrap(
        &head.vault_id,
        head.key_epoch,
        keys.master_dek(),
        &session_key,
    )?)
}

/// Verifies Master Password against `head.bin` (used for high-sensitivity `requireReprompt` checks).
#[wasm_bindgen]
pub fn wasm_verify_master_password(
    head_bytes: &[u8],
    master_password: &str,
) -> Result<bool, JsValue> {
    let head = VaultHead::from_bytes(head_bytes)?;
    let pw_bytes = Zeroizing::new(master_password.as_bytes().to_vec());
    Ok(head.unlock_with_master_password(&pw_bytes).is_ok())
}

/// Unlocks `head.bin` with 256-bit Recovery Code and rotates to a new Master Password (`key_epoch += 1`),
/// returning `(new_head_bytes, new_session_wrap_bytes)` without touching `snap.bin`!
#[wasm_bindgen]
pub struct WasmHeadRotationOutput {
    head_bytes: Vec<u8>,
    session_wrap_bytes: Vec<u8>,
    key_epoch: u64,
}

#[wasm_bindgen]
impl WasmHeadRotationOutput {
    #[wasm_bindgen(getter)]
    pub fn head_bytes(&self) -> Vec<u8> {
        self.head_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn session_wrap_bytes(&self) -> Vec<u8> {
        self.session_wrap_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

#[wasm_bindgen]
pub fn wasm_recover_and_reset_master_password(
    head_bytes: &[u8],
    recovery_code_input: &str,
    new_master_password: &str,
    session_key_bytes: &[u8],
    now_ms: f64,
) -> Result<WasmHeadRotationOutput, JsValue> {
    let mut head = VaultHead::from_bytes(head_bytes)?;
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let recovery_secret = RecoveryCode::parse(recovery_code_input)?;
    let keys = head.unlock_with_recovery_secret(&recovery_secret)?;
    let mut pointer = head.decrypt_pointer(&keys)?;
    pointer.updated_at_ms = now_ms as u64;

    let new_params = head.kdf_params.with_fresh_salt()?;
    let pw_bytes = Zeroizing::new(new_master_password.as_bytes().to_vec());
    let new_master_kek = derive_master_kek(&pw_bytes, &new_params)?;
    head.rotate_master_kek(&keys, &new_master_kek, new_params, &pointer)?;

    let new_head_bytes = head.to_bytes()?;
    let session_wrap_bytes = SessionWrappedDekBlob::wrap(
        &head.vault_id,
        head.key_epoch,
        keys.master_dek(),
        &session_key,
    )?;
    Ok(WasmHeadRotationOutput {
        head_bytes: new_head_bytes,
        session_wrap_bytes,
        key_epoch: head.key_epoch,
    })
}

/// Changes Master Password using current Master Password (`key_epoch += 1`, zero full-vault re-encryption).
#[wasm_bindgen]
pub fn wasm_change_master_password(
    head_bytes: &[u8],
    current_master_password: &str,
    new_master_password: &str,
    session_key_bytes: &[u8],
    now_ms: f64,
) -> Result<WasmHeadRotationOutput, JsValue> {
    let mut head = VaultHead::from_bytes(head_bytes)?;
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let old_pw = Zeroizing::new(current_master_password.as_bytes().to_vec());
    let keys = head.unlock_with_master_password(&old_pw)?;
    let mut pointer = head.decrypt_pointer(&keys)?;
    pointer.updated_at_ms = now_ms as u64;

    let new_params = head.kdf_params.with_fresh_salt()?;
    let new_pw = Zeroizing::new(new_master_password.as_bytes().to_vec());
    let new_master_kek = derive_master_kek(&new_pw, &new_params)?;
    head.rotate_master_kek(&keys, &new_master_kek, new_params, &pointer)?;

    let new_head_bytes = head.to_bytes()?;
    let session_wrap_bytes = SessionWrappedDekBlob::wrap(
        &head.vault_id,
        head.key_epoch,
        keys.master_dek(),
        &session_key,
    )?;
    Ok(WasmHeadRotationOutput {
        head_bytes: new_head_bytes,
        session_wrap_bytes,
        key_epoch: head.key_epoch,
    })
}

/// Creates a local device PIN wrapper blob from an active session-wrapped DEK.
#[wasm_bindgen]
pub fn wasm_create_pin_wrap(
    session_key_bytes: &[u8],
    session_wrap_bytes: &[u8],
    pin: &str,
) -> Result<Vec<u8>, JsValue> {
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let (vault_id, key_epoch, dek) = SessionWrappedDekBlob::unwrap(session_wrap_bytes, &session_key)?;
    let pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
    Ok(PinWrappedDekBlob::create(&vault_id, key_epoch, &dek, &pin_bytes)?)
}

/// Unwraps a local device PIN wrapper blob and re-wraps DEK under a fresh ephemeral `session_key_bytes`.
#[wasm_bindgen]
pub fn wasm_unlock_with_pin_wrap(
    head_bytes: &[u8],
    pin_wrap_bytes: &[u8],
    pin: &str,
    session_key_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let head = VaultHead::from_bytes(head_bytes)?;
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
    let (vault_id, pin_epoch, dek) = PinWrappedDekBlob::unwrap_dek(pin_wrap_bytes, &pin_bytes)?;
    if vault_id != head.vault_id || pin_epoch != head.key_epoch {
        return Err(VaultError::CryptoAuthFailed.into());
    }
    let keys = VaultKeyHierarchy::from_master_dek(dek)?;
    let _ = head.decrypt_pointer(&keys)?;
    Ok(SessionWrappedDekBlob::wrap(
        &head.vault_id,
        head.key_epoch,
        keys.master_dek(),
        &session_key,
    )?)
}

#[wasm_bindgen]
pub fn wasm_verify_pin_wrap(pin_wrap_bytes: &[u8], pin: &str) -> Result<bool, JsValue> {
    let pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
    Ok(PinWrappedDekBlob::unwrap_dek(pin_wrap_bytes, &pin_bytes).is_ok())
}

/// Creates a local WebAuthn PRF (Windows Hello) wrapper blob after closed-loop 32-byte PRF verification.
#[wasm_bindgen]
pub fn wasm_create_prf_wrap(
    session_key_bytes: &[u8],
    session_wrap_bytes: &[u8],
    prf_output_32b: &[u8],
    prf_salt_32b: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if prf_salt_32b.len() != 32 {
        return Err(VaultError::InvalidInput("prf_salt must be 32 bytes".into()).into());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(prf_salt_32b);
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let (vault_id, key_epoch, dek) = SessionWrappedDekBlob::unwrap(session_wrap_bytes, &session_key)?;
    Ok(PrfWrappedDekBlob::create(
        &vault_id,
        key_epoch,
        &dek,
        prf_output_32b,
        &salt,
    )?)
}

/// Unwraps a local WebAuthn PRF wrapper blob into a fresh ephemeral `session_wrap` (< 1ms HKDF + AEAD).
#[wasm_bindgen]
pub fn wasm_unlock_with_prf_wrap(
    head_bytes: &[u8],
    prf_wrap_bytes: &[u8],
    prf_output_32b: &[u8],
    session_key_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let head = VaultHead::from_bytes(head_bytes)?;
    let session_key = SecretKey::from_slice(session_key_bytes)?;
    let (vault_id, prf_epoch, dek) = PrfWrappedDekBlob::unwrap_dek(prf_wrap_bytes, prf_output_32b)?;
    if vault_id != head.vault_id || prf_epoch != head.key_epoch {
        return Err(VaultError::CryptoAuthFailed.into());
    }
    let keys = VaultKeyHierarchy::from_master_dek(dek)?;
    let _ = head.decrypt_pointer(&keys)?;
    Ok(SessionWrappedDekBlob::wrap(
        &head.vault_id,
        head.key_epoch,
        keys.master_dek(),
        &session_key,
    )?)
}

/// Exports encrypted `.vaultpack` inside KDF Web Worker.
#[wasm_bindgen]
pub fn wasm_export_vaultpack(
    session_key_bytes: &[u8],
    session_wrap_bytes: &[u8],
    head_bytes: &[u8],
    snap_bytes: &[u8],
    backup_password: &str,
    now_ms: f64,
) -> Result<Vec<u8>, JsValue> {
    let mut temp_session = VaultSession::new();
    temp_session.restore_from_session_wrap(
        session_key_bytes,
        session_wrap_bytes,
        head_bytes,
        snap_bytes,
    )?;
    let head = VaultHead::from_bytes(head_bytes)?;
    let kdf_params = head.kdf_params.with_fresh_salt()?;
    let pw_bytes = Zeroizing::new(backup_password.as_bytes().to_vec());
    let snapshot = temp_session.snapshot_ref()?;
    let pack = export_vaultpack(snapshot, &pw_bytes, kdf_params, now_ms as u64)?;
    temp_session.lock_and_zeroize();
    Ok(pack)
}

#[wasm_bindgen]
pub struct WasmImportVaultpackOutput {
    imported_count: usize,
    head_bytes: Vec<u8>,
    snap_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl WasmImportVaultpackOutput {
    #[wasm_bindgen(getter)]
    pub fn imported_count(&self) -> usize {
        self.imported_count
    }

    #[wasm_bindgen(getter)]
    pub fn head_bytes(&self) -> Vec<u8> {
        self.head_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn snap_bytes(&self) -> Vec<u8> {
        self.snap_bytes.clone()
    }
}

#[wasm_bindgen]
pub fn wasm_import_vaultpack_into_vault(
    session_key_bytes: &[u8],
    session_wrap_bytes: &[u8],
    head_bytes: &[u8],
    snap_bytes: &[u8],
    vaultpack_bytes: &[u8],
    backup_password: &str,
    now_ms: f64,
) -> Result<WasmImportVaultpackOutput, JsValue> {
    let pw_bytes = Zeroizing::new(backup_password.as_bytes().to_vec());
    let mut imported_snap = import_vaultpack(vaultpack_bytes, &pw_bytes)?;
    let incoming_items = std::mem::take(&mut imported_snap.items);
    imported_snap.zeroize_all();

    let mut temp_session = VaultSession::new();
    temp_session.restore_from_session_wrap(
        session_key_bytes,
        session_wrap_bytes,
        head_bytes,
        snap_bytes,
    )?;
    let (imported_count, new_head_bytes, new_snap_bytes) =
        temp_session.import_items_merge(incoming_items, now_ms as u64)?;
    temp_session.lock_and_zeroize();
    Ok(WasmImportVaultpackOutput {
        imported_count,
        head_bytes: new_head_bytes,
        snap_bytes: new_snap_bytes,
    })
}

// ============================================================================
// Service Worker Fast Session Engine (< 5ms wake-up, zero Argon2id blocking)
// ============================================================================

#[wasm_bindgen]
pub struct WasmMutationResult {
    item_json: String,
    count: usize,
    head_bytes: Vec<u8>,
    snap_bytes: Vec<u8>,
}

impl Drop for WasmMutationResult {
    fn drop(&mut self) { self.item_json.zeroize(); }
}

#[wasm_bindgen]
impl WasmMutationResult {
    #[wasm_bindgen(getter)]
    pub fn item_json(&self) -> String {
        self.item_json.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn count(&self) -> usize {
        self.count
    }

    #[wasm_bindgen(getter)]
    pub fn head_bytes(&self) -> Vec<u8> {
        self.head_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn snap_bytes(&self) -> Vec<u8> {
        self.snap_bytes.clone()
    }
}

#[wasm_bindgen]
pub struct WasmVaultEngine {
    inner: VaultSession,
}

impl Default for WasmVaultEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmVaultEngine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: VaultSession::new(),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    pub fn lock_and_zeroize(&mut self) {
        self.inner.lock_and_zeroize();
    }

    pub fn restore_from_session(
        &mut self,
        session_key_bytes: &[u8],
        session_wrap_bytes: &[u8],
        head_bytes: &[u8],
        snap_bytes: &[u8],
    ) -> Result<(), JsValue> {
        Ok(self.inner.restore_from_session_wrap(
            session_key_bytes,
            session_wrap_bytes,
            head_bytes,
            snap_bytes,
        )?)
    }

    pub fn list_summaries_json(&self) -> Result<String, JsValue> {
        let summaries = self.inner.list_summaries()?;
        let arr: Vec<JVal> = summaries.iter().map(|s| s.to_json_value()).collect();
        Ok(JVal::Arr(arr).stringify())
    }

    pub fn get_item_json(&self, item_id: &str, reprompt_verified: bool) -> Result<String, JsValue> {
        let item = self.inner.get_item(item_id, reprompt_verified)?;
        Ok(item.to_json_value().stringify())
    }

    pub fn upsert_item_json(
        &mut self,
        item_json: String,
        now_ms: f64,
        device_name: Option<String>,
    ) -> Result<WasmMutationResult, JsValue> {
        let item_json = Zeroizing::new(item_json);
        let incoming = VaultItem::from_json_str(&item_json)?;
        let (saved, head_bytes, snap_bytes) =
            self.inner.upsert_item(incoming, now_ms as u64, device_name)?;
        let saved_json = saved.to_json_value().stringify();
        Ok(WasmMutationResult {
            item_json: saved_json,
            count: 1,
            head_bytes,
            snap_bytes,
        })
    }

    pub fn import_records_json(&mut self, rows: String, now_ms: f64, commit: bool) -> Result<WasmMutationResult, JsValue> {
        let rows = Zeroizing::new(rows);
        let (items, item_json) = browser_csv::plan(&self.inner.snapshot_ref()?.items, &rows, now_ms as u64)?;
        let (count, head_bytes, snap_bytes) = if commit && !items.is_empty() {
            self.inner.import_items_merge(items, now_ms as u64)?
        } else {
            (0, Vec::new(), Vec::new())
        };
        Ok(WasmMutationResult { item_json, count, head_bytes, snap_bytes })
    }

    pub fn set_trashed(
        &mut self,
        item_id: &str,
        trashed: bool,
        now_ms: f64,
    ) -> Result<WasmMutationResult, JsValue> {
        let (head_bytes, snap_bytes) = self.inner.set_trashed(item_id, trashed, now_ms as u64)?;
        Ok(WasmMutationResult {
            item_json: String::new(),
            count: 1,
            head_bytes,
            snap_bytes,
        })
    }

    pub fn delete_permanently(
        &mut self,
        item_id: &str,
        now_ms: f64,
    ) -> Result<WasmMutationResult, JsValue> {
        let (head_bytes, snap_bytes) = self.inner.delete_permanently(item_id, now_ms as u64)?;
        Ok(WasmMutationResult {
            item_json: String::new(),
            count: 1,
            head_bytes,
            snap_bytes,
        })
    }

    pub fn empty_trash(&mut self, now_ms: f64) -> Result<WasmMutationResult, JsValue> {
        let (count, head_bytes, snap_bytes) = self.inner.empty_trash(now_ms as u64)?;
        Ok(WasmMutationResult {
            item_json: String::new(),
            count,
            head_bytes,
            snap_bytes,
        })
    }

}


// ============================================================================
// Stateless Utility Bindings (Generators, Strength Meter, HIBP k-Anonymity, Card/URI helpers)
// ============================================================================

#[wasm_bindgen]
pub fn wasm_generate_password(options_json: &str) -> Result<String, JsValue> {
    let opts = PasswordGeneratorOptions::from_json_str(options_json)?;
    let pw = generate_random_password(&opts)?;
    Ok(pw.as_str().to_string())
}

#[wasm_bindgen]
pub fn wasm_generate_passphrase(options_json: &str) -> Result<String, JsValue> {
    let opts = PassphraseGeneratorOptions::from_json_str(options_json)?;
    let phrase = generate_eff_passphrase(&opts)?;
    Ok(phrase.as_str().to_string())
}

#[wasm_bindgen]
pub fn wasm_evaluate_password_strength(password: &str, hints_json: &str) -> Result<String, JsValue> {
    let hints: Vec<String> = if hints_json.trim_ascii().is_empty() {
        Vec::new()
    } else {
        JVal::parse(hints_json)
            .ok()
            .and_then(|v| {
                v.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(JVal::as_str)
                        .map(|s| s.to_string())
                        .collect()
                })
            })
            .unwrap_or_default()
    };
    let report = evaluate_password_strength(password, &hints);
    Ok(report.to_json_value().stringify())
}

#[wasm_bindgen]
pub fn wasm_hibp_prefix(password: &str) -> String {
    let (prefix, _suffix) = hibp_sha1_prefix_and_suffix(password);
    prefix
}

#[wasm_bindgen]
pub fn wasm_hibp_match_range(password: &str, range_response: &str) -> u64 {
    hibp_match_range_response(password, range_response)
}

#[wasm_bindgen]
pub fn wasm_detect_card_brand(card_number: &str) -> String {
    CardBrand::detect(card_number).as_str().to_string()
}

#[wasm_bindgen]
pub fn wasm_infer_default_uri_rule(uri: &str) -> String {
    infer_default_uri_match_rule(uri).as_str().to_string()
}

#[wasm_bindgen]
pub fn wasm_blake3_digest_hex(text: &str) -> String {
    let bytes = Zeroizing::new(text.as_bytes().to_vec());
    encode_hex_lower(blake3::hash(&bytes).as_bytes())
}

#[wasm_bindgen]
pub fn wasm_inspect_head_metadata(head_bytes: &[u8]) -> Result<String, JsValue> {
    let head = VaultHead::from_bytes(head_bytes)?;
    Ok(JVal::Obj(vec![
        ("vaultId", JVal::Str(head.vault_id)),
        ("keyEpoch", JVal::Uint(head.key_epoch)),
        ("mCostKib", JVal::Uint(head.kdf_params.m_cost_kib as u64)),
        ("tCost", JVal::Uint(head.kdf_params.t_cost as u64)),
        ("pCost", JVal::Uint(head.kdf_params.p_cost as u64)),
    ])
    .stringify())
}

// ============================================================================
// Comprehensive Phase 1 Unit & Security Test Suite (`cargo test -p vault-core`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        pad_to_256_bucket, unpad_from_256_bucket, FileRole, SealedEnvelope, BUCKET_SIZE,
    };
    use crate::model::{
        CardBrand, CredentialData, CustomField, DeveloperCredential, DeveloperCredentialSubtype,
        IdentityCredential, LoginCredential, PaymentCardCredential, UriEntry, UriMatchRule,
        MAX_PASSWORD_HISTORY,
    };
    use crate::sync_codec::{
        decode_msgpack_zstd_padded, encode_msgpack_zstd_padded, open_snapshot,
    };

    fn fast_test_kdf() -> KdfParams {
        let mut salt = [0u8; 32];
        csprng_fill(&mut salt).unwrap();
        KdfParams {
            m_cost_kib: 32_768, // Minimum legal 32 MiB floor per spec
            t_cost: 2,
            p_cost: 4,
            salt,
        }
    }

    #[test]
    fn key_hierarchy_dual_unwrap_and_zero_reencrypt_password_rotation() {
        let kdf = fast_test_kdf();
        let session_key = SecretKey::random().unwrap();
        let (head_bytes, snap_bytes, recovery_code, session_wrap, _vault_id, init_epoch) =
            initialize_new_vault(b"CorrectHorse#2026!", kdf, session_key.as_bytes(), 1_700_000_000_000)
                .expect("init vault");
        assert_eq!(init_epoch, 1);

        // Insert a confidential item and persist snapshot
        let mut session = VaultSession::new();
        session
            .restore_from_session_wrap(
                session_key.as_bytes(),
                &session_wrap,
                &head_bytes,
                &snap_bytes,
            )
            .unwrap();

        let sample_item = VaultItem {
            id: String::new(),
            title: "Example Bank".into(),
            data: CredentialData::Login(LoginCredential {
                username: "alice@example-bank.com".into(),
                passkey_data: Vec::new(),
                password: "MyUniqueTestSecret_9981".into(),
                uris: vec![UriEntry {
                    uri: "https://example-bank.com/login".into(),
                    match_rule: UriMatchRule::BaseDomain,
                }],
                password_history: Vec::new(),
                totp_uri: None,
            }),
            note: "Top secret banking note".into(),
            custom_fields: vec![CustomField {
                name: "WirePIN".into(),
                value: "774411".into(),
                hidden: true,
            }],
            tags: vec!["finance".into()],
            pinned: true,
            require_reprompt: true,
            trashed: false,
            trashed_at_ms: None,
            created_at_ms: 0,
            updated_at_ms: 0,
            revision: 0,
        };
        let (saved_item, head_v1, snap_before_rotation) = session
            .upsert_item(sample_item, 1_700_000_005_000, Some("Win11-Edge".into()))
            .unwrap();

        // Zero-plaintext audit on serialized head.bin and snap.bin
        for needle in [
            b"MyUniqueTestSecret_9981".as_slice(),
            b"example-bank.com".as_slice(),
            b"alice@example-bank.com".as_slice(),
            b"774411".as_slice(),
        ] {
            assert!(
                !head_v1.windows(needle.len()).any(|w| w == needle),
                "head.bin leaked plaintext marker!"
            );
            assert!(
                !snap_before_rotation.windows(needle.len()).any(|w| w == needle),
                "snap.bin leaked plaintext marker!"
            );
        }

        // 1. Both Master Password and 256-bit Recovery Code unwrap the exact same Master DEK
        let head_parsed = VaultHead::from_bytes(&head_v1).unwrap();
        let keys_from_pw = head_parsed
            .unlock_with_master_password(b"CorrectHorse#2026!")
            .expect("unlock via master password");
        let parsed_rec_secret = RecoveryCode::parse(&recovery_code).expect("parse recovery code");
        let keys_from_rec = head_parsed
            .unlock_with_recovery_secret(&parsed_rec_secret)
            .expect("unlock via 256-bit recovery code");
        assert_eq!(
            keys_from_pw.master_dek().as_bytes(),
            keys_from_rec.master_dek().as_bytes(),
            "Master Password and Recovery Code must unwrap identical Master DEK"
        );

        // 2. Rotate Master Password -> ONLY head.bin changes; old snap_before_rotation decrypts cleanly!
        let rotated = wasm_change_master_password(
            &head_v1,
            "CorrectHorse#2026!",
            "BrandNewMasterPass$2027",
            session_key.as_bytes(),
            1_700_000_010_000.0,
        )
        .expect("change master password");
        assert_eq!(rotated.key_epoch(), 2);

        let head_v2 = VaultHead::from_bytes(&rotated.head_bytes()).unwrap();
        assert!(
            head_v2
                .unlock_with_master_password(b"CorrectHorse#2026!")
                .is_err(),
            "old master password must no longer unlock head.bin"
        );
        let keys_after_rot = head_v2
            .unlock_with_master_password(b"BrandNewMasterPass$2027")
            .expect("new master password unlocks head.bin");
        let pointer_v2 = head_v2.decrypt_pointer(&keys_after_rot).unwrap();

        // Decrypt `snap_before_rotation` without re-encrypting it!
        let decrypted_old_snap = open_snapshot(
            &keys_after_rot,
            Some(&pointer_v2.latest_snapshot_id),
            &snap_before_rotation,
        )
        .expect("old snapshot must decrypt directly after head rotation");
        assert_eq!(decrypted_old_snap.items.len(), 1);
        assert_eq!(decrypted_old_snap.items[0].id, saved_item.id);

        // Recovery code also still works and can reset master password again
        let reset_via_rec = wasm_recover_and_reset_master_password(
            &rotated.head_bytes(),
            &recovery_code,
            "RecoveredMaster!99",
            session_key.as_bytes(),
            1_700_000_020_000.0,
        )
        .expect("reset via recovery code");
        assert_eq!(reset_via_rec.key_epoch(), 3);
        let head_v3 = VaultHead::from_bytes(&reset_via_rec.head_bytes()).unwrap();
        assert!(head_v3.unlock_with_master_password(b"RecoveredMaster!99").is_ok());
    }

    #[test]
    fn aead_bitflip_and_aad_role_swap_rejected() {
        let key = SecretKey::random().unwrap();
        let env = SealedEnvelope::seal_bucketed(
            &key,
            FileRole::Wal,
            "01931b02_d4f1_001",
            42,
            b"secret delta payload",
        )
        .unwrap();
        assert_eq!(env.ciphertext.len() % BUCKET_SIZE, 0);

        // 1-bit flip anywhere in ciphertext must fail authentication
        let mut tampered_ct = env.clone();
        tampered_ct.ciphertext[17] ^= 0x01;
        assert_eq!(
            tampered_ct.open_bucketed(&key, FileRole::Wal, Some("01931b02_d4f1_001")).unwrap_err(),
            VaultError::CryptoAuthFailed
        );

        // 1-bit flip in Poly1305 tag must fail authentication
        let mut tampered_tag = env.clone();
        tampered_tag.tag[0] ^= 0x80;
        assert_eq!(
            tampered_tag.open_bucketed(&key, FileRole::Wal, Some("01931b02_d4f1_001")).unwrap_err(),
            VaultError::CryptoAuthFailed
        );

        // Forging `file_role` (masquerading a `wal` ciphertext as `snap`) must fail AAD authentication
        let mut role_forged = env.clone();
        role_forged.file_role = FileRole::Snap;
        assert_eq!(
            role_forged.open_bucketed(&key, FileRole::Snap, Some("01931b02_d4f1_001")).unwrap_err(),
            VaultError::CryptoAuthFailed
        );

        // Forging `hlc_epoch` must fail AAD authentication
        let mut epoch_forged = env.clone();
        epoch_forged.hlc_epoch = 43;
        assert_eq!(
            epoch_forged.open_bucketed(&key, FileRole::Wal, Some("01931b02_d4f1_001")).unwrap_err(),
            VaultError::CryptoAuthFailed
        );
    }

    #[test]
    fn bucket_padding_256b_alignment_and_msgpack_zstd_roundtrip() {
        for len in [0usize, 1, 17, 251, 252, 253, 255, 256, 508, 512, 1024, 4099] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let padded = pad_to_256_bucket(&data);
            assert!(padded.len() >= BUCKET_SIZE);
            assert_eq!(
                padded.len() % BUCKET_SIZE,
                0,
                "plain len {len} produced non-256B aligned padded length {}",
                padded.len()
            );
            let unpadded = unpad_from_256_bucket(&padded).unwrap();
            assert_eq!(unpadded.as_slice(), data.as_slice());

            let encoded = encode_msgpack_zstd_padded(&data).unwrap();
            assert_eq!(encoded.as_slice().len() % BUCKET_SIZE, 0);
            let decoded: Vec<u8> = decode_msgpack_zstd_padded(encoded.as_slice()).unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn password_history_retains_latest_20_in_reverse_chronological_order() {
        let mut item = VaultItem {
            id: "login-1".into(),
            title: "GitHub".into(),
            data: CredentialData::Login(LoginCredential {
                username: "dev@example.com".into(),
                passkey_data: Vec::new(),
                password: "pw_0".into(),
                uris: vec![UriEntry {
                    uri: "https://github.com".into(),
                    match_rule: UriMatchRule::BaseDomain,
                }],
                password_history: Vec::new(),
                totp_uri: None,
            }),
            note: String::new(),
            custom_fields: Vec::new(),
            tags: Vec::new(),
            pinned: false,
            require_reprompt: false,
            trashed: false,
            trashed_at_ms: None,
            created_at_ms: 1000,
            updated_at_ms: 1000,
            revision: 1,
        };

        // Modify password 25 times: pw_0 -> pw_1 -> ... -> pw_25
        for step in 1..=25u64 {
            let mut next = item.clone();
            if let CredentialData::Login(ref mut l) = next.data {
                l.password = format!("pw_{step}");
                l.password_history.clear();
            }
            item.apply_update(next, 1000 + step * 1000, Some("Desktop".into()));
        }

        let CredentialData::Login(final_login) = &item.data else {
            panic!("expected login item");
        };
        assert_eq!(final_login.password, "pw_25");
        assert_eq!(final_login.password_history.len(), MAX_PASSWORD_HISTORY);
        // Most recent previous password is pw_24 (changed at step 25), oldest kept is pw_5 (changed at step 6)
        assert_eq!(final_login.password_history[0].password, "pw_24");
        assert_eq!(final_login.password_history[19].password, "pw_5");
        for win in final_login.password_history.windows(2) {
            assert!(
                win[0].changed_at_ms > win[1].changed_at_ms,
                "passwordHistory must be strictly reverse-chronological"
            );
        }
    }

    #[test]
    fn all_credential_models_reprompt_and_card_brand_detection() {
        assert_eq!(CardBrand::detect("6222021234567890123"), CardBrand::UnionPay);
        assert_eq!(CardBrand::detect("4111 1111 1111 1234"), CardBrand::Visa);
        assert_eq!(CardBrand::detect("5425 2334 3010 9903"), CardBrand::Mastercard);
        assert_eq!(CardBrand::detect("3782 822463 10005"), CardBrand::Amex);
        assert_eq!(CardBrand::detect("3530 1113 3330 0000"), CardBrand::Jcb);

        assert_eq!(
            infer_default_uri_match_rule("http://192.168.1.2:8080"),
            UriMatchRule::Host
        );
        assert_eq!(
            infer_default_uri_match_rule("http://localhost:5173"),
            UriMatchRule::Host
        );
        assert_eq!(
            infer_default_uri_match_rule("https://login.github.com/session"),
            UriMatchRule::BaseDomain
        );

        let kdf = fast_test_kdf();
        let session_key = SecretKey::random().unwrap();
        let (head_bytes, snap_bytes, _rec, session_wrap, _vid, _ep) =
            initialize_new_vault(b"VaultPass#12345", kdf, session_key.as_bytes(), 1000).unwrap();
        let mut session = VaultSession::new();
        session
            .restore_from_session_wrap(session_key.as_bytes(), &session_wrap, &head_bytes, &snap_bytes)
            .unwrap();

        // Payment card (reprompt enabled)
        let (card_saved, _, _) = session
            .upsert_item(
                VaultItem {
                    id: String::new(),
                    title: "CMB Credit Card".into(),
                    data: CredentialData::PaymentCard(PaymentCardCredential {
                        cardholder_name: "ZHANG SAN".into(),
                        card_number: "6225758812349876".into(),
                        brand: CardBrand::Other,
                        exp_month: "09".into(),
                        exp_year: "29".into(),
                        cvv: "831".into(),
                        card_pin: "192837".into(),
                        billing_address: "Shanghai".into(),
                    }),
                    note: String::new(),
                    custom_fields: Vec::new(),
                    tags: vec!["bank".into()],
                    pinned: false,
                    require_reprompt: true,
                    trashed: false,
                    trashed_at_ms: None,
                    created_at_ms: 0,
                    updated_at_ms: 0,
                    revision: 0,
                },
                2000,
                None,
            )
            .unwrap();

        // Identity & Developer items
        session
            .upsert_item(
                VaultItem {
                    id: String::new(),
                    title: "Personal Identity".into(),
                    data: CredentialData::Identity(IdentityCredential {
                        full_name: "Zhang San".into(),
                        phone: "13800138000".into(),
                        email: "zhang@example.com".into(),
                        national_id_or_passport: "310101199501011234".into(),
                        country: "CN".into(),
                        province: "Shanghai".into(),
                        city: "Shanghai".into(),
                        address_line: "Pudong Ave 1".into(),
                        postal_code: "200120".into(),
                        company: "Acme Ltd".into(),
                        tax_id: "91310000XXXX".into(),
                    }),
                    note: String::new(),
                    custom_fields: Vec::new(),
                    tags: Vec::new(),
                    pinned: false,
                    require_reprompt: false,
                    trashed: false,
                    trashed_at_ms: None,
                    created_at_ms: 0,
                    updated_at_ms: 0,
                    revision: 0,
                },
                3000,
                None,
            )
            .unwrap();

        session
            .upsert_item(
                VaultItem {
                    id: String::new(),
                    title: "Prod Server SSH".into(),
                    data: CredentialData::Developer(DeveloperCredential {
                        subtype: DeveloperCredentialSubtype::SshKey,
                        service_or_product: "prod-bastion".into(),
                        token_or_license: String::new(),
                        public_key: "ssh-ed25519 AAAAC3NzaC1...".into(),
                        private_key: "-----BEGIN OPENSSH PRIVATE KEY-----...".into(),
                        expires_at_ms: None,
                    }),
                    note: String::new(),
                    custom_fields: Vec::new(),
                    tags: vec!["infra".into()],
                    pinned: false,
                    require_reprompt: true,
                    trashed: false,
                    trashed_at_ms: None,
                    created_at_ms: 0,
                    updated_at_ms: 0,
                    revision: 0,
                },
                4000,
                None,
            )
            .unwrap();

        let summaries = session.list_summaries().unwrap();
        assert_eq!(summaries.len(), 3);
        let card_summary = summaries.iter().find(|s| s.id == card_saved.id).unwrap();
        assert_eq!(card_summary.card_brand, Some(CardBrand::UnionPay));
        assert_eq!(card_summary.card_last4.as_deref(), Some("9876"));
        assert!(!card_summary.subtitle.contains("62257588"));

        // RequireReprompt gate must block unverified reads
        assert_eq!(
            session.get_item(&card_saved.id, false).unwrap_err(),
            VaultError::RepromptRequired
        );
        assert!(session.get_item(&card_saved.id, true).is_ok());
    }

    #[test]
    fn generators_eff_wordlist_hibp_and_vaultpack_roundtrip() {
        let words = crate::generator::eff_large_wordlist().unwrap();
        assert_eq!(words.len(), 7776);
        assert_eq!(words.first().map(String::as_str), Some("abacus"));
        assert_eq!(words.last().map(String::as_str), Some("zoom"));

        let pw = generate_random_password(&PasswordGeneratorOptions {
            length: 32,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            min_digits: 4,
            min_symbols: 4,
            exclude_ambiguous: true,
        })
        .unwrap();
        assert_eq!(pw.len(), 32);
        assert!(!pw.chars().any(|c| "0O1lI".contains(c)));

        let phrase = generate_eff_passphrase(&PassphraseGeneratorOptions {
            word_count: 5,
            separator: "-".into(),
            capitalize: true,
            include_number: true,
        })
        .unwrap();
        assert_eq!(phrase.split('-').count(), 6);

        // Known SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = hibp_sha1_prefix_and_suffix("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix.as_str(), "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let mock_range = "003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10432001\r\n";
        assert_eq!(hibp_match_range_response("password", mock_range), 10_432_001);

        // `.vaultpack` encrypted export & import
        let mut snap = model::VaultSnapshot::new_empty("v1".into(), "snap_1".into(), 5000);
        snap.items.push(VaultItem {
            id: "id-pack-1".into(),
            title: "Pack Secret".into(),
            data: CredentialData::Login(LoginCredential {
                username: "pack@user.io".into(),
                passkey_data: Vec::new(),
                password: "UltraSecretPackPassword!2026".into(),
                uris: Vec::new(),
                password_history: Vec::new(),
                totp_uri: None,
            }),
            note: String::new(),
            custom_fields: Vec::new(),
            tags: Vec::new(),
            pinned: false,
            require_reprompt: false,
            trashed: false,
            trashed_at_ms: None,
            created_at_ms: 5000,
            updated_at_ms: 5000,
            revision: 1,
        });
        let pack_bytes = export_vaultpack(&snap, b"BackupPass#99", fast_test_kdf(), 6000).unwrap();
        assert!(!pack_bytes
            .windows(b"UltraSecretPackPassword!2026".len())
            .any(|w| w == b"UltraSecretPackPassword!2026"));
        assert!(import_vaultpack(&pack_bytes, b"WrongPass").is_err());
        let restored = import_vaultpack(&pack_bytes, b"BackupPass#99").unwrap();
        assert_eq!(restored.items.len(), 1);
        assert_eq!(restored.items[0].title, "Pack Secret");
    }

    #[test]
    fn password_audit_excludes_standalone_authenticator_entries() {
        let otp = VaultItem::from_json_str(r#"{"id":"otp","title":"Authenticator","data":{"kind":"login","password":"","totpUri":"JBSWY3DPEHPK3PXP"}}"#).unwrap();
        let missing = VaultItem::from_json_str(r#"{"id":"missing","title":"Missing password","data":{"kind":"login","password":""}}"#).unwrap();
        let weak = VaultItem::from_json_str(r#"{"id":"weak","title":"Login","data":{"kind":"login","password":"123456","totpUri":"JBSWY3DPEHPK3PXP"}}"#).unwrap();
        let report = crate::audit::audit_vault_items(&[otp, missing, weak]);
        assert_eq!(report.total_login_items, 2);
        assert_eq!(report.weak_items.len(), 2);
        assert!(report.weak_items.iter().all(|finding| finding.item_id != "otp"));
    }

    #[test]
    fn audit_suggests_second_factors_only_for_sensitive_password_logins() {
        let items: Vec<_> = [
            r#"{"id":"provider","data":{"kind":"login","password":"fixture","uris":[{"uri":"https://work.example"},{"uri":"https://ACCOUNTS.Google.Com.:443/signin"}]}}"#,
            r#"{"id":"protected","requireReprompt":true,"data":{"kind":"login","password":"fixture","uris":[{"uri":"https://bank.example"}]}}"#,
            r#"{"id":"recorded","data":{"kind":"login","password":"fixture","uris":[{"uri":"https://github.com"}],"totpUri":"JBSWY3DPEHPK3PXP"}}"#,
            r#"{"id":"passkey-only","data":{"kind":"login","uris":[{"uri":"https://github.com"}]}}"#,
            r#"{"id":"unrelated","data":{"kind":"login","password":"fixture","uris":[{"uri":"https://example.test"}]}}"#,
            r#"{"id":"spoofed","data":{"kind":"login","password":"fixture","uris":[{"uri":"https://fakegithub.com"},{"uri":"https://github.com.example.test"},{"uri":"https://github.com@example.test"},{"uri":"file://github.com"},{"uri":"https://github.com","matchRule":"regex"}]}}"#,
            r#"{"id":"removed","trashed":true,"data":{"kind":"login","password":"fixture","uris":[{"uri":"https://github.com"}]}}"#,
        ].into_iter().map(|item| VaultItem::from_json_str(item).unwrap()).collect();
        let report = crate::audit::audit_vault_items(&items);
        assert_eq!(report.missing_2fa_item_ids, ["provider", "protected"]);
    }

    #[test]
    fn thousand_credentials_snapshot_compact_size_and_roundtrip() {
        let dek = SecretKey::random().unwrap();
        let keys = VaultKeyHierarchy::from_master_dek(dek).unwrap();
        let mut snap = model::VaultSnapshot::new_empty(
            "vault-1000".into(),
            "snap_benchmark_1000".into(),
            1_700_000_000_000,
        );
        for idx in 0..1000usize {
            snap.items.push(VaultItem {
                id: format!("01931a8f-d4f1-4000-8000-{idx:012x}"),
                title: format!("Service Account #{idx}"),
                data: CredentialData::Login(LoginCredential {
                    username: format!("engineer_{idx}@corp-domain.example.com"),
                    passkey_data: Vec::new(),
                    password: format!("S3cur3#P@ssw0rd_K9m!{idx:04x}_XyZ"),
                    uris: vec![UriEntry {
                        uri: format!("https://portal-{}.corp-domain.example.com/auth/login", idx % 50),
                        match_rule: UriMatchRule::BaseDomain,
                    }],
                    password_history: vec![model::PasswordHistoryEntry {
                        password: format!("OldP@ss_{idx:04x}_2025!"),
                        changed_at_ms: 1_695_000_000_000 + (idx as u64) * 1000,
                        source_device: Some("Workstation-Edge".into()),
                    }],
                    totp_uri: Some(format!(
                        "otpauth://totp/Corp:engineer_{idx}?secret=JBSWY3DPEHPK3PXP&issuer=Corp"
                    )),
                }),
                note: "Standard production SSO credential with 2FA enabled.".into(),
                custom_fields: Vec::new(),
                tags: vec!["work".into(), "production".into()],
                pinned: idx < 10,
                require_reprompt: idx % 20 == 0,
                trashed: false,
                trashed_at_ms: None,
                created_at_ms: 1_690_000_000_000,
                updated_at_ms: 1_700_000_000_000 + (idx as u64),
                revision: 2,
            });
        }

        let snap_bytes = crate::sync_codec::seal_snapshot(&keys, &mut snap).unwrap();
        assert!(
            snap_bytes.len() <= 240 * 1024,
            "1,000 credentials snap.bin size {} exceeded 240 KiB budget",
            snap_bytes.len()
        );
        let reopened = open_snapshot(&keys, Some("snap_benchmark_1000"), &snap_bytes).unwrap();
        assert_eq!(reopened.items.len(), 1000);
        assert_eq!(reopened.items[999].title, "Service Account #999");
    }
    #[test]
    fn session_rejects_authenticated_but_stale_snapshot() {
        let session_key = [7u8; 32];
        let (head, initial_snap, _, wrap, _, _) =
            initialize_new_vault(b"Valid-Master-Password", fast_test_kdf(), &session_key, 1000).unwrap();
        let mut session = VaultSession::new();
        session.restore_from_session_wrap(&session_key, &wrap, &head, &initial_snap).unwrap();
        let item = VaultItem::from_json_str(r#"{"title":"New item","data":{"kind":"login","password":"secret"}}"#).unwrap();
        let (_, current_head, current_snap) = session.upsert_item(item, 2000, None).unwrap();
        let mut restored = VaultSession::new();
        assert!(restored.restore_from_session_wrap(&session_key, &wrap, &current_head, &initial_snap).is_err());
        assert!(!restored.is_unlocked());
        restored.restore_from_session_wrap(&session_key, &wrap, &current_head, &current_snap).unwrap();
        assert_eq!(restored.list_summaries().unwrap().len(), 1);
    }

    #[test]
    fn imported_kdf_parameters_have_resource_limits() {
        let mut params = fast_test_kdf();
        params.m_cost_kib = u32::MAX;
        assert!(params.validate().is_err());
        params = fast_test_kdf();
        params.t_cost = u32::MAX;
        assert!(params.validate().is_err());
        params = fast_test_kdf();
        params.p_cost = u32::MAX;
        assert!(params.validate().is_err());
    }

    #[test]
    fn compact_codecs_interoperate_with_reference_implementations() {
        use crate::sync_codec::MsgPackWire;
        let item = VaultItem::from_json_str(r#"{"title":"标准兼容性","data":{"kind":"login","password":"Interop#2026"},"tags":["测试"]}"#).unwrap();
        let mut encoded = Vec::new();
        item.encode_msgpack(&mut encoded);
        let value: serde_json::Value = rmp_serde::from_slice(&encoded).unwrap();
        assert!(value.is_array());
        let reference_encoded = rmp_serde::to_vec(&value).unwrap();
        let decoded = VaultItem::decode_msgpack(&mut crate::sync_codec::MpReader::new(&reference_encoded)).unwrap();
        assert_eq!(decoded, item);
        let payload = encoded.repeat(500);
        let compressed = crate::sync_codec::zstd_compress(&payload);
        // Node's libzstd provides an independent implementation without adding C code to WASM.
        fn reference_zstd(input: &[u8], level: Option<i32>) -> Vec<u8> {
            use std::io::Write;
            use std::process::{Command, Stdio};
            let script = "const z=require('node:zlib'),fs=require('node:fs');const input=fs.readFileSync(0);const level=process.argv[1];const result=level==='decode'?z.zstdDecompressSync(input):z.zstdCompressSync(input,{params:{[z.constants.ZSTD_c_compressionLevel]:Number(level)}});fs.writeFileSync(process.argv[2],result);";
            let output_path = std::env::temp_dir().join(format!("vault-codec-reference-{}.bin", std::process::id()));
            let mut child = Command::new("node").args(["-e", script, &level.map(|n| n.to_string()).unwrap_or_else(|| "decode".into())]).arg(&output_path)
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("Node.js with Zstandard support is required for codec interoperability tests");
            child.stdin.take().unwrap().write_all(input).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            let bytes = std::fs::read(&output_path).unwrap();
            std::fs::remove_file(output_path).unwrap();
            bytes
        }
        let external = reference_zstd(&compressed, None);
        assert_eq!(external.len(), payload.len(), "reference decoded length");
        assert!(external == payload, "reference decoded bytes differ");
        for level in [1, 3, 9, 19] {
            let reference = reference_zstd(&payload, Some(level));
            assert!(crate::sync_codec::zstd_decompress_bounded(&reference, payload.len()).unwrap() == payload, "reference level {level} roundtrip differs");
        }
    }

    #[test]
    fn archives_reject_unknown_schema_and_trailing_bytes() {
        let snap = model::VaultSnapshot::new_empty("version-test".into(), "snap-test".into(), 1000);
        let original = export_vaultpack(&snap, b"Backup-Password#2026", fast_test_kdf(), 1000).unwrap();
        let mut unknown = original.clone();
        unknown[4] = 99;
        assert!(import_vaultpack(&unknown, b"Backup-Password#2026").is_err());
        let mut trailing = original;
        trailing.push(0);
        assert!(import_vaultpack(&trailing, b"Backup-Password#2026").is_err());
        let (mut head, _, _, _, _, _) = initialize_new_vault(b"Master-Password#2026", fast_test_kdf(), &[3u8; 32], 1000).unwrap();
        head[4] = 99;
        assert!(VaultHead::from_bytes(&head).is_err());
    }

    #[test]
    fn snapshots_with_legacy_item_array_headers_remain_readable() {
        use crate::sync_codec::MsgPackWire;
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::random().unwrap()).unwrap();
        let mut snapshot = model::VaultSnapshot::new_empty("legacy-vault".into(), "snap-legacy".into(), 1000);
        snapshot.items.push(VaultItem::from_json_str(r#"{"title":"Legacy item","data":{"kind":"login","password":"Old-Secret#2026"}}"#).unwrap());
        let mut item_bytes = Vec::new();
        snapshot.items[0].encode_msgpack(&mut item_bytes);
        let mut raw = Vec::new();
        snapshot.encode_msgpack(&mut raw);
        let item_start = raw.windows(item_bytes.len()).position(|bytes| bytes == item_bytes).unwrap();
        raw[item_start] = 0x9c; // Pre-release writer declared 12 fields while writing 13.
        let mac = keys.compute_state_mac(&raw);
        let mac_start = raw.len() - 32;
        raw[mac_start..].copy_from_slice(&mac);
        let compressed = crate::sync_codec::zstd_compress(&raw);
        let envelope = SealedEnvelope::seal_bucketed(keys.snap_key(), FileRole::Snap, "snap-legacy", 1, &compressed).unwrap().to_bytes().unwrap();
        let restored = open_snapshot(&keys, Some("snap-legacy"), &envelope).unwrap();
        assert_eq!(restored.items[0].title, "Legacy item");
        assert_eq!(restored.state_mac, mac);
    }

    #[test]
    fn authenticated_snapshot_with_unknown_login_field_is_not_rewritten() {
        use crate::sync_codec::{MpReader, MsgPackWire};
        let keys = VaultKeyHierarchy::from_master_dek(SecretKey::random().unwrap()).unwrap();
        let mut snapshot = model::VaultSnapshot::new_empty("forward-vault".into(), "snap-forward".into(), 1000);
        let item = VaultItem::from_json_str(r#"{"id":"x","title":"y","data":{"kind":"login"}}"#).unwrap();
        let mut encoded = Vec::new();
        item.encode_msgpack(&mut encoded);
        snapshot.items.push(item);
        let mut raw = Vec::new();
        snapshot.encode_msgpack(&mut raw);
        let start = raw.windows(encoded.len()).position(|bytes| bytes == encoded).unwrap();
        let mut reader = MpReader::new(&encoded);
        assert_eq!(reader.read_array_len(), 13);
        assert_eq!(reader.read_string(), "x");
        assert_eq!(reader.read_string(), "y");
        assert_eq!(reader.read_u8(), 1);
        let login_start = start + reader.position();
        assert_eq!(reader.read_array_len(), 5);
        assert_eq!(reader.read_string(), "");
        assert_eq!(reader.read_string(), "");
        assert_eq!(reader.read_array_len(), 0);
        assert_eq!(reader.read_array_len(), 0);
        assert_eq!(reader.read_opt_string(), None);
        assert_eq!(raw[login_start], 0x95);
        // Skip the optional Passkey slot to reach a genuinely unknown seventh field.
        raw[login_start] = 0x97;
        raw.splice(start + reader.position()..start + reader.position(), [0xc4, 0, 0x01]);
        let mac = keys.compute_state_mac(&raw);
        let mac_start = raw.len() - 32;
        raw[mac_start..].copy_from_slice(&mac);
        let compressed = crate::sync_codec::zstd_compress(&raw);
        let envelope = SealedEnvelope::seal_bucketed(keys.snap_key(), FileRole::Snap, "snap-forward", 1, &compressed).unwrap().to_bytes().unwrap();
        assert!(open_snapshot(&keys, Some("snap-forward"), &envelope).is_err());
    }

}
