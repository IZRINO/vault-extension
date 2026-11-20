use vault_core::{audit::audit_vault_items, session::VaultSession};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Read an authenticated local snapshot and return only audit findings, not credentials.
#[wasm_bindgen]
pub fn wasm_audit_snapshot(key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snapshot: &[u8]) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let mut session = VaultSession::new();
    session.restore_from_session_wrap(&key, &wrap, head, snapshot)?;
    let report = audit_vault_items(&session.snapshot_ref()?.items);
    session.lock_and_zeroize();
    Ok(report.to_json_value().stringify())
}
