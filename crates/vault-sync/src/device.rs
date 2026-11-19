use std::collections::{BTreeMap, BTreeSet};
use vault_core::error::VaultError;
use vault_core::json_lite::JVal;
use vault_core::model::{DeviceMetadata, VaultSnapshot};
use vault_core::sync_codec::{MpReader, mp_write_array_len, mp_write_str, mp_write_uint};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{batch::invalid, journal::valid_device, remote};

pub(crate) const MAX_DEVICES: usize = 256;

#[derive(Default)]
pub(crate) struct Provenance {
    pub(crate) writers: BTreeMap<String, String>,
    pub(crate) last_edits: BTreeMap<String, u32>,
}

impl Provenance {
    pub(crate) fn read(bytes: &[u8]) -> Result<Self, VaultError> {
        let mut out = Self::default();
        if bytes.is_empty() { return Ok(out); }
        let mut rd = MpReader::new(bytes);
        if rd.read_array_len() != 2 { return Err(invalid()); }
        let writers = rd.read_array_len();
        for _ in 0..writers {
            if rd.read_array_len() != 2 { return Err(invalid()); }
            let (item, device) = (rd.read_string(), rd.read_string());
            if item.is_empty() || !valid_device(&device) || out.writers.insert(item, device).is_some() { return Err(invalid()); }
        }
        let stats = rd.read_array_len();
        if stats > MAX_DEVICES as u32 { return Err(invalid()); }
        for _ in 0..stats {
            if rd.read_array_len() != 2 { return Err(invalid()); }
            let device = rd.read_string();
            let edits = u32::try_from(rd.read_u64()).map_err(|_| invalid())?;
            if !valid_device(&device) || out.last_edits.insert(device, edits).is_some() { return Err(invalid()); }
        }
        rd.finish()?;
        Ok(out)
    }

    pub(crate) fn store(mut self, snapshot: &mut VaultSnapshot) {
        let devices: BTreeSet<_> = snapshot.device_registry.iter().map(|device| device.device_id.as_str()).collect();
        self.last_edits.retain(|id, _| devices.contains(id.as_str()));
        let ids: BTreeSet<_> = snapshot.items.iter().map(|item| item.id.as_str()).collect();
        self.writers.retain(|id, _| ids.contains(id.as_str()));
        snapshot.sync_provenance.clear();
        if self.last_edits.is_empty() && self.writers.is_empty() { return; }
        let out = &mut snapshot.sync_provenance;
        mp_write_array_len(out, 2);
        mp_write_array_len(out, self.writers.len());
        for (item, device) in self.writers {
            mp_write_array_len(out, 2);
            mp_write_str(out, &item);
            mp_write_str(out, &device);
        }
        mp_write_array_len(out, self.last_edits.len());
        for (device, count) in self.last_edits {
            mp_write_array_len(out, 2);
            mp_write_str(out, &device);
            mp_write_uint(out, u64::from(count));
        }
    }
}

pub(crate) fn source(devices: &[DeviceMetadata], device_id: Option<&str>, fallback: &str) -> String {
    let Some(id) = device_id.filter(|id| valid_device(id)) else { return fallback.into(); };
    devices.iter().find(|row| row.device_id == id && !row.device_name.trim().is_empty())
        .map_or_else(|| format!("设备 {}", &id[..8]), |row| row.device_name.clone())
}

pub(crate) fn indexed(devices: &[DeviceMetadata]) -> Result<BTreeMap<&str, &DeviceMetadata>, VaultError> {
    let map: BTreeMap<_, _> = devices.iter().map(|device| (device.device_id.as_str(), device)).collect();
    if devices.len() > MAX_DEVICES || map.len() != devices.len() || devices.iter().any(|device|
        !valid_device(&device.device_id) || device.dev_tag.len() != 8 ||
        !device.dev_tag.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) ||
        device.device_name.len() > 240 || device.os_arch.len() > 80 ||
        device.browser.len() > 80 || device.ext_version.len() > 40) { return Err(invalid()); }
    Ok(map)
}

pub(crate) fn merge(base: &[DeviceMetadata], ours: &[DeviceMetadata], theirs: &[DeviceMetadata]) -> Result<Vec<DeviceMetadata>, VaultError> {
    let (base, ours, theirs) = (indexed(base)?, indexed(ours)?, indexed(theirs)?);
    let ids: BTreeSet<_> = base.keys().chain(ours.keys()).chain(theirs.keys()).copied().collect();
    let mut out = Vec::new();
    for id in ids {
        let (b, o, t) = (base.get(id).copied(), ours.get(id).copied(), theirs.get(id).copied());
        let value = if o == t || o == b { t } else if t == b { o }
            else if let (Some(o), Some(t)) = (o, t) {
                Some(if (o.last_seen_at_ms, &o.dev_tag, &o.device_name) >= (t.last_seen_at_ms, &t.dev_tag, &t.device_name) { o } else { t })
            } else { None }; // A concurrent removal never silently reclaims an obsolete identity.
        out.extend(value.cloned());
    }
    if out.len() > MAX_DEVICES { return Err(invalid()); }
    Ok(out)
}

fn value(device: &DeviceMetadata, edits: Option<&u32>) -> JVal {
    JVal::Obj(vec![("id", JVal::Str(device.device_id.clone())), ("name", JVal::Str(device.device_name.clone())),
        ("system", JVal::Str(device.os_arch.clone())), ("browser", JVal::Str(device.browser.clone())),
        ("version", JVal::Str(device.ext_version.clone())), ("created", JVal::Uint(device.created_at_ms)),
        ("lastSeen", JVal::Uint(device.last_seen_at_ms)), ("lastEditCount", edits.map_or(JVal::Null, |count| JVal::Uint(u64::from(*count))))])
}

fn update(snapshot: &mut VaultSnapshot, input: &JVal) -> Result<(), VaultError> {
    let action = input.get_str("action");
    let id = input.get_str("id");
    let tag = input.get_str("tag");
    let time = input.get_u64("time");
    if !valid_device(&id) { return Err(invalid()); }
    let existing = snapshot.device_registry.iter_mut().find(|device| device.device_id == id);
    match (action.as_str(), existing) {
        ("seen", Some(device)) if device.dev_tag == tag => {
            if time.saturating_sub(device.last_seen_at_ms) >= 60_000 { device.last_seen_at_ms = time; }
        }
        ("seen", _) => {}
        ("remove", Some(_)) => { snapshot.device_registry.retain(|device| device.device_id != id); }
        ("track" | "rename" | "claim", found) => {
            if action == "claim" && found.is_none() || action == "rename" && found.is_none() { return Err(invalid()); }
            let name = input.get_str("name");
            if action != "track" && name.trim().is_empty() { return Err(invalid()); }
            if let Some(device) = found {
                if action != "track" { device.device_name = name; }
                if action == "claim" {
                    device.dev_tag = tag;
                    device.os_arch = input.get_str("system");
                    device.browser = input.get_str("browser");
                    device.ext_version = input.get_str("version");
                }
                device.last_seen_at_ms = time.max(device.last_seen_at_ms);
            } else {
                snapshot.device_registry.push(DeviceMetadata { device_id: id, dev_tag: tag, device_name: name,
                    os_arch: input.get_str("system"), browser: input.get_str("browser"), ext_version: input.get_str("version"),
                    created_at_ms: time, last_seen_at_ms: time });
            }
        }
        _ => return Err(invalid()),
    }
    snapshot.device_registry.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    indexed(&snapshot.device_registry)?;
    Ok(())
}

#[wasm_bindgen]
pub fn wasm_sync_devices(key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8]) -> Result<String, JsValue> {
    let (key, wrap) = (Zeroizing::new(key), Zeroizing::new(wrap));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let snapshot = super::verified_snapshot(&keys, &vault, epoch, head, snap)?;
    indexed(&snapshot.device_registry)?;
    let provenance = Provenance::read(&snapshot.sync_provenance)?;
    Ok(JVal::Arr(snapshot.device_registry.iter().map(|device| value(device, provenance.last_edits.get(&device.device_id))).collect()).stringify())
}

#[wasm_bindgen]
pub fn wasm_sync_device_change(key: Vec<u8>, wrap: Vec<u8>, head: &[u8], snap: &[u8], action: String) -> Result<remote::Replayed, JsValue> {
    let (key, wrap, action) = (Zeroizing::new(key), Zeroizing::new(wrap), Zeroizing::new(action));
    let (vault, epoch, keys) = super::keys(&key, &wrap)?;
    let mut snapshot = super::verified_snapshot(&keys, &vault, epoch, head, snap)?;
    update(&mut snapshot, &JVal::parse(&action)?)?;
    remote::materialize(&keys, head, snapshot).map_err(Into::into)
}
