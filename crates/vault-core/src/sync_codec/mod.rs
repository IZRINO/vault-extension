mod zstd_tiny;

use zeroize::{Zeroize, Zeroizing};

pub use self::zstd_tiny::{zstd_compress, zstd_decompress_bounded};

use crate::crypto::{
    csprng_fill, derive_master_kek, derive_recovery_kek, FileRole, KdfParams, SealedEnvelope,
    SecretBytes, SecretKey, VaultKeyHierarchy, WrappedKey, SCHEMA_VERSION,
};
use crate::error::VaultError;
use crate::json_lite::concat2;
use crate::model::{
    CardBrand, CredentialData, CustomField, DeveloperCredential, DeveloperCredentialSubtype,
    DeviceMetadata, IdentityCredential, LoginCredential, PasswordHistoryEntry,
    PaymentCardCredential, UriEntry, UriMatchRule, VaultItem, VaultSnapshot,
};

pub const HEAD_MAGIC: [u8; 4] = *b"VLTH";
pub const VAULTPACK_MAGIC: [u8; 4] = *b"VLTP";
const MAX_MSGPACK_BYTES: usize = 32 * 1024 * 1024;
const MAX_VAULTPACK_BYTES: usize = 16 * 1024 * 1024;
const VAULTPACK_HEADER_BYTES: usize = 62;

fn check_vaultpack_size(bytes: usize) -> Result<(), VaultError> {
    if bytes > MAX_VAULTPACK_BYTES {
        return Err(VaultError::VaultpackTooLarge);
    }
    Ok(())
}

// ============================================================================
// Compact Direct-Slice RFC MessagePack Wire Codec (zero `rmp` / `io::Cursor` bloat)
// ============================================================================

pub struct MpReader<'a> {
    buf: &'a [u8],
    pos: usize,
    err: bool,
}

impl<'a> MpReader<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            err: false,
        }
    }

    #[inline]
    pub fn finish(&self) -> Result<(), VaultError> {
        if self.err {
            Err(mp_read_err())
        } else {
            Ok(())
        }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn consumed_since(&self, start: usize) -> &[u8] {
        self.buf.get(start..self.pos).unwrap_or_default()
    }

    #[inline(never)]
    fn take(&mut self, n: usize) -> &'a [u8] {
        if self.err {
            return &[];
        }
        let Some(end) = self.pos.checked_add(n) else {
            self.err = true;
            return &[];
        };
        if end > self.buf.len() {
            self.err = true;
            return &[];
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        s
    }

    #[inline(never)]
    fn byte(&mut self) -> u8 {
        let s = self.take(1);
        if s.is_empty() { 0 } else { s[0] }
    }

    #[inline(never)]
    fn be_len(&mut self, width: usize) -> usize {
        let b = self.take(width);
        let mut v = 0usize;
        for &x in b {
            v = (v << 8) | (x as usize);
        }
        v
    }

    #[inline(never)]
    pub fn read_array_len(&mut self) -> u32 {
        if self.err {
            return 0;
        }
        let m = self.byte();
        match m {
            0x90..=0x9f => (m & 0x0f) as u32,
            0xdc => self.be_len(2) as u32,
            0xdd => self.be_len(4) as u32,
            _ => {
                self.err = true;
                0
            }
        }
    }

    #[inline(never)]
    pub fn read_bool(&mut self) -> bool {
        if self.err {
            return false;
        }
        match self.byte() {
            0xc2 => false,
            0xc3 => true,
            _ => {
                self.err = true;
                false
            }
        }
    }

    #[inline(never)]
    pub fn read_u64(&mut self) -> u64 {
        if self.err {
            return 0;
        }
        let m = self.byte();
        match m {
            0x00..=0x7f => m as u64,
            0xcc => self.byte() as u64,
            0xcd => self.be_len(2) as u64,
            0xce => self.be_len(4) as u64,
            0xcf => {
                let b = self.take(8);
                if b.len() < 8 {
                    0
                } else {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(b);
                    u64::from_be_bytes(arr)
                }
            }
            0xd0 => {
                let v = self.byte() as i8;
                if v < 0 {
                    self.err = true;
                    0
                } else {
                    v as u64
                }
            }
            0xd1 => {
                let b = self.take(2);
                if b.len() < 2 {
                    0
                } else {
                    let v = i16::from_be_bytes([b[0], b[1]]);
                    if v < 0 {
                        self.err = true;
                        0
                    } else {
                        v as u64
                    }
                }
            }
            0xd2 => {
                let b = self.take(4);
                if b.len() < 4 {
                    0
                } else {
                    let v = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                    if v < 0 {
                        self.err = true;
                        0
                    } else {
                        v as u64
                    }
                }
            }
            0xd3 => {
                let b = self.take(8);
                if b.len() < 8 {
                    0
                } else {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(b);
                    let v = i64::from_be_bytes(arr);
                    if v < 0 {
                        self.err = true;
                        0
                    } else {
                        v as u64
                    }
                }
            }
            _ => {
                self.err = true;
                0
            }
        }
    }

    #[inline(never)]
    pub fn read_u8(&mut self) -> u8 {
        let v = self.read_u64();
        if v > 255 {
            self.err = true;
            0
        } else {
            v as u8
        }
    }

    #[inline(never)]
    pub fn read_opt_u64(&mut self) -> Option<u64> {
        if self.err {
            return None;
        }
        if self.pos < self.buf.len() && self.buf[self.pos] == 0xc0 {
            self.pos += 1;
            return None;
        }
        Some(self.read_u64())
    }

    #[inline(never)]
    pub fn read_string(&mut self) -> String {
        if self.err {
            return String::new();
        }
        let m = self.byte();
        let len = match m {
            0xa0..=0xbf => (m & 0x1f) as usize,
            0xd9 => self.be_len(1),
            0xda => self.be_len(2),
            0xdb => self.be_len(4),
            _ => {
                self.err = true;
                return String::new();
            }
        };
        let slice = self.take(len);
        if self.err {
            return String::new();
        }
        match std::str::from_utf8(slice) {
            Ok(s) => s.to_string(),
            Err(_) => {
                self.err = true;
                String::new()
            }
        }
    }

    #[inline(never)]
    pub fn read_opt_string(&mut self) -> Option<String> {
        if self.err {
            return None;
        }
        if self.pos < self.buf.len() && self.buf[self.pos] == 0xc0 {
            self.pos += 1;
            return None;
        }
        Some(self.read_string())
    }

    #[inline(never)]
    pub fn read_bin_vec(&mut self) -> Vec<u8> {
        if self.err {
            return Vec::new();
        }
        let m = self.byte();
        let len = match m {
            0xc4 => self.be_len(1),
            0xc5 => self.be_len(2),
            0xc6 => self.be_len(4),
            _ => {
                self.err = true;
                return Vec::new();
            }
        };
        let s = self.take(len);
        if self.err { Vec::new() } else { s.to_vec() }
    }

    fn require_array_len(&mut self, expected: u32) {
        self.err |= self.read_array_len() != expected;
    }

    fn read_tag(&mut self, max: u8) -> u8 {
        let tag = self.read_u8();
        self.err |= tag > max;
        tag
    }

    fn decode_object<T: MsgPackWire>(&mut self) -> Result<T, VaultError> {
        let value = T::decode_msgpack(self)?;
        if self.err || self.pos != self.buf.len() { return Err(mp_read_err()); }
        Ok(value)
    }
}

#[inline(never)]
fn mp_read_err() -> VaultError {
    VaultError::InvalidFormat("msgpack decode error".into())
}

#[inline(never)]
pub fn mp_write_array_len(wr: &mut Vec<u8>, len: usize) {
    if len <= 15 {
        wr.push(0x90 | (len as u8));
    } else if len <= 0xffff {
        wr.push(0xdc);
        wr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        wr.push(0xdd);
        wr.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

#[inline(never)]
pub fn mp_write_bool(wr: &mut Vec<u8>, val: bool) {
    wr.push(if val { 0xc3 } else { 0xc2 });
}

#[inline(never)]
pub fn mp_write_uint(wr: &mut Vec<u8>, val: u64) {
    if val <= 0x7f {
        wr.push(val as u8);
    } else if val <= 0xff {
        wr.push(0xcc);
        wr.push(val as u8);
    } else if val <= 0xffff {
        wr.push(0xcd);
        wr.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xffff_ffff {
        wr.push(0xce);
        wr.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        wr.push(0xcf);
        wr.extend_from_slice(&val.to_be_bytes());
    }
}

#[inline(never)]
pub fn mp_write_opt_u64(wr: &mut Vec<u8>, val: Option<u64>) {
    match val {
        Some(v) => mp_write_uint(wr, v),
        None => wr.push(0xc0),
    }
}

#[inline(never)]
pub fn mp_write_str(wr: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let len = b.len();
    if len <= 31 {
        wr.push(0xa0 | (len as u8));
    } else if len <= 0xff {
        wr.push(0xd9);
        wr.push(len as u8);
    } else if len <= 0xffff {
        wr.push(0xda);
        wr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        wr.push(0xdb);
        wr.extend_from_slice(&(len as u32).to_be_bytes());
    }
    wr.extend_from_slice(b);
}

#[inline(never)]
fn mp_write_opt_str(wr: &mut Vec<u8>, val: &Option<String>) {
    match val {
        Some(s) => mp_write_str(wr, s),
        None => wr.push(0xc0),
    }
}

#[inline(never)]
pub fn mp_write_bin(wr: &mut Vec<u8>, b: &[u8]) {
    let len = b.len();
    if len <= 0xff {
        wr.push(0xc4);
        wr.push(len as u8);
    } else if len <= 0xffff {
        wr.push(0xc5);
        wr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        wr.push(0xc6);
        wr.extend_from_slice(&(len as u32).to_be_bytes());
    }
    wr.extend_from_slice(b);
}

pub trait MsgPackWire: Sized {
    fn encode_msgpack(&self, wr: &mut Vec<u8>);
    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError>;
}

impl MsgPackWire for Vec<u8> {
    fn encode_msgpack(&self, wr: &mut Vec<u8>) {
        mp_write_bin(wr, self);
    }
    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        let v = rd.read_bin_vec();
        rd.finish()?;
        Ok(v)
    }
}

impl MsgPackWire for HeadEncryptedPointer {
    fn encode_msgpack(&self, wr: &mut Vec<u8>) {
        mp_write_array_len(wr, 5);
        mp_write_str(wr, &self.latest_snapshot_id);
        mp_write_array_len(wr, self.recent_snapshot_ids.len());
        for s in &self.recent_snapshot_ids {
            mp_write_str(wr, s);
        }
        mp_write_uint(wr, self.snapshot_epoch);
        mp_write_bin(wr, &self.state_root_mac);
        mp_write_uint(wr, self.updated_at_ms);
    }

    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        let len = rd.read_array_len();
        if rd.err || len != 5 {
            return Err(mp_read_err());
        }
        let latest_snapshot_id = rd.read_string();
        let rlen = rd.read_array_len() as usize;
        let mut recent_snapshot_ids = Vec::with_capacity(rlen.min(32));
        for _ in 0..rlen {
            if rd.err {
                break;
            }
            recent_snapshot_ids.push(rd.read_string());
        }
        let snapshot_epoch = rd.read_u64();
        let mac_vec = rd.read_bin_vec();
        let updated_at_ms = rd.read_u64();
        rd.finish()?;
        if mac_vec.len() != 32 {
            return Err(mp_read_err());
        }
        let mut state_root_mac = [0u8; 32];
        state_root_mac.copy_from_slice(&mac_vec);
        Ok(Self {
            latest_snapshot_id,
            recent_snapshot_ids,
            snapshot_epoch,
            state_root_mac,
            updated_at_ms,
        })
    }
}

impl MsgPackWire for VaultItem {
    fn encode_msgpack(&self, wr: &mut Vec<u8>) {
        mp_write_array_len(wr, 13);
        mp_write_str(wr, &self.id);
        mp_write_str(wr, &self.title);
        match &self.data {
            CredentialData::Login(l) => {
                mp_write_uint(wr, 1);
                mp_write_array_len(wr, if l.passkey_data.is_empty() { 5 } else { 6 });
                mp_write_str(wr, &l.username);
                mp_write_str(wr, &l.password);
                mp_write_array_len(wr, l.uris.len());
                for u in &l.uris {
                    mp_write_array_len(wr, 2);
                    mp_write_str(wr, &u.uri);
                    mp_write_uint(wr, u.match_rule.to_u8() as u64);
                }
                mp_write_array_len(wr, l.password_history.len());
                for h in &l.password_history {
                    mp_write_array_len(wr, 3);
                    mp_write_str(wr, &h.password);
                    mp_write_uint(wr, h.changed_at_ms);
                    mp_write_opt_str(wr, &h.source_device);
                }
                mp_write_opt_str(wr, &l.totp_uri);
                if !l.passkey_data.is_empty() { mp_write_bin(wr, &l.passkey_data); }
            }
            CredentialData::PaymentCard(c) => {
                mp_write_uint(wr, 2);
                mp_write_array_len(wr, 8);
                mp_write_str(wr, &c.cardholder_name);
                mp_write_str(wr, &c.card_number);
                mp_write_uint(wr, c.brand.to_u8() as u64);
                mp_write_str(wr, &c.exp_month);
                mp_write_str(wr, &c.exp_year);
                mp_write_str(wr, &c.cvv);
                mp_write_str(wr, &c.card_pin);
                mp_write_str(wr, &c.billing_address);
            }
            CredentialData::Identity(id) => {
                mp_write_uint(wr, 3);
                mp_write_array_len(wr, 11);
                mp_write_str(wr, &id.full_name);
                mp_write_str(wr, &id.phone);
                mp_write_str(wr, &id.email);
                mp_write_str(wr, &id.national_id_or_passport);
                mp_write_str(wr, &id.country);
                mp_write_str(wr, &id.province);
                mp_write_str(wr, &id.city);
                mp_write_str(wr, &id.address_line);
                mp_write_str(wr, &id.postal_code);
                mp_write_str(wr, &id.company);
                mp_write_str(wr, &id.tax_id);
            }
            CredentialData::Developer(d) => {
                mp_write_uint(wr, 4);
                mp_write_array_len(wr, 6);
                mp_write_uint(wr, d.subtype.to_u8() as u64);
                mp_write_str(wr, &d.service_or_product);
                mp_write_str(wr, &d.token_or_license);
                mp_write_str(wr, &d.public_key);
                mp_write_str(wr, &d.private_key);
                mp_write_opt_u64(wr, d.expires_at_ms);
            }
        }
        mp_write_str(wr, &self.note);
        mp_write_array_len(wr, self.custom_fields.len());
        for cf in &self.custom_fields {
            mp_write_array_len(wr, 3);
            mp_write_str(wr, &cf.name);
            mp_write_str(wr, &cf.value);
            mp_write_bool(wr, cf.hidden);
        }
        mp_write_array_len(wr, self.tags.len());
        for t in &self.tags {
            mp_write_str(wr, t);
        }
        mp_write_bool(wr, self.pinned);
        mp_write_bool(wr, self.require_reprompt);
        mp_write_bool(wr, self.trashed);
        mp_write_opt_u64(wr, self.trashed_at_ms);
        mp_write_uint(wr, self.created_at_ms);
        mp_write_array_len(wr, 2);
        mp_write_uint(wr, self.updated_at_ms);
        mp_write_uint(wr, self.revision);
    }

    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        let len = rd.read_array_len();
        // The pre-release writer declared 12 fields but wrote 13.
        if rd.err || !matches!(len, 12 | 13) {
            return Err(mp_read_err());
        }
        let id = rd.read_string();
        let title = rd.read_string();
        let kind_tag = rd.read_u8();
        let data = match kind_tag {
            1 => {
                let dlen = rd.read_array_len();
                if !(4..=6).contains(&dlen) { return Err(mp_read_err()); }
                let username = rd.read_string();
                let password = rd.read_string();
                let ulen = rd.read_array_len() as usize;
                let mut uris = Vec::with_capacity(ulen.min(64));
                for _ in 0..ulen {
                    if rd.err {
                        break;
                    }
                    rd.require_array_len(2);
                    let uri = rd.read_string();
                    let rule = UriMatchRule::from_u8(rd.read_tag(5));
                    uris.push(UriEntry {
                        uri,
                        match_rule: rule,
                    });
                }
                let hlen = rd.read_array_len() as usize;
                let mut password_history = Vec::with_capacity(hlen.min(32));
                for _ in 0..hlen {
                    if rd.err {
                        break;
                    }
                    rd.require_array_len(3);
                    let pw = rd.read_string();
                    let changed_at_ms = rd.read_u64();
                    let source_device = rd.read_opt_string();
                    password_history.push(PasswordHistoryEntry {
                        password: pw,
                        changed_at_ms,
                        source_device,
                    });
                }
                let totp_uri = if dlen >= 5 { rd.read_opt_string() } else { None };
                let passkey_data = if dlen >= 6 { rd.read_bin_vec() } else { Vec::new() };
                CredentialData::Login(LoginCredential {
                    username,
                    password,
                    uris,
                    password_history,
                    totp_uri,
                    passkey_data,
                })
            }
            2 => {
                rd.require_array_len(8);
                let cardholder_name = rd.read_string();
                let card_number = rd.read_string();
                let brand = CardBrand::from_u8(rd.read_tag(6));
                let exp_month = rd.read_string();
                let exp_year = rd.read_string();
                let cvv = rd.read_string();
                let card_pin = rd.read_string();
                let billing_address = rd.read_string();
                CredentialData::PaymentCard(PaymentCardCredential {
                    cardholder_name,
                    card_number,
                    brand,
                    exp_month,
                    exp_year,
                    cvv,
                    card_pin,
                    billing_address,
                })
            }
            3 => {
                rd.require_array_len(11);
                let full_name = rd.read_string();
                let phone = rd.read_string();
                let email = rd.read_string();
                let national_id_or_passport = rd.read_string();
                let country = rd.read_string();
                let province = rd.read_string();
                let city = rd.read_string();
                let address_line = rd.read_string();
                let postal_code = rd.read_string();
                let company = rd.read_string();
                let tax_id = rd.read_string();
                CredentialData::Identity(IdentityCredential {
                    full_name,
                    phone,
                    email,
                    national_id_or_passport,
                    country,
                    province,
                    city,
                    address_line,
                    postal_code,
                    company,
                    tax_id,
                })
            }
            4 => {
                rd.require_array_len(6);
                let subtype = DeveloperCredentialSubtype::from_u8(rd.read_tag(3));
                let service_or_product = rd.read_string();
                let token_or_license = rd.read_string();
                let public_key = rd.read_string();
                let private_key = rd.read_string();
                let expires_at_ms = rd.read_opt_u64();
                CredentialData::Developer(DeveloperCredential {
                    subtype,
                    service_or_product,
                    token_or_license,
                    public_key,
                    private_key,
                    expires_at_ms,
                })
            }
            _ => {
                return Err(VaultError::InvalidFormat(
                    "unknown credential kind tag".into(),
                ))
            }
        };

        let note = rd.read_string();
        let cflen = rd.read_array_len() as usize;
        let mut custom_fields = Vec::with_capacity(cflen.min(64));
        for _ in 0..cflen {
            if rd.err {
                break;
            }
            rd.require_array_len(3);
            let name = rd.read_string();
            let value = rd.read_string();
            let hidden = rd.read_bool();
            custom_fields.push(CustomField {
                name,
                value,
                hidden,
            });
        }
        let tlen = rd.read_array_len() as usize;
        let mut tags = Vec::with_capacity(tlen.min(64));
        for _ in 0..tlen {
            if rd.err {
                break;
            }
            tags.push(rd.read_string());
        }
        let pinned = rd.read_bool();
        let require_reprompt = rd.read_bool();
        let trashed = rd.read_bool();
        let trashed_at_ms = rd.read_opt_u64();
        let created_at_ms = rd.read_u64();
        rd.require_array_len(2);
        let updated_at_ms = rd.read_u64();
        let revision = rd.read_u64();
        rd.finish()?;

        Ok(Self {
            id,
            title,
            data,
            note,
            custom_fields,
            tags,
            pinned,
            require_reprompt,
            trashed,
            trashed_at_ms,
            created_at_ms,
            updated_at_ms,
            revision,
        })
    }
}

impl MsgPackWire for DeviceMetadata {
    fn encode_msgpack(&self, wr: &mut Vec<u8>) {
        mp_write_array_len(wr, 8);
        mp_write_str(wr, &self.device_id);
        mp_write_str(wr, &self.dev_tag);
        mp_write_str(wr, &self.device_name);
        mp_write_str(wr, &self.os_arch);
        mp_write_str(wr, &self.browser);
        mp_write_str(wr, &self.ext_version);
        mp_write_uint(wr, self.created_at_ms);
        mp_write_uint(wr, self.last_seen_at_ms);
    }

    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        rd.require_array_len(8);
        let device_id = rd.read_string();
        let dev_tag = rd.read_string();
        let device_name = rd.read_string();
        let os_arch = rd.read_string();
        let browser = rd.read_string();
        let ext_version = rd.read_string();
        let created_at_ms = rd.read_u64();
        let last_seen_at_ms = rd.read_u64();
        rd.finish()?;
        Ok(Self {
            device_id,
            dev_tag,
            device_name,
            os_arch,
            browser,
            ext_version,
            created_at_ms,
            last_seen_at_ms,
        })
    }
}

impl MsgPackWire for VaultSnapshot {
    fn encode_msgpack(&self, wr: &mut Vec<u8>) {
        mp_write_array_len(wr, if self.sync_provenance.is_empty() { 8 } else { 9 });
        mp_write_str(wr, &self.vault_id);
        mp_write_str(wr, &self.snapshot_id);
        mp_write_uint(wr, self.snapshot_epoch);
        mp_write_uint(wr, self.hlc_timestamp);
        mp_write_array_len(wr, self.items.len());
        for item in &self.items {
            item.encode_msgpack(wr);
        }
        mp_write_array_len(wr, self.device_registry.len());
        for dev in &self.device_registry {
            dev.encode_msgpack(wr);
        }
        mp_write_array_len(wr, self.included_wal_ids.len());
        for wid in &self.included_wal_ids {
            mp_write_str(wr, wid);
        }
        if !self.sync_provenance.is_empty() { mp_write_bin(wr, &self.sync_provenance); }
        // open_snapshot authenticates the stored bytes and expects the MAC at the tail.
        mp_write_bin(wr, &self.state_mac);
    }

    fn decode_msgpack(rd: &mut MpReader<'_>) -> Result<Self, VaultError> {
        let len = rd.read_array_len();
        if rd.err || (len != 8 && len != 9) {
            return Err(mp_read_err());
        }
        let vault_id = rd.read_string();
        let snapshot_id = rd.read_string();
        let snapshot_epoch = rd.read_u64();
        let hlc_timestamp = rd.read_u64();
        let ilen = rd.read_array_len() as usize;
        let mut items = Vec::with_capacity(ilen.min(4096));
        for _ in 0..ilen {
            if rd.err {
                break;
            }
            items.push(VaultItem::decode_msgpack(rd)?);
        }
        let dlen = rd.read_array_len() as usize;
        let mut device_registry = Vec::with_capacity(dlen.min(64));
        for _ in 0..dlen {
            if rd.err {
                break;
            }
            device_registry.push(DeviceMetadata::decode_msgpack(rd)?);
        }
        let wlen = rd.read_array_len() as usize;
        let mut included_wal_ids = Vec::with_capacity(wlen.min(256));
        for _ in 0..wlen {
            if rd.err {
                break;
            }
            included_wal_ids.push(rd.read_string());
        }
        let sync_provenance = if len == 9 { rd.read_bin_vec() } else { Vec::new() };
        let mac_vec = rd.read_bin_vec();
        rd.finish()?;
        if mac_vec.len() != 32 {
            return Err(mp_read_err());
        }
        let mut state_mac = [0u8; 32];
        state_mac.copy_from_slice(&mac_vec);
        Ok(Self {
            vault_id,
            snapshot_id,
            snapshot_epoch,
            hlc_timestamp,
            items,
            device_registry,
            included_wal_ids,
            sync_provenance,
            state_mac,
        })
    }
}

fn read_exact_slice<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], VaultError> {
    if buf.len() < pos.saturating_add(len) {
        return Err(VaultError::InvalidFormat("binary header truncated".into()));
    }
    let slice = &buf[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn read_exact_arr<const N: usize>(buf: &[u8], pos: &mut usize) -> Result<[u8; N], VaultError> {
    let s = read_exact_slice(buf, pos, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(s);
    Ok(out)
}

/// Encrypted pointer block inside `head.bin` (keeps snapshot IDs and history opaque on disk/WebDAV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadEncryptedPointer {
    pub latest_snapshot_id: String,
    pub recent_snapshot_ids: Vec<String>,
    pub snapshot_epoch: u64,
    pub state_root_mac: [u8; 32],
    pub updated_at_ms: u64,
}

/// `head.bin`: holds public KDF parameters + `key_epoch` + dual-wrapped Master DEK (`master` + `recovery`)
/// + an encrypted & bucket-aligned pointer envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHead {
    pub magic: [u8; 4],
    pub schema_version: u16,
    pub vault_id: String,
    pub key_epoch: u64,
    pub kdf_params: KdfParams,
    pub recovery_salt: [u8; 32],
    pub wrapped_dek_master: WrappedKey,
    pub wrapped_dek_recovery: WrappedKey,
    pub encrypted_pointer_envelope: Vec<u8>,
}

impl VaultHead {
    pub fn create_new(
        vault_id: String,
        master_kek: &SecretKey,
        kdf_params: KdfParams,
        recovery_secret: &SecretKey,
        keys: &VaultKeyHierarchy,
        pointer: &HeadEncryptedPointer,
    ) -> Result<Self, VaultError> {
        kdf_params.validate()?;
        let key_epoch = 1u64;
        let mut recovery_salt = [0u8; 32];
        csprng_fill(&mut recovery_salt)?;
        let recovery_kek = derive_recovery_kek(recovery_secret, &recovery_salt)?;

        let master_obj = concat2(&vault_id, ":master");
        let recovery_obj = concat2(&vault_id, ":recovery");
        let wrapped_dek_master = WrappedKey::wrap(
            master_kek,
            keys.master_dek(),
            FileRole::Head,
            &master_obj,
            key_epoch,
        )?;
        let wrapped_dek_recovery = WrappedKey::wrap(
            &recovery_kek,
            keys.master_dek(),
            FileRole::Head,
            &recovery_obj,
            1, // recovery wrapping stays valid across master password changes unless recovery is explicitly rotated
        )?;

        let pointer_env = seal_compact_object(
            keys.head_payload_key(),
            FileRole::Head,
            &concat2(&vault_id, ":pointer"),
            key_epoch,
            pointer,
        )?;

        Ok(Self {
            magic: HEAD_MAGIC,
            schema_version: SCHEMA_VERSION,
            vault_id,
            key_epoch,
            kdf_params,
            recovery_salt,
            wrapped_dek_master,
            wrapped_dek_recovery,
            encrypted_pointer_envelope: pointer_env,
        })
    }

    pub fn unlock_with_master_kek(&self, master_kek: &SecretKey) -> Result<VaultKeyHierarchy, VaultError> {
        let master_obj = concat2(&self.vault_id, ":master");
        let dek = self.wrapped_dek_master.unwrap(
            master_kek,
            FileRole::Head,
            &master_obj,
            self.key_epoch,
        )?;
        VaultKeyHierarchy::from_master_dek(dek)
    }

    pub fn unlock_with_master_password(
        &self,
        master_password: &[u8],
    ) -> Result<VaultKeyHierarchy, VaultError> {
        let master_kek = derive_master_kek(master_password, &self.kdf_params)?;
        self.unlock_with_master_kek(&master_kek)
    }

    pub fn unlock_with_recovery_secret(
        &self,
        recovery_secret: &SecretKey,
    ) -> Result<VaultKeyHierarchy, VaultError> {
        let recovery_kek = derive_recovery_kek(recovery_secret, &self.recovery_salt)?;
        let recovery_obj = concat2(&self.vault_id, ":recovery");
        let dek = self
            .wrapped_dek_recovery
            .unwrap(&recovery_kek, FileRole::Head, &recovery_obj, 1)?;
        VaultKeyHierarchy::from_master_dek(dek)
    }

    /// Rotates the Master Password (`wrapped_dek_master` + `kdf_params` + `key_epoch += 1`)
    /// WITHOUT re-encrypting the underlying Master DEK or existing `snap` ciphertexts!
    pub fn rotate_master_kek(
        &mut self,
        keys: &VaultKeyHierarchy,
        new_master_kek: &SecretKey,
        new_kdf_params: KdfParams,
        pointer: &HeadEncryptedPointer,
    ) -> Result<(), VaultError> {
        new_kdf_params.validate()?;
        let next_epoch = self.key_epoch.saturating_add(1);
        let master_obj = concat2(&self.vault_id, ":master");
        self.wrapped_dek_master = WrappedKey::wrap(
            new_master_kek,
            keys.master_dek(),
            FileRole::Head,
            &master_obj,
            next_epoch,
        )?;
        self.kdf_params = new_kdf_params;
        self.key_epoch = next_epoch;
        self.encrypted_pointer_envelope = seal_compact_object(
            keys.head_payload_key(),
            FileRole::Head,
            &concat2(&self.vault_id, ":pointer"),
            next_epoch,
            pointer,
        )?;
        Ok(())
    }

    pub fn decrypt_pointer(
        &self,
        keys: &VaultKeyHierarchy,
    ) -> Result<HeadEncryptedPointer, VaultError> {
        let ptr_obj = concat2(&self.vault_id, ":pointer");
        open_compact_object(
            keys.head_payload_key(),
            FileRole::Head,
            Some(&ptr_obj),
            &self.encrypted_pointer_envelope,
        )
    }

    pub fn update_pointer(
        &mut self,
        keys: &VaultKeyHierarchy,
        pointer: &HeadEncryptedPointer,
    ) -> Result<(), VaultError> {
        self.encrypted_pointer_envelope = seal_compact_object(
            keys.head_payload_key(),
            FileRole::Head,
            &concat2(&self.vault_id, ":pointer"),
            self.key_epoch,
            pointer,
        )?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let vid = self.vault_id.as_bytes();
        if vid.len() > u16::MAX as usize {
            return Err(VaultError::InvalidInput("vault_id too long".into()));
        }
        let mut out = Vec::with_capacity(280 + vid.len() + self.encrypted_pointer_envelope.len());
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        out.extend_from_slice(&(vid.len() as u16).to_le_bytes());
        out.extend_from_slice(vid);
        out.extend_from_slice(&self.key_epoch.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.m_cost_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.t_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.p_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf_params.salt);
        out.extend_from_slice(&self.recovery_salt);
        for wk in [&self.wrapped_dek_master, &self.wrapped_dek_recovery] {
            out.extend_from_slice(&wk.nonce);
            out.extend_from_slice(&wk.tag);
            out.extend_from_slice(&wk.ciphertext);
        }
        out.extend_from_slice(&(self.encrypted_pointer_envelope.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.encrypted_pointer_envelope);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        let mut pos = 0usize;
        let magic = read_exact_arr::<4>(bytes, &mut pos)?;
        if magic != HEAD_MAGIC {
            return Err(VaultError::InvalidFormat("invalid head.bin magic".into()));
        }
        let schema_version = u16::from_le_bytes(read_exact_arr::<2>(bytes, &mut pos)?);
        if schema_version != SCHEMA_VERSION {
            return Err(VaultError::InvalidFormat("unsupported head version".into()));
        }
        let vid_len = u16::from_le_bytes(read_exact_arr::<2>(bytes, &mut pos)?) as usize;
        let vault_id = std::str::from_utf8(read_exact_slice(bytes, &mut pos, vid_len)?)
            .map_err(|_| VaultError::InvalidFormat("invalid vault_id utf8".into()))?
            .to_string();
        let key_epoch = u64::from_le_bytes(read_exact_arr::<8>(bytes, &mut pos)?);
        let m_cost_kib = u32::from_le_bytes(read_exact_arr::<4>(bytes, &mut pos)?);
        let t_cost = u32::from_le_bytes(read_exact_arr::<4>(bytes, &mut pos)?);
        let p_cost = u32::from_le_bytes(read_exact_arr::<4>(bytes, &mut pos)?);
        let salt = read_exact_arr::<32>(bytes, &mut pos)?;
        let recovery_salt = read_exact_arr::<32>(bytes, &mut pos)?;
        let read_wk = |p: &mut usize| -> Result<WrappedKey, VaultError> {
            Ok(WrappedKey {
                nonce: read_exact_arr::<24>(bytes, p)?,
                tag: read_exact_arr::<16>(bytes, p)?,
                ciphertext: read_exact_arr::<32>(bytes, p)?,
            })
        };
        let wrapped_dek_master = read_wk(&mut pos)?;
        let wrapped_dek_recovery = read_wk(&mut pos)?;
        let env_len = u32::from_le_bytes(read_exact_arr::<4>(bytes, &mut pos)?) as usize;
        let encrypted_pointer_envelope = read_exact_slice(bytes, &mut pos, env_len)?.to_vec();
        if pos != bytes.len() {
            return Err(VaultError::InvalidFormat("trailing bytes in head.bin".into()));
        }
        let head = Self {
            magic,
            schema_version,
            vault_id,
            key_epoch,
            kdf_params: KdfParams {
                m_cost_kib,
                t_cost,
                p_cost,
                salt,
            },
            recovery_salt,
            wrapped_dek_master,
            wrapped_dek_recovery,
            encrypted_pointer_envelope,
        };
        head.kdf_params.validate()?;
        Ok(head)
    }
}

/// Encodes a Rust structure via `MessagePack` -> `Zstandard` -> `256-byte bucket padding`.
pub fn encode_msgpack_zstd_padded<T: MsgPackWire>(value: &T) -> Result<SecretBytes, VaultError> {
    let mut msgpack = Vec::new();
    value.encode_msgpack(&mut msgpack);
    let compressed = Zeroizing::new(zstd_compress(msgpack.as_slice()));
    msgpack.zeroize();
    let padded = crate::crypto::pad_to_256_bucket(&compressed);
    Ok(SecretBytes::new(padded))
}

/// Decodes `256-byte bucket padded` -> `Zstandard` -> `MessagePack`.
pub fn decode_msgpack_zstd_padded<T: MsgPackWire>(padded: &[u8]) -> Result<T, VaultError> {
    let compressed = crate::crypto::unpad_from_256_bucket(padded)?;
    let mut raw = zstd_decompress_bounded(compressed.as_slice(), MAX_MSGPACK_BYTES)?;
    let mut reader = MpReader::new(raw.as_slice());
    let decoded = reader.decode_object();
    raw.zeroize();
    decoded
}

/// Compresses (`MsgPack` + `Zstd`) and seals into a 256-byte bucket-aligned `XChaCha20-Poly1305` envelope.
pub fn seal_compact_object<T: MsgPackWire>(
    key: &SecretKey,
    role: FileRole,
    object_id: &str,
    hlc_epoch: u64,
    value: &T,
) -> Result<Vec<u8>, VaultError> {
    let mut msgpack = Zeroizing::new(Vec::new());
    value.encode_msgpack(&mut msgpack);
    if msgpack.len() > MAX_MSGPACK_BYTES {
        return Err(VaultError::CompactObjectTooLarge);
    }
    let mut compressed = Zeroizing::new(zstd_compress(msgpack.as_slice()));
    msgpack.zeroize();
    let env = SealedEnvelope::seal_bucketed(key, role, object_id, hlc_epoch, &compressed)?;
    compressed.zeroize();
    env.to_bytes()
}

pub fn open_compact_object<T: MsgPackWire>(
    key: &SecretKey,
    expected_role: FileRole,
    expected_object_id: Option<&str>,
    envelope_bytes: &[u8],
) -> Result<T, VaultError> {
    let env = SealedEnvelope::from_bytes(envelope_bytes)?;
    let compressed = env.open_bucketed(key, expected_role, expected_object_id)?;
    let mut decompressed = zstd_decompress_bounded(compressed.as_slice(), MAX_MSGPACK_BYTES)?;
    let mut reader = MpReader::new(decompressed.as_slice());
    let res = reader.decode_object();
    decompressed.zeroize();
    res
}

/// Seals a `VaultSnapshot` with a BLAKE3 keyed state MAC and `snap` AEAD subkey.
pub fn seal_snapshot(
    keys: &VaultKeyHierarchy,
    snapshot: &mut VaultSnapshot,
) -> Result<Vec<u8>, VaultError> {
    snapshot.state_mac = [0u8; 32];
    let mut mac_input = Vec::new();
    snapshot.encode_msgpack(&mut mac_input);
    snapshot.state_mac = keys.compute_state_mac(&mac_input);
    mac_input.zeroize();

    seal_compact_object(
        keys.snap_key(),
        FileRole::Snap,
        &snapshot.snapshot_id,
        snapshot.snapshot_epoch,
        snapshot,
    )
}

/// Opens and verifies both the AEAD tag + AAD role and the internal BLAKE3 state MAC of a `VaultSnapshot`.
pub fn open_snapshot(
    keys: &VaultKeyHierarchy,
    expected_snapshot_id: Option<&str>,
    snap_bytes: &[u8],
) -> Result<VaultSnapshot, VaultError> {
    let env = SealedEnvelope::from_bytes(snap_bytes)?;
    let compressed = env.open_bucketed(keys.snap_key(), FileRole::Snap, expected_snapshot_id)?;
    let mut raw = Zeroizing::new(zstd_decompress_bounded(compressed.as_slice(), MAX_MSGPACK_BYTES)?);
    // Authenticate the bytes actually stored. Re-encoding would invalidate older compact encodings.
    if raw.len() < 34 || raw[raw.len() - 34..raw.len() - 32] != [0xc4, 32] {
        return Err(mp_read_err());
    }
    let mac_start = raw.len() - 32;
    let mut recorded_mac = [0u8; 32];
    recorded_mac.copy_from_slice(&raw[mac_start..]);
    raw[mac_start..].fill(0);
    let computed_mac = keys.compute_state_mac(&raw);
    if recorded_mac != computed_mac {
        return Err(VaultError::CryptoAuthFailed);
    }
    raw[mac_start..].copy_from_slice(&recorded_mac);
    MpReader::new(&raw).decode_object()
}

pub fn export_vaultpack(
    snapshot: &VaultSnapshot,
    backup_password: &[u8],
    kdf_params: KdfParams,
    now_ms: u64,
) -> Result<Vec<u8>, VaultError> {
    kdf_params.validate()?;
    let backup_kek = derive_master_kek(backup_password, &kdf_params)?;
    let env_bytes = seal_compact_object(
        &backup_kek,
        FileRole::VaultPack,
        "vaultpack:v1",
        now_ms,
        snapshot,
    )?;
    let file_len = VAULTPACK_HEADER_BYTES + env_bytes.len();
    check_vaultpack_size(file_len)?;
    let mut out = Vec::with_capacity(file_len);
    out.extend_from_slice(&VAULTPACK_MAGIC);
    out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    out.extend_from_slice(&now_ms.to_le_bytes());
    out.extend_from_slice(&kdf_params.m_cost_kib.to_le_bytes());
    out.extend_from_slice(&kdf_params.t_cost.to_le_bytes());
    out.extend_from_slice(&kdf_params.p_cost.to_le_bytes());
    out.extend_from_slice(&kdf_params.salt);
    out.extend_from_slice(&(env_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&env_bytes);
    Ok(out)
}

pub fn import_vaultpack(raw: &[u8], backup_password: &[u8]) -> Result<VaultSnapshot, VaultError> {
    check_vaultpack_size(raw.len())?;
    let mut pos = 0usize;
    let magic = read_exact_arr::<4>(raw, &mut pos)?;
    if magic != VAULTPACK_MAGIC {
        return Err(VaultError::InvalidFormat(
            "not a valid .vaultpack encrypted archive".into(),
        ));
    }
    let schema_version = u16::from_le_bytes(read_exact_arr::<2>(raw, &mut pos)?);
    if schema_version != SCHEMA_VERSION {
        return Err(VaultError::InvalidFormat("unsupported vaultpack version".into()));
    }
    let _exported_at = u64::from_le_bytes(read_exact_arr::<8>(raw, &mut pos)?);
    let m_cost_kib = u32::from_le_bytes(read_exact_arr::<4>(raw, &mut pos)?);
    let t_cost = u32::from_le_bytes(read_exact_arr::<4>(raw, &mut pos)?);
    let p_cost = u32::from_le_bytes(read_exact_arr::<4>(raw, &mut pos)?);
    let salt = read_exact_arr::<32>(raw, &mut pos)?;
    let env_len = u32::from_le_bytes(read_exact_arr::<4>(raw, &mut pos)?) as usize;
    let env_bytes = read_exact_slice(raw, &mut pos, env_len)?;
    if pos != raw.len() {
        return Err(VaultError::InvalidFormat("trailing bytes in vaultpack".into()));
    }
    let kdf_params = KdfParams {
        m_cost_kib,
        t_cost,
        p_cost,
        salt,
    };
    kdf_params.validate()?;
    let backup_kek = derive_master_kek(backup_password, &kdf_params)?;
    open_compact_object(
        &backup_kek,
        FileRole::VaultPack,
        Some("vaultpack:v1"),
        env_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vaultpack_file_limit_includes_the_header_and_rejects_oversize_before_decoding() {
        let largest_envelope = MAX_VAULTPACK_BYTES - VAULTPACK_HEADER_BYTES;
        assert!(check_vaultpack_size(VAULTPACK_HEADER_BYTES + largest_envelope).is_ok());
        assert_eq!(check_vaultpack_size(VAULTPACK_HEADER_BYTES + largest_envelope + 1), Err(VaultError::VaultpackTooLarge));
        let oversized = vec![0; MAX_VAULTPACK_BYTES + 1];
        assert!(matches!(import_vaultpack(&oversized, b"unused"), Err(VaultError::VaultpackTooLarge)));
    }
}
