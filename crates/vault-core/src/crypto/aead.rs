use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key, Tag, XChaCha20Poly1305, XNonce,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::VaultError;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = crypto, js_name = getRandomValues)]
    fn js_crypto_get_random_values(dest: &mut [u8]) -> Result<(), JsValue>;
}

pub const SECRET_KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const BUCKET_SIZE: usize = 256;
pub const ENVELOPE_MAGIC: [u8; 4] = *b"VLTE";
pub const SCHEMA_VERSION: u16 = 1;

/// 256-bit secret key material zeroized automatically when dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, VaultError> {
        if slice.len() != SECRET_KEY_LEN {
            return Err(VaultError::InvalidInput("expected 32-byte key".into()));
        }
        let mut arr = [0u8; SECRET_KEY_LEN];
        arr.copy_from_slice(slice);
        Ok(Self(arr))
    }

    pub fn random() -> Result<Self, VaultError> {
        let mut bytes = [0u8; SECRET_KEY_LEN];
        csprng_fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }
}

/// Variable-length sensitive buffer zeroized automatically when dropped.
#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

pub fn csprng_fill(dest: &mut [u8]) -> Result<(), VaultError> {
    #[cfg(target_arch = "wasm32")]
    {
        // WebCrypto getRandomValues supports up to 65536 bytes per call
        for chunk in dest.chunks_mut(65536) {
            js_crypto_get_random_values(chunk).map_err(|_| VaultError::RngFailure)?;
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::getrandom(dest).map_err(|_| VaultError::RngFailure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileRole {
    Head = 1,
    Snap = 2,
    Wal = 3,
    VaultPack = 4,
    SessionWrap = 5,
    PinWrap = 6,
    PrfWrap = 7,
}

impl FileRole {
    pub fn from_u8(val: u8) -> Result<Self, VaultError> {
        match val {
            1 => Ok(Self::Head),
            2 => Ok(Self::Snap),
            3 => Ok(Self::Wal),
            4 => Ok(Self::VaultPack),
            5 => Ok(Self::SessionWrap),
            6 => Ok(Self::PinWrap),
            7 => Ok(Self::PrfWrap),
            _ => Err(VaultError::InvalidFormat("unknown file_role tag".into())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Snap => "snap",
            Self::Wal => "wal",
            Self::VaultPack => "pack",
            Self::SessionWrap => "session",
            Self::PinWrap => "pin",
            Self::PrfWrap => "prf",
        }
    }
}

/// Canonical Authenticated Associated Data (AAD) bound into Poly1305 MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeAad {
    pub magic: [u8; 4],
    pub schema_version: u16,
    pub file_role: FileRole,
    pub object_id: String,
    pub hlc_epoch: u64,
}

impl EnvelopeAad {
    pub fn new(file_role: FileRole, object_id: impl Into<String>, hlc_epoch: u64) -> Self {
        Self {
            magic: ENVELOPE_MAGIC,
            schema_version: SCHEMA_VERSION,
            file_role,
            object_id: object_id.into(),
            hlc_epoch,
        }
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let obj_bytes = self.object_id.as_bytes();
        let mut out = Vec::with_capacity(4 + 2 + 1 + 4 + obj_bytes.len() + 8);
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        out.push(self.file_role as u8);
        out.extend_from_slice(&(obj_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(obj_bytes);
        out.extend_from_slice(&self.hlc_epoch.to_le_bytes());
        out
    }
}

/// Pads arbitrary payload to an exact positive multiple of 256 bytes:
/// `[u32_le(plain.len())] || plain || 0x00...`
pub fn pad_to_256_bucket(plain: &[u8]) -> Vec<u8> {
    let raw_len = 4usize.saturating_add(plain.len());
    let bucket_count = raw_len.div_ceil(BUCKET_SIZE).max(1);
    let total_len = bucket_count * BUCKET_SIZE;
    let mut buf = vec![0u8; total_len];
    buf[..4].copy_from_slice(&(plain.len() as u32).to_le_bytes());
    buf[4..4 + plain.len()].copy_from_slice(plain);
    buf
}

/// Unpads a 256-byte aligned buffer, rejecting malformed lengths or non-zero trailer bytes.
pub fn unpad_from_256_bucket(padded: &[u8]) -> Result<SecretBytes, VaultError> {
    if padded.is_empty() || padded.len() % BUCKET_SIZE != 0 {
        return Err(VaultError::InvalidFormat(
            "padded buffer length is not a positive multiple of 256 bytes".into(),
        ));
    }
    let plain_len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    let used = 4usize
        .checked_add(plain_len)
        .ok_or_else(|| VaultError::InvalidFormat("padded length overflow".into()))?;
    if used > padded.len() || (padded.len() - used) >= BUCKET_SIZE {
        return Err(VaultError::InvalidFormat(
            "invalid bucket padding length header".into(),
        ));
    }
    let mut diff = 0u8;
    for &b in &padded[used..] {
        diff |= b;
    }
    if diff != 0 {
        return Err(VaultError::InvalidFormat(
            "non-zero bytes detected in bucket padding trailer".into(),
        ));
    }
    Ok(SecretBytes::new(padded[4..used].to_vec()))
}

/// Wrapped 256-bit key container (`XChaCha20-Poly1305` detached tag + 24B random nonce).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; XNONCE_LEN],
    pub tag: [u8; TAG_LEN],
    pub ciphertext: [u8; SECRET_KEY_LEN],
}

impl WrappedKey {
    pub fn wrap(
        kek: &SecretKey,
        target_key: &SecretKey,
        role: FileRole,
        object_id: &str,
        hlc_epoch: u64,
    ) -> Result<Self, VaultError> {
        let mut nonce = [0u8; XNONCE_LEN];
        csprng_fill(&mut nonce)?;
        let aad = EnvelopeAad::new(role, object_id, hlc_epoch).to_canonical_bytes();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_bytes()));
        let mut buf = *target_key.as_bytes();
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut buf)
            .map_err(|_| VaultError::CryptoAuthFailed)?;
        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(tag.as_slice());
        Ok(Self {
            nonce,
            tag: tag_arr,
            ciphertext: buf,
        })
    }

    pub fn unwrap(
        &self,
        kek: &SecretKey,
        expected_role: FileRole,
        expected_object_id: &str,
        hlc_epoch: u64,
    ) -> Result<SecretKey, VaultError> {
        let aad =
            EnvelopeAad::new(expected_role, expected_object_id, hlc_epoch).to_canonical_bytes();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.as_bytes()));
        let mut buf = self.ciphertext;
        if cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&self.nonce),
                &aad,
                &mut buf,
                Tag::from_slice(&self.tag),
            )
            .is_err()
        {
            buf.zeroize();
            return Err(VaultError::CryptoAuthFailed);
        }
        let out = SecretKey::from_bytes(buf);
        buf.zeroize();
        Ok(out)
    }
}

/// Authenticated encryption envelope whose `ciphertext` payload is strictly aligned to 256B buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    pub schema_version: u16,
    pub file_role: FileRole,
    pub object_id: String,
    pub hlc_epoch: u64,
    pub nonce: [u8; XNONCE_LEN],
    pub tag: [u8; TAG_LEN],
    pub ciphertext: Vec<u8>,
}

impl SealedEnvelope {
    pub fn seal_bucketed(
        key: &SecretKey,
        role: FileRole,
        object_id: impl Into<String>,
        hlc_epoch: u64,
        payload: &[u8],
    ) -> Result<Self, VaultError> {
        let object_id = object_id.into();
        let mut nonce = [0u8; XNONCE_LEN];
        csprng_fill(&mut nonce)?;
        let aad = EnvelopeAad {
            magic: ENVELOPE_MAGIC,
            schema_version: SCHEMA_VERSION,
            file_role: role,
            object_id: object_id.clone(),
            hlc_epoch,
        };
        let aad_bytes = aad.to_canonical_bytes();
        let mut buffer = pad_to_256_bucket(payload);
        debug_assert_eq!(buffer.len() % BUCKET_SIZE, 0);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad_bytes, &mut buffer)
            .map_err(|_| {
                buffer.zeroize();
                VaultError::CryptoAuthFailed
            })?;

        let mut tag_arr = [0u8; TAG_LEN];
        tag_arr.copy_from_slice(tag.as_slice());

        Ok(Self {
            schema_version: SCHEMA_VERSION,
            file_role: role,
            object_id,
            hlc_epoch,
            nonce,
            tag: tag_arr,
            ciphertext: buffer,
        })
    }

    pub fn open_bucketed(
        &self,
        key: &SecretKey,
        expected_role: FileRole,
        expected_object_id: Option<&str>,
    ) -> Result<SecretBytes, VaultError> {
        if self.ciphertext.is_empty() || self.ciphertext.len() % BUCKET_SIZE != 0 {
            return Err(VaultError::InvalidFormat(
                "envelope ciphertext payload is not 256-byte bucket aligned".into(),
            ));
        }
        let object_id_for_aad = expected_object_id.unwrap_or(&self.object_id);
        if self.file_role != expected_role || self.object_id != object_id_for_aad {
            return Err(VaultError::CryptoAuthFailed);
        }
        let aad = EnvelopeAad {
            magic: ENVELOPE_MAGIC,
            schema_version: self.schema_version,
            file_role: expected_role,
            object_id: object_id_for_aad.to_string(),
            hlc_epoch: self.hlc_epoch,
        };
        let aad_bytes = aad.to_canonical_bytes();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let mut buffer = self.ciphertext.clone();
        if cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&self.nonce),
                &aad_bytes,
                &mut buffer,
                Tag::from_slice(&self.tag),
            )
            .is_err()
        {
            buffer.zeroize();
            return Err(VaultError::CryptoAuthFailed);
        }
        let unpadded = unpad_from_256_bucket(&buffer);
        buffer.zeroize();
        unpadded
    }

    /// Deterministic binary wire format:
    /// `VLTE` (4B) | `schema_version` (u16 LE) | `file_role` (u8) | `obj_len` (u16 LE) | `object_id`
    /// | `hlc_epoch` (u64 LE) | `nonce` (24B) | `tag` (16B) | `ct_len` (u32 LE) | `ciphertext` (256B * k)
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let obj_bytes = self.object_id.as_bytes();
        if obj_bytes.len() > u16::MAX as usize {
            return Err(VaultError::InvalidInput("object_id too long".into()));
        }
        let mut out =
            Vec::with_capacity(4 + 2 + 1 + 2 + obj_bytes.len() + 8 + 24 + 16 + 4 + self.ciphertext.len());
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        out.push(self.file_role as u8);
        out.extend_from_slice(&(obj_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(obj_bytes);
        out.extend_from_slice(&self.hlc_epoch.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, VaultError> {
        if raw.len() < 4 + 2 + 1 + 2 + 8 + 24 + 16 + 4 {
            return Err(VaultError::InvalidFormat("envelope truncated".into()));
        }
        if raw[..4] != ENVELOPE_MAGIC {
            return Err(VaultError::InvalidFormat("invalid envelope magic".into()));
        }
        let schema_version = u16::from_le_bytes([raw[4], raw[5]]);
        let file_role = FileRole::from_u8(raw[6])?;
        let obj_len = u16::from_le_bytes([raw[7], raw[8]]) as usize;
        let mut pos = 9usize;
        if raw.len() < pos + obj_len + 8 + 24 + 16 + 4 {
            return Err(VaultError::InvalidFormat("envelope header truncated".into()));
        }
        let object_id = std::str::from_utf8(&raw[pos..pos + obj_len])
            .map_err(|_| VaultError::InvalidFormat("invalid utf8 in object_id".into()))?
            .to_string();
        pos += obj_len;

        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&raw[pos..pos + 8]);
        let hlc_epoch = u64::from_le_bytes(epoch_bytes);
        pos += 8;

        let mut nonce = [0u8; XNONCE_LEN];
        nonce.copy_from_slice(&raw[pos..pos + XNONCE_LEN]);
        pos += XNONCE_LEN;

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&raw[pos..pos + TAG_LEN]);
        pos += TAG_LEN;

        let ct_len =
            u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;
        if raw.len() != pos + ct_len {
            return Err(VaultError::InvalidFormat(
                "envelope ciphertext length mismatch".into(),
            ));
        }
        if ct_len == 0 || ct_len % BUCKET_SIZE != 0 {
            return Err(VaultError::InvalidFormat(
                "envelope ciphertext is not 256-byte bucket aligned".into(),
            ));
        }
        Ok(Self {
            schema_version,
            file_role,
            object_id,
            hlc_epoch,
            nonce,
            tag,
            ciphertext: raw[pos..pos + ct_len].to_vec(),
        })
    }
}
