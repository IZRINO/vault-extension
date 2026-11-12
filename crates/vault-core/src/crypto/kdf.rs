use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::aead::{csprng_fill, SecretKey, SECRET_KEY_LEN};
use crate::error::VaultError;

pub const DEFAULT_M_COST_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 4;

pub const MIN_M_COST_KIB: u32 = 32_768; // 32 MiB security floor
pub const MIN_T_COST: u32 = 2;
pub const MIN_P_COST: u32 = 1;

/// Unambiguous 32-character alphabet (excludes 0, O, 1, I) for 256-bit Emergency Recovery Code.
const RECOVERY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 32],
}

impl KdfParams {
    pub fn new_default_random() -> Result<Self, VaultError> {
        let mut salt = [0u8; 32];
        csprng_fill(&mut salt)?;
        Ok(Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
            salt,
        })
    }

    pub fn with_fresh_salt(&self) -> Result<Self, VaultError> {
        self.validate()?;
        let mut salt = [0u8; 32];
        csprng_fill(&mut salt)?;
        Ok(Self {
            m_cost_kib: self.m_cost_kib,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            salt,
        })
    }

    pub fn validate(&self) -> Result<(), VaultError> {
        if self.m_cost_kib > 262_144 || self.t_cost > 10 || self.p_cost > 16 {
            return Err(VaultError::InvalidKdfParams(
                "Argon2id parameters exceed local resource limits".into(),
            ));
        }
        if self.m_cost_kib < MIN_M_COST_KIB {
            return Err(VaultError::InvalidKdfParams(
                "Argon2id memory cost is below minimum 32 MiB (32768 KiB)".into(),
            ));
        }
        if self.t_cost < MIN_T_COST {
            return Err(VaultError::InvalidKdfParams(
                "Argon2id time cost is below minimum 2".into(),
            ));
        }
        if self.p_cost < MIN_P_COST {
            return Err(VaultError::InvalidKdfParams(
                "Argon2id parallelism must be >= 1".into(),
            ));
        }
        Ok(())
    }
}

/// Calibrates Argon2id parameters from a measured 32 MiB (t=2, p=4) probe runtime,
/// targeting ~300ms-600ms while enforcing the `>= 32 MiB` security floor.
pub fn calibrate_kdf_params(probe_32mib_t2_ms: f64) -> Result<KdfParams, VaultError> {
    let mut salt = [0u8; 32];
    csprng_fill(&mut salt)?;
    let (m_cost_kib, t_cost) = if probe_32mib_t2_ms <= 160.0 {
        (65_536, 3) // 64 MiB, t=3 (~3x probe)
    } else if probe_32mib_t2_ms <= 280.0 {
        (65_536, 2) // 64 MiB, t=2 (~2x probe)
    } else if probe_32mib_t2_ms <= 420.0 {
        (49_152, 2) // 48 MiB, t=2 (~1.5x probe)
    } else {
        (MIN_M_COST_KIB, MIN_T_COST) // 32 MiB, t=2 floor
    };
    Ok(KdfParams {
        m_cost_kib,
        t_cost,
        p_cost: DEFAULT_P_COST,
        salt,
    })
}

pub fn derive_argon2id_seed(secret: &[u8], params: &KdfParams) -> Result<SecretKey, VaultError> {
    if secret.is_empty() {
        return Err(VaultError::InvalidInput(
            "secret/password must not be empty".into(),
        ));
    }
    params.validate()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(SECRET_KEY_LEN),
    )
    .map_err(|_| VaultError::InvalidKdfParams("invalid Argon2id params".into()))?;

    let mut memory = Zeroizing::new(vec![argon2::Block::default(); argon_params.block_count()]);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; SECRET_KEY_LEN];
    argon2
        .hash_password_into_with_memory(secret, &params.salt, &mut out, memory.as_mut_slice())
        .map_err(|_| VaultError::InvalidKdfParams("Argon2id derivation failed".into()))?;
    let key = SecretKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

fn hkdf_expand_32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Result<SecretKey, VaultError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; SECRET_KEY_LEN];
    hk.expand(info, &mut okm)
        .map_err(|_| VaultError::InvalidInput("HKDF expand failed".into()))?;
    let key = SecretKey::from_bytes(okm);
    okm.zeroize();
    Ok(key)
}

/// Master Password -> Argon2id -> HKDF-SHA256("vault:kek:v1") -> Master KEK.
pub fn derive_master_kek(
    master_password: &[u8],
    params: &KdfParams,
) -> Result<SecretKey, VaultError> {
    let seed = derive_argon2id_seed(master_password, params)?;
    hkdf_expand_32(Some(&params.salt), seed.as_bytes(), b"vault:kek:v1")
}

/// Local PIN -> Argon2id (32 MiB, t=2, p=4) -> HKDF-SHA256("vault:pin:kek:v1") -> PIN KEK.
pub fn derive_pin_kek(pin: &[u8], params: &KdfParams) -> Result<SecretKey, VaultError> {
    let seed = derive_argon2id_seed(pin, params)?;
    hkdf_expand_32(Some(&params.salt), seed.as_bytes(), b"vault:pin:kek:v1")
}

/// WebAuthn PRF 32-byte deterministic output -> HKDF-SHA256("vault:prf:kek:v1") -> PRF KEK.
pub fn derive_prf_kek(prf_output: &[u8], prf_salt: &[u8; 32]) -> Result<SecretKey, VaultError> {
    if prf_output.len() != SECRET_KEY_LEN {
        return Err(VaultError::InvalidInput(
            "WebAuthn PRF output must be exactly 32 bytes".into(),
        ));
    }
    if prf_output.iter().all(|&b| b == 0) {
        return Err(VaultError::InvalidInput(
            "WebAuthn PRF output must not be all zeros".into(),
        ));
    }
    hkdf_expand_32(Some(prf_salt), prf_output, b"vault:prf:kek:v1")
}

/// 256-bit Recovery Secret -> HKDF-SHA256("vault:recovery:kek:v1") -> Recovery KEK.
pub fn derive_recovery_kek(
    recovery_secret: &SecretKey,
    recovery_salt: &[u8; 32],
) -> Result<SecretKey, VaultError> {
    hkdf_expand_32(
        Some(recovery_salt),
        recovery_secret.as_bytes(),
        b"vault:recovery:kek:v1",
    )
}

/// High-entropy 256-bit Emergency Recovery Code formatted as 13 groups of 4 chars (`XXXX-XXXX-...`).
/// Carries 256 bits of CSPRNG entropy + 4-bit BLAKE3 checksum = 260 bits = 52 Base32 characters.
pub struct RecoveryCode;

impl RecoveryCode {
    pub fn generate() -> Result<(Zeroizing<String>, SecretKey), VaultError> {
        let secret = SecretKey::random()?;
        let formatted = Self::encode(&secret);
        Ok((formatted, secret))
    }

    pub fn encode(secret: &SecretKey) -> Zeroizing<String> {
        let raw = secret.as_bytes();
        let checksum_nibble = blake3::hash(raw).as_bytes()[0] & 0x0F;

        // Pack 256 bits + 4 checksum bits = 260 bits -> 52 5-bit symbols
        let mut bits = Vec::with_capacity(260);
        for &byte in raw {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }
        for shift in (0..4).rev() {
            bits.push((checksum_nibble >> shift) & 1);
        }

        let mut out = String::with_capacity(52 + 12);
        for (group_idx, chunk) in bits.chunks(20).enumerate() {
            if group_idx > 0 {
                out.push('-');
            }
            for sym_bits in chunk.chunks(5) {
                let idx = ((sym_bits[0] << 4)
                    | (sym_bits[1] << 3)
                    | (sym_bits[2] << 2)
                    | (sym_bits[3] << 1)
                    | sym_bits[4]) as usize;
                out.push(RECOVERY_ALPHABET[idx] as char);
            }
        }
        bits.zeroize();
        Zeroizing::new(out)
    }

    pub fn parse(input: &str) -> Result<SecretKey, VaultError> {
        let mut cleaned = Zeroizing::new(Vec::with_capacity(52));
        for &b in input.as_bytes() {
            if b == b'-' || b.is_ascii_whitespace() {
                continue;
            }
            let upper = b.to_ascii_uppercase();
            let pos = RECOVERY_ALPHABET
                .iter()
                .position(|&c| c == upper)
                .ok_or_else(|| {
                    VaultError::InvalidRecoveryCode("invalid character in recovery code".into())
                })?;
            cleaned.push(pos as u8);
        }
        if cleaned.len() != 52 {
            return Err(VaultError::InvalidRecoveryCode(
                "expected 52 recovery characters (13 groups of 4)".into(),
            ));
        }

        let mut bits = Zeroizing::new(Vec::with_capacity(260));
        for &sym in cleaned.iter() {
            for shift in (0..5).rev() {
                bits.push((sym >> shift) & 1);
            }
        }

        let mut raw = [0u8; SECRET_KEY_LEN];
        for (byte_idx, chunk) in bits[..256].chunks(8).enumerate() {
            let mut b = 0u8;
            for &bit in chunk {
                b = (b << 1) | bit;
            }
            raw[byte_idx] = b;
        }
        let parsed_checksum =
            (bits[256] << 3) | (bits[257] << 2) | (bits[258] << 1) | bits[259];
        let expected_checksum = blake3::hash(&raw).as_bytes()[0] & 0x0F;
        if parsed_checksum != expected_checksum {
            raw.zeroize();
            return Err(VaultError::InvalidRecoveryCode(
                "recovery code checksum mismatch (check for typos)".into(),
            ));
        }
        let secret = SecretKey::from_bytes(raw);
        raw.zeroize();
        Ok(secret)
    }
}

/// Complete three-tier sub-key hierarchy derived deterministically from the 256-bit Master DEK.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKeyHierarchy {
    master_dek: SecretKey,
    snap_key: SecretKey,
    wal_key: SecretKey,
    manifest_key: SecretKey,
    head_payload_key: SecretKey,
}

impl VaultKeyHierarchy {
    pub fn from_master_dek(master_dek: SecretKey) -> Result<Self, VaultError> {
        let snap_key = hkdf_expand_32(None, master_dek.as_bytes(), b"vault:snap:aead:v1")?;
        let wal_key = hkdf_expand_32(None, master_dek.as_bytes(), b"vault:wal:aead:v1")?;
        let manifest_key = hkdf_expand_32(None, master_dek.as_bytes(), b"vault:manifest:v1")?;
        let head_payload_key = hkdf_expand_32(None, master_dek.as_bytes(), b"vault:head:aead:v1")?;
        Ok(Self {
            master_dek,
            snap_key,
            wal_key,
            manifest_key,
            head_payload_key,
        })
    }

    pub fn master_dek(&self) -> &SecretKey {
        &self.master_dek
    }

    pub fn snap_key(&self) -> &SecretKey {
        &self.snap_key
    }

    pub fn wal_key(&self) -> &SecretKey {
        &self.wal_key
    }

    pub fn manifest_key(&self) -> &SecretKey {
        &self.manifest_key
    }

    pub fn head_payload_key(&self) -> &SecretKey {
        &self.head_payload_key
    }

    pub fn compute_state_mac(&self, canonical_bytes: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(self.manifest_key.as_bytes(), canonical_bytes).as_bytes()
    }
}
