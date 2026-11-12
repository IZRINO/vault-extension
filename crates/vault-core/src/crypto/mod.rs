pub mod aead;
pub mod kdf;

pub use aead::{
    csprng_fill, pad_to_256_bucket, unpad_from_256_bucket, EnvelopeAad, FileRole, SealedEnvelope,
    SecretBytes, SecretKey, WrappedKey, BUCKET_SIZE, ENVELOPE_MAGIC, SCHEMA_VERSION,
    SECRET_KEY_LEN, TAG_LEN, XNONCE_LEN,
};
pub use kdf::{
    calibrate_kdf_params, derive_argon2id_seed, derive_master_kek, derive_pin_kek, derive_prf_kek,
    derive_recovery_kek, KdfParams, RecoveryCode, VaultKeyHierarchy, DEFAULT_M_COST_KIB,
    DEFAULT_P_COST, DEFAULT_T_COST, MIN_M_COST_KIB,
};
