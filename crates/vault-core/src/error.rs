use wasm_bindgen::JsValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    CryptoAuthFailed,
    InvalidFormat(String),
    InvalidKdfParams(String),
    InvalidRecoveryCode(String),
    InvalidInput(String),
    VaultLocked,
    ItemNotFound(String),
    RepromptRequired,
    RngFailure,
    CodecError(String),
}

impl VaultError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CryptoAuthFailed => "CRYPTO_AUTH_FAILED",
            Self::InvalidFormat(_) => "INVALID_FORMAT",
            Self::InvalidKdfParams(_) => "INVALID_KDF_PARAMS",
            Self::InvalidRecoveryCode(_) => "INVALID_RECOVERY_CODE",
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::VaultLocked => "VAULT_LOCKED",
            Self::ItemNotFound(_) => "ITEM_NOT_FOUND",
            Self::RepromptRequired => "REPROMPT_REQUIRED",
            Self::RngFailure => "RNG_FAILURE",
            Self::CodecError(_) => "CODEC_ERROR",
        }
    }

    pub fn to_wire_message(&self) -> String {
        let detail: &str = match self {
            Self::CryptoAuthFailed => "AEAD authentication failed or invalid key/AAD",
            Self::InvalidFormat(msg)
            | Self::InvalidKdfParams(msg)
            | Self::InvalidRecoveryCode(msg)
            | Self::InvalidInput(msg)
            | Self::CodecError(msg) => msg.as_str(),
            Self::VaultLocked => "vault session is currently locked",
            Self::ItemNotFound(id) => id.as_str(),
            Self::RepromptRequired => "secondary verification required for high-sensitivity item",
            Self::RngFailure => "CSPRNG entropy source unavailable",
        };
        let code = self.code();
        let mut out = String::with_capacity(code.len() + 2 + detail.len());
        out.push_str(code);
        out.push_str(": ");
        out.push_str(detail);
        out
    }
}

impl From<VaultError> for JsValue {
    fn from(err: VaultError) -> Self {
        JsValue::from_str(&err.to_wire_message())
    }
}
