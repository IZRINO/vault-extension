use crate::{
    bitwarden::text,
    portable::{INVALID, KeyImportError, MappingError},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::pkcs8::{EncodePrivateKey, SecretDocument};
use serde::{Deserialize, Deserializer, de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor}};
use serde_json::Value;
use std::{fmt, io::ErrorKind};
use vault_passkeys::Passkey;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, MappingError>;
const MAX_CONTENT: usize = 12 * 1024;
const MAX_DEPTH: usize = 16;

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "v")]
    version: u64,
    #[serde(rename = "c", deserialize_with = "envelope_bytes")]
    bytes: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
struct NativeKey {
    key: CoseKey,
    #[serde(rename = "cid")]
    credential_id: Vec<u8>,
    #[serde(rename = "rid")]
    rp_id: String,
    #[serde(rename = "uhd")]
    user_handle: Option<Vec<u8>>,
    #[serde(rename = "cnt")]
    counter: Option<u32>,
    #[serde(rename = "un")]
    account: Option<String>,
    #[serde(rename = "ext", default)]
    extensions: Extensions,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Extensions {
    hmac_secret: Option<de::IgnoredAny>,
}

#[derive(Deserialize)]
struct Tagged<T> {
    t: String,
    c: T,
}

#[derive(Deserialize)]
struct CoseKey {
    #[serde(rename = "kty")]
    kind: Tagged<String>,
    #[serde(rename = "alg")]
    algorithm: Tagged<String>,
    #[serde(rename = "par")]
    parameters: Vec<(Tagged<i64>, Tagged<Parameter>)>,
}

#[derive(Deserialize)]
struct Integer {
    inner: [u8; 16],
}

enum Parameter {
    Integer(Integer),
    Bytes(Zeroizing<[u8; 32]>),
}

fn envelope_bytes<'de, D: Deserializer<'de>>(reader: D) -> std::result::Result<Zeroizing<Vec<u8>>, D::Error> {
    struct EnvelopeBytes;
    impl<'de> Visitor<'de> for EnvelopeBytes {
        type Value = Zeroizing<Vec<u8>>;

        fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt.write_str("a bounded Proton passkey payload")
        }

        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> std::result::Result<Self::Value, E> {
            if bytes.len() > MAX_CONTENT { return Err(E::custom(INVALID)); }
            Ok(Zeroizing::new(bytes.to_vec()))
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error> {
            let length = seq.size_hint().filter(|len| *len <= MAX_CONTENT).ok_or_else(|| de::Error::custom(INVALID))?;
            let mut bytes = Zeroizing::new(vec![0u8; length]);
            for byte in bytes.iter_mut() {
                *byte = seq.next_element()?.ok_or_else(|| de::Error::custom(INVALID))?;
            }
            Ok(bytes)
        }
    }
    reader.deserialize_any(EnvelopeBytes)
}

impl<'de> Deserialize<'de> for Parameter {
    fn deserialize<D: Deserializer<'de>>(reader: D) -> std::result::Result<Self, D::Error> {
        struct ParameterValue;
        impl<'de> Visitor<'de> for ParameterValue {
            type Value = Parameter;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("a curve identifier or a 32-byte COSE parameter")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> std::result::Result<Self::Value, A::Error> {
                Integer::deserialize(de::value::MapAccessDeserializer::new(map)).map(Parameter::Integer)
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> std::result::Result<Self::Value, E> {
                let mut result = Zeroizing::new([0u8; 32]);
                if bytes.len() != result.len() { return Err(E::custom(INVALID)); }
                result.copy_from_slice(bytes);
                Ok(Parameter::Bytes(result))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error> {
                let mut result = Zeroizing::new([0u8; 32]);
                if seq.size_hint() != Some(result.len()) { return Err(de::Error::custom(INVALID)); }
                for byte in result.iter_mut() {
                    *byte = seq.next_element()?.ok_or_else(|| de::Error::custom(INVALID))?;
                }
                Ok(Parameter::Bytes(result))
            }
        }
        reader.deserialize_any(ParameterValue)
    }
}

fn read<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_CONTENT || !matches!(bytes.first(), Some(0x80..=0x8f | 0xde | 0xdf)) { return Err(INVALID); }
    let mut reader = rmp_serde::Deserializer::from_read_ref(bytes);
    reader.set_max_depth(MAX_DEPTH);
    let value = T::deserialize(&mut reader).map_err(|_| INVALID)?;
    // A u8 only reads a scalar, so EOF while reading its marker means there are no trailing bytes.
    match u8::deserialize(&mut reader) {
        Err(rmp_serde::decode::Error::InvalidMarkerRead(error)) if error.kind() == ErrorKind::UnexpectedEof => Ok(value),
        _ => Err(INVALID),
    }
}

impl CoseKey {
    fn to_pkcs8(&self) -> Result<SecretDocument> {
        if self.kind.t != "assign" || self.algorithm.t != "assign" || self.parameters.len() > 4 { return Err(INVALID); }
        let mut params = [None; 4];
        for (label, value) in &self.parameters {
            if label.t != "int" || !(-4..=-1).contains(&label.c) { return Err(INVALID); }
            if !matches!((value.t.as_str(), &value.c), ("int", Parameter::Integer(_)) | ("bytes", Parameter::Bytes(_))) {
                return Err(INVALID);
            }
            let slot = &mut params[(-label.c - 1) as usize];
            if slot.replace(&value.c).is_some() { return Err(INVALID); }
        }
        let [Some(Parameter::Integer(curve)), Some(Parameter::Bytes(x)), y, Some(Parameter::Bytes(secret))] = params else {
            return Err(INVALID);
        };
        let curve = i128::from_le_bytes(curve.inner);
        // The public coordinates must identify the supplied private key, not just the declared curve.
        match (self.kind.c.as_str(), self.algorithm.c.as_str(), curve, y) {
            ("EC2", "ES256", 1, Some(Parameter::Bytes(y))) => {
                let key = p256::ecdsa::SigningKey::from_slice(secret.as_ref()).map_err(|_| INVALID)?;
                let public = key.verifying_key().to_encoded_point(false);
                if public.x().map(|p| p.as_ref()) != Some(x.as_ref()) || public.y().map(|p| p.as_ref()) != Some(y.as_ref()) {
                    return Err(INVALID);
                }
                key.to_pkcs8_der().map_err(|_| INVALID)
            }
            ("OKP", "EdDSA", 6, None) => {
                let key = ed25519_dalek::SigningKey::from_bytes(secret);
                if key.verifying_key().as_bytes() != &**x { return Err(INVALID); }
                key.to_pkcs8_der().map_err(|_| INVALID)
            }
            _ => Err(INVALID),
        }
    }
}

fn base64_bytes(value: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() > limit.div_ceil(3) * 4 { return Err(INVALID); }
    let mut bytes = Zeroizing::new(vec![0; base64::decoded_len_estimate(value.len())]);
    let length = STANDARD.decode_slice(value, &mut bytes).map_err(|_| INVALID)?;
    if length > limit { return Err(INVALID); }
    // Leave no discarded capacity containing secret data.
    bytes[length..].fill(0);
    bytes.truncate(length);
    Ok(bytes)
}

fn same_id(record: &Value, field: &str, expected: &[u8], limit: usize) -> Result<()> {
    if let Some(value) = record.get(field) {
        let bytes = base64_bytes(value.as_str().ok_or(INVALID)?, limit)?;
        if bytes.as_slice() != expected { return Err(INVALID); }
    }
    Ok(())
}

pub(crate) fn read_key(record: &Value, fallback_account: &str) -> std::result::Result<Passkey, KeyImportError> {
    let content = text(record, "content");
    let bytes = base64_bytes(content, MAX_CONTENT)?;
    let envelope: Envelope = read(&bytes)?;
    if envelope.version != 1 { return Err(KeyImportError::UnsupportedVersion); }
    let native: NativeKey = read(&envelope.bytes)?;
    if native.extensions.hmac_secret.is_some() { return Err(KeyImportError::Invalid); }
    if let Some(rp_id) = record.get("rpId") {
        if rp_id.as_str() != Some(native.rp_id.as_str()) { return Err(KeyImportError::Invalid); }
    }
    same_id(record, "credentialId", &native.credential_id, 1023)?;
    same_id(record, "userHandle", native.user_handle.as_deref().unwrap_or_default(), 64)?;
    let discoverable = native.user_handle.is_some();
    let handle = match native.user_handle {
        Some(handle) => { same_id(record, "userId", &handle, 64)?; handle }
        None => base64_bytes(text(record, "userId"), 64)?.to_vec(),
    };
    let account = [text(record, "userName"), native.account.as_deref().unwrap_or(""), fallback_account]
        .into_iter().find(|value| !value.is_empty()).unwrap_or("");
    let eligible = record.get("backupEligible").map(|v| v.as_bool().ok_or(INVALID)).transpose()?.unwrap_or(true);
    let der = native.key.to_pkcs8()?;
    Passkey::from_pkcs8(native.credential_id, native.rp_id, handle, account.to_owned(), der.as_bytes(),
        discoverable, eligible, native.counter).map_err(KeyImportError::from)
}
