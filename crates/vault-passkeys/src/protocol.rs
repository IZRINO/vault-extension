use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::signature::Signer;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
#[cfg(feature = "authenticator")]
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Host, Url};
#[cfg(feature = "authenticator")]
use vault_core::crypto::csprng_fill;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub type Failure = &'static str;
pub const INVALID: Failure = "The passkey data or request is invalid.";
const UV: u8 = 0x04;
const UP: u8 = 0x01;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
#[cfg(feature = "authenticator")]
const AT: u8 = 0x40;

pub fn validate_rp(origin: &str, rp: &str) -> Result<(), Failure> {
    let url = Url::parse(origin).map_err(|_| INVALID)?;
    let Some(Host::Domain(host)) = url.host() else { return Err(INVALID); };
    if url.origin().ascii_serialization() != origin || host.ends_with('.') || rp.ends_with('.') || rp.len() > 253 ||
        !rp.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-') {
        return Err(INVALID);
    }
    if host == "localhost" && rp == "localhost" && matches!(url.scheme(), "https" | "http") { return Ok(()); }
    if url.scheme() != "https" || psl::domain_str(host).is_none() || psl::domain_str(rp).is_none() ||
        !(host == rp || host.strip_suffix(rp).is_some_and(|prefix| prefix.ends_with('.'))) { return Err(INVALID); }
    Ok(())
}

pub fn decode(value: &str, min: usize, max: usize) -> Result<Vec<u8>, Failure> {
    if value.len() > max.saturating_mul(2) { return Err(INVALID); }
    let result = B64.decode(value).map_err(|_| INVALID)?;
    if !(min..=max).contains(&result.len()) { return Err(INVALID); }
    Ok(result)
}

pub struct Ceremony<'a> { pub origin: &'a str, pub rp: &'a str, pub challenge: &'a str }
impl<'a> Ceremony<'a> {
    pub fn new(origin: &'a str, rp: &'a str, challenge: &'a str) -> Self { Self { origin, rp, challenge } }
    fn client_data(&self, operation: &str) -> Result<Vec<u8>, Failure> {
        validate_rp(self.origin, self.rp)?;
        decode(self.challenge, 16, 1024)?;
        let data = serde_json::json!({ "type": operation, "challenge": self.challenge, "origin": self.origin, "crossOrigin": false });
        serde_json::to_vec(&data).map_err(|_| INVALID)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebResponse {
    pub id: String,
    pub client_data_json: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_object: Option<String>,
    pub authenticator_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Passkey {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub account: String,
    pub algorithm: i32,
    secret: [u8; 32],
    pub discoverable: bool,
    pub eligible: bool,
    pub increment: bool,
    pub count: u32,
    pub count_unverified: bool,
    pub pack_backup_verified: bool,
}

impl Passkey {
    #[cfg(feature = "authenticator")]
    pub fn register(request: &Ceremony<'_>, user: &[u8], account: &str, algorithm: i32,
        verified: bool, increment: bool) -> Result<(Self, WebResponse), Failure> {
        let client = request.client_data("webauthn.create")?;
        if !(1..=64).contains(&user.len()) || account.len() > 1024 || !matches!(algorithm, -7 | -8) { return Err(INVALID); }
        let mut id = vec![0u8; 32];
        csprng_fill(&mut id).map_err(|_| INVALID)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        loop {
            csprng_fill(secret.as_mut()).map_err(|_| INVALID)?;
            if algorithm != -7 || p256::ecdsa::SigningKey::from_slice(secret.as_ref()).is_ok() { break; }
        }
        let key = Self { credential_id: id, rp_id: request.rp.into(), user_handle: user.to_vec(), account: account.into(),
            algorithm, secret: *secret, discoverable: true, eligible: true, increment, count: 0, count_unverified: false,
            pack_backup_verified: false };
        let mut data = key.auth_data(UP | AT | if verified { UV } else { 0 }, false, 0);
        data.extend_from_slice(&[0u8; 16]); // Anonymized AAGUID for none attestation.
        data.extend_from_slice(&(key.credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(&key.credential_id);
        let (cose, public) = key.public()?;
        data.extend_from_slice(&cose);
        use ciborium::Value;
        let object = encode_cbor(Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(Vec::new())),
            (Value::Text("authData".into()), Value::Bytes(data.clone())),
        ]))?;
        let response = WebResponse { id: B64.encode(&key.credential_id), client_data_json: B64.encode(client),
            attestation_object: Some(B64.encode(object)), authenticator_data: Some(B64.encode(data)), public_key: Some(B64.encode(public)),
            public_key_algorithm: Some(algorithm), signature: None, user_handle: None };
        Ok((key, response))
    }

    pub fn assert(&self, request: &Ceremony<'_>, verified: bool, backed_up: bool, count: u32) -> Result<WebResponse, Failure> {
        let client = request.client_data("webauthn.get")?;
        if self.rp_id != request.rp || self.count_unverified ||
            if self.increment { self.count.checked_add(1) != Some(count) } else { count != 0 } { return Err(INVALID); }
        let data = self.auth_data(UP | if verified { UV } else { 0 }, backed_up, count);
        let mut to_sign = data.clone();
        to_sign.extend_from_slice(&Sha256::digest(&client));
        let signature = match self.algorithm {
            -7 => {
                let signing = p256::ecdsa::SigningKey::from_slice(&self.secret).map_err(|_| INVALID)?;
                let signature: p256::ecdsa::Signature = signing.sign(&to_sign);
                signature.to_der().as_bytes().to_vec()
            }
            -8 => ed25519_dalek::SigningKey::from_bytes(&self.secret).sign(&to_sign).to_bytes().to_vec(),
            _ => return Err(INVALID),
        };
        Ok(WebResponse { id: B64.encode(&self.credential_id), client_data_json: B64.encode(client), attestation_object: None,
            authenticator_data: Some(B64.encode(data)), public_key: None, public_key_algorithm: None,
            signature: Some(B64.encode(signature)), user_handle: Some(B64.encode(&self.user_handle)) })
    }

    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let secret = match self.algorithm {
            -7 => p256::ecdsa::SigningKey::from_slice(&self.secret).map_err(|_| INVALID)?.to_pkcs8_der().map_err(|_| INVALID)?,
            -8 => ed25519_dalek::SigningKey::from_bytes(&self.secret).to_pkcs8_der().map_err(|_| INVALID)?,
            _ => return Err(INVALID),
        };
        Ok(Zeroizing::new(secret.as_bytes().to_vec()))
    }

    pub fn from_pkcs8(
        credential_id: Vec<u8>, rp_id: String, user_handle: Vec<u8>, account: String, bytes: &[u8],
        discoverable: bool, eligible: bool, counter: Option<u32>,
    ) -> Result<Self, Failure> {
        validate_rp(&format!("https://{rp_id}"), &rp_id)?;
        if !(1..=1023).contains(&credential_id.len()) || !(1..=64).contains(&user_handle.len()) || account.len() > 1024 { return Err(INVALID); }
        let (algorithm, secret) = if let Ok(p256) = p256::ecdsa::SigningKey::from_pkcs8_der(bytes) {
            (-7, Zeroizing::new(<[u8; 32]>::from(p256.to_bytes())))
        } else if let Ok(ed) = ed25519_dalek::SigningKey::from_pkcs8_der(bytes) {
            (-8, Zeroizing::new(ed.to_bytes()))
        } else { return Err(INVALID); };
        Ok(Self { credential_id, rp_id, user_handle, account, algorithm, secret: *secret, discoverable, eligible,
            increment: counter.is_some(), count: counter.unwrap_or(0), count_unverified: counter.is_some(), pack_backup_verified: false })
    }

    pub fn same_key(&self, other: &Self) -> bool {
        self.credential_id == other.credential_id && self.rp_id == other.rp_id && self.user_handle == other.user_handle &&
            self.algorithm == other.algorithm && self.secret == other.secret && self.eligible == other.eligible
    }

    fn auth_data(&self, flags: u8, backed_up: bool, count: u32) -> Vec<u8> {
        let mut data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        data.push(flags | if self.eligible { BE | if backed_up { BS } else { 0 } } else { 0 });
        data.extend_from_slice(&count.to_be_bytes());
        data
    }

    #[cfg(feature = "authenticator")]
    fn public(&self) -> Result<(Vec<u8>, Vec<u8>), Failure> {
        match self.algorithm {
            -7 => {
                let signing = p256::ecdsa::SigningKey::from_slice(&self.secret).map_err(|_| INVALID)?;
                let public = signing.verifying_key();
                let point = public.to_encoded_point(false);
                let cose = encode_cose(2, -7, 1, point.x().ok_or(INVALID)?, Some(point.y().ok_or(INVALID)?))?;
                Ok((cose, public.to_public_key_der().map_err(|_| INVALID)?.as_bytes().to_vec()))
            }
            -8 => {
                let signing = ed25519_dalek::SigningKey::from_bytes(&self.secret);
                let public = signing.verifying_key();
                let cose = encode_cose(1, -8, 6, &public.to_bytes(), None)?;
                Ok((cose, public.to_public_key_der().map_err(|_| INVALID)?.as_bytes().to_vec()))
            }
            _ => Err(INVALID),
        }
    }
}

#[cfg(feature = "authenticator")]
fn encode_cbor(value: ciborium::Value) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).map_err(|_| INVALID)?;
    Ok(out)
}

#[cfg(feature = "authenticator")]
fn encode_cose(key_type: i32, algorithm: i32, curve: i32, x: &[u8], y: Option<&[u8]>) -> Result<Vec<u8>, Failure> {
    use ciborium::Value;
    let int = |n: i32| Value::Integer(n.into());
    let mut fields = vec![(int(1), int(key_type)), (int(3), int(algorithm)), (int(-1), int(curve)), (int(-2), Value::Bytes(x.to_vec()))];
    if let Some(y) = y { fields.push((int(-3), Value::Bytes(y.to_vec()))); }
    encode_cbor(Value::Map(fields))
}
