use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::csprng_fill;
use crate::error::VaultError;
use crate::json_lite::{bytes_find, compact_sort_by, concat3, encode_hex_lower, JVal};

pub const MAX_PASSWORD_HISTORY: usize = 20;

/// Generates a random RFC 4122 v4 UUID string (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`).
pub fn generate_uuid_v4() -> Result<String, VaultError> {
    let mut b = [0u8; 16];
    csprng_fill(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = encode_hex_lower(&b);
    let mut out = String::with_capacity(36);
    out.push_str(&hex[0..8]);
    out.push('-');
    out.push_str(&hex[8..12]);
    out.push('-');
    out.push_str(&hex[12..16]);
    out.push('-');
    out.push_str(&hex[16..20]);
    out.push('-');
    out.push_str(&hex[20..32]);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UriMatchRule {
    #[default]
    BaseDomain,
    Host,
    StartsWith,
    Exact,
    Regex,
    Never,
}

impl UriMatchRule {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BaseDomain => "base_domain",
            Self::Host => "host",
            Self::StartsWith => "starts_with",
            Self::Exact => "exact",
            Self::Regex => "regex",
            Self::Never => "never",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "host" => Self::Host,
            "starts_with" => Self::StartsWith,
            "exact" => Self::Exact,
            "regex" => Self::Regex,
            "never" => Self::Never,
            _ => Self::BaseDomain,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::BaseDomain => 0,
            Self::Host => 1,
            Self::StartsWith => 2,
            Self::Exact => 3,
            Self::Regex => 4,
            Self::Never => 5,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Host,
            2 => Self::StartsWith,
            3 => Self::Exact,
            4 => Self::Regex,
            5 => Self::Never,
            _ => Self::BaseDomain,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriEntry {
    pub uri: String,
    pub match_rule: UriMatchRule,
}

fn extract_authority_slice(uri: &str) -> &str {
    let trimmed = uri.trim_ascii();
    let bytes = trimmed.as_bytes();
    let rest = if let Some(idx) = bytes_find(bytes, b"://") {
        &trimmed[idx + 3..]
    } else {
        trimmed
    };
    let end = rest
        .as_bytes()
        .iter()
        .position(|&b| b == b'/' || b == b'?' || b == b'#')
        .unwrap_or(rest.len());
    &rest[..end]
}

/// Automatically tightens localhost / loopback / private LAN / `.local` / `.lan` URIs to `Host` (Host+Port) match.
pub fn infer_default_uri_match_rule(uri: &str) -> UriMatchRule {
    let authority = extract_authority_slice(uri).to_ascii_lowercase();
    let ab = authority.as_bytes();
    let host = if ab.first() == Some(&b'[') {
        let end = ab.iter().position(|&b| b == b']').unwrap_or(ab.len());
        &authority[1..end]
    } else {
        let end = ab.iter().position(|&b| b == b':').unwrap_or(ab.len());
        &authority[..end]
    };

    if host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || is_private_ipv4(host)
    {
        UriMatchRule::Host
    } else {
        UriMatchRule::BaseDomain
    }
}

fn is_private_ipv4(host: &str) -> bool {
    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    let mut start = 0usize;
    let bytes = host.as_bytes();
    for i in 0..=bytes.len() {
        if i == bytes.len() || bytes[i] == b'.' {
            if idx >= 4 || start == i {
                return false;
            }
            let Ok(v) = host[start..i].parse::<u8>() else {
                return false;
            };
            octets[idx] = v;
            idx += 1;
            start = i + 1;
        }
    }
    if idx != 4 {
        return false;
    }
    let (o0, o1) = (octets[0], octets[1]);
    o0 == 10 || (o0 == 172 && (16..=31).contains(&o1)) || (o0 == 192 && o1 == 168) || o0 == 127
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at_ms: u64,
    pub source_device: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardBrand {
    UnionPay,
    Visa,
    Mastercard,
    Amex,
    Jcb,
    Discover,
    #[default]
    Other,
}

impl CardBrand {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnionPay => "union_pay",
            Self::Visa => "visa",
            Self::Mastercard => "mastercard",
            Self::Amex => "amex",
            Self::Jcb => "jcb",
            Self::Discover => "discover",
            Self::Other => "other",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "union_pay" | "unionpay" => Self::UnionPay,
            "visa" => Self::Visa,
            "mastercard" => Self::Mastercard,
            "amex" => Self::Amex,
            "jcb" => Self::Jcb,
            "discover" => Self::Discover,
            _ => Self::Other,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Other => 0,
            Self::UnionPay => 1,
            Self::Visa => 2,
            Self::Mastercard => 3,
            Self::Amex => 4,
            Self::Jcb => 5,
            Self::Discover => 6,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::UnionPay,
            2 => Self::Visa,
            3 => Self::Mastercard,
            4 => Self::Amex,
            5 => Self::Jcb,
            6 => Self::Discover,
            _ => Self::Other,
        }
    }

    pub fn detect(card_number: &str) -> Self {
        let digits: Vec<u8> = card_number
            .as_bytes()
            .iter()
            .copied()
            .filter(u8::is_ascii_digit)
            .collect();
        if digits.is_empty() {
            return Self::Other;
        }
        if digits.starts_with(b"62") || digits.starts_with(b"81") {
            return Self::UnionPay;
        }
        if digits[0] == b'4' {
            return Self::Visa;
        }
        if digits.starts_with(b"34") || digits.starts_with(b"37") {
            return Self::Amex;
        }
        if digits.len() >= 4 {
            let p4 = ((digits[0] - b'0') as u16) * 1000
                + ((digits[1] - b'0') as u16) * 100
                + ((digits[2] - b'0') as u16) * 10
                + ((digits[3] - b'0') as u16);
            if (3528..=3589).contains(&p4) {
                return Self::Jcb;
            }
            if (2221..=2720).contains(&p4) {
                return Self::Mastercard;
            }
            if p4 == 6011 {
                return Self::Discover;
            }
        }
        if digits.len() >= 2 {
            let p2 = (digits[0] - b'0') * 10 + (digits[1] - b'0');
            if (51..=55).contains(&p2) {
                return Self::Mastercard;
            }
            if p2 == 65 {
                return Self::Discover;
            }
        }
        Self::Other
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::UnionPay => "UnionPay",
            Self::Visa => "Visa",
            Self::Mastercard => "Mastercard",
            Self::Amex => "Amex",
            Self::Jcb => "JCB",
            Self::Discover => "Discover",
            Self::Other => "Card",
        }
    }
}

pub fn extract_card_last4(card_number: &str) -> String {
    let digits: Vec<u8> = card_number
        .as_bytes()
        .iter()
        .copied()
        .filter(u8::is_ascii_digit)
        .collect();
    let start = digits.len().saturating_sub(4);
    String::from_utf8(digits[start..].to_vec()).unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct LoginCredential {
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub uris: Vec<UriEntry>,
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Reserved for Phase 2 built-in 2FA attachment (`otpauth://` or raw seed config)
    pub totp_uri: Option<String>,
    /// Versioned authenticator records. Never projected into the editable JSON representation.
    pub passkey_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct PaymentCardCredential {
    pub cardholder_name: String,
    pub card_number: String,
    #[zeroize(skip)]
    pub brand: CardBrand,
    pub exp_month: String,
    pub exp_year: String,
    pub cvv: String,
    pub card_pin: String,
    pub billing_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct IdentityCredential {
    pub full_name: String,
    pub phone: String,
    pub email: String,
    pub national_id_or_passport: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub address_line: String,
    pub postal_code: String,
    pub company: String,
    pub tax_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeveloperCredentialSubtype {
    #[default]
    ApiToken,
    LicenseKey,
    SshKey,
}

impl DeveloperCredentialSubtype {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApiToken => "api_token",
            Self::LicenseKey => "license_key",
            Self::SshKey => "ssh_key",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "license_key" => Self::LicenseKey,
            "ssh_key" => Self::SshKey,
            _ => Self::ApiToken,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::ApiToken => 0,
            Self::LicenseKey => 1,
            Self::SshKey => 2,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::LicenseKey,
            2 => Self::SshKey,
            _ => Self::ApiToken,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize, ZeroizeOnDrop)]
pub struct DeveloperCredential {
    #[zeroize(skip)]
    pub subtype: DeveloperCredentialSubtype,
    pub service_or_product: String,
    pub token_or_license: String,
    pub public_key: String,
    pub private_key: String,
    #[zeroize(skip)]
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialKind {
    #[default]
    Login,
    PaymentCard,
    Identity,
    Developer,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::PaymentCard => "payment_card",
            Self::Identity => "identity",
            Self::Developer => "developer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialData {
    Login(LoginCredential),
    PaymentCard(PaymentCardCredential),
    Identity(IdentityCredential),
    Developer(DeveloperCredential),
}

impl CredentialData {
    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::Login(login) => login.zeroize(),
            Self::PaymentCard(card) => card.zeroize(),
            Self::Identity(id) => id.zeroize(),
            Self::Developer(dev) => dev.zeroize(),
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Login(_) => "login",
            Self::PaymentCard(_) => "payment_card",
            Self::Identity(_) => "identity",
            Self::Developer(_) => "developer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[zeroize(skip)]
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultItem {
    pub id: String,
    pub title: String,
    pub data: CredentialData,
    pub note: String,
    pub custom_fields: Vec<CustomField>,
    pub tags: Vec<String>,
    pub pinned: bool,
    pub require_reprompt: bool,
    pub trashed: bool,
    pub trashed_at_ms: Option<u64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub revision: u64,
}

impl Drop for VaultItem {
    fn drop(&mut self) {
        self.zeroize_sensitive();
        self.id.zeroize();
        self.title.zeroize();
        self.tags.zeroize();
    }
}

impl VaultItem {
    pub fn zeroize_sensitive(&mut self) {
        self.data.zeroize_secrets();
        self.note.zeroize();
        for cf in &mut self.custom_fields {
            cf.zeroize();
        }
    }

    /// Normalizes derived attributes (such as auto-detecting card brand and URI default match rules)
    /// and maintains the 20-entry reverse-chronological `passwordHistory` invariant when updating a Login item.
    pub fn apply_update(&mut self, mut incoming: VaultItem, now_ms: u64, source_device: Option<String>) {
        incoming.normalize_derived_fields();

        if let (CredentialData::Login(old_login), CredentialData::Login(new_login)) =
            (&self.data, &mut incoming.data)
        {
            if !old_login.passkey_data.is_empty() {
                new_login.passkey_data.clone_from(&old_login.passkey_data);
            }
            let mut merged_history = if new_login.password_history.is_empty() {
                old_login.password_history.clone()
            } else {
                new_login.password_history.clone()
            };

            if !old_login.password.is_empty() && old_login.password != new_login.password {
                merged_history.insert(
                    0,
                    PasswordHistoryEntry {
                        password: old_login.password.clone(),
                        changed_at_ms: now_ms,
                        source_device,
                    },
                );
            }
            // Keep reverse chronological order and strictly cap at 20 entries
            compact_sort_by(&mut merged_history, |a, b| b.changed_at_ms.cmp(&a.changed_at_ms));
            if merged_history.len() > MAX_PASSWORD_HISTORY {
                for dropped in merged_history.drain(MAX_PASSWORD_HISTORY..) {
                    let mut d = dropped;
                    d.zeroize();
                }
            }
            new_login.password_history = merged_history;
        }

        incoming.id = self.id.clone();
        incoming.created_at_ms = self.created_at_ms;
        incoming.updated_at_ms = now_ms;
        incoming.revision = self.revision.saturating_add(1);
        if incoming.trashed && incoming.trashed_at_ms.is_none() {
            incoming.trashed_at_ms = Some(now_ms);
        } else if !incoming.trashed {
            incoming.trashed_at_ms = None;
        }

        self.zeroize_sensitive();
        *self = incoming;
    }

    pub fn normalize_derived_fields(&mut self) {
        match &mut self.data {
            CredentialData::PaymentCard(card) => {
                let detected = CardBrand::detect(&card.card_number);
                if detected != CardBrand::Other {
                    card.brand = detected;
                }
            }
            CredentialData::Login(login) => {
                for u in &mut login.uris {
                    u.uri = u.uri.trim_ascii().to_string();
                }
                login.uris.retain(|u| !u.uri.is_empty());
            }
            _ => {}
        }
        let mut clean_tags = Vec::with_capacity(self.tags.len());
        for tag in &self.tags {
            let t = tag.trim_ascii();
            if !t.is_empty() && !clean_tags.iter().any(|existing: &String| existing == t) {
                clean_tags.push(t.to_string());
            }
        }
        self.tags = clean_tags;
    }

    pub fn to_summary(&self) -> VaultItemSummary {
        let (subtitle, primary_domain, card_brand, card_last4, dev_subtype, has_totp) = match &self.data {
            CredentialData::Login(login) => {
                let primary = login
                    .uris
                    .first()
                    .map(|u| extract_host_display(&u.uri))
                    .unwrap_or_default();
                let sub = if !login.username.is_empty() {
                    login.username.clone()
                } else {
                    primary.clone()
                };
                (
                    sub,
                    Some(primary).filter(|s| !s.is_empty()),
                    None,
                    None,
                    None,
                    login.totp_uri.as_ref().is_some_and(|t| !t.trim_ascii().is_empty()),
                )
            }
            CredentialData::PaymentCard(card) => {
                let last4 = extract_card_last4(&card.card_number);
                let brand = if card.brand == CardBrand::Other {
                    CardBrand::detect(&card.card_number)
                } else {
                    card.brand
                };
                let masked = if last4.is_empty() {
                    brand.display_name().to_string()
                } else {
                    concat3(brand.display_name(), " •••• ", &last4)
                };
                (
                    masked,
                    None,
                    Some(brand),
                    Some(last4),
                    None,
                    false,
                )
            }
            CredentialData::Identity(id) => {
                let sub = if !id.full_name.is_empty() {
                    id.full_name.clone()
                } else if !id.email.is_empty() {
                    id.email.clone()
                } else {
                    id.phone.clone()
                };
                (sub, None, None, None, None, false)
            }
            CredentialData::Developer(dev) => {
                let sub = if !dev.service_or_product.is_empty() {
                    dev.service_or_product.clone()
                } else {
                    match dev.subtype {
                        DeveloperCredentialSubtype::ApiToken => "API Token".into(),
                        DeveloperCredentialSubtype::LicenseKey => "Software License".into(),
                        DeveloperCredentialSubtype::SshKey => "SSH Keypair".into(),
                    }
                };
                (sub, None, None, None, Some(dev.subtype), false)
            }
        };

        VaultItemSummary {
            id: self.id.clone(),
            title: self.title.clone(),
            kind: self.data.kind_name().to_string(),
            subtitle,
            primary_domain,
            card_brand,
            card_last4,
            dev_subtype,
            has_totp,
            tags: self.tags.clone(),
            pinned: self.pinned,
            require_reprompt: self.require_reprompt,
            trashed: self.trashed,
            trashed_at_ms: self.trashed_at_ms,
            updated_at_ms: self.updated_at_ms,
        }
    }
}

pub fn extract_host_display(uri: &str) -> String {
    extract_authority_slice(uri).to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultItemSummary {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub subtitle: String,
    pub primary_domain: Option<String>,
    pub card_brand: Option<CardBrand>,
    pub card_last4: Option<String>,
    pub dev_subtype: Option<DeveloperCredentialSubtype>,
    pub has_totp: bool,
    pub tags: Vec<String>,
    pub pinned: bool,
    pub require_reprompt: bool,
    pub trashed: bool,
    pub trashed_at_ms: Option<u64>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMetadata {
    pub device_id: String,
    pub dev_tag: String,
    pub device_name: String,
    pub os_arch: String,
    pub browser: String,
    pub ext_version: String,
    pub created_at_ms: u64,
    pub last_seen_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSnapshot {
    pub vault_id: String,
    pub snapshot_id: String,
    pub snapshot_epoch: u64,
    pub hlc_timestamp: u64,
    pub items: Vec<VaultItem>,
    pub device_registry: Vec<DeviceMetadata>,
    pub included_wal_ids: Vec<String>,
    pub state_mac: [u8; 32],
}

impl Drop for VaultSnapshot {
    fn drop(&mut self) { self.zeroize_all(); }
}

impl VaultSnapshot {
    pub fn new_empty(vault_id: String, snapshot_id: String, now_ms: u64) -> Self {
        Self {
            vault_id,
            snapshot_id,
            snapshot_epoch: 1,
            hlc_timestamp: now_ms,
            items: Vec::new(),
            device_registry: Vec::new(),
            included_wal_ids: Vec::new(),
            state_mac: [0u8; 32],
        }
    }

    pub fn zeroize_all(&mut self) {
        for item in &mut self.items {
            item.zeroize_sensitive();
        }
        self.items.clear();
    }
}

// ============================================================================
// Zero-Monomorphization JSON Value Mapping for UI / WASM Boundary
// ============================================================================

impl VaultItem {
    pub fn to_json_value(&self) -> JVal {
        let data_val = match &self.data {
            CredentialData::Login(l) => JVal::Obj(vec![
                ("kind", JVal::Str("login".into())),
                ("username", JVal::Str(l.username.clone())),
                ("password", JVal::Str(l.password.clone())),
                (
                    "uris",
                    JVal::Arr(
                        l.uris
                            .iter()
                            .map(|u| {
                                JVal::Obj(vec![
                                    ("uri", JVal::Str(u.uri.clone())),
                                    ("matchRule", JVal::Str(u.match_rule.as_str().into())),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "passwordHistory",
                    JVal::Arr(
                        l.password_history
                            .iter()
                            .map(|h| {
                                JVal::Obj(vec![
                                    ("password", JVal::Str(h.password.clone())),
                                    ("changedAtMs", JVal::Uint(h.changed_at_ms)),
                                    ("sourceDevice", JVal::opt_str(&h.source_device)),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("totpUri", JVal::opt_str(&l.totp_uri)),
            ]),
            CredentialData::PaymentCard(c) => JVal::Obj(vec![
                ("kind", JVal::Str("payment_card".into())),
                ("cardholderName", JVal::Str(c.cardholder_name.clone())),
                ("cardNumber", JVal::Str(c.card_number.clone())),
                ("brand", JVal::Str(c.brand.as_str().into())),
                ("expMonth", JVal::Str(c.exp_month.clone())),
                ("expYear", JVal::Str(c.exp_year.clone())),
                ("cvv", JVal::Str(c.cvv.clone())),
                ("cardPin", JVal::Str(c.card_pin.clone())),
                ("billingAddress", JVal::Str(c.billing_address.clone())),
            ]),
            CredentialData::Identity(id) => JVal::Obj(vec![
                ("kind", JVal::Str("identity".into())),
                ("fullName", JVal::Str(id.full_name.clone())),
                ("phone", JVal::Str(id.phone.clone())),
                ("email", JVal::Str(id.email.clone())),
                ("nationalIdOrPassport", JVal::Str(id.national_id_or_passport.clone())),
                ("country", JVal::Str(id.country.clone())),
                ("province", JVal::Str(id.province.clone())),
                ("city", JVal::Str(id.city.clone())),
                ("addressLine", JVal::Str(id.address_line.clone())),
                ("postalCode", JVal::Str(id.postal_code.clone())),
                ("company", JVal::Str(id.company.clone())),
                ("taxId", JVal::Str(id.tax_id.clone())),
            ]),
            CredentialData::Developer(d) => JVal::Obj(vec![
                ("kind", JVal::Str("developer".into())),
                ("subtype", JVal::Str(d.subtype.as_str().into())),
                ("serviceOrProduct", JVal::Str(d.service_or_product.clone())),
                ("tokenOrLicense", JVal::Str(d.token_or_license.clone())),
                ("publicKey", JVal::Str(d.public_key.clone())),
                ("privateKey", JVal::Str(d.private_key.clone())),
                ("expiresAtMs", JVal::opt_u64(d.expires_at_ms)),
            ]),
        };

        JVal::Obj(vec![
            ("id", JVal::Str(self.id.clone())),
            ("title", JVal::Str(self.title.clone())),
            ("data", data_val),
            ("note", JVal::Str(self.note.clone())),
            (
                "customFields",
                JVal::Arr(
                    self.custom_fields
                        .iter()
                        .map(|cf| {
                            JVal::Obj(vec![
                                ("name", JVal::Str(cf.name.clone())),
                                ("value", JVal::Str(cf.value.clone())),
                                ("hidden", JVal::Bool(cf.hidden)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("tags", JVal::Arr(self.tags.iter().cloned().map(JVal::Str).collect())),
            ("pinned", JVal::Bool(self.pinned)),
            ("requireReprompt", JVal::Bool(self.require_reprompt)),
            ("trashed", JVal::Bool(self.trashed)),
            ("trashedAtMs", JVal::opt_u64(self.trashed_at_ms)),
            ("createdAtMs", JVal::Uint(self.created_at_ms)),
            ("updatedAtMs", JVal::Uint(self.updated_at_ms)),
            ("revision", JVal::Uint(self.revision)),
        ])
    }

    pub fn from_json_str(s: &str) -> Result<Self, VaultError> {
        let v = JVal::parse(s)?;
        Self::from_json_value(&v)
    }

    pub fn from_json_value(obj: &JVal) -> Result<Self, VaultError> {
        let data_obj = obj
            .get_field("data")
            .ok_or_else(|| VaultError::InvalidInput("item.data must be a JSON object".into()))?;
        let kind = data_obj.get_str("kind");
        let data = match kind.as_str() {
            "login" => {
                let uris = data_obj
                    .get_field("uris")
                    .and_then(JVal::as_array)
                    .map(|arr| {
                        arr.iter()
                            .map(|uo| {
                                let uri = uo.get_str("uri");
                                let match_rule = uo
                                    .get_field("matchRule")
                                    .and_then(JVal::as_str)
                                    .map(UriMatchRule::from_str_lossy)
                                    .unwrap_or_else(|| infer_default_uri_match_rule(&uri));
                                UriEntry { uri, match_rule }
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let password_history = data_obj
                    .get_field("passwordHistory")
                    .and_then(JVal::as_array)
                    .map(|arr| {
                        arr.iter()
                            .map(|ho| PasswordHistoryEntry {
                                password: ho.get_str("password"),
                                changed_at_ms: ho.get_u64("changedAtMs"),
                                source_device: ho
                                    .get_field("sourceDevice")
                                    .and_then(JVal::as_str)
                                    .map(|s| s.to_string()),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                CredentialData::Login(LoginCredential {
                    passkey_data: Vec::new(),
                    username: data_obj.get_str("username"),
                    password: data_obj.get_str("password"),
                    uris,
                    password_history,
                    totp_uri: data_obj
                        .get_field("totpUri")
                        .and_then(JVal::as_str)
                        .filter(|s| !s.trim_ascii().is_empty())
                        .map(|s| s.to_string()),
                })
            }
            "payment_card" => CredentialData::PaymentCard(PaymentCardCredential {
                cardholder_name: data_obj.get_str("cardholderName"),
                card_number: data_obj.get_str("cardNumber"),
                brand: CardBrand::from_str_lossy(&data_obj.get_str("brand")),
                exp_month: data_obj.get_str("expMonth"),
                exp_year: data_obj.get_str("expYear"),
                cvv: data_obj.get_str("cvv"),
                card_pin: data_obj.get_str("cardPin"),
                billing_address: data_obj.get_str("billingAddress"),
            }),
            "identity" => CredentialData::Identity(IdentityCredential {
                full_name: data_obj.get_str("fullName"),
                phone: data_obj.get_str("phone"),
                email: data_obj.get_str("email"),
                national_id_or_passport: data_obj.get_str("nationalIdOrPassport"),
                country: data_obj.get_str("country"),
                province: data_obj.get_str("province"),
                city: data_obj.get_str("city"),
                address_line: data_obj.get_str("addressLine"),
                postal_code: data_obj.get_str("postalCode"),
                company: data_obj.get_str("company"),
                tax_id: data_obj.get_str("taxId"),
            }),
            "developer" => CredentialData::Developer(DeveloperCredential {
                subtype: DeveloperCredentialSubtype::from_str_lossy(&data_obj.get_str("subtype")),
                service_or_product: data_obj.get_str("serviceOrProduct"),
                token_or_license: data_obj.get_str("tokenOrLicense"),
                public_key: data_obj.get_str("publicKey"),
                private_key: data_obj.get_str("privateKey"),
                expires_at_ms: data_obj.get_opt_u64("expiresAtMs"),
            }),
            _ => {
                return Err(VaultError::InvalidInput(
                    "unsupported credential kind".into(),
                ))
            }
        };

        let custom_fields = obj
            .get_field("customFields")
            .and_then(JVal::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|co| CustomField {
                        name: co.get_str("name"),
                        value: co.get_str("value"),
                        hidden: co.get_bool("hidden"),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let tags = obj
            .get_field("tags")
            .and_then(JVal::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(JVal::as_str)
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            id: obj.get_str("id"),
            title: obj.get_str("title"),
            data,
            note: obj.get_str("note"),
            custom_fields,
            tags,
            pinned: obj.get_bool("pinned"),
            require_reprompt: obj.get_bool("requireReprompt"),
            trashed: obj.get_bool("trashed"),
            trashed_at_ms: obj.get_opt_u64("trashedAtMs"),
            created_at_ms: obj.get_u64("createdAtMs"),
            updated_at_ms: obj.get_u64("updatedAtMs"),
            revision: obj.get_u64("revision"),
        })
    }
}

impl VaultItemSummary {
    pub fn to_json_value(&self) -> JVal {
        JVal::Obj(vec![
            ("id", JVal::Str(self.id.clone())),
            ("title", JVal::Str(self.title.clone())),
            ("kind", JVal::Str(self.kind.clone())),
            ("subtitle", JVal::Str(self.subtitle.clone())),
            ("primaryDomain", JVal::opt_str(&self.primary_domain)),
            (
                "cardBrand",
                match self.card_brand {
                    Some(b) => JVal::Str(b.as_str().into()),
                    None => JVal::Null,
                },
            ),
            ("cardLast4", JVal::opt_str(&self.card_last4)),
            (
                "devSubtype",
                match self.dev_subtype {
                    Some(s) => JVal::Str(s.as_str().into()),
                    None => JVal::Null,
                },
            ),
            ("hasTotp", JVal::Bool(self.has_totp)),
            ("tags", JVal::Arr(self.tags.iter().cloned().map(JVal::Str).collect())),
            ("pinned", JVal::Bool(self.pinned)),
            ("requireReprompt", JVal::Bool(self.require_reprompt)),
            ("trashed", JVal::Bool(self.trashed)),
            ("trashedAtMs", JVal::opt_u64(self.trashed_at_ms)),
            ("updatedAtMs", JVal::Uint(self.updated_at_ms)),
        ])
    }
}
