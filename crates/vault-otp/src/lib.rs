use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SETUP_BYTES: usize = 64 * 1024;
const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Algorithm { Sha1, Sha256, Sha512 }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind { Totp, Hotp, Steam }

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self { Self::Totp => "totp", Self::Hotp => "hotp", Self::Steam => "steam" }
    }
}

pub struct Otp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    pub kind: Kind,
    pub counter: u64,
    pub label: String,
    pub issuer: String,
    pub code_display: Zeroizing<String>,
}

impl Drop for Otp {
    fn drop(&mut self) { self.label.zeroize(); self.issuer.zeroize(); }
}

fn invalid() -> &'static str {
    "验证码设置密钥无效。请检查 Base32 密钥或 otpauth://totp、hotp、steam 链接。"
}

pub fn uri_decode(value: &str, query: bool) -> Result<Zeroizing<String>, &'static str> {
    fn hex(b: u8) -> Option<u8> { (b as char).to_digit(16).map(|n| n as u8) }
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        decoded.push(if b == b'%' {
            let hi = bytes.next().and_then(hex).ok_or_else(invalid)?;
            let lo = bytes.next().and_then(hex).ok_or_else(invalid)?;
            (hi << 4) | lo
        } else if b == b'+' && query { b' ' } else { b });
    }
    Ok(Zeroizing::new(core::str::from_utf8(&decoded).map_err(|_| invalid())?.into()))
}

pub fn uri_encode(value: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { encoded.push(b as char); }
        else {
            encoded.push('%');
            encoded.push(HEX[(b >> 4) as usize] as char);
            encoded.push(HEX[(b & 15) as usize] as char);
        }
    }
    encoded
}

fn base32(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut secret = Zeroizing::new(Vec::with_capacity(128));
    let (mut bits, mut acc, mut symbols, mut padding) = (0, 0u16, 0, 0);
    for &b in value {
        let c = b.to_ascii_uppercase();
        let digit = match c {
            b' ' | b'\t' | b'\r' | b'\n' | b'-' => continue,
            b'=' => { padding += 1; continue; }
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(invalid()),
        };
        if padding != 0 { return Err(invalid()); }
        symbols += 1;
        acc = (acc << 5) | u16::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            secret.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
            if secret.len() > 128 { return Err(invalid()); }
        }
    }
    let remainder = symbols % 8;
    if secret.len() < 10 || acc != 0 || ![0, 2, 4, 5, 7].contains(&remainder)
        || (padding != 0 && padding != (8 - remainder) % 8) { return Err(invalid()); }
    Ok(secret)
}

fn encode_base32(secret: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut encoded = Zeroizing::new(String::new());
    let (mut acc, mut bits) = (0u16, 0);
    for &b in secret {
        acc = (acc << 8) | u16::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            encoded.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 { encoded.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char); }
    encoded
}

pub fn parse(value: &str) -> Result<Otp, &'static str> {
    let value = value.trim();
    if value.len() > MAX_SETUP_BYTES { return Err(invalid()); }
    let mut result = Otp {
        secret: Zeroizing::new(Vec::new()), algorithm: Algorithm::Sha1, digits: 6, period: 30,
        kind: Kind::Totp, counter: 0, label: String::new(), issuer: String::new(),
        code_display: Zeroizing::new(String::new()),
    };
    if let Some(uri) = value.strip_prefix("otpauth://") {
        let (kind, uri) = uri.split_once('/').ok_or_else(invalid)?;
        result.kind = match kind { "totp" => Kind::Totp, "hotp" => Kind::Hotp, "steam" => Kind::Steam, _ => return Err(invalid()) };
        let (label, params) = uri.split_once('?').ok_or_else(invalid)?;
        if label.is_empty() || uri.contains('#') { return Err(invalid()); }
        result.label = uri_decode(label, false)?.to_string();
        let mut seen = 0u16;
        for param in params.split('&') {
            let (key, value) = param.split_once('=').ok_or_else(invalid)?;
            let flag = match key {
                "secret" => 1, "algorithm" => 2, "digits" => 4, "period" => 8, "counter" => 16,
                "issuer" => 32, "codeDisplay" => 64, _ => continue,
            };
            if seen & flag != 0 { return Err(invalid()); }
            seen |= flag;
            let decoded = uri_decode(value, true)?;
            match flag {
                1 => result.secret = base32(decoded.as_bytes())?,
                2 => result.algorithm = if decoded.eq_ignore_ascii_case("SHA1") { Algorithm::Sha1 }
                    else if decoded.eq_ignore_ascii_case("SHA256") { Algorithm::Sha256 }
                    else if decoded.eq_ignore_ascii_case("SHA512") { Algorithm::Sha512 }
                    else { return Err(invalid()); },
                4 => result.digits = decoded.parse::<u32>().map_err(|_| invalid())?,
                8 => result.period = decoded.parse::<u64>().ok().filter(|p| (1..=86400).contains(p)).ok_or_else(invalid)?,
                16 => result.counter = decoded.parse::<u64>().map_err(|_| invalid())?,
                32 => result.issuer = decoded.to_string(),
                _ => result.code_display = decoded,
            }
        }
        if result.secret.is_empty() || (result.kind == Kind::Hotp && seen & 16 == 0) { return Err(invalid()); }
        if result.issuer.is_empty() {
            if let Some((issuer, _)) = result.label.split_once(':') { result.issuer = issuer.into(); }
        }
        if result.kind == Kind::Totp && result.issuer.eq_ignore_ascii_case("Steam") { result.kind = Kind::Steam; }
        if result.kind == Kind::Steam {
            if result.algorithm != Algorithm::Sha1 || result.period != 30 || (seen & 4 != 0 && ![5, 6].contains(&result.digits)) {
                return Err(invalid());
            }
            result.digits = 5;
        } else if !(6..=8).contains(&result.digits) { return Err(invalid()); }
    } else {
        result.secret = base32(value.as_bytes())?;
    }
    Ok(result)
}

impl Otp {
    pub fn account(&self) -> &str {
        self.label.strip_prefix(&format!("{}:", self.issuer)).unwrap_or(&self.label)
    }

    pub fn canonical_uri(&self) -> Zeroizing<String> {
        let algorithm = match self.algorithm { Algorithm::Sha1 => "SHA1", Algorithm::Sha256 => "SHA256", Algorithm::Sha512 => "SHA512" };
        let label = if self.label.is_empty() { "Account" } else { &self.label };
        let mut uri = Zeroizing::new(format!("otpauth://{}/{}?secret={}&algorithm={algorithm}&digits={}&period={}&issuer={}",
            self.kind.as_str(), uri_encode(label), &*encode_base32(&self.secret), self.digits, self.period, uri_encode(&self.issuer)));
        if self.kind == Kind::Hotp { uri.push_str(&format!("&counter={}", self.counter)); }
        if !self.code_display.is_empty() { uri.push_str(&format!("&codeDisplay={}", uri_encode(&self.code_display))); }
        uri
    }

    /// Counter and display changes must never make a used HOTP seed importable again.
    pub fn identity(&self) -> String {
        let mut hash = Sha256::new();
        let label = if self.kind == Kind::Hotp { "" } else { &self.label };
        let issuer = if self.kind == Kind::Hotp { "" } else { &self.issuer };
        for field in [label, issuer, self.kind.as_str(),
            &format!("{}:{}:{}", self.algorithm as u8, self.digits, self.period)]
        {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(&*self.secret);
        hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn code_for_counter(&self, counter: u64) -> String {
        fn truncate(hash: &[u8]) -> u32 {
            let offset = (hash[hash.len() - 1] & 15) as usize;
            u32::from_be_bytes([hash[offset], hash[offset + 1], hash[offset + 2], hash[offset + 3]]) & 0x7fff_ffff
        }
        let counter = counter.to_be_bytes();
        macro_rules! sign {
            ($digest:ty) => {{
                let mut mac = Hmac::<$digest>::new_from_slice(&self.secret).expect("HMAC supports any key length");
                mac.update(&counter);
                let mut hash = mac.finalize().into_bytes();
                let result = truncate(&hash);
                hash.as_mut_slice().zeroize();
                result
            }};
        }
        let mut value = match self.algorithm {
            Algorithm::Sha1 => sign!(Sha1), Algorithm::Sha256 => sign!(Sha256), Algorithm::Sha512 => sign!(Sha512),
        };
        let mut code = [b'0'; 8];
        if self.kind == Kind::Steam {
            for digit in &mut code[..5] {
                *digit = STEAM_ALPHABET[(value % STEAM_ALPHABET.len() as u32) as usize];
                value /= STEAM_ALPHABET.len() as u32;
            }
        } else {
            value %= 10u32.pow(self.digits);
            for digit in code[..self.digits as usize].iter_mut().rev() {
                *digit += (value % 10) as u8;
                value /= 10;
            }
        }
        core::str::from_utf8(&code[..self.digits as usize]).expect("ASCII code").into()
    }

    fn code_at(&self, seconds: u64) -> (String, u64) {
        (self.code_for_counter(seconds / self.period), (seconds / self.period + 1) * self.period)
    }
}

#[wasm_bindgen]
pub fn wasm_validate_totp(setup: String) -> Result<(), JsValue> {
    parse(&Zeroizing::new(setup)).map(|_| ()).map_err(JsValue::from_str)
}

fn valid_time(timestamp: f64) -> Result<u64, &'static str> {
    if !timestamp.is_finite() || !(0.0..=253_402_300_799.0).contains(&timestamp) { return Err("设备时间无效。"); }
    Ok(timestamp as u64)
}

#[wasm_bindgen]
pub fn wasm_totp_at(setup: String, timestamp_secs: f64) -> Result<String, JsValue> {
    let otp = parse(&Zeroizing::new(setup)).map_err(JsValue::from_str)?;
    if otp.kind == Kind::Hotp { return Err(JsValue::from_str("请点击生成计数验证码。")); }
    let (code, valid_to) = otp.code_at(valid_time(timestamp_secs).map_err(JsValue::from_str)?);
    Ok(format!("{code}:{valid_to}"))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Code {
    kind: &'static str,
    value: String,
    valid_to: Option<u64>,
    next_value: Option<String>,
    counter: Option<String>,
    next_setup_key: Option<Zeroizing<String>>,
}

fn generate(setup: &str, timestamp_secs: f64, offset_secs: i32) -> Result<String, &'static str> {
    let mut otp = parse(setup)?;
    let code = if otp.kind == Kind::Hotp {
        let counter = otp.counter;
        otp.counter = counter.checked_add(1).ok_or("计数器已用尽，请重新设置网站的两步验证。")?;
        Code { kind: "hotp", value: otp.code_for_counter(counter), valid_to: None, next_value: None,
            counter: Some(counter.to_string()), next_setup_key: Some(otp.canonical_uri()) }
    } else {
        let time = valid_time(timestamp_secs + f64::from(offset_secs))?;
        let (value, valid_to) = otp.code_at(time);
        Code { kind: otp.kind.as_str(), value, valid_to: Some(valid_to),
            next_value: (valid_to - time < 5).then(|| otp.code_at(valid_to).0), counter: None, next_setup_key: None }
    };
    serde_json::to_string(&code).map_err(|_| invalid())
}

#[wasm_bindgen]
pub fn wasm_otp_at(setup: String, timestamp_secs: f64, offset_secs: i32) -> Result<String, JsValue> {
    generate(&Zeroizing::new(setup), timestamp_secs, offset_secs).map_err(JsValue::from_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc_6238_appendix_b() {
        for (algorithm, (hash, key)) in [
            (Algorithm::Sha1, &b"12345678901234567890"[..]),
            (Algorithm::Sha256, &b"12345678901234567890123456789012"[..]),
            (Algorithm::Sha512, &b"1234567890123456789012345678901234567890123456789012345678901234"[..]),
        ].into_iter().enumerate() {
            let mut otp = parse(SECRET).unwrap();
            otp.secret = Zeroizing::new(key.to_vec()); otp.algorithm = hash; otp.digits = 8;
            for (time, codes) in [
                (59, ["94287082", "46119246", "90693936"]),
                (1_111_111_109, ["07081804", "68084774", "25091201"]),
                (1_111_111_111, ["14050471", "67062674", "99943326"]),
                (1_234_567_890, ["89005924", "91819424", "93441116"]),
                (2_000_000_000, ["69279037", "90698825", "38618901"]),
                (20_000_000_000, ["65353130", "77737706", "47863826"]),
            ] { assert_eq!(otp.code_at(time).0, codes[algorithm]); }
        }
    }

    #[test]
    fn rfc_4226_appendix_d_and_counter_precision() {
        let mut otp = parse(&format!("otpauth://hotp/Example?secret={SECRET}&counter=0")).unwrap();
        for (counter, expected) in ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"].into_iter().enumerate() {
            assert_eq!(otp.code_for_counter(counter as u64), expected);
        }
        otp.counter = 9_007_199_254_740_993;
        let generated: serde_json::Value = serde_json::from_str(&generate(&otp.canonical_uri(), 0.0, 0).unwrap()).unwrap();
        assert_eq!(generated["counter"], "9007199254740993");
        assert!(generated["nextSetupKey"].as_str().unwrap().contains("counter=9007199254740994"));
        let identity = otp.identity();
        otp.counter = u64::MAX;
        assert_eq!(identity, otp.identity());
        assert!(generate(&otp.canonical_uri(), 0.0, 0).is_err());
    }

    #[test]
    fn steam_guard_and_issuer_detection() {
        let otp = parse(&format!("otpauth://steam/Steam%3Atester?secret={SECRET}&issuer=Steam&digits=5")).unwrap();
        assert_eq!(otp.code_at(59).0, "PV9M4");
        let alias = parse(&format!("otpauth://totp/Steam%3Atester?secret={SECRET}&issuer=Steam")).unwrap();
        assert_eq!(otp.code_at(59), alias.code_at(59));
        assert_eq!(parse(&otp.canonical_uri()).unwrap().code_at(59), otp.code_at(59));
    }

    #[test]
    fn next_code_and_clock_compensation() {
        let generated: serde_json::Value = serde_json::from_str(&generate(SECRET, 59.0, 0).unwrap()).unwrap();
        assert_eq!(generated["value"], "287082");
        assert_eq!(generated["nextValue"], "359152");
        let adjusted: serde_json::Value = serde_json::from_str(&generate(SECRET, 49.0, 11).unwrap()).unwrap();
        assert_eq!(adjusted["value"], "359152");
        assert!(generate(SECRET, 0.0, -1).is_err());
    }

    #[test]
    fn rejects_ambiguous_links_and_normalizes_secrets() {
        assert_eq!(parse("gezd-gnbv gy3t qojq gezdgnbvgy3tqojq").unwrap().code_at(59), ("287082".into(), 60));
        for value in ["2345", "otpauth://hotp/account?secret=GEZDGNBVGY3TQOJQ", "GEZDGNBVGY3TQOJQ="] {
            assert!(parse(value).is_err());
        }
        let uri = format!("otpauth://totp/Example?secret={SECRET}&digits=8&period=60");
        assert_eq!(parse(&uri).unwrap().code_at(119), ("94287082".into(), 120));
        for suffix in ["&period=0", "&secret=JBSWY3DPEHPK3PXP"] { assert!(parse(&(uri.clone() + suffix)).is_err()); }
    }
}
