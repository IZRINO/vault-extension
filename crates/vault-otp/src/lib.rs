use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

enum Algorithm { Sha1, Sha256, Sha512 }

pub(crate) struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

fn invalid() -> &'static str {
    "验证码设置密钥无效。请检查 Base32 密钥或 otpauth://totp 链接。"
}

fn uri_decode(value: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|n| n as u8)
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        decoded.push(if b == b'%' {
            let hi = bytes.next().and_then(hex).ok_or_else(invalid)?;
            let lo = bytes.next().and_then(hex).ok_or_else(invalid)?;
            (hi << 4) | lo
        } else { b });
    }
    Ok(decoded)
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
        || (padding != 0 && padding != (8 - remainder) % 8)
    {
        return Err(invalid());
    }
    Ok(secret)
}

fn parse(value: &str) -> Result<Totp, &'static str> {
    let value = value.trim_ascii();
    if value.len() > 4096 { return Err(invalid()); }
    let mut result = Totp { secret: Zeroizing::new(Vec::new()), algorithm: Algorithm::Sha1, digits: 6, period: 30 };
    if let Some(uri) = value.strip_prefix("otpauth://totp/") {
        let (label, params) = uri.split_once('?').ok_or_else(invalid)?;
        if label.is_empty() || uri.contains('#') { return Err(invalid()); }
        let mut seen = 0u8;
        for param in params.split('&') {
            let (key, value) = param.split_once('=').ok_or_else(invalid)?;
            let flag = match key { "secret" => 1, "algorithm" => 2, "digits" => 4, "period" => 8, _ => continue };
            if seen & flag != 0 { return Err(invalid()); }
            seen |= flag;
            let decoded = uri_decode(value)?;
            let value = core::str::from_utf8(&decoded).map_err(|_| invalid())?;
            match flag {
                1 => result.secret = base32(&decoded)?,
                2 => {
                    result.algorithm = if value.eq_ignore_ascii_case("SHA1") { Algorithm::Sha1 }
                        else if value.eq_ignore_ascii_case("SHA256") { Algorithm::Sha256 }
                        else if value.eq_ignore_ascii_case("SHA512") { Algorithm::Sha512 }
                        else { return Err(invalid()); };
                }
                4 => result.digits = value.parse::<u32>().ok().filter(|d| (6..=8).contains(d)).ok_or_else(invalid)?,
                _ => result.period = value.parse::<u64>().ok().filter(|p| (1..=86400).contains(p)).ok_or_else(invalid)?,
            }
        }
        if result.secret.is_empty() { return Err(invalid()); }
    } else {
        result.secret = base32(value.as_bytes())?;
    }
    Ok(result)
}

impl Totp {
    pub(crate) fn code_at(&self, seconds: u64) -> (String, u64) {
        fn truncate(hash: &[u8]) -> u32 {
            let offset = (hash[hash.len() - 1] & 0x0f) as usize;
            u32::from_be_bytes([hash[offset], hash[offset + 1], hash[offset + 2], hash[offset + 3]]) & 0x7fff_ffff
        }
        let step = seconds / self.period;
        let counter = step.to_be_bytes();
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
        let integer = match self.algorithm {
            Algorithm::Sha1 => sign!(Sha1),
            Algorithm::Sha256 => sign!(Sha256),
            Algorithm::Sha512 => sign!(Sha512),
        };
        let mut value = integer % 10u32.pow(self.digits);
        let mut code = [b'0'; 8];
        for digit in code[..self.digits as usize].iter_mut().rev() {
            *digit += (value % 10) as u8;
            value /= 10;
        }
        let valid_to = (step + 1) * self.period;
        (core::str::from_utf8(&code[..self.digits as usize]).expect("ASCII digits").into(), valid_to)
    }
}

#[wasm_bindgen]
pub fn wasm_validate_totp(setup: String) -> Result<(), JsValue> {
    let setup = Zeroizing::new(setup);
    parse(&setup).map(|_| ()).map_err(JsValue::from_str)
}

#[wasm_bindgen]
pub fn wasm_totp_at(setup: String, timestamp_secs: f64) -> Result<String, JsValue> {
    let setup = Zeroizing::new(setup);
    if !timestamp_secs.is_finite() || timestamp_secs < 0.0 || timestamp_secs > 253_402_300_799.0 {
        return Err(JsValue::from_str("设备时间无效。"));
    }
    let (code, valid_to) = parse(&setup).map_err(JsValue::from_str)?.code_at(timestamp_secs as u64);
    Ok(format!("{code}:{valid_to}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_appendix_b() {
        let algorithms = [
            (Algorithm::Sha1, &b"12345678901234567890"[..]),
            (Algorithm::Sha256, &b"12345678901234567890123456789012"[..]),
            (Algorithm::Sha512, &b"1234567890123456789012345678901234567890123456789012345678901234"[..]),
        ];
        for (algorithm, (hash, key)) in algorithms.into_iter().enumerate() {
            let totp = Totp { secret: Zeroizing::new(key.to_vec()), algorithm: hash, digits: 8, period: 30 };
            for (time, codes) in [
                (59, ["94287082", "46119246", "90693936"]),
                (1_111_111_109, ["07081804", "68084774", "25091201"]),
                (1_111_111_111, ["14050471", "67062674", "99943326"]),
                (1_234_567_890, ["89005924", "91819424", "93441116"]),
                (2_000_000_000, ["69279037", "90698825", "38618901"]),
                (20_000_000_000, ["65353130", "77737706", "47863826"]),
            ] {
                assert_eq!(totp.code_at(time).0, codes[algorithm]);
            }
        }
    }

    #[test]
    fn supports_manual_setup_and_rejects_ambiguous_links() {
        assert_eq!(parse("gezd-gnbv gy3t qojq gezdgnbvgy3tqojq").unwrap().code_at(59), ("287082".into(), 60));
        let link = "otpauth://totp/Example%3Aaccount?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60";
        assert_eq!(parse(link).unwrap().code_at(119), ("94287082".into(), 120));
        for invalid in ["2345", "otpauth://hotp/account?secret=GEZDGNBVGY3TQOJQ", "GEZDGNBVGY3TQOJQ="] {
            assert!(parse(invalid).is_err());
        }
        assert!(parse(&(link.to_owned() + "&period=0")).is_err());
    }
}
