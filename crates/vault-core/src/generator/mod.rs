use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::crypto::csprng_fill;
use crate::error::VaultError;
use crate::json_lite::JVal;
use crate::sync_codec::zstd_decompress_bounded;

static EFF_WORDLIST_ZST: &[u8] = include_bytes!("eff_wordlist.zst");
static EFF_WORDS: OnceLock<Vec<String>> = OnceLock::new();

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/~";
const AMBIGUOUS: &[u8] = b"0O1lI";

/// Unbiased uniform random integer in `[0, upper_bound)` using rejection sampling.
pub fn random_uniform_u32(upper_bound: u32) -> Result<u32, VaultError> {
    if upper_bound <= 1 {
        return Ok(0);
    }
    let zone = u32::MAX - (u32::MAX % upper_bound);
    let mut buf = [0u8; 4];
    loop {
        csprng_fill(&mut buf)?;
        let candidate = u32::from_le_bytes(buf);
        if candidate < zone {
            return Ok(candidate % upper_bound);
        }
    }
}

fn csprng_shuffle<T>(slice: &mut [T]) -> Result<(), VaultError> {
    for i in (1..slice.len()).rev() {
        let j = random_uniform_u32((i + 1) as u32)? as usize;
        slice.swap(i, j);
    }
    Ok(())
}

/// Decompresses and decodes the embedded 7,776-word official EFF Large Wordlist on first use.
pub fn eff_large_wordlist() -> Result<&'static [String], VaultError> {
    if let Some(words) = EFF_WORDS.get() {
        return Ok(words.as_slice());
    }
    let decoded = zstd_decompress_bounded(EFF_WORDLIST_ZST, 256 * 1024)?;
    let mut words = Vec::with_capacity(7776);
    let mut prev: Vec<u8> = Vec::with_capacity(16);
    let mut pos = 0usize;
    while pos + 2 <= decoded.len() {
        let common = decoded[pos] as usize;
        let suffix_len = decoded[pos + 1] as usize;
        pos += 2;
        if common > prev.len() || pos + suffix_len > decoded.len() {
            return Err(VaultError::CodecError(
                "corrupted embedded EFF wordlist".into(),
            ));
        }
        let mut current = Vec::with_capacity(common + suffix_len);
        current.extend_from_slice(&prev[..common]);
        current.extend_from_slice(&decoded[pos..pos + suffix_len]);
        pos += suffix_len;
        let word = String::from_utf8(current.clone())
            .map_err(|_| VaultError::CodecError("invalid UTF-8 in EFF wordlist".into()))?;
        words.push(word);
        prev = current;
    }
    if words.len() != 7776 {
        return Err(VaultError::CodecError(
            "unexpected EFF wordlist count".into(),
        ));
    }
    let _ = EFF_WORDS.set(words);
    Ok(EFF_WORDS.get().expect("EFF_WORDS initialized").as_slice())
}

#[derive(Debug, Clone)]
pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub min_digits: usize,
    pub min_symbols: usize,
    pub exclude_ambiguous: bool,
}

impl PasswordGeneratorOptions {
    pub fn from_json_str(s: &str) -> Result<Self, VaultError> {
        let mut opts = Self::default();
        if s.trim_ascii().is_empty() {
            return Ok(opts);
        }
        let v = JVal::parse(s)?;
        if let Some(n) = v.get_field("length").and_then(JVal::as_u64) {
            opts.length = n as usize;
        }
        if let Some(b) = v.get_field("lowercase").and_then(JVal::as_bool) {
            opts.lowercase = b;
        }
        if let Some(b) = v.get_field("uppercase").and_then(JVal::as_bool) {
            opts.uppercase = b;
        }
        if let Some(b) = v.get_field("digits").and_then(JVal::as_bool) {
            opts.digits = b;
        }
        if let Some(b) = v.get_field("symbols").and_then(JVal::as_bool) {
            opts.symbols = b;
        }
        if let Some(n) = v.get_field("minDigits").and_then(JVal::as_u64) {
            opts.min_digits = n as usize;
        }
        if let Some(n) = v.get_field("minSymbols").and_then(JVal::as_u64) {
            opts.min_symbols = n as usize;
        }
        if let Some(b) = v.get_field("excludeAmbiguous").and_then(JVal::as_bool) {
            opts.exclude_ambiguous = b;
        }
        Ok(opts)
    }
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            min_digits: 2,
            min_symbols: 2,
            exclude_ambiguous: true,
        }
    }
}

fn filter_pool(pool: &[u8], exclude_ambiguous: bool) -> Vec<u8> {
    pool.iter()
        .copied()
        .filter(|b| !exclude_ambiguous || !AMBIGUOUS.contains(b))
        .collect()
}

pub fn generate_random_password(
    opts: &PasswordGeneratorOptions,
) -> Result<Zeroizing<String>, VaultError> {
    if !(8..=128).contains(&opts.length) {
        return Err(VaultError::InvalidInput(
            "password length must be between 8 and 128 characters".into(),
        ));
    }
    let lower = if opts.lowercase {
        filter_pool(LOWERCASE, opts.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let upper = if opts.uppercase {
        filter_pool(UPPERCASE, opts.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let digits = if opts.digits {
        filter_pool(DIGITS, opts.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let symbols = if opts.symbols {
        filter_pool(SYMBOLS, opts.exclude_ambiguous)
    } else {
        Vec::new()
    };

    let mut combined = Vec::new();
    combined.extend_from_slice(&lower);
    combined.extend_from_slice(&upper);
    combined.extend_from_slice(&digits);
    combined.extend_from_slice(&symbols);

    if combined.is_empty() {
        return Err(VaultError::InvalidInput(
            "at least one character class must be enabled".into(),
        ));
    }

    let mut chars: Vec<u8> = Vec::with_capacity(opts.length);

    let req_lower = usize::from(!lower.is_empty());
    let req_upper = usize::from(!upper.is_empty());
    let req_digits = if digits.is_empty() {
        0
    } else {
        opts.min_digits.max(1)
    };
    let req_symbols = if symbols.is_empty() {
        0
    } else {
        opts.min_symbols.max(1)
    };

    for _ in 0..req_lower {
        if chars.len() < opts.length {
            let idx = random_uniform_u32(lower.len() as u32)? as usize;
            chars.push(lower[idx]);
        }
    }
    for _ in 0..req_upper {
        if chars.len() < opts.length {
            let idx = random_uniform_u32(upper.len() as u32)? as usize;
            chars.push(upper[idx]);
        }
    }
    for _ in 0..req_digits {
        if chars.len() < opts.length {
            let idx = random_uniform_u32(digits.len() as u32)? as usize;
            chars.push(digits[idx]);
        }
    }
    for _ in 0..req_symbols {
        if chars.len() < opts.length {
            let idx = random_uniform_u32(symbols.len() as u32)? as usize;
            chars.push(symbols[idx]);
        }
    }

    while chars.len() < opts.length {
        let idx = random_uniform_u32(combined.len() as u32)? as usize;
        chars.push(combined[idx]);
    }

    csprng_shuffle(&mut chars)?;
    let out = String::from_utf8(chars)
        .map_err(|_| VaultError::CodecError("generated non-ASCII password byte".into()))?;
    Ok(Zeroizing::new(out))
}

#[derive(Debug, Clone)]
pub struct PassphraseGeneratorOptions {
    pub word_count: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl PassphraseGeneratorOptions {
    pub fn from_json_str(s: &str) -> Result<Self, VaultError> {
        let mut opts = Self::default();
        if s.trim_ascii().is_empty() {
            return Ok(opts);
        }
        let v = JVal::parse(s)?;
        if let Some(n) = v.get_field("wordCount").and_then(JVal::as_u64) {
            opts.word_count = n as usize;
        }
        if let Some(sep) = v.get_field("separator").and_then(JVal::as_str) {
            opts.separator = sep.to_string();
        }
        if let Some(b) = v.get_field("capitalize").and_then(JVal::as_bool) {
            opts.capitalize = b;
        }
        if let Some(b) = v.get_field("includeNumber").and_then(JVal::as_bool) {
            opts.include_number = b;
        }
        Ok(opts)
    }
}

impl Default for PassphraseGeneratorOptions {
    fn default() -> Self {
        Self {
            word_count: 5,
            separator: "-".into(),
            capitalize: false,
            include_number: true,
        }
    }
}

pub fn generate_eff_passphrase(
    opts: &PassphraseGeneratorOptions,
) -> Result<Zeroizing<String>, VaultError> {
    if !(3..=12).contains(&opts.word_count) {
        return Err(VaultError::InvalidInput(
            "passphrase word_count must be between 3 and 12".into(),
        ));
    }
    let wordlist = eff_large_wordlist()?;
    let mut selected = Vec::with_capacity(opts.word_count + usize::from(opts.include_number));
    for _ in 0..opts.word_count {
        let idx = random_uniform_u32(wordlist.len() as u32)? as usize;
        let mut w = wordlist[idx].clone();
        if opts.capitalize {
            if let Some(first) = w.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
        }
        selected.push(w);
    }
    if opts.include_number {
        let digit = random_uniform_u32(10)?;
        let mut ds = String::with_capacity(1);
        ds.push((b'0' + digit as u8) as char);
        selected.push(ds);
    }
    Ok(Zeroizing::new(selected.join(&opts.separator)))
}
