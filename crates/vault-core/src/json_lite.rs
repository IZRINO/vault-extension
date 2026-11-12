use zeroize::Zeroize;
use crate::error::VaultError;

/// Lightweight RFC 8259 JSON value avoiding `serde_json` / `BTreeMap` / `zmij` WASM code bloat.
#[derive(Clone, PartialEq, Eq)]
pub enum JVal {
    Null,
    Bool(bool),
    Uint(u64),
    /// Fixed-point 1-decimal representation (`724` => `72.4`) to avoid 12 KB float formatting tables.
    Tenths(u32),
    Str(String),
    Arr(Vec<JVal>),
    Obj(Vec<(&'static str, JVal)>),
    ParsedObj(Vec<(String, JVal)>),
}

impl Drop for JVal {
    fn drop(&mut self) {
        match self {
            Self::Str(value) => value.zeroize(),
            Self::ParsedObj(entries) => {
                for (key, _) in entries { key.zeroize(); }
            }
            _ => {}
        }
        // Nested values are dropped recursively, clearing their string buffers too.
    }
}

impl JVal {
    pub fn opt_str(s: &Option<String>) -> Self {
        match s {
            Some(v) => Self::Str(v.clone()),
            None => Self::Null,
        }
    }

    pub fn opt_u64(v: Option<u64>) -> Self {
        match v {
            Some(n) => Self::Uint(n),
            None => Self::Null,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JVal]> {
        match self {
            Self::Arr(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    pub fn get_field(&self, key: &str) -> Option<&JVal> {
        match self {
            Self::ParsedObj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            Self::Obj(entries) => entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_str(&self, key: &str) -> String {
        self.get_field(key)
            .and_then(Self::as_str)
            .unwrap_or("")
            .to_string()
    }

    pub fn get_bool(&self, key: &str) -> bool {
        self.get_field(key).and_then(Self::as_bool).unwrap_or(false)
    }

    pub fn get_u64(&self, key: &str) -> u64 {
        self.get_field(key).and_then(Self::as_u64).unwrap_or(0)
    }

    pub fn get_opt_u64(&self, key: &str) -> Option<u64> {
        self.get_field(key).and_then(Self::as_u64)
    }

    pub fn stringify(&self) -> String {
        let mut out = String::with_capacity(256);
        self.write_into(&mut out);
        out
    }

    fn write_into(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Uint(n) => push_u64_dec(out, *n),
            Self::Tenths(t) => {
                push_u64_dec(out, (*t / 10) as u64);
                out.push('.');
                out.push((b'0' + (*t % 10) as u8) as char);
            }
            Self::Str(s) => write_escaped_str(out, s),
            Self::Arr(items) => {
                out.push('[');
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    item.write_into(out);
                }
                out.push(']');
            }
            Self::Obj(entries) => {
                out.push('{');
                for (idx, (k, v)) in entries.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    write_escaped_str(out, k);
                    out.push(':');
                    v.write_into(out);
                }
                out.push('}');
            }
            Self::ParsedObj(entries) => {
                out.push('{');
                for (idx, (k, v)) in entries.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    write_escaped_str(out, k);
                    out.push(':');
                    v.write_into(out);
                }
                out.push('}');
            }
        }
    }

    pub fn parse(input: &str) -> Result<Self, VaultError> {
        let bytes = input.as_bytes();
        let mut pos = 0usize;
        skip_ws(bytes, &mut pos);
        let val = parse_val(bytes, &mut pos, 0)?;
        skip_ws(bytes, &mut pos);
        if pos != bytes.len() {
            return Err(VaultError::InvalidInput("trailing JSON characters".into()));
        }
        Ok(val)
    }
}

pub fn push_u64_dec(out: &mut String, mut n: u64) {
    if n == 0 {
        out.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut len = 0usize;
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        out.push(digits[len] as char);
    }
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

pub fn encode_hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_UPPER[(b >> 4) as usize] as char);
        out.push(HEX_UPPER[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn encode_hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

fn write_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    let bytes = s.as_bytes();
    let mut last_plain = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: Option<&'static str> = match b {
            b'"' => Some("\\\""),
            b'\\' => Some("\\\\"),
            b'\n' => Some("\\n"),
            b'\r' => Some("\\r"),
            b'\t' => Some("\\t"),
            0x08 => Some("\\b"),
            0x0c => Some("\\f"),
            0x00..=0x1f => None,
            _ => continue,
        };
        if last_plain < i {
            out.push_str(&s[last_plain..i]);
        }
        if let Some(seq) = esc {
            out.push_str(seq);
        } else {
            out.push_str("\\u00");
            out.push(HEX_LOWER[(b >> 4) as usize] as char);
            out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
        }
        last_plain = i + 1;
    }
    if last_plain < bytes.len() {
        out.push_str(&s[last_plain..]);
    }
    out.push('"');
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() {
        match bytes[*pos] {
            b' ' | b'\t' | b'\r' | b'\n' => *pos += 1,
            _ => break,
        }
    }
}

fn parse_val(bytes: &[u8], pos: &mut usize, depth: usize) -> Result<JVal, VaultError> {
    if depth > 32 {
        return Err(VaultError::InvalidInput("JSON nesting too deep".into()));
    }
    skip_ws(bytes, pos);
    if *pos >= bytes.len() {
        return Err(VaultError::InvalidInput("unexpected end of JSON".into()));
    }
    match bytes[*pos] {
        b'n' => {
            if bytes.get(*pos..*pos + 4) == Some(b"null") {
                *pos += 4;
                Ok(JVal::Null)
            } else {
                Err(VaultError::InvalidInput("invalid JSON null".into()))
            }
        }
        b't' => {
            if bytes.get(*pos..*pos + 4) == Some(b"true") {
                *pos += 4;
                Ok(JVal::Bool(true))
            } else {
                Err(VaultError::InvalidInput("invalid JSON true".into()))
            }
        }
        b'f' => {
            if bytes.get(*pos..*pos + 5) == Some(b"false") {
                *pos += 5;
                Ok(JVal::Bool(false))
            } else {
                Err(VaultError::InvalidInput("invalid JSON false".into()))
            }
        }
        b'"' => Ok(JVal::Str(parse_string(bytes, pos)?)),
        b'[' => parse_array(bytes, pos, depth + 1),
        b'{' => parse_object(bytes, pos, depth + 1),
        b'-' | b'0'..=b'9' => parse_number(bytes, pos),
        _ => Err(VaultError::InvalidInput("unexpected JSON token".into())),
    }
}

fn parse_hex4(bytes: &[u8], pos: &mut usize) -> Result<u16, VaultError> {
    if *pos + 4 > bytes.len() {
        return Err(VaultError::InvalidInput("truncated \\u escape".into()));
    }
    let mut val = 0u16;
    for _ in 0..4 {
        let b = bytes[*pos];
        *pos += 1;
        let nib = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(VaultError::InvalidInput("invalid hex in \\u escape".into())),
        };
        val = (val << 4) | (nib as u16);
    }
    Ok(val)
}

fn parse_string(bytes: &[u8], pos: &mut usize) -> Result<String, VaultError> {
    *pos += 1; // skip opening '"'
    let mut out = String::new();
    let mut chunk_start = *pos;
    while *pos < bytes.len() {
        let b = bytes[*pos];
        match b {
            b'"' => {
                if chunk_start < *pos {
                    let seg = std::str::from_utf8(&bytes[chunk_start..*pos])
                        .map_err(|_| VaultError::InvalidInput("invalid UTF-8 in JSON".into()))?;
                    out.push_str(seg);
                }
                *pos += 1;
                return Ok(out);
            }
            b'\\' => {
                if chunk_start < *pos {
                    let seg = std::str::from_utf8(&bytes[chunk_start..*pos])
                        .map_err(|_| VaultError::InvalidInput("invalid UTF-8 in JSON".into()))?;
                    out.push_str(seg);
                }
                *pos += 1;
                if *pos >= bytes.len() {
                    return Err(VaultError::InvalidInput("unterminated JSON escape".into()));
                }
                let esc = bytes[*pos];
                *pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\x08'),
                    b'f' => out.push('\x0c'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hi = parse_hex4(bytes, pos)?;
                        let codepoint = if (0xD800..=0xDBFF).contains(&hi) {
                            if bytes.get(*pos..*pos + 2) != Some(b"\\u") {
                                return Err(VaultError::InvalidInput("unpaired surrogate".into()));
                            }
                            *pos += 2;
                            let lo = parse_hex4(bytes, pos)?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err(VaultError::InvalidInput("invalid low surrogate".into()));
                            }
                            0x10000 + (((hi as u32 - 0xD800) << 10) | (lo as u32 - 0xDC00))
                        } else {
                            hi as u32
                        };
                        let ch = char::from_u32(codepoint)
                            .ok_or_else(|| VaultError::InvalidInput("invalid unicode scalar".into()))?;
                        out.push(ch);
                    }
                    _ => return Err(VaultError::InvalidInput("unknown JSON escape".into())),
                }
                chunk_start = *pos;
            }
            0x00..=0x1f => return Err(VaultError::InvalidInput("unescaped control char in JSON".into())),
            _ => *pos += 1,
        }
    }
    Err(VaultError::InvalidInput("unterminated JSON string".into()))
}

fn parse_number(bytes: &[u8], pos: &mut usize) -> Result<JVal, VaultError> {
    let neg = bytes[*pos] == b'-';
    if neg {
        *pos += 1;
    }
    if *pos >= bytes.len() || !bytes[*pos].is_ascii_digit() {
        return Err(VaultError::InvalidInput("invalid JSON number".into()));
    }
    let mut acc = 0u64;
    while *pos < bytes.len() && bytes[*pos].is_ascii_digit() {
        acc = acc.saturating_mul(10).saturating_add((bytes[*pos] - b'0') as u64);
        *pos += 1;
    }
    if *pos < bytes.len() && bytes[*pos] == b'.' {
        *pos += 1;
        if *pos >= bytes.len() || !bytes[*pos].is_ascii_digit() {
            return Err(VaultError::InvalidInput("invalid JSON fraction".into()));
        }
        while *pos < bytes.len() && bytes[*pos].is_ascii_digit() {
            *pos += 1;
        }
    }
    if *pos < bytes.len() && (bytes[*pos] == b'e' || bytes[*pos] == b'E') {
        *pos += 1;
        if *pos < bytes.len() && (bytes[*pos] == b'+' || bytes[*pos] == b'-') {
            *pos += 1;
        }
        if *pos >= bytes.len() || !bytes[*pos].is_ascii_digit() {
            return Err(VaultError::InvalidInput("invalid JSON exponent".into()));
        }
        while *pos < bytes.len() && bytes[*pos].is_ascii_digit() {
            *pos += 1;
        }
    }
    Ok(JVal::Uint(if neg { 0 } else { acc }))
}

fn parse_array(bytes: &[u8], pos: &mut usize, depth: usize) -> Result<JVal, VaultError> {
    *pos += 1;
    skip_ws(bytes, pos);
    let mut items = Vec::new();
    if *pos < bytes.len() && bytes[*pos] == b']' {
        *pos += 1;
        return Ok(JVal::Arr(items));
    }
    loop {
        items.push(parse_val(bytes, pos, depth)?);
        skip_ws(bytes, pos);
        if *pos >= bytes.len() {
            return Err(VaultError::InvalidInput("unterminated JSON array".into()));
        }
        match bytes[*pos] {
            b',' => *pos += 1,
            b']' => {
                *pos += 1;
                return Ok(JVal::Arr(items));
            }
            _ => return Err(VaultError::InvalidInput("expected ',' or ']' in JSON array".into())),
        }
    }
}

fn parse_object(bytes: &[u8], pos: &mut usize, depth: usize) -> Result<JVal, VaultError> {
    *pos += 1;
    skip_ws(bytes, pos);
    let mut entries = Vec::new();
    if *pos < bytes.len() && bytes[*pos] == b'}' {
        *pos += 1;
        return Ok(JVal::ParsedObj(entries));
    }
    loop {
        skip_ws(bytes, pos);
        if *pos >= bytes.len() || bytes[*pos] != b'"' {
            return Err(VaultError::InvalidInput("expected string key in JSON object".into()));
        }
        let key = parse_string(bytes, pos)?;
        skip_ws(bytes, pos);
        if *pos >= bytes.len() || bytes[*pos] != b':' {
            return Err(VaultError::InvalidInput("expected ':' in JSON object".into()));
        }
        *pos += 1;
        let val = parse_val(bytes, pos, depth)?;
        entries.push((key, val));
        skip_ws(bytes, pos);
        if *pos >= bytes.len() {
            return Err(VaultError::InvalidInput("unterminated JSON object".into()));
        }
        match bytes[*pos] {
            b',' => *pos += 1,
            b'}' => {
                *pos += 1;
                return Ok(JVal::ParsedObj(entries));
            }
            _ => return Err(VaultError::InvalidInput("expected ',' or '}' in JSON object".into())),
        }
    }
}

// ============================================================================
// Zero-Table Byte String Helpers (avoids Unicode White_Space & TwoWaySearcher)
// ============================================================================

#[inline]
pub fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[inline]
pub fn bytes_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[inline]
pub fn concat2(a: &str, b: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len());
    s.push_str(a);
    s.push_str(b);
    s
}

#[inline]
pub fn concat3(a: &str, b: &str, c: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len() + c.len());
    s.push_str(a);
    s.push_str(b);
    s.push_str(c);
    s
}

/// Compact Ciura-gap Shellsort (`O(n log^2 n)`) avoiding 22+ KiB of monomorphized
/// `core::slice::sort::unstable` (`ipnsort` + `smallsort` + `heapsort`) in WASM.
pub fn compact_sort_by<T, F>(slice: &mut [T], mut cmp: F)
where
    F: FnMut(&T, &T) -> core::cmp::Ordering,
{
    const GAPS: [usize; 8] = [701, 301, 132, 57, 23, 10, 4, 1];
    let len = slice.len();
    if len < 2 {
        return;
    }
    for &gap in &GAPS {
        if gap >= len {
            continue;
        }
        for i in gap..len {
            let mut j = i;
            while j >= gap && cmp(&slice[j - gap], &slice[j]) == core::cmp::Ordering::Greater {
                slice.swap(j - gap, j);
                j -= gap;
            }
        }
    }
}
