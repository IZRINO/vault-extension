use super::{first, Batch, Login, Record, Result, INVALID, MAX_FILE, MAX_ROWS, PASSWORD};
use serde::{Deserialize, Deserializer, de::{Error, SeqAccess, Visitor}};
use std::{collections::{BTreeMap, VecDeque}, fmt, io::{Cursor, Read}, marker::PhantomData};
use vault_otp::{encode_base32, parse, uri_decode, uri_encode};
use zeroize::Zeroizing;

const UNSUPPORTED: &str = "该验证码的类型或生成参数不受支持。";
const FREEOTP_FORMAT: &str = "请选择 FreeOTP+ 的 JSON 或密钥 URI 文本导出，不要选择应用设置或系统备份。";
const WINAUTH_FORMAT: &str = "请选择 WinAuth 导出的 TXT 或 ZIP；应用配置与公钥加密 PGP 不在此处导入。";
const WINAUTH_ZIP_ERROR: &str = "WinAuth ZIP 文件密码错误或文件损坏；没有写入任何条目。";

#[derive(Clone, Copy, PartialEq, Eq)]
enum UriDialect { FreeOtpPlus, WinAuth }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FreeOtpExport {
    #[serde(deserialize_with = "bounded_rows")]
    tokens: Vec<FreeOtpToken>,
    #[serde(deserialize_with = "bounded_rows")]
    token_order: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FreeOtpToken {
    label: String,
    label_alt: Option<String>,
    issuer_alt: String,
    issuer_ext: String,
    issuer_int: String,
    category: String,
    #[serde(rename = "type")]
    kind: String,
    secret: Option<JavaSecret>,
    algo: Option<String>,
    digits: Option<u64>,
    period: Option<u64>,
    counter: Option<i64>,
}

fn bounded_rows<'de, D: Deserializer<'de>, T: Deserialize<'de>>(de: D) -> std::result::Result<Vec<T>, D::Error> {
    struct Rows<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Rows<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("a bounded backup array") }
        fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> std::result::Result<Self::Value, A::Error> {
            let mut rows = Vec::new();
            while let Some(row) = input.next_element()? {
                if rows.len() == MAX_ROWS { return Err(A::Error::custom("backup row limit")); }
                rows.push(row);
            }
            Ok(rows)
        }
    }
    de.deserialize_seq(Rows(PhantomData))
}

// Deserialize directly into wiped byte storage; a serde_json::Value tree would retain
// a second copy of every numeric seed byte, even when an entry is never imported.
struct JavaSecret { bytes: Zeroizing<Vec<u8>>, valid: bool }

impl<'de> Deserialize<'de> for JavaSecret {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        struct SecretBytes;
        impl<'de> Visitor<'de> for SecretBytes {
            type Value = JavaSecret;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("a Java byte array") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> std::result::Result<Self::Value, A::Error> {
                let mut bytes = Zeroizing::new(Vec::with_capacity(128));
                let mut valid = true;
                for _ in 0..128 {
                    let Some(value) = input.next_element::<i64>()? else { return Ok(JavaSecret { bytes, valid }); };
                    valid &= (-128..=255).contains(&value);
                    bytes.push(value as u8);
                }
                if input.next_element::<serde::de::IgnoredAny>()?.is_some() { return Err(A::Error::custom("backup seed limit")); }
                Ok(JavaSecret { bytes, valid })
            }
        }
        de.deserialize_seq(SecretBytes)
    }
}

struct Token<'a> {
    kind: &'a str, account: &'a str, issuer: &'a str, seed: &'a str,
    algorithm: &'a str, digits: u64, period: u64, counter: Option<u64>, category: &'a str,
}

impl Token<'_> {
    fn into_record(self) -> Result<Record> {
        let Self { kind, account, issuer, seed, algorithm, digits, period, counter, category } = self;
        if account.trim().is_empty() || account.len() > 1024 || issuer.len() > 1024
            || category.len() > 1024 || seed.len() > 256 || seed.is_empty() {
            return Err(INVALID);
        }
        if !matches!(algorithm, "SHA1" | "SHA256" | "SHA512") { return Err(UNSUPPORTED); }
        let kind = match (kind, issuer) {
            ("totp", "Steam") if algorithm == "SHA1" && digits == 5 && period == 30 => "steam",
            (_, issuer) if issuer.eq_ignore_ascii_case("Steam") => return Err(UNSUPPORTED),
            ("totp" | "hotp", _) if (6..=8).contains(&digits) => kind,
            _ => return Err(UNSUPPORTED),
        };
        // A leading colon represents an empty issuer and preserves ':' in the account on reparse.
        let label = if issuer.is_empty() && !account.contains(':') { account.to_owned() } else { format!("{issuer}:{account}") };
        let mut uri = Zeroizing::new(format!("otpauth://{kind}/{}?secret={}&algorithm={algorithm}&digits={digits}&period={period}&issuer={}",
            uri_encode(&label), &*Zeroizing::new(uri_encode(seed)), uri_encode(issuer)));
        if kind == "hotp" { uri.push_str(&format!("&counter={}", counter.ok_or(INVALID)?)); }
        let otp = parse(&uri).map_err(|_| INVALID)?;
        Ok(Record { title: first(&[issuer, account]).into(), note: String::new(), pinned: false, custom_fields: [],
            tags: (!category.is_empty()).then(|| category.to_owned()).into_iter().collect(),
            data: Login { kind: "login".into(), username: account.into(), totp_uri: otp.canonical_uri().to_string() },
        })
    }
}

fn append(batch: &mut Batch, result: Result<Record>) {
    match result {
        Ok(record) => batch.rows.push(record),
        Err(UNSUPPORTED) => batch.unsupported += 1,
        Err(_) => batch.invalid += 1,
    }
}

fn backup_text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes)).map(str::trim_start).map_err(|_| INVALID)
}

pub(super) fn freeotp_plus(bytes: &[u8], password: &str) -> Result<Batch> {
    if !password.is_empty() { return Err(FREEOTP_FORMAT); }
    let text = backup_text(bytes).map_err(|_| FREEOTP_FORMAT)?;
    if text.starts_with('{') { freeotp_json(text.as_bytes()) }
    else if text.starts_with("otpauth://") { uri_lines(text, UriDialect::FreeOtpPlus) }
    else { Err(FREEOTP_FORMAT) }
}

fn freeotp_json(bytes: &[u8]) -> Result<Batch> {
    let FreeOtpExport { tokens, token_order } = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    // The native writer can emit repeated IDs. Each occurrence consumes the next unused row.
    let mut ids = BTreeMap::<String, VecDeque<usize>>::new();
    let mut display_ids = BTreeMap::<String, VecDeque<usize>>::new();
    let mut unqualified = BTreeMap::<&str, VecDeque<usize>>::new();
    let display_issuer = |index: usize| {
        let token = &tokens[index];
        first(&[&token.issuer_alt, &token.issuer_ext, &token.issuer_int])
    };
    for (index, token) in tokens.iter().enumerate() {
        let label = &token.label;
        let id_issuer = first(&[&token.issuer_int, &token.issuer_ext]);
        let shown = display_issuer(index);
        if label.trim().is_empty() || label.len() > 1024 || id_issuer.len() > 1024 || shown.len() > 1024 { continue; }
        let id = if id_issuer.is_empty() { label.to_owned() } else { format!("{id_issuer}:{label}") };
        ids.entry(id).or_default().push_back(index);
        if shown.is_empty() { unqualified.entry(label).or_default().push_back(index); }
        else { display_ids.entry(format!("{shown}:{label}")).or_default().push_back(index); }
    }
    let mut used = vec![false; tokens.len()];
    let mut batch = Batch::default();
    for key in &token_order {
        if key.is_empty() || key.len() > 2049 {
            batch.invalid += 1;
            continue;
        }
        let take = |queue: Option<&mut VecDeque<usize>>| -> Option<usize> {
            let queue = queue?;
            while queue.front().is_some_and(|&index| used[index]) { queue.pop_front(); }
            queue.pop_front()
        };
        let (index, fallback) = if let Some(i) = take(ids.get_mut(key)) { (i, "") }
            else if let Some(i) = key.strip_prefix(':').and_then(|label| take(unqualified.get_mut(label))) { (i, "") }
            else if let Some(i) = take(display_ids.get_mut(key)) { (i, "") }
            else if let Some((issuer, label)) = key.split_once(':') {
                let Some(i) = take(unqualified.get_mut(label)) else { batch.invalid += 1; continue; };
                (i, issuer)
            } else { batch.invalid += 1; continue; };
        used[index] = true;
        append(&mut batch, freeotp_row(&tokens[index], first(&[display_issuer(index), fallback])));
    }
    batch.invalid += used.iter().filter(|&&matched| !matched).count();
    Ok(batch)
}

fn freeotp_row(row: &FreeOtpToken, issuer: &str) -> Result<Record> {
    let kind = match row.kind.as_str() { "TOTP" => "totp", "HOTP" => "hotp", _ => return Err(UNSUPPORTED) };
    let secret = row.secret.as_ref().filter(|v| v.valid && v.bytes.len() >= 10).ok_or(INVALID)?;
    let counter = if kind == "hotp" { Some(row.counter.and_then(|n| u64::try_from(n).ok()).ok_or(INVALID)?) } else { None };
    Token { kind, account: row.label_alt.as_deref().unwrap_or(&row.label), issuer,
        seed: &encode_base32(&secret.bytes), algorithm: row.algo.as_deref().unwrap_or("SHA1"),
        digits: row.digits.unwrap_or(6), period: row.period.unwrap_or(30), counter, category: &row.category }.into_record()
}

pub(super) fn winauth(bytes: &[u8], password: &str) -> Result<Batch> {
    let archive;
    let bytes = if bytes.starts_with(b"PK\x03\x04") {
        archive = winauth_zip(bytes, password)?;
        archive.as_slice()
    } else {
        if !password.is_empty() { return Err(WINAUTH_FORMAT); }
        bytes
    };
    let text = backup_text(bytes).map_err(|_| WINAUTH_FORMAT)?;
    if !text.starts_with("otpauth://") && !text.starts_with('#') { return Err(WINAUTH_FORMAT); }
    uri_lines(text, UriDialect::WinAuth)
}

fn winauth_zip(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| INVALID)?;
    if archive.len() != 1 { return Err(WINAUTH_FORMAT); }
    let metadata = archive.by_index_raw(0).map_err(|_| INVALID)?;
    if !metadata.is_file() || metadata.is_symlink() || metadata.name().contains(['/', '\\', ':'])
        || !metadata.name().to_ascii_lowercase().ends_with(".txt") || metadata.size() > MAX_FILE as u64 {
        return Err(WINAUTH_FORMAT);
    }
    let encrypted = metadata.encrypted();
    drop(metadata);
    if encrypted && password.is_empty() { return Err(PASSWORD); }
    if !encrypted && !password.is_empty() { return Err("此 WinAuth ZIP 无需文件密码，请留空。"); }
    let entry = if encrypted { archive.by_index_decrypt(0, password.as_bytes()).map_err(|_| WINAUTH_ZIP_ERROR)? }
        else { archive.by_index(0).map_err(|_| INVALID)? };
    let mut out = Zeroizing::new(Vec::new());
    entry.take(MAX_FILE as u64 + 1).read_to_end(&mut out).map_err(|_| if encrypted { WINAUTH_ZIP_ERROR } else { INVALID })?;
    if out.len() > MAX_FILE { return Err(INVALID); }
    Ok(out)
}

fn uri_lines(text: &str, dialect: UriDialect) -> Result<Batch> {
    let mut batch = Batch::default();
    let lines = text.lines().map(str::trim).filter(|line| !(line.is_empty() || dialect == UriDialect::WinAuth && line.starts_with('#')));
    for (index, line) in lines.enumerate() {
        if index == MAX_ROWS { return Err(INVALID); }
        append(&mut batch, read_uri(line, dialect));
    }
    Ok(batch)
}

fn read_uri(line: &str, dialect: UriDialect) -> Result<Record> {
    if line.len() > vault_otp::MAX_SETUP_BYTES || line.contains('#') { return Err(INVALID); }
    let (kind, rest) = line.strip_prefix("otpauth://").and_then(|line| line.split_once('/')).ok_or(INVALID)?;
    if !matches!(kind, "totp" | "hotp") { return Err(UNSUPPORTED); }
    let (label, query) = rest.split_once('?').ok_or(INVALID)?;
    let mut params = BTreeMap::new();
    for part in query.split('&') {
        let (key, value) = part.split_once('=').ok_or(INVALID)?;
        if params.len() == 24 || key.is_empty() || !key.bytes().all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
            || params.insert(key.to_ascii_lowercase(), value).is_some() {
            return Err(INVALID);
        }
    }
    let decode = |name| params.get(name).map(|v| uri_decode(v, true)).transpose();
    let issuer = decode("issuer")?.unwrap_or_default();
    let seed = decode("secret")?.ok_or(INVALID)?;
    let algorithm = decode("algorithm")?.unwrap_or_else(|| Zeroizing::new("SHA1".to_owned()));
    let digits = decode("digits")?.ok_or(INVALID)?.parse::<u64>().map_err(|_| INVALID)?;
    let period = decode("period")?.map_or(Ok(30), |v| v.parse::<u64>().map_err(|_| INVALID))?;
    if dialect == UriDialect::WinAuth && (algorithm.as_str() != "SHA1" || period != 30) { return Err(UNSUPPORTED); }
    let counter = if kind == "hotp" {
        let source = decode("counter")?.ok_or(INVALID)?.parse::<i64>().map_err(|_| INVALID)?;
        let next = match dialect {
            UriDialect::FreeOtpPlus => source.checked_sub(1).filter(|_| source > 0),
            UriDialect::WinAuth => source.checked_add(1).filter(|_| source >= 0),
        };
        Some(next.ok_or(INVALID)? as u64)
    } else { None };
    let prefix = format!("{}:", &*issuer);
    let account = if dialect == UriDialect::WinAuth {
        // WinAuth writes the issuer literally but form-encodes the account, including '+' → '%2b'.
        let raw = if issuer.is_empty() { label } else { label.strip_prefix(&prefix).ok_or(INVALID)? };
        if raw.contains(':') { return Err(INVALID); }
        uri_decode(raw, true)?
    } else {
        let text = uri_decode(label, false)?;
        let account = if issuer.is_empty() {
            match text.strip_prefix(':') {
                Some(account) => account,
                None if text.contains(':') => return Err(INVALID),
                None => &text,
            }
        } else { text.strip_prefix(&prefix).ok_or(INVALID)? };
        Zeroizing::new(account.to_owned())
    };
    Token { kind, account: &account, issuer: &issuer, seed: &seed, algorithm: &algorithm, digits, period, counter, category: "" }.into_record()
}
