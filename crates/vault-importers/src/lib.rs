use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

mod ente_auth;
mod bitwarden;
mod migration_csv;
mod authenticators;
mod cxf;
mod keepass_kdbx;
mod portable;
mod protected_jwe;
mod proton_passkey;
mod vendor_archives;

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECORDS: usize = 5001; // header + 5,000 data records
const MAX_COLUMNS: usize = 64;
const QUOTING: &str = "CSV 的引号格式有误，请从浏览器重新导出。";

#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Start, Plain, Quoted, Closed }

fn read_csv(data: &str) -> Result<Zeroizing<Vec<Vec<String>>>, &'static str> {
    let mut records = Zeroizing::new(Vec::new());
    let mut row = Zeroizing::new(Vec::new());
    let mut field = Zeroizing::new(String::new());
    let mut input = data.chars().peekable();
    let mut state = State::Start;
    while let Some(ch) = input.next() {
        if state == State::Quoted {
            if ch == '"' {
                if input.peek() == Some(&'"') {
                    input.next();
                    field.push('"');
                } else {
                    state = State::Closed;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        if matches!(ch, ',' | '\n' | '\r') {
            if row.len() == MAX_COLUMNS { return Err("CSV 超过 64 列，请使用浏览器直接导出的文件。"); }
            row.push(std::mem::take(&mut *field));
            if ch != ',' {
                if ch == '\r' && input.peek() == Some(&'\n') { input.next(); }
                if row.len() > 1 || !row[0].trim().is_empty() {
                    records.push(std::mem::take(&mut *row));
                    if records.len() > MAX_RECORDS { return Err("单次最多导入 5,000 行，请分批导入。"); }
                } else {
                    row.clear();
                }
            }
            state = State::Start;
        } else if ch == '"' && state == State::Start {
            state = State::Quoted;
        } else if ch == '"' || state == State::Closed {
            return Err(QUOTING);
        } else {
            field.push(ch);
            state = State::Plain;
        }
    }
    if state == State::Quoted { return Err(QUOTING); }
    if state != State::Start || !row.is_empty() {
        if row.len() == MAX_COLUMNS || records.len() == MAX_RECORDS {
            return Err("CSV 超过 64 列或 5,000 行，请分批导入。");
        }
        row.push(std::mem::take(&mut *field));
        if row.len() > 1 || !row[0].trim().is_empty() { records.push(std::mem::take(&mut *row)); }
    }
    Ok(records)
}

#[derive(Serialize)]
struct LoginRow<'a> {
    title: &'a str,
    url: &'a str,
    username: &'a str,
    password: &'a str,
    note: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Parsed<'a> {
    rows: Vec<LoginRow<'a>>,
    invalid: usize,
    ignored_otp: usize,
}

fn parse(data: &[u8]) -> Result<String, &'static str> {
    if data.len() > MAX_BYTES { return Err("CSV 不能超过 2 MiB，请分批导入。"); }
    let input = std::str::from_utf8(data).map_err(|_| "CSV 不是 UTF-8 编码，请从浏览器重新导出。")?;
    let records = read_csv(input.trim_start_matches('\u{feff}'))?;
    let (head, rows) = records.split_first().ok_or("没有找到 CSV 表头。")?;
    let column = |aliases: &[&str]| -> Result<Option<usize>, &'static str> {
        let mut matching = head.iter().enumerate().filter(|(_, name)| {
            let name = name.trim();
            aliases.iter().any(|alias| name.eq_ignore_ascii_case(alias))
        });
        let index = matching.next().map(|(index, _)| index);
        if matching.next().is_some() { return Err("CSV 包含重复的字段列，请保留一列后重试。"); }
        Ok(index)
    };
    let url = column(&["url", "website", "网站", "网址"])?.ok_or("缺少网站列，请使用浏览器导出的登录密码 CSV。")?;
    let password = column(&["password", "密码"])?.ok_or("缺少密码列，请使用浏览器导出的登录密码 CSV。")?;
    let title = column(&["name", "title", "名称", "标题"])?;
    let username = column(&["username", "user", "用户名", "账号"])?;
    let note = column(&["note", "notes", "备注"])?;
    let otp = column(&["otpauth", "otp", "totp"])?;
    let mut parsed = Parsed { rows: Vec::new(), invalid: 0, ignored_otp: 0 };
    for row in rows {
        let get = |idx: Option<usize>| idx.and_then(|idx| row.get(idx)).map(String::as_str).unwrap_or("");
        if !get(otp).trim().is_empty() { parsed.ignored_otp += 1; }
        let (site, secret) = (get(Some(url)).trim(), get(Some(password)));
        if row.len() != head.len() || site.is_empty() || secret.is_empty() {
            parsed.invalid += 1;
            continue;
        }
        parsed.rows.push(LoginRow { title: get(title).trim(), url: site, username: get(username), password: secret, note: get(note) });
    }
    serde_json::to_string(&parsed).map_err(|_| "无法读取 CSV。")
}

#[wasm_bindgen]
pub fn wasm_parse_browser_csv(bytes: Vec<u8>) -> Result<String, JsValue> {
    let bytes = Zeroizing::new(bytes);
    parse(&bytes).map_err(|message| JsValue::from_str(&format!("CSV: {message}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn decode(data: &str) -> Value { serde_json::from_str(&parse(data.as_bytes()).unwrap()).unwrap() }

    #[test]
    fn chromium_with_bom_quoted_commas_password_spacing_and_multiline_notes() {
        let output = decode("\u{feff}name,url,username,password,note\r\n\"Work, Mail\",https://mail.example,u,\" S\"\"ecret \",\"Line 1\r\nLine 2\"\r\n");
        assert_eq!(output["rows"][0], json!({
            "title": "Work, Mail", "url": "https://mail.example", "username": "u",
            "password": " S\"ecret ", "note": "Line 1\r\nLine 2"
        }));
    }

    #[test]
    fn handles_firefox_and_safari_headers_and_reports_skips() {
        let firefox = decode("\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\nhttps://example.test,user,secret,,,,,,");
        assert_eq!(firefox["rows"][0]["username"], "user");
        let safari = decode("Title,URL,Username,Password,Notes,OTPAuth\n邮件,https://example.test,用户,秘密,备注,example-otp\n无密码,https://other.test,user,,,");
        assert_eq!(safari["rows"][0]["title"], "邮件");
        assert_eq!(safari["invalid"], 1);
        assert_eq!(safari["ignoredOtp"], 1);
    }

    #[test]
    fn rejects_ambiguous_headers_bad_quotes_and_unsupported_encoding() {
        assert!(parse(b"url,password,Password\na,b,c").is_err());
        assert!(parse(b"name,password\na,b").is_err());
        assert!(parse(b"url,password\nhttps://example.test,\"not closed").is_err());
        assert!(parse(&[0xff, 0xfe, b'a']).is_err());
        assert!(parse(&vec![0; MAX_BYTES + 1]).is_err());
    }
}
