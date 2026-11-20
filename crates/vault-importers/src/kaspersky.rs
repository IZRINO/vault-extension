use crate::{
    bitwarden::SecretJson,
    migration_csv::valid_additional_url,
    portable::{Batch, MappingError, add_record},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const INVALID: MappingError = "请选择 Kaspersky Password Manager 导出的英文 UTF-8 凭证文本。";
const MAX_ROWS: usize = 5_000;
const MAX_LINES: usize = 200_000;

fn tail<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let value = line.strip_prefix(label)?.strip_prefix(':')?;
    Some(value.strip_prefix(' ').unwrap_or(value))
}

fn is_start(line: &str) -> bool {
    ["Website name", "Application", "Account name", "Name"].iter().any(|label| tail(line, label).is_some())
}

fn record_follows(lines: &[&str]) -> bool {
    let labels: &[&str] = match lines.first().copied() {
        None => return true,
        Some(line) if tail(line, "Name").is_some() => &["Name", "Text"],
        Some(line) if tail(line, "Website name").is_some() => &["Website name", "Website URL", "Login name", "Login", "Password"],
        Some(line) if tail(line, "Application").is_some() => &["Application", "Login name", "Login", "Password"],
        Some(line) if tail(line, "Account name").is_some() => &["Account name", "Login name", "Login", "Password"],
        _ => return false,
    };
    lines.len() >= labels.len() && lines.iter().zip(labels).all(|(line, label)| tail(line, label).is_some())
}

fn print_text(lines: &[&str], first: &str) -> Zeroizing<String> {
    let mut result = Zeroizing::new(first.to_owned());
    let last = lines.iter().rposition(|line| !line.is_empty()).map_or(0, |i| i + 1);
    for line in &lines[..last] {
        result.push('\n');
        result.push_str(line);
    }
    result
}

fn parse_record(lines: &[&str], batch: &mut Batch) -> Result<(), MappingError> {
    let Some((first, rest)) = lines.split_first() else { return Ok(()); };
    if let Some(title) = tail(first, "Name") {
        let Some(note) = rest.first().and_then(|line| tail(line, "Text")) else { batch.invalid += 1; return Ok(()); };
        let note = print_text(&rest[1..], note);
        let record = SecretJson(json!({ "title":title, "note":&*note, "data":{ "kind":"developer", "subtype":"secure_note" } }));
        return add_record(batch, &record.0, Vec::new(), "kaspersky", "");
    }
    let web = tail(first, "Website name");
    let application = tail(first, "Application");
    let Some(source_title) = web.or(application).or_else(|| tail(first, "Account name")) else { batch.unsupported += 1; return Ok(()); };
    let (rest, url) = if web.is_some() {
        let Some((url, rest)) = rest.split_first().and_then(|(line, rest)| tail(line, "Website URL").map(|url| (url, rest)))
            else { batch.invalid += 1; return Ok(()); };
        (rest, url)
    } else { (rest, "") };
    let [login_name, login, password, remaining @ ..] = rest else { batch.invalid += 1; return Ok(()); };
    let (Some(label), Some(user), Some(password)) = (tail(login_name, "Login name"), tail(login, "Login"), tail(password, "Password"))
        else { batch.invalid += 1; return Ok(()); };
    let note = match remaining {
        [] => Zeroizing::new(String::new()),
        [comment, rest @ ..] if comment.is_empty() && rest.iter().all(|line| line.is_empty()) => Zeroizing::new(String::new()),
        [comment, rest @ ..] => {
            let Some(comment) = tail(comment, "Comment") else { batch.invalid += 1; return Ok(()); };
            print_text(rest, comment)
        }
    };
    let title = if let Some(application) = application.filter(|_| !label.is_empty()) {
        Zeroizing::new(format!("{application} / {label}"))
    } else { Zeroizing::new(if label.is_empty() { source_title } else { label }.to_owned()) };
    let mut uris = Vec::<Value>::new();
    let url = url.trim();
    if !url.is_empty() {
        if valid_additional_url(url) { uris.push(json!({ "uri":url })); }
        else if url.split('.').count() > 1 && url.split('.').all(|label|
            !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
        {
            let with_scheme = Zeroizing::new(format!("https://{url}"));
            if valid_additional_url(&with_scheme) { uris.push(json!({ "uri":&*with_scheme, "matchRule":"host" })); }
            else { batch.unsupported += 1; }
        } else { batch.unsupported += 1; }
    }
    let record = SecretJson(json!({ "title":&*title, "note":&*note, "data":{ "kind":"login", "username":user,
        "password":password, "uris":uris } }));
    add_record(batch, &record.0, Vec::new(), "kaspersky", "")
}

pub(crate) fn read(bytes: &[u8]) -> Result<Batch, MappingError> {
    let input = std::str::from_utf8(bytes).map_err(|_| INVALID)?.trim_start_matches('\u{feff}');
    let is_heading = |line: &str| matches!(line.trim_ascii(), "" | "Websites" | "Website accounts" | "Applications" | "Accounts" | "Other Accounts" | "Notes");
    let lines = input.lines().take(MAX_LINES + 1).collect::<Vec<_>>();
    if lines.len() > MAX_LINES || !lines.iter().any(|line| is_start(line)) { return Err(INVALID); }
    let mut batch = Batch::default();
    let mut start = 0;
    let mut found = 0;
    for (index, line) in lines.iter().enumerate() {
        if *line != "---" { continue; }
        let following = &lines[index + 1..];
        let record = following.iter().position(|line| !is_heading(line)).map_or(&[][..], |offset| &following[offset..]);
        if !record_follows(record) { continue; }
        if let Some(offset) = lines[start..index].iter().position(|line| !is_heading(line)) {
            found += 1;
            if found > MAX_ROWS { return Err(INVALID); }
            parse_record(&lines[start + offset..index], &mut batch)?;
        }
        start = index + 1;
    }
    if let Some(offset) = lines[start..].iter().position(|line| !is_heading(line)) {
        found += 1;
        if found > MAX_ROWS { return Err(INVALID); }
        parse_record(&lines[start + offset..], &mut batch)?;
    }
    if found == 0 { return Err(INVALID); }
    Ok(batch)
}
