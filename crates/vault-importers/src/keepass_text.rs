use crate::{keepass_kdbx::{Entry, add_entry}, portable::{Batch, INVALID, LIMIT, MappingError}};
use base64::{Engine, engine::general_purpose::STANDARD};
use quick_xml::{Reader, events::{BytesRef, BytesStart, Event}};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

type Result<T> = std::result::Result<T, MappingError>;
const KP: &[&str] = &["Account", "Login Name", "Password", "Web Site", "Comments"];
const XC: &[&str] = &["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP", "Icon", "Last Modified", "Created"];

pub(crate) fn read(bytes: &[u8], password: &str) -> Result<Batch> {
    if bytes.is_empty() || bytes.len() > LIMIT { return Err(INVALID); }
    let input = std::str::from_utf8(bytes).map_err(|_| INVALID)?.trim_start_matches('\u{feff}');
    if !password.is_empty() { return Err("XML 或 CSV 不需要文件密码；加密库请选择原始 KDBX 文件。"); }
    if input.trim_start().starts_with('<') { return xml(input); }
    if input.len() > crate::MAX_BYTES { return Err("KeePass CSV 不能超过 2 MiB。"); }
    csv(input)
}

fn csv(input: &str) -> Result<Batch> {
    let legacy = input.lines().next().is_some_and(|line| line == "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"");
    let rows = crate::read_csv_mode(input, legacy)?;
    let (head, rows) = rows.split_first().ok_or(INVALID)?;
    if (legacy && head != KP) || (!legacy && head != XC) {
        return Err("请选择 KeePass KDBX、KeePass 2.x 明文 XML 或 KeePass/KeePassXC 原生 CSV。");
    }
    let mut batch = Batch::default();
    for row in rows {
        if row.len() != head.len() { batch.invalid += 1; continue; }
        let mut entry = Entry::default();
        let fields = if legacy {
            [("Title", 0), ("UserName", 1), ("Password", 2), ("URL", 3), ("Notes", 4)].as_slice()
        } else {
            if !row[0].is_empty() { entry.tags.push(row[0].clone()); }
            entry.updated = date(&row[8]); entry.created = date(&row[9]);
            [("Title", 1), ("UserName", 2), ("Password", 3), ("URL", 4), ("Notes", 5), ("otp", 6)].as_slice()
        };
        entry.fields = fields.iter().map(|(key, index)| (*key, (row[*index].as_str(), false))).collect();
        add_entry(&mut batch, entry)?;
    }
    Ok(batch)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XmlFile {
    meta: XmlMeta,
    root: XmlRoot,
}
#[derive(Deserialize)]
struct XmlMeta {
    #[serde(rename = "RecycleBinUUID", default)] recycle: String,
}
#[derive(Deserialize)]
struct XmlRoot {
    #[serde(rename = "Group")] group: XmlGroup,
}
#[derive(Deserialize)]
struct XmlGroup {
    #[serde(rename = "UUID")] uuid: String,
    #[serde(rename = "Name", default)] name: String,
    #[serde(rename = "Entry", default)] entries: Vec<XmlEntry>,
    #[serde(rename = "Group", default)] groups: Vec<XmlGroup>,
}
#[derive(Deserialize)]
struct XmlEntry {
    #[serde(rename = "UUID")] uuid: String,
    #[serde(rename = "Tags", default)] tags: String,
    #[serde(rename = "String", default)] strings: Vec<XmlString>,
    #[serde(rename = "History", default)] history: XmlHistory,
    #[serde(rename = "Times", default)] times: XmlTimes,
    #[serde(rename = "Binary", default)] attachments: Vec<serde::de::IgnoredAny>,
}
#[derive(Default, Deserialize)]
struct XmlHistory {
    #[serde(rename = "Entry", default)] entries: Vec<XmlEntry>,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XmlTimes {
    #[serde(default)] creation_time: String,
    #[serde(default)] last_modification_time: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XmlString { key: String, value: XmlValue }
#[derive(Deserialize)]
struct XmlValue {
    #[serde(rename = "@ProtectInMemory", default)] protect: String,
    #[serde(rename = "$text", default)] value: String,
}
impl Drop for XmlValue {
    fn drop(&mut self) { self.value.zeroize(); }
}

fn date(value: &str) -> Option<u64> {
    if let Ok(time) = chrono::DateTime::parse_from_rfc3339(value) { return time.timestamp_millis().try_into().ok(); }
    let bytes: [u8; 8] = STANDARD.decode(value).ok()?.try_into().ok()?;
    let seconds = u64::from_le_bytes(bytes).checked_sub(62_135_596_800)?;
    // Both exporters use years 1–9999, not arbitrary binary values.
    (seconds <= 253_402_300_799).then(|| seconds * 1000)
}

fn uuid(value: &str) -> Result<String> {
    let id: [u8; 16] = STANDARD.decode(value).map_err(|_| INVALID)?.try_into().map_err(|_| INVALID)?;
    let hex = hex::encode(id);
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}

fn reference(reference: &BytesRef<'_>) -> Result<()> {
    if reference.is_char_ref() {
        match reference.resolve_char_ref().map_err(|_| INVALID)? {
            Some('\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}') => Ok(()),
            _ => Err(INVALID),
        }
    } else if matches!(&**reference, "amp" | "lt" | "gt" | "apos" | "quot") { Ok(()) }
    else { Err(INVALID) }
}

fn preflight(input: &str) -> Result<()> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().check_comments = true;
    let (mut depth, mut root, mut groups, mut entries, mut events) = (0usize, false, 0, 0, 0);
    let check = |element: &BytesStart, depth: usize, root: &mut bool, groups: &mut usize, entries: &mut usize| {
        if depth == 0 {
            if *root || element.name().as_ref() != "KeePassFile" { return Err(INVALID); }
            *root = true;
        }
        match element.local_name().as_ref() {
            "Group" => *groups += 1,
            "Entry" => *entries += 1, // includes history entries
            _ => {}
        }
        if *groups > 5000 || *entries > 25_000 { return Err(INVALID); }
        for attribute in element.attributes() {
            let attribute = attribute.map_err(|_| INVALID)?;
            let value = attribute.value.as_ref();
            if value.contains('<') { return Err(INVALID); }
            for part in value.split('&').skip(1) {
                reference(&BytesRef::new(part.split_once(';').ok_or(INVALID)?.0))?;
            }
            if attribute.key.local_name().as_ref() == "Protected" && !attribute.value.eq_ignore_ascii_case("false") {
                return Err("此 KeePass XML 含加密值，请直接导入原始 KDBX。");
            }
        }
        Ok(())
    };
    loop {
        events += 1;
        if events > 1_000_000 { return Err(INVALID); }
        match reader.read_event().map_err(|_| INVALID)? {
            Event::Start(element) => {
                check(&element, depth, &mut root, &mut groups, &mut entries)?;
                depth += 1;
                if depth > 80 { return Err(INVALID); }
            }
            Event::Empty(element) => check(&element, depth, &mut root, &mut groups, &mut entries)?,
            Event::End(_) => depth = depth.checked_sub(1).ok_or(INVALID)?,
            Event::Decl(decl) if decl.encoding().is_some_and(|enc| !enc.is_ok_and(|enc| enc.eq_ignore_ascii_case("utf-8"))) => return Err(INVALID),
            Event::DocType(_) | Event::PI(_) => return Err(INVALID),
            Event::Text(text) if depth == 0 && !text.bytes().all(|byte| byte.is_ascii_whitespace()) => return Err(INVALID),
            Event::CData(_) if depth == 0 => return Err(INVALID),
            Event::GeneralRef(entity) => {
                if depth == 0 { return Err(INVALID); }
                reference(&entity)?;
            }
            Event::Eof => return if root && depth == 0 { Ok(()) } else { Err(INVALID) },
            _ => {}
        }
    }
}

fn fields(entry: &XmlEntry) -> Result<BTreeMap<&str, (&str, bool)>> {
    if entry.strings.len() > 128 { return Err(INVALID); }
    let mut fields = BTreeMap::new();
    for field in &entry.strings {
        let hidden = field.value.protect.eq_ignore_ascii_case("true");
        if !hidden && !field.value.protect.is_empty() && !field.value.protect.eq_ignore_ascii_case("false") { return Err(INVALID); }
        if fields.insert(field.key.as_str(), (field.value.value.as_str(), hidden)).is_some() { return Err(INVALID); }
    }
    Ok(fields)
}

fn xml(input: &str) -> Result<Batch> {
    preflight(input)?;
    let file: XmlFile = quick_xml::de::from_str(input).map_err(|_| INVALID)?;
    let recycle = if file.meta.recycle.is_empty() { None } else { Some(uuid(&file.meta.recycle)?) };
    let mut batch = Batch::default();
    visit(&file.root.group, "", false, recycle.as_deref(), &mut BTreeSet::new(), &mut 0, &mut batch)?;
    Ok(batch)
}

fn visit(group: &XmlGroup, parent: &str, trashed: bool, recycle: Option<&str>, ids: &mut BTreeSet<String>,
         count: &mut usize, batch: &mut Batch) -> Result<()> {
    let id = uuid(&group.uuid)?;
    let trashed = trashed || recycle.is_some_and(|recycle| recycle == id);
    if !ids.insert(id) { return Err(INVALID); }
    let path = if parent.is_empty() { group.name.clone() } else { format!("{parent}/{}", group.name) };
    if path.len() > 4096 { return Err(INVALID); }
    for item in &group.entries {
        *count += 1;
        if *count > 5000 { return Err(INVALID); }
        let id = uuid(&item.uuid)?;
        if !ids.insert(id.clone()) { return Err(INVALID); }
        let mut tags = Vec::new();
        for tag in item.tags.split([';', ',', '\t']).map(str::trim).filter(|tag| !tag.is_empty()) {
            if tags.len() == 32 || tag.len() > 1024 { batch.unsupported += 1; continue; }
            tags.push(tag.to_owned());
        }
        if !path.is_empty() { tags.push(path.clone()); }
        let mut history = Vec::new();
        for old in &item.history.entries {
            if old.uuid != item.uuid || !old.history.entries.is_empty() { return Err(INVALID); }
            let fields = fields(old)?;
            if let Some((password, _)) = fields.get("Password") {
                history.push((*password, date(&old.times.last_modification_time).unwrap_or(0)));
            }
        }
        history.sort_by_key(|(_, time)| std::cmp::Reverse(*time));
        history.truncate(20);
        batch.unsupported += item.attachments.len();
        add_entry(batch, Entry { fields: fields(item)?, tags, history, id: &id, trashed,
            created: date(&item.times.creation_time), updated: date(&item.times.last_modification_time) })?;
    }
    for child in &group.groups { visit(child, &path, trashed, recycle, ids, count, batch)?; }
    Ok(())
}
