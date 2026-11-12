use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use crate::json_lite::{bytes_contains, compact_sort_by, encode_hex_upper, JVal};
use crate::model::{CredentialData, VaultItem};

const COMMON_WEAK_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "abc123",
    "admin",
    "admin123",
    "welcome",
    "letmein",
    "iloveyou",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "changeme",
    "passw0rd",
    "p@ssw0rd",
    "88888888",
    "666666",
    "111111",
    "000000",
];

const KEYBOARD_ROWS: &[&str] = &[
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "01234567890",
    "abcdefghijklmnopqrstuvwxyz",
];

#[derive(Debug, Clone)]
pub struct PasswordStrengthReport {
    pub entropy_tenths: u32,
    /// 0 = very weak, 1 = weak, 2 = fair, 3 = strong, 4 = very strong
    pub score: u8,
    pub label: String,
    pub warnings: Vec<String>,
}

impl PasswordStrengthReport {
    pub fn to_json_value(&self) -> JVal {
        JVal::Obj(vec![
            ("entropyBits", JVal::Tenths(self.entropy_tenths)),
            ("score", JVal::Uint(self.score as u64)),
            ("label", JVal::Str(self.label.clone())),
            (
                "warnings",
                JVal::Arr(self.warnings.iter().cloned().map(JVal::Str).collect()),
            ),
        ])
    }
}
/// Pure-local password entropy & pattern evaluator (zxcvbn-inspired).
pub fn evaluate_password_strength(password: &str, user_hints: &[String]) -> PasswordStrengthReport {
    if password.is_empty() {
        return PasswordStrengthReport {
            entropy_tenths: 0,
            score: 0,
            label: "very_weak".into(),
            warnings: vec!["密码为空".into()],
        };
    }

    let lower_pw = Zeroizing::new(password.to_ascii_lowercase());
    let mut warnings = Vec::new();

    if COMMON_WEAK_PASSWORDS.iter().any(|&w| lower_pw.as_str() == w) {
        return PasswordStrengthReport {
            entropy_tenths: 80,
            score: 0,
            label: "very_weak".into(),
            warnings: vec!["命中高频常见弱口令词典".into()],
        };
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_unicode = false;

    let pw_bytes = password.as_bytes();
    let mut char_count = 0usize;
    let mut effective_len = 0.0f64;
    let mut prev_byte: Option<u8> = None;
    for &b in pw_bytes {
        // Skip UTF-8 continuation bytes (`10xxxxxx`) when counting characters
        if (b & 0xC0) == 0x80 {
            continue;
        }
        char_count += 1;
        if prev_byte == Some(b) {
            effective_len += 0.2;
        } else {
            effective_len += 1.0;
        }
        prev_byte = Some(b);
        if b.is_ascii_lowercase() {
            has_lower = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else if b.is_ascii_punctuation() || b == b' ' {
            has_symbol = true;
        } else {
            has_unicode = true;
        }
    }

    let mut pool = 0usize;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 33;
    }
    if has_unicode {
        pool += 100;
    }
    let pool = pool.max(10) as f64;

    let mut entropy = effective_len * pool.log2();

    if char_count < 8 {
        warnings.push("密码长度不足 8 位".into());
        entropy *= 0.65;
    }

    let mut has_seq = false;
    if lower_pw.len() >= 4 {
        let bytes = lower_pw.as_bytes();
        for win in bytes.windows(4) {
            if win.iter().all(u8::is_ascii) {
                let rev = [win[3], win[2], win[1], win[0]];
                if KEYBOARD_ROWS
                    .iter()
                    .any(|row| bytes_contains(row.as_bytes(), win) || bytes_contains(row.as_bytes(), &rev))
                {
                    has_seq = true;
                    break;
                }
            }
        }
    }
    if has_seq {
        warnings.push("包含连续键盘或顺序字符序列".into());
        entropy = (entropy - 14.0).max(6.0);
    }

    for hint in user_hints {
        let h = hint.trim_ascii().to_ascii_lowercase();
        if h.len() >= 3 && bytes_contains(lower_pw.as_bytes(), h.as_bytes()) {
            warnings.push("包含账号名或网站特征词".into());
            entropy = (entropy - 16.0).max(6.0);
            break;
        }
    }

    let entropy_tenths = (entropy.max(0.0) * 10.0).round() as u32;
    let (score, label) = if entropy_tenths < 280 {
        (0, "very_weak")
    } else if entropy_tenths < 420 {
        (1, "weak")
    } else if entropy_tenths < 580 {
        (2, "fair")
    } else if entropy_tenths < 780 {
        (3, "strong")
    } else {
        (4, "very_strong")
    };

    PasswordStrengthReport {
        entropy_tenths,
        score,
        label: label.into(),
        warnings,
    }
}

#[derive(Debug, Clone)]
pub struct WeakItemFinding {
    pub item_id: String,
    pub title: String,
    pub username: String,
    pub score: u8,
    pub entropy_tenths: u32,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReusedPasswordGroup {
    pub count: usize,
    pub item_ids: Vec<String>,
    pub titles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VaultSecurityAuditReport {
    pub health_score: u8,
    pub total_login_items: usize,
    pub weak_items: Vec<WeakItemFinding>,
    pub reused_groups: Vec<ReusedPasswordGroup>,
    pub missing_2fa_item_ids: Vec<String>,
}

impl VaultSecurityAuditReport {
    pub fn to_json_value(&self) -> JVal {
        JVal::Obj(vec![
            ("healthScore", JVal::Uint(self.health_score as u64)),
            ("totalLoginItems", JVal::Uint(self.total_login_items as u64)),
            (
                "weakItems",
                JVal::Arr(
                    self.weak_items
                        .iter()
                        .map(|w| {
                            JVal::Obj(vec![
                                ("itemId", JVal::Str(w.item_id.clone())),
                                ("title", JVal::Str(w.title.clone())),
                                ("username", JVal::Str(w.username.clone())),
                                ("score", JVal::Uint(w.score as u64)),
                                ("entropyBits", JVal::Tenths(w.entropy_tenths)),
                                (
                                    "warnings",
                                    JVal::Arr(w.warnings.iter().cloned().map(JVal::Str).collect()),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "reusedGroups",
                JVal::Arr(
                    self.reused_groups
                        .iter()
                        .map(|g| {
                            JVal::Obj(vec![
                                ("count", JVal::Uint(g.count as u64)),
                                (
                                    "itemIds",
                                    JVal::Arr(g.item_ids.iter().cloned().map(JVal::Str).collect()),
                                ),
                                (
                                    "titles",
                                    JVal::Arr(g.titles.iter().cloned().map(JVal::Str).collect()),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "missing2faItemIds",
                JVal::Arr(
                    self.missing_2fa_item_ids
                        .iter()
                        .cloned()
                        .map(JVal::Str)
                        .collect(),
                ),
            ),
        ])
    }
}
/// Runs a zero-leakage offline security health check over in-memory decrypted vault items.
pub fn audit_vault_items(items: &[VaultItem]) -> VaultSecurityAuditReport {
    let mut total_login_items = 0usize;
    let mut weak_items = Vec::new();
    let mut missing_2fa_item_ids = Vec::new();
    let mut by_pw_digest: Vec<([u8; 32], Vec<(String, String)>)> = Vec::new();

    let ephemeral_hash_salt = crate::crypto::SecretKey::random()
        .map(|k| *k.as_bytes())
        .unwrap_or([0x5Au8; 32]);

    for item in items {
        if item.trashed {
            continue;
        }
        if let CredentialData::Login(login) = &item.data {
            total_login_items += 1;
            let mut hints = vec![item.title.clone(), login.username.clone()];
            if let Some(u) = login.uris.first() {
                hints.push(crate::model::extract_host_display(&u.uri));
            }
            let eval = evaluate_password_strength(&login.password, &hints);
            if eval.score <= 2 {
                weak_items.push(WeakItemFinding {
                    item_id: item.id.clone(),
                    title: item.title.clone(),
                    username: login.username.clone(),
                    score: eval.score,
                    entropy_tenths: eval.entropy_tenths,
                    warnings: eval.warnings,
                });
            }
            if !login.password.is_empty() {
                let digest = *blake3::keyed_hash(&ephemeral_hash_salt, login.password.as_bytes())
                    .as_bytes();
                if let Some((_, list)) = by_pw_digest.iter_mut().find(|(d, _)| *d == digest) {
                    list.push((item.id.clone(), item.title.clone()));
                } else {
                    by_pw_digest.push((digest, vec![(item.id.clone(), item.title.clone())]));
                }
            }
            if login
                .totp_uri
                .as_ref()
                .is_none_or(|s| s.trim_ascii().is_empty())
            {
                missing_2fa_item_ids.push(item.id.clone());
            }
        }
    }

    let mut reused_groups: Vec<ReusedPasswordGroup> = by_pw_digest
        .into_iter()
        .filter(|(_, entries)| entries.len() >= 2)
        .map(|(_, entries)| ReusedPasswordGroup {
            count: entries.len(),
            item_ids: entries.iter().map(|e| e.0.clone()).collect(),
            titles: entries.iter().map(|e| e.1.clone()).collect(),
        })
        .collect();
    compact_sort_by(&mut reused_groups, |a, b| b.count.cmp(&a.count));

    let health_score = if total_login_items == 0 {
        100
    } else {
        let reused_count: usize = reused_groups.iter().map(|g| g.count).sum();
        let penalty = (weak_items.len() * 12) + (reused_count * 10);
        100u8.saturating_sub(penalty.min(95) as u8)
    };

    VaultSecurityAuditReport {
        health_score,
        total_login_items,
        weak_items,
        reused_groups,
        missing_2fa_item_ids,
    }
}

/// Computes uppercase SHA-1 hex digest of `password` and splits it for Have I Been Pwned k-Anonymity:
/// `(5_char_prefix, Zeroizing<35_char_suffix>)`.
pub fn hibp_sha1_prefix_and_suffix(password: &str) -> (String, Zeroizing<String>) {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let hex = Zeroizing::new(encode_hex_upper(digest.as_slice()));
    let prefix = hex[..5].to_string();
    let suffix = Zeroizing::new(hex[5..].to_string());
    (prefix, suffix)
}

/// Matches the local 35-char SHA-1 suffix against the HIBP `/range/{prefix}` response body (`SUFFIX:COUNT`).
pub fn hibp_match_range_response(password: &str, range_response: &str) -> u64 {
    let (_prefix, suffix) = hibp_sha1_prefix_and_suffix(password);
    let body = range_response.as_bytes();
    let mut start = 0usize;
    for i in 0..=body.len() {
        if i == body.len() || body[i] == b'\n' {
            let line = range_response[start..i].trim_ascii();
            if let Some(colon_pos) = line.as_bytes().iter().position(|&b| b == b':') {
                let cand_suffix = line[..colon_pos].trim_ascii();
                let count_str = line[colon_pos + 1..].trim_ascii();
                if cand_suffix.eq_ignore_ascii_case(suffix.as_str()) {
                    return count_str.parse::<u64>().unwrap_or(1);
                }
            }
            start = i + 1;
        }
    }
    0
}
