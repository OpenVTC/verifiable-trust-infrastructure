//! Community theme — one stylesheet the console and the member portal draw
//! over their built-in look (`vtc/community/theme/{show,update}/0.1`).
//!
//! One row in the `community` keyspace at [`THEME_STORAGE_KEY`], beside the
//! profile and branding and backed up with them. An empty stylesheet removes
//! the row.
//!
//! Nothing is stored that is not in the **theme profile** (update/0.1, items
//! P1–P8), and [`check_stylesheet`] is that check. The console runs its own
//! (`admin-ui/src/lib/theme-profile.ts`) before it draws anything; the two
//! are held to the same answers by `admin-ui/src/lib/theme-profile.vectors.json`,
//! which the tests below read. A change to either checker without the other
//! fails one of the two suites.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Storage key in the `community` keyspace.
pub const THEME_STORAGE_KEY: &[u8] = b"community/theme";

/// A stylesheet's bound in UTF-8 bytes (update item 2).
pub const MAX_STYLESHEET_BYTES: usize = 32768;

/// The stored theme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredTheme {
    /// In the theme profile, comments removed.
    pub stylesheet: String,
    pub updated_at: DateTime<Utc>,
}

/// Where a stylesheet leaves the theme profile — `outsideProfile`'s `details`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileViolation {
    /// `P1` … `P8`.
    pub rule: &'static str,
    /// 1-based, in Unicode code points.
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl std::fmt::Display for ProfileViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {}, column {}: {} ({})",
            self.line, self.column, self.message, self.rule
        )
    }
}

/// The stored theme, if any.
pub async fn load_theme(ks: &KeyspaceHandle) -> Result<Option<StoredTheme>, AppError> {
    match ks.get_raw(THEME_STORAGE_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AppError::Internal(format!("community theme decode: {e}"))),
        None => Ok(None),
    }
}

/// The stylesheet `theme/show` answers: the stored one only while it is still
/// in the profile (show item 3), else the empty string.
pub async fn shown_stylesheet(ks: &KeyspaceHandle) -> Result<Option<StoredTheme>, AppError> {
    let Some(theme) = load_theme(ks).await? else {
        return Ok(None);
    };
    match check_stylesheet(&theme.stylesheet) {
        Ok(_) => Ok(Some(theme)),
        Err(v) => {
            tracing::warn!(
                violation = %v,
                "stored community theme is outside the theme profile; answering none"
            );
            Ok(None)
        }
    }
}

/// Store `stylesheet` — already checked, comments removed — and return the
/// row. The empty stylesheet removes the theme and returns `None`.
pub async fn store_theme(
    ks: &KeyspaceHandle,
    stylesheet: &str,
    now: DateTime<Utc>,
) -> Result<Option<StoredTheme>, AppError> {
    if stylesheet.is_empty() {
        ks.remove(THEME_STORAGE_KEY.to_vec()).await?;
        return Ok(None);
    }
    let row = StoredTheme {
        stylesheet: stylesheet.to_string(),
        updated_at: now,
    };
    let key = String::from_utf8(THEME_STORAGE_KEY.to_vec()).expect("key is ASCII");
    ks.insert(key, &row).await?;
    Ok(Some(row))
}

/// The digest the audit record names instead of the text (update item 6):
/// lowercase hex SHA-256 of the stored stylesheet's UTF-8.
#[must_use]
pub fn stylesheet_digest(stylesheet: &str) -> String {
    hex::encode(Sha256::digest(stylesheet.as_bytes()))
}

// ── The theme profile ────────────────────────────────────────────────

/// Check `css` against the theme profile. On success, the stylesheet with its
/// comments removed — the only normalisation (update item 4).
pub fn check_stylesheet(css: &str) -> Result<String, ProfileViolation> {
    if css.len() > MAX_STYLESHEET_BYTES {
        return Err(ProfileViolation {
            rule: "P1",
            line: 1,
            column: 1,
            message: format!("longer than {MAX_STYLESHEET_BYTES} bytes"),
        });
    }
    let original: Vec<char> = css.chars().collect();
    let run = || -> Result<String, Refusal> {
        let (text, kept) = strip_comments(&original)?;
        Parser {
            s: &text,
            kept: &kept,
            i: 0,
        }
        .sheet()?;
        Ok(text.iter().collect())
    };
    run().map_err(|r| {
        let (line, column) = position(&original, r.at);
        ProfileViolation {
            rule: r.rule,
            line,
            column,
            message: r.message,
        }
    })
}

struct Refusal {
    rule: &'static str,
    /// Index into the original, in code points.
    at: usize,
    message: String,
}

fn position(css: &[char], at: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for &c in &css[..at.min(css.len())] {
        if c == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

/// Remove comments outside strings. `kept[i]` is the original index of `text[i]`.
fn strip_comments(css: &[char]) -> Result<(Vec<char>, Vec<usize>), Refusal> {
    let mut text = Vec::with_capacity(css.len());
    let mut kept = Vec::with_capacity(css.len());
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < css.len() {
        let c = css[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c == '/' && css.get(i + 1) == Some(&'*') {
            let end =
                (i + 2..css.len().saturating_sub(1)).find(|&j| css[j] == '*' && css[j + 1] == '/');
            match end {
                Some(e) => {
                    i = e + 2;
                    continue;
                }
                None => {
                    return Err(Refusal {
                        rule: "P1",
                        at: i,
                        message: "unterminated comment".into(),
                    });
                }
            }
        }
        text.push(c);
        kept.push(i);
        i += 1;
    }
    if quote.is_some() {
        return Err(Refusal {
            rule: "P1",
            at: kept.last().copied().unwrap_or(0),
            message: "unterminated string".into(),
        });
    }
    Ok((text, kept))
}

const MEDIA_PRELUDES: [&str; 2] = [
    "(prefers-color-scheme: light)",
    "(prefers-color-scheme: dark)",
];

const TOKEN_SELECTORS: [&str; 3] = [
    ":root",
    ":root[data-theme=\"light\"]",
    ":root[data-theme=\"dark\"]",
];

const BANNED_FUNCTIONS: [&str; 9] = [
    "url",
    "src",
    "image",
    "image-set",
    "cross-fade",
    "element",
    "attr",
    "paint",
    "env",
];

const FREE_PROPERTIES: [&str; 21] = [
    "color",
    "background-color",
    "accent-color",
    "caret-color",
    "outline-color",
    "text-decoration-color",
    "font-family",
    "font-weight",
    "font-style",
    "text-decoration-line",
    "text-transform",
    "border-style",
    "border-top-style",
    "border-right-style",
    "border-bottom-style",
    "border-left-style",
    "border-color",
    "border-top-color",
    "border-right-color",
    "border-bottom-color",
    "border-left-color",
];

const BORDER_WIDTHS: [&str; 5] = [
    "border-width",
    "border-top-width",
    "border-right-width",
    "border-bottom-width",
    "border-left-width",
];

const BORDER_RADII: [&str; 5] = [
    "border-radius",
    "border-top-left-radius",
    "border-top-right-radius",
    "border-bottom-right-radius",
    "border-bottom-left-radius",
];

const PSEUDO_CLASSES: [&str; 9] = [
    "hover",
    "focus",
    "focus-visible",
    "focus-within",
    "active",
    "disabled",
    "checked",
    "first-child",
    "last-child",
];

const PSEUDO_ELEMENTS: [&str; 2] = ["placeholder", "selection"];

struct Parser<'a> {
    s: &'a [char],
    kept: &'a [usize],
    i: usize,
}

type Step<T = ()> = Result<T, Refusal>;

impl Parser<'_> {
    fn at(&self, i: usize) -> usize {
        if self.kept.is_empty() {
            return 0;
        }
        self.kept[i.min(self.kept.len() - 1)]
    }

    fn refuse<T>(&self, rule: &'static str, message: impl Into<String>, i: usize) -> Step<T> {
        Err(Refusal {
            rule,
            at: self.at(i),
            message: message.into(),
        })
    }

    fn sheet(&mut self) -> Step {
        for (j, &c) in self.s.iter().enumerate() {
            if c == '\\' {
                return self.refuse("P2", "escapes are not allowed", j);
            }
            if c == '<' {
                return self.refuse("P2", "`<` is not allowed", j);
            }
        }
        self.ws();
        while self.i < self.s.len() {
            if self.s[self.i] == '@' {
                self.at_rule()?;
            } else {
                self.style_rule()?;
            }
            self.ws();
        }
        Ok(())
    }

    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_whitespace() {
            self.i += 1;
        }
    }

    /// Text up to the next of `stops` outside strings and brackets.
    fn until(&mut self, stops: &[char]) -> (String, usize) {
        let start = self.i;
        let mut depth: i32 = 0;
        let mut quote: Option<char> = None;
        while self.i < self.s.len() {
            let c = self.s[self.i];
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                }
            } else if c == '"' || c == '\'' {
                quote = Some(c);
            } else if c == '(' || c == '[' {
                depth += 1;
            } else if c == ')' || c == ']' {
                depth -= 1;
            } else if depth == 0 && stops.contains(&c) {
                break;
            }
            self.i += 1;
        }
        (self.s[start..self.i].iter().collect(), start)
    }

    fn expect(&mut self, c: char, rule: &'static str) -> Step {
        if self.s.get(self.i) != Some(&c) {
            return self.refuse(rule, format!("expected `{c}`"), self.i);
        }
        self.i += 1;
        Ok(())
    }

    fn at_rule(&mut self) -> Step {
        let start = self.i;
        let (text, _) = self.until(&['{', ';']);
        let trimmed = text.trim();
        let body = &trimmed[1..];
        let name_len = body
            .find(|c: char| !(c.is_ascii_alphabetic() || c == '-'))
            .unwrap_or(body.len());
        let name = &body[..name_len];
        if !name.eq_ignore_ascii_case("media") {
            return self.refuse("P3", format!("@{name} is not allowed"), start);
        }
        let prelude = normalise_media(&body[name_len..]);
        if !MEDIA_PRELUDES.contains(&prelude.as_str()) {
            return self.refuse(
                "P3",
                "only @media (prefers-color-scheme: light|dark) is allowed",
                start,
            );
        }
        self.expect('{', "P3")?;
        self.ws();
        while self.i < self.s.len() && self.s[self.i] != '}' {
            if self.s[self.i] == '@' {
                return self.refuse("P3", "an at-rule may not be nested", self.i);
            }
            self.style_rule()?;
            self.ws();
        }
        self.expect('}', "P1")
    }

    fn style_rule(&mut self) -> Step {
        let (selector, start) = self.until(&['{', '}', ';']);
        if self.s.get(self.i) != Some(&'{') {
            return self.refuse("P1", "expected a style rule", self.i);
        }
        let normalised = collapse_ws(selector.trim());
        if normalised.is_empty() {
            return self.refuse("P1", "empty selector", start);
        }
        let token = TOKEN_SELECTORS.contains(&normalised.as_str());
        if !token {
            self.selector_list(&selector, start)?;
        }
        self.i += 1;
        self.declarations(token)?;
        self.expect('}', "P1")
    }

    fn declarations(&mut self, token: bool) -> Step {
        loop {
            self.ws();
            if self.i >= self.s.len() || self.s[self.i] == '}' {
                return Ok(());
            }
            if self.s[self.i] == ';' {
                self.i += 1;
                continue;
            }
            let (text, start) = self.until(&[';', '}']);
            self.declaration(&text, start, token)?;
        }
    }

    fn declaration(&self, text: &str, start: usize, token: bool) -> Step {
        let chars: Vec<char> = text.chars().collect();
        let Some(colon) = chars.iter().position(|&c| c == ':') else {
            return self.refuse("P1", "expected `property: value`", start);
        };
        let raw_name: String = chars[..colon].iter().collect::<String>().trim().to_string();
        let after: String = chars[colon + 1..].iter().collect();
        let value = after.trim().to_string();
        let lead = after.chars().count() - after.trim_start().chars().count();
        let value_at = start + colon + 1 + lead;
        if value.is_empty() {
            return self.refuse("P1", format!("{raw_name} has no value"), value_at);
        }
        if strip_strings(&value).contains('!') {
            return self.refuse("P5", "!important is not allowed", value_at);
        }
        if let Some(f) = banned_function(&value) {
            return self.refuse("P4", format!("{f}() is not allowed"), value_at);
        }

        let token_rule = if token { "P6" } else { "P8" };
        if raw_name.starts_with("--") {
            if !is_custom_property(&raw_name) {
                return self.refuse(
                    token_rule,
                    format!("{raw_name} is not a valid token name"),
                    start,
                );
            }
            if raw_name.starts_with("--protected-") {
                return self.refuse(token_rule, "--protected-* tokens are reserved", start);
            }
            if value.chars().count() > 512 {
                return self.refuse(
                    token_rule,
                    format!("{raw_name} is longer than 512 characters"),
                    value_at,
                );
            }
            return Ok(());
        }
        if token {
            return self.refuse(
                "P6",
                format!("a :root rule declares tokens only, not {raw_name}"),
                start,
            );
        }

        let name = raw_name.to_ascii_lowercase();
        if FREE_PROPERTIES.contains(&name.as_str()) {
            return Ok(());
        }
        if name == "background-image" {
            if !gradients_or_none(&value) {
                return self.refuse("P8", "background-image takes gradients or none", value_at);
            }
            return Ok(());
        }
        if BORDER_WIDTHS.contains(&name.as_str()) {
            if !bounded_lengths(&value, 4.0, &["thin", "medium"]) {
                return self.refuse("P8", format!("{name} is at most 4px"), value_at);
            }
            return Ok(());
        }
        if BORDER_RADII.contains(&name.as_str()) {
            if !bounded_lengths(&value.replacen('/', " ", 1), 32.0, &[]) {
                return self.refuse("P8", format!("{name} is at most 32px"), value_at);
            }
            return Ok(());
        }
        if name == "letter-spacing" {
            if !letter_spacing_ok(&value) {
                return self.refuse("P8", "letter-spacing is at most 0.2em either way", value_at);
            }
            return Ok(());
        }
        self.refuse("P8", format!("{raw_name} is not a theme property"), start)
    }

    // ── Selectors (P7) ───────────────────────────────────────────────

    fn selector_list(&self, selector: &str, start: usize) -> Step {
        let chars: Vec<char> = selector.chars().collect();
        for (part, offset) in split_top_level(&chars, ',') {
            let lead = part.iter().take_while(|c| c.is_whitespace()).count();
            let trimmed = trim_chars(&part);
            if trimmed.is_empty() {
                return self.refuse("P7", "empty selector", start + offset);
            }
            self.complex(trimmed, start + offset + lead)?;
        }
        Ok(())
    }

    /// Compounds joined by combinators.
    fn complex(&self, sel: &[char], base: usize) -> Step {
        let mut j = 0;
        while j < sel.len() {
            let c = sel[j];
            if c.is_whitespace() || c == '>' || c == '+' || c == '~' {
                j += 1;
                continue;
            }
            j = self.simple(sel, j, base)?;
        }
        if let Some(last) = sel.iter().rev().find(|c| !c.is_whitespace())
            && matches!(last, '>' | '+' | '~')
        {
            return self.refuse(
                "P7",
                "a combinator needs a selector after it",
                base + sel.len() - 1,
            );
        }
        Ok(())
    }

    /// One simple selector at `j`; the index after it.
    fn simple(&self, sel: &[char], j: usize, base: usize) -> Step<usize> {
        let c = sel[j];
        if c == '.' || c == '#' {
            let n = ident_len(&sel[j + 1..]);
            if n == 0 {
                return self.refuse("P7", format!("expected a name after `{c}`"), base + j);
            }
            return Ok(j + 1 + n);
        }
        if c == '[' {
            let Some(end) = matching(sel, j, '[', ']') else {
                return self.refuse("P7", "unterminated attribute selector", base + j);
            };
            if !attribute_ok(trim_chars(&sel[j + 1..end])) {
                return self.refuse(
                    "P7",
                    "not an attribute selector the profile allows",
                    base + j,
                );
            }
            return Ok(end + 1);
        }
        if c == ':' {
            if sel.get(j + 1) == Some(&':') {
                let n = ident_len(&sel[j + 2..]);
                let name: String = sel[j + 2..j + 2 + n].iter().collect();
                if n == 0 || !PSEUDO_ELEMENTS.contains(&name.to_ascii_lowercase().as_str()) {
                    return self.refuse("P7", format!("::{name} is not allowed"), base + j);
                }
                return Ok(j + 2 + n);
            }
            let n = ident_len(&sel[j + 1..]);
            if n == 0 {
                return self.refuse("P7", "expected a pseudo-class", base + j);
            }
            let name: String = sel[j + 1..j + 1 + n]
                .iter()
                .collect::<String>()
                .to_ascii_lowercase();
            let after = j + 1 + n;
            if sel.get(after) == Some(&'(') {
                let Some(end) = matching(sel, after, '(', ')') else {
                    return self.refuse("P7", "unterminated pseudo-class", base + j);
                };
                let arg = trim_chars(&sel[after + 1..end]);
                match name.as_str() {
                    "nth-child" => {
                        if !nth_ok(&arg.iter().collect::<String>()) {
                            return self.refuse(
                                "P7",
                                "not an :nth-child() argument the profile allows",
                                base + j,
                            );
                        }
                    }
                    "not" => {
                        if arg.is_empty() {
                            return self.refuse("P7", ":not() needs a selector", base + j);
                        }
                        for (part, _) in split_top_level(arg, ',') {
                            self.complex(trim_chars(&part), base + after + 1)?;
                        }
                    }
                    _ => return self.refuse("P7", format!(":{name}() is not allowed"), base + j),
                }
                return Ok(end + 1);
            }
            if !PSEUDO_CLASSES.contains(&name.as_str()) {
                return self.refuse("P7", format!(":{name} is not allowed"), base + j);
            }
            return Ok(after);
        }
        let n = ident_len(&sel[j..]);
        if n == 0 {
            return self.refuse(
                "P7",
                format!("`{c}` is not allowed in a selector"),
                base + j,
            );
        }
        Ok(j + n)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `(prefers-color-scheme : dark )` → `(prefers-color-scheme: dark)`.
fn normalise_media(prelude: &str) -> String {
    let collapsed = collapse_ws(prelude.trim()).to_ascii_lowercase();
    let mut out = String::new();
    let chars: Vec<char> = collapsed.chars().collect();
    let mut k = 0;
    while k < chars.len() {
        let c = chars[k];
        match c {
            '(' => {
                out.push('(');
                while chars.get(k + 1) == Some(&' ') {
                    k += 1;
                }
            }
            ')' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(')');
            }
            ':' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push_str(": ");
                while chars.get(k + 1) == Some(&' ') {
                    k += 1;
                }
            }
            _ => out.push(c),
        }
        k += 1;
    }
    out
}

fn is_custom_property(name: &str) -> bool {
    let rest = &name[2..];
    let mut chars = rest.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn strip_strings(v: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    for c in v.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None => out.push(c),
        }
    }
    out
}

/// The first banned function in `value`, matched case-insensitively at a
/// name boundary and allowing whitespace before `(`.
fn banned_function(value: &str) -> Option<&'static str> {
    let lower: Vec<char> = value.to_ascii_lowercase().chars().collect();
    let boundary =
        |k: usize| k == 0 || !(lower[k - 1].is_ascii_alphanumeric() || lower[k - 1] == '-');
    // Longest names first, so `image-set(` reports as itself.
    let mut names = BANNED_FUNCTIONS;
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    for k in 0..lower.len() {
        if !boundary(k) {
            continue;
        }
        for name in names {
            let n: Vec<char> = name.chars().collect();
            if lower[k..].starts_with(&n) {
                let mut e = k + n.len();
                while e < lower.len() && lower[e].is_whitespace() {
                    e += 1;
                }
                if lower.get(e) == Some(&'(') {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn ident_len(s: &[char]) -> usize {
    let mut k = 0;
    if s.first() == Some(&'-') {
        k = 1;
    }
    match s.get(k) {
        Some(c) if c.is_ascii_alphabetic() || *c == '_' => {}
        _ => return 0,
    }
    k += 1;
    while k < s.len() && (s[k].is_ascii_alphanumeric() || s[k] == '_' || s[k] == '-') {
        k += 1;
    }
    k
}

fn trim_chars(s: &[char]) -> &[char] {
    let start = s.iter().position(|c| !c.is_whitespace()).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|c| !c.is_whitespace())
        .map_or(start, |e| e + 1);
    &s[start..end]
}

fn matching(s: &[char], open: usize, o: char, c: char) -> Option<usize> {
    let mut depth = 0;
    let mut quote: Option<char> = None;
    for (k, &ch) in s.iter().enumerate().skip(open) {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

fn split_top_level(s: &[char], sep: char) -> Vec<(Vec<char>, usize)> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut from = 0;
    for (k, &ch) in s.iter().enumerate() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if ch == '(' || ch == '[' {
            depth += 1;
        } else if ch == ')' || ch == ']' {
            depth -= 1;
        } else if depth == 0 && ch == sep {
            out.push((s[from..k].to_vec(), from));
            from = k + 1;
        }
    }
    out.push((s[from..].to_vec(), from));
    out
}

/// `name`, or `name op value [i|s]` with a quoted or identifier value.
fn attribute_ok(inner: &[char]) -> bool {
    let n = ident_len(inner);
    if n == 0 || inner[0] == '-' {
        return false;
    }
    let rest = trim_chars(&inner[n..]);
    if rest.is_empty() {
        return true;
    }
    let op_len = if rest.first() == Some(&'=') {
        1
    } else if rest.len() >= 2 && "~|^$*".contains(rest[0]) && rest[1] == '=' {
        2
    } else {
        return false;
    };
    let after_op = trim_chars(&rest[op_len..]);
    let value_len = match after_op.first() {
        Some(&q) if q == '"' || q == '\'' => match after_op[1..].iter().position(|&c| c == q) {
            Some(p) => p + 2,
            None => return false,
        },
        _ => ident_len(after_op),
    };
    if value_len == 0 {
        return false;
    }
    let flag = &after_op[value_len..];
    if flag.is_empty() {
        return true;
    }
    if !flag[0].is_whitespace() {
        return false;
    }
    let f = trim_chars(flag);
    f.len() == 1 && (f[0] == 'i' || f[0] == 's')
}

/// `odd`, `even`, `An+B` forms, or an integer.
fn nth_ok(arg: &str) -> bool {
    let a = arg.to_ascii_lowercase();
    if a == "odd" || a == "even" {
        return true;
    }
    let compact: String = a.chars().filter(|c| !c.is_whitespace()).collect();
    // Whitespace is allowed only around the B sign, as in the console's check.
    if a.contains(' ') {
        let Some(npos) = a.find('n') else {
            return false;
        };
        if a[..npos].contains(' ') {
            return false;
        }
    }
    let s = compact.strip_prefix(['+', '-']).unwrap_or(&compact);
    match s.find('n') {
        None => !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()),
        Some(p) => {
            if !s[..p].chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            let b = &s[p + 1..];
            if b.is_empty() {
                return true;
            }
            let digits = b.strip_prefix(['+', '-']);
            matches!(digits, Some(d) if !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
        }
    }
}

fn gradients_or_none(value: &str) -> bool {
    if value.eq_ignore_ascii_case("none") {
        return true;
    }
    let chars: Vec<char> = value.chars().collect();
    split_top_level(&chars, ',').into_iter().all(|(part, _)| {
        let t = trim_chars(&part);
        let s: String = t.iter().collect::<String>().to_ascii_lowercase();
        let body = s.strip_prefix("repeating-").unwrap_or(&s);
        let is_gradient = ["linear-gradient(", "radial-gradient(", "conic-gradient("]
            .iter()
            .any(|g| body.starts_with(g));
        is_gradient
            && t.iter()
                .position(|&c| c == '(')
                .and_then(|open| matching(t, open, '(', ')'))
                == Some(t.len() - 1)
    })
}

/// Space-separated lengths, each `0`, `Npx` with N ≤ `max`, or a keyword.
fn bounded_lengths(value: &str, max: f64, keywords: &[&str]) -> bool {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.is_empty() || parts.len() > 8 {
        return false;
    }
    parts.iter().all(|p| {
        let lower = p.to_ascii_lowercase();
        if keywords.contains(&lower.as_str()) || lower == "0" {
            return true;
        }
        lower
            .strip_suffix("px")
            .filter(|n| is_unsigned_decimal(n))
            .and_then(|n| n.parse::<f64>().ok())
            .is_some_and(|n| n <= max)
    })
}

/// `12`, `1.5`, `.5` — no sign, no exponent.
fn is_unsigned_decimal(n: &str) -> bool {
    let (int, frac) = match n.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (n, None),
    };
    let int_ok = int.chars().all(|c| c.is_ascii_digit());
    match frac {
        None => !int.is_empty() && int_ok,
        Some(f) => int_ok && !f.is_empty() && f.chars().all(|c| c.is_ascii_digit()),
    }
}

/// `normal`, `0`, or `±Nem` with |N| ≤ 0.2.
fn letter_spacing_ok(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    if v == "normal" || v == "0" {
        return true;
    }
    let Some(n) = v.strip_suffix("em") else {
        return false;
    };
    let unsigned = n.strip_prefix('-').unwrap_or(n);
    is_unsigned_decimal(unsigned) && n.parse::<f64>().is_ok_and(|x| x.abs() <= 0.2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    /// The console's vectors: both checkers must answer them the same way.
    const VECTORS: &str = include_str!("../../admin-ui/src/lib/theme-profile.vectors.json");

    #[derive(Deserialize)]
    struct Vectors {
        accept: Vec<Accept>,
        refuse: Vec<Refuse>,
    }
    #[derive(Deserialize)]
    struct Accept {
        name: String,
        css: String,
        stored: String,
    }
    #[derive(Deserialize)]
    struct Refuse {
        name: String,
        css: String,
        rule: String,
        line: usize,
        column: usize,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(VECTORS).expect("theme-profile.vectors.json parses")
    }

    #[test]
    fn accepts_what_the_console_accepts() {
        for v in vectors().accept {
            assert_eq!(check_stylesheet(&v.css), Ok(v.stored), "{}", v.name);
        }
    }

    #[test]
    fn refuses_what_the_console_refuses_at_the_same_place() {
        for v in vectors().refuse {
            let got = check_stylesheet(&v.css).expect_err(&v.name);
            assert_eq!(
                (got.rule, got.line, got.column),
                (v.rule.as_str(), v.line, v.column),
                "{}: {}",
                v.name,
                got.message
            );
        }
    }

    #[test]
    fn the_bound_counts_bytes_not_characters() {
        let css = format!("/*{}*/", "é".repeat(MAX_STYLESHEET_BYTES / 2));
        assert!(css.chars().count() < MAX_STYLESHEET_BYTES);
        assert_eq!(check_stylesheet(&css).unwrap_err().rule, "P1");
    }

    #[test]
    fn every_builtin_theme_is_in_the_profile() {
        for (name, css) in [
            (
                "forest",
                include_str!("../../admin-ui/src/styles/themes/forest.css"),
            ),
            (
                "ocean",
                include_str!("../../admin-ui/src/styles/themes/ocean.css"),
            ),
            (
                "slate",
                include_str!("../../admin-ui/src/styles/themes/slate.css"),
            ),
            (
                "sunset",
                include_str!("../../admin-ui/src/styles/themes/sunset.css"),
            ),
            (
                "contrast",
                include_str!("../../admin-ui/src/styles/themes/contrast.css"),
            ),
        ] {
            assert!(
                check_stylesheet(css).is_ok(),
                "{name}: {:?}",
                check_stylesheet(css)
            );
        }
    }

    #[test]
    fn digest_is_hex_sha256() {
        assert_eq!(
            stylesheet_digest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    async fn ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("community").unwrap();
        (dir, store, ks)
    }

    #[tokio::test]
    async fn store_load_and_remove() {
        let (_d, _s, ks) = ks().await;
        assert_eq!(load_theme(&ks).await.unwrap(), None);
        let now = Utc::now();
        let row = store_theme(&ks, ":root { --brand: #0a7f5c; }", now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(load_theme(&ks).await.unwrap(), Some(row));
        assert_eq!(store_theme(&ks, "", now).await.unwrap(), None);
        assert_eq!(load_theme(&ks).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_stored_theme_outside_the_profile_is_shown_as_none() {
        let (_d, _s, ks) = ks().await;
        store_theme(&ks, ".a { display: none; }", Utc::now())
            .await
            .unwrap();
        assert_eq!(shown_stylesheet(&ks).await.unwrap(), None);
    }
}
