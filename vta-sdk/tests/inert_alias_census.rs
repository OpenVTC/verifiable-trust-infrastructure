//! Census: no `#[serde(alias = "…")]` under `protocols/` may be a no-op.
//!
//! ## The invariant
//!
//! An alias exists so a member spelled the *old* way still decodes. If the alias
//! equals the member's own serialized name, it accepts what would be accepted
//! anyway and buys nothing — and its presence claims a fold happened that did
//! not.
//!
//! That is not a tidiness complaint. It is how #1000 half-shipped.
//!
//! ## What it missed, and why nobody noticed
//!
//! #1000 folded 53 wire structs to lowerCamelCase and gave 126 members an alias
//! for the retired spelling. Two structs got the aliases and **not** the
//! `#[serde(rename_all = "camelCase")]` that gives them meaning, so they kept
//! emitting snake_case with `alias = "created_at"` sitting on a member already
//! called `created_at`:
//!
//! - `SeedInfo` — inside `ListSeedsResultBody`, which *was* folded. `seeds/list`
//!   therefore emitted a body that disagreed with itself,
//!   `{"seeds":[{"created_at":…}],"activeSeedId":1}`. Fixed in #1034.
//! - `CapabilitiesResponse` — still open, see [`INERT_BY_DECISION`].
//!
//! Both were found by hand, months later, while auditing something else. Nothing
//! failed: the code compiled, every test passed, and the attributes read as
//! though the work was done. A reviewer looking at the diff sees `alias =
//! "created_at"` and reasonably assumes the member is now `createdAt`.
//!
//! ## Why the class, not the instances
//!
//! Fixing the two found instances leaves the next fold free to repeat it, and
//! the next fold is coming — the REST bodies #1000 deferred are still snake_case.
//! An inert alias is decidable from the source, so it is decided here, once, for
//! every wire type at the same time.
//!
//! Parsed with `syn`, like [`payload_null_census`](../payload_null_census.rs) and
//! for the same reason: these attributes wrap across lines, and a line-oriented
//! regex misreads them in the direction that lets a violation through.

use std::fs;
use std::path::{Path, PathBuf};

use syn::{Fields, Item, ItemStruct, Meta};

/// Structs whose inert aliases are a **recorded decision**, not an oversight.
///
/// An entry says: this type deliberately still emits snake_case, and the alias
/// is kept for the fold that is coming. Anything else belongs in a fix.
const INERT_BY_DECISION: &[(&str, &str)] = &[
    (
        "CapabilitiesResponse",
        "Served on `GET /capabilities` as well as the Trust-Task and DIDComm \
         surfaces. #1000 never touched its emission, so folding it is a fresh \
         REST wire change of exactly the kind that PR deferred — not the \
         completion of a half-done one, which is what made SeedInfo \
         unambiguous. Tracked in #1039; the aliases stay so the eventual fold \
         is a one-line change.",
    ),
    (
        "UpdateRetentionBody",
        "Found by this census, not by anyone reading the file. Its sibling \
         `RetentionResultBody` — one screen down, same task — IS folded, so \
         `audit/update-retention` takes a snake_case request and returns a \
         camelCase response. Plainly a miss. Deferred anyway because it is a \
         REQUEST body: folding changes what clients SEND, on the Trust-Task, \
         DIDComm and REST surfaces at once, and an agent that predates the \
         change rejects the new spelling. SeedInfo is safe to finish precisely \
         because its containing body already moved; this one has not moved at \
         all. Tracked in #1039.",
    ),
];

/// One alias that accepts what would be accepted anyway.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    file: String,
    strukt: String,
    field: String,
    alias: String,
}

fn protocols_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("protocols")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("protocols/ is readable") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `snake_case` → `camelCase`, matching what `serde`'s `rename_all` does.
fn to_camel(ident: &str) -> String {
    let mut out = String::with_capacity(ident.len());
    let mut upper_next = false;
    for c in ident.chars() {
        if c == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(c.to_uppercase());
            upper_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The container-level `rename_all` value, if any.
fn rename_all(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let Meta::List(l) = &attr.meta else { continue };
        let tokens = l.tokens.to_string();
        if let Some(idx) = tokens.find("rename_all") {
            // `rename_all = "camelCase"` — take the next quoted run.
            let rest = &tokens[idx..];
            if let Some(open) = rest.find('"')
                && let Some(close) = rest[open + 1..].find('"')
            {
                return Some(rest[open + 1..open + 1 + close].to_string());
            }
        }
    }
    None
}

/// Every `alias = "…"` on a field.
fn aliases(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut found = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let Meta::List(l) = &attr.meta else { continue };
        let tokens = l.tokens.to_string();
        let mut cursor = tokens.as_str();
        while let Some(idx) = cursor.find("alias") {
            let rest = &cursor[idx..];
            if let Some(open) = rest.find('"') {
                if let Some(close) = rest[open + 1..].find('"') {
                    found.push(rest[open + 1..open + 1 + close].to_string());
                    cursor = &rest[open + 1 + close..];
                    continue;
                }
            }
            break;
        }
    }
    found
}

/// The field's explicit `rename = "…"`, if any. Wins over `rename_all`.
fn explicit_rename(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let Meta::List(l) = &attr.meta else { continue };
        let tokens = l.tokens.to_string();
        // Careful: `rename_all` contains `rename`. Only a bare `rename` counts.
        for (idx, _) in tokens.match_indices("rename") {
            if tokens[idx..].starts_with("rename_all") {
                continue;
            }
            let rest = &tokens[idx..];
            if let Some(open) = rest.find('"')
                && let Some(close) = rest[open + 1..].find('"')
            {
                return Some(rest[open + 1..open + 1 + close].to_string());
            }
        }
    }
    None
}

/// What this member is actually called on the wire.
fn effective_name(field_ident: &str, attrs: &[syn::Attribute], container: Option<&str>) -> String {
    if let Some(explicit) = explicit_rename(attrs) {
        return explicit;
    }
    match container {
        Some("camelCase") => to_camel(field_ident),
        // Only camelCase is used in this crate; anything else is reported as-is
        // rather than guessed at, so a new convention surfaces here rather than
        // being silently mis-evaluated.
        _ => field_ident.to_string(),
    }
}

fn inspect(strukt: &ItemStruct, file: &str, out: &mut Vec<Violation>) {
    let container = rename_all(&strukt.attrs);
    let Fields::Named(fields) = &strukt.fields else {
        return;
    };
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let ident = ident.to_string();
        let effective = effective_name(&ident, &field.attrs, container.as_deref());
        for alias in aliases(&field.attrs) {
            if alias == effective {
                out.push(Violation {
                    file: file.to_string(),
                    strukt: strukt.ident.to_string(),
                    field: ident.clone(),
                    alias,
                });
            }
        }
    }
}

/// No alias under `protocols/` accepts only what is already accepted.
#[test]
fn no_wire_type_carries_an_inert_alias() {
    let mut files = Vec::new();
    rust_sources(&protocols_dir(), &mut files);
    files.sort();

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for path in &files {
        let src = fs::read_to_string(path).expect("wire source is readable");
        let ast = syn::parse_file(&src).expect("wire source parses");
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        for item in ast.items {
            if let Item::Struct(s) = item {
                inspect(&s, &rel, &mut violations);
            }
        }
    }
    violations.sort();

    let excused: Vec<&str> = INERT_BY_DECISION.iter().map(|(s, _)| *s).collect();
    let unexcused: Vec<&Violation> = violations
        .iter()
        .filter(|v| !excused.contains(&v.strukt.as_str()))
        .collect();

    assert!(
        unexcused.is_empty(),
        "these `serde(alias)` attributes accept only what is already accepted:\n{}\n\n\
         An alias equal to the member's own serialized name does nothing, and \
         implies a fold that did not happen. Either:\n\
         \n\
         - add `#[serde(rename_all = \"camelCase\")]` to the container, which is \
           what the alias was written to accompany; or\n\
         - if this type is deliberately staying snake_case, record it in \
           INERT_BY_DECISION with the reason.\n\
         \n\
         Deleting the alias is usually wrong — it is the only thing that will let \
         an older producer keep working once the fold lands.",
        unexcused
            .iter()
            .map(|v| format!(
                "  {}: {}.{} — alias = \"{}\"",
                v.file, v.strukt, v.field, v.alias
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every name in [`INERT_BY_DECISION`] is still inert.
///
/// Without this the exception list only grows: a type could be folded and its
/// entry left behind, quietly excusing a struct that no longer needs it — and
/// the next genuine violation in that struct would pass unnoticed.
#[test]
fn the_exception_list_has_no_stale_entries() {
    let mut files = Vec::new();
    rust_sources(&protocols_dir(), &mut files);

    let mut violations = Vec::new();
    for path in &files {
        let src = fs::read_to_string(path).expect("wire source is readable");
        let ast = syn::parse_file(&src).expect("wire source parses");
        for item in ast.items {
            if let Item::Struct(s) = item {
                inspect(&s, "", &mut violations);
            }
        }
    }

    let still_inert: Vec<String> = violations.iter().map(|v| v.strukt.clone()).collect();
    let stale: Vec<&str> = INERT_BY_DECISION
        .iter()
        .map(|(s, _)| *s)
        .filter(|s| !still_inert.contains(&s.to_string()))
        .collect();

    assert!(
        stale.is_empty(),
        "INERT_BY_DECISION excuses these, but they carry no inert alias any more \
         — they were fixed, and the entry should go:\n  {}",
        stale.join("\n  ")
    );
}

/// The census sees the wire types at all.
///
/// A move of `protocols/`, or a `syn` upgrade that changes how these attributes
/// parse, would leave both tests above passing over an empty set — green because
/// nothing was examined. The alias count is asserted rather than the file count,
/// because it is the thing the parser has to actually understand.
#[test]
fn the_census_is_not_scanning_an_empty_set() {
    let mut files = Vec::new();
    rust_sources(&protocols_dir(), &mut files);
    assert!(
        files.len() >= 30,
        "only {} files under protocols/ — the walk is broken, do not lower this floor",
        files.len()
    );

    let root = protocols_dir();
    let mut total_aliases = 0usize;
    for path in &files {
        let src = fs::read_to_string(path).expect("wire source is readable");
        let ast = syn::parse_file(&src).expect("wire source parses");
        for item in ast.items {
            let Item::Struct(s) = item else { continue };
            let Fields::Named(fields) = &s.fields else {
                continue;
            };
            for field in &fields.named {
                total_aliases += aliases(&field.attrs).len();
            }
        }
    }
    let _ = root;
    assert!(
        total_aliases >= 80,
        "only {total_aliases} serde aliases found under protocols/; #1000 added \
         126. The attribute parser has stopped understanding them — fix it rather \
         than lowering this floor."
    );
}
