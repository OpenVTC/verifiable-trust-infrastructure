//! Census: a `deny_unknown_fields` wire type must carry an `ext` member.
//!
//! ## The invariant
//!
//! SPEC.md §4.5.1 gives every Trust Task payload an `ext` slot for
//! ecosystem-defined extension members, and the published schemas declare it —
//! `acl/list/0.1`, `policy/list/0.2` and the rest all list `ext` among their
//! properties. So a conforming producer may send one.
//!
//! `#[serde(deny_unknown_fields)]` on a struct that has no `ext` field turns
//! that permission into a hard rejection of the whole document:
//!
//! ```text
//! malformed request: payload parse: unknown field `ext`, expected one of
//! `role`, `scope`, `direction`, `subjectPrefix`, `pageSize`, `cursor`
//! ```
//!
//! The two clauses are not in conflict and the fix is not to drop
//! `deny_unknown_fields`: carrying `ext` explicitly keeps a *typo* refused,
//! which is the guard that clause was there for, while letting through the one
//! member the spec says is always allowed.
//!
//! ## Why a census rather than another fixture
//!
//! Seven of these structs already carry `ext`, with the reasoning written out
//! on each. Sixteen did not — including `acl/list`, `policy/list`, every
//! `vta/memory/*` body, `app-state` writes, config read and patch, and both
//! credential-issuance bodies. Nothing failed at build time and nothing failed
//! in the conformance table, because both of those exercise the members a
//! fixture happens to set and this defect lives in the member it leaves unset.
//!
//! It surfaced from a browser-based management console: two of its panes died
//! outright, and the operator was shown a parse error naming a field the spec
//! had told the client it could send. Whether a caller trips this is decided
//! entirely by whether it populates `ext` — so a partial fix reads as a working
//! system right up until a conforming peer appears.
//!
//! The invariant is a property of the *source*, so it is checked against the
//! source, once, for every wire type at the same time.
//!
//! ## Scope
//!
//! Every `deny_unknown_fields` struct under `vta-sdk/src/protocols/`. Genuine
//! exceptions go in [`NO_EXT_BY_DESIGN`] with a reason; there is no way to pass
//! by silence.
//!
//! Parsed with `syn`, not grepped — the attribute is routinely written across
//! several lines, and a line-oriented regex misreads that in exactly the
//! direction that lets a violation through.

use std::fs;
use std::path::{Path, PathBuf};

use syn::{Fields, Item, ItemStruct, Meta};

/// Types that legitimately admit no `ext`, each with the reason.
///
/// An entry here is a claim that the *published schema* declares no `ext` slot
/// for this type — not that adding the field is inconvenient. A type whose
/// schema has one, listed here, re-opens the defect this file exists to
/// prevent.
const NO_EXT_BY_DESIGN: &[(&str, &str)] = &[];

/// One `deny_unknown_fields` type that would reject a conforming `ext`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    file: String,
    strukt: String,
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

fn denies_unknown_fields(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("serde")
            && matches!(&attr.meta, Meta::List(l) if l.tokens.to_string().contains("deny_unknown_fields"))
    })
}

/// `#[cfg(test)]` items are not wire types.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && matches!(&attr.meta, Meta::List(l) if l.tokens.to_string().contains("test"))
    })
}

fn inspect_struct(s: &ItemStruct, file: &str, inspected: &mut usize, out: &mut Vec<Violation>) {
    if !denies_unknown_fields(&s.attrs) {
        return;
    }
    let Fields::Named(fields) = &s.fields else {
        return;
    };
    *inspected += 1;

    let has_ext = fields
        .named
        .iter()
        .any(|f| f.ident.as_ref().is_some_and(|i| i == "ext"));
    if has_ext {
        return;
    }
    if NO_EXT_BY_DESIGN.iter().any(|(st, _)| s.ident == st) {
        return;
    }

    out.push(Violation {
        file: file.to_string(),
        strukt: s.ident.to_string(),
    });
}

fn walk_items(items: &[Item], file: &str, inspected: &mut usize, out: &mut Vec<Violation>) {
    for item in items {
        match item {
            Item::Struct(s) if !is_cfg_test(&s.attrs) => inspect_struct(s, file, inspected, out),
            Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    walk_items(inner, file, inspected, out);
                }
            }
            _ => {}
        }
    }
}

#[test]
fn deny_unknown_fields_types_accept_ext() {
    let root = protocols_dir();
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    files.sort();

    assert!(
        files.len() > 10,
        "found only {} source files under {} — the walk is broken, and a \
         census that inspects nothing passes vacuously",
        files.len(),
        root.display()
    );

    let mut inspected = 0usize;
    let mut violations = Vec::new();

    for path in &files {
        let src = fs::read_to_string(path).expect("source file is readable");
        let parsed = syn::parse_file(&src)
            .unwrap_or_else(|e| panic!("{}: does not parse: {e}", path.display()));
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        walk_items(&parsed.items, &rel, &mut inspected, &mut violations);
    }

    assert!(
        inspected > 15,
        "inspected only {inspected} deny_unknown_fields types — the walk is \
         broken, and a census that inspects nothing passes vacuously"
    );

    violations.sort();
    assert!(
        violations.is_empty(),
        "{} wire type(s) deny unknown fields but carry no `ext`, so a producer \
         doing exactly what SPEC §4.5.1 and the published schema allow has its \
         whole document rejected:\n{}\n\nAdd:\n\n    /// Ecosystem-defined \
         extension members (SPEC §4.5.1).\n    #[serde(default, \
         skip_serializing_if = \"Option::is_none\")]\n    pub ext: \
         Option<Value>,\n\nKeep `deny_unknown_fields` — it is what still \
         refuses a typo.",
        violations.len(),
        violations
            .iter()
            .map(|v| format!("  {}::{}", v.file, v.strukt))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
