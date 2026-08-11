//! Census: no wire member under `protocols/` may serialize as `null`.
//!
//! ## The invariant
//!
//! An unset optional member must be **absent** from the serialized payload,
//! never `null`. Trust Task schemas type each optional member by what it holds
//! — `"string"`, `"object"`, `"integer"` — and none of them accepts null, so a
//! `None` that serializes as `null` is refused on arrival by the recipient's
//! `validate_payload`:
//!
//! ```text
//! payload does not conform to https://trusttasks.org/spec/keys/create/0.1:
//! payload failed schema validation: null is not of type "string"
//! ```
//!
//! ## Why a census rather than another fixture
//!
//! This defect has now shipped twice, on unrelated tasks, roughly a month
//! apart:
//!
//! - #895 — `vta/webvh/dids/update/1.0`. Every *partial* update was rejected,
//!   once per unset member. `pnm did-mgmt dids edit --label x` could not run at
//!   all, and supplying more flags did not help: each one removed a single null
//!   and left the rest.
//! - #919 — `keys/create/0.1`. Every call that did not carry a BIP-39 phrase
//!   sent `"mnemonic": null`, so nothing downstream could mint a key over
//!   DIDComm or TSP. An OpenVTC community join died on its first round-trip.
//!
//! Both were found in production, by a person, from a rejected request. Both
//! were one missing attribute. The second was introduced by a refactor that
//! moved a call off a hand-rolled map — which skipped its `None`s — onto a
//! struct that did not, which is a shape any future fold can reproduce.
//!
//! Per-task fixtures cannot close this: they prove the members a fixture
//! happens to set, and this bug lives in the members it happens to leave unset.
//! The invariant is a property of the *source*, so it is checked against the
//! source, once, for every wire type at the same time.
//!
//! ## Scope
//!
//! Every `Option<T>` field of every `Serialize`-deriving struct under
//! `vta-sdk/src/protocols/` — the crate's wire types. Genuine exceptions go in
//! [`NULLABLE_BY_DESIGN`] with a reason; there is no way to pass by silence.
//!
//! Parsed with `syn`, not grepped. The attribute is routinely written across
//! several lines, and a line-oriented regex misreads that in exactly the
//! direction that lets a violation through.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use syn::{Fields, Item, ItemStruct, Meta, Type};

/// Members that are legitimately nullable, each with the reason.
///
/// An entry here is a claim that `null` is the *correct* wire form for this
/// member — not that the fix is inconvenient. Adding one without a spec that
/// admits null re-opens the defect this file exists to prevent.
const NULLABLE_BY_DESIGN: &[(&str, &str, &str)] = &[(
    "GetKeyResponseBody",
    "key",
    "`keys/show/0.1#response` types this `oneOf: [KeyRecord, null]` and \
         requires it present. Null is the answer meaning \"the custodian holds \
         no key for this identifier\" — a successful answer, not an error, and \
         a caller that cannot tell absence from failure retries a lookup that \
         will never succeed. Omitting the member would violate `required`.",
)];

/// One `Option` member that would reach the wire as `null`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    file: String,
    strukt: String,
    field: String,
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

/// Does this attribute list derive `Serialize`?
///
/// A `Deserialize`-only type never reaches the wire from here, so
/// `skip_serializing_if` on it would be inert.
fn derives_serialize(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive")
            && matches!(&attr.meta, Meta::List(l) if l.tokens.to_string().contains("Serialize"))
    })
}

fn skips_none(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("serde")
            && matches!(&attr.meta, Meta::List(l) if l.tokens.to_string().contains("skip_serializing_if"))
    })
}

fn is_option(ty: &Type) -> bool {
    let Type::Path(p) = ty else { return false };
    p.path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "Option")
}

/// `#[cfg(test)]` items are not wire types.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && matches!(&attr.meta, Meta::List(l) if l.tokens.to_string().contains("test"))
    })
}

fn inspect_struct(s: &ItemStruct, file: &str, inspected: &mut usize, out: &mut Vec<Violation>) {
    if !derives_serialize(&s.attrs) {
        return;
    }
    let Fields::Named(fields) = &s.fields else {
        return;
    };

    for field in &fields.named {
        if !is_option(&field.ty) {
            continue;
        }
        *inspected += 1;

        let name = field
            .ident
            .as_ref()
            .expect("named field has an ident")
            .to_string();

        if skips_none(&field.attrs) {
            continue;
        }
        if NULLABLE_BY_DESIGN
            .iter()
            .any(|(st, f, _)| s.ident == st && *f == name)
        {
            continue;
        }

        out.push(Violation {
            file: file.to_string(),
            strukt: s.ident.to_string(),
            field: name,
        });
    }
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
fn no_wire_member_serializes_as_null() {
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

    // Teeth. A parser that silently matches nothing — a `syn` upgrade changing
    // how `Meta::List` renders, a refactor moving the wire types elsewhere —
    // would otherwise report a clean census over an empty set.
    assert!(
        inspected > 100,
        "the census inspected only {inspected} Option members across {} files. \
         There are well over a hundred; this means the parser stopped \
         recognising them, not that they went away.",
        files.len()
    );

    violations.sort();
    assert!(
        violations.is_empty(),
        "these wire members serialize as `null` when unset, and every Trust \
         Task schema that types them rejects null:\n\n{}\n\n\
         Add `#[serde(default, skip_serializing_if = \"Option::is_none\")]` so \
         an unset member is absent from the payload. If `null` really is the \
         correct wire form — the spec must say so, as `keys/show`'s `key` does \
         — add it to NULLABLE_BY_DESIGN with that reason.\n\n\
         This has shipped twice as a production outage (#895, #919). It is one \
         attribute.",
        violations
            .iter()
            .map(|v| format!("  {}: {}::{}", v.file, v.strukt, v.field))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every allowlist entry names a member that still exists and still lacks the
/// skip — so a stale exemption cannot outlive the thing it exempts.
///
/// The other direction of the same coverage assertion the conformance sweep
/// makes: an exemption for a member that has since been fixed or deleted reads
/// as "null is fine here" to the next person, and nothing would ever say
/// otherwise.
#[test]
fn every_allowlist_entry_is_still_live() {
    let root = protocols_dir();
    let mut files = Vec::new();
    rust_sources(&root, &mut files);

    let mut unskipped_options: BTreeSet<(String, String)> = BTreeSet::new();
    for path in &files {
        let src = fs::read_to_string(path).expect("source file is readable");
        let parsed = syn::parse_file(&src).expect("source parses");
        collect_unskipped(&parsed.items, &mut unskipped_options);
    }

    for (strukt, field, reason) in NULLABLE_BY_DESIGN {
        assert!(
            !reason.trim().is_empty(),
            "{strukt}::{field}: an exemption must state why null is correct"
        );
        assert!(
            unskipped_options.contains(&(strukt.to_string(), field.to_string())),
            "NULLABLE_BY_DESIGN exempts {strukt}::{field}, but no such \
             unskipped Option member exists any more — it was renamed, \
             removed, or given the skip. Drop the entry."
        );
    }
}

fn collect_unskipped(items: &[Item], out: &mut BTreeSet<(String, String)>) {
    for item in items {
        match item {
            Item::Struct(s) if !is_cfg_test(&s.attrs) && derives_serialize(&s.attrs) => {
                if let Fields::Named(fields) = &s.fields {
                    for field in &fields.named {
                        if is_option(&field.ty) && !skips_none(&field.attrs) {
                            out.insert((
                                s.ident.to_string(),
                                field
                                    .ident
                                    .as_ref()
                                    .expect("named field has an ident")
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
            Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    collect_unskipped(inner, out);
                }
            }
            _ => {}
        }
    }
}
