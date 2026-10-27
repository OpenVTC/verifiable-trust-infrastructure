//! Census: a published crate's growth enums are `#[non_exhaustive]`, and its
//! must-match enums are not.
//!
//! ## Why
//!
//! In a published crate a new variant on a public enum is a breaking change
//! unless the enum is `#[non_exhaustive]`: every downstream exhaustive `match`
//! stops compiling. It happened here five times in one week (#1231, #1234,
//! #1244, #1247, #1250 — RELEASING.md, *What actually counts as breaking*), each
//! time on a type that was always going to grow. Marking such a type once makes
//! every later addition an ordinary minor change.
//!
//! The opposite mistake matters as much. Some enums are exhaustive on purpose:
//! a caller must consider every arm, and a wildcard would be the bug —
//! `VerifiedAssertion` (whose `Attested` arm demands a follow-up Nitro check),
//! `ActScope` / `ApproveScope` (CLAUDE.md, *Never test
//! `allowed_contexts.is_empty()`*). Those must never be marked.
//!
//! ## The rules
//!
//! The census parses (with `syn`, as `generated_wire_types_census.rs` does)
//! every source file of every **published library crate** — a workspace member
//! without `publish = false` that has a `src/lib.rs` — and finds each `pub enum`.
//!
//! 1. A `pub enum` whose name ends in one of [`GROWTH_SUFFIXES`] — an error,
//!    refusal, kind, event, status, capability, reason or code vocabulary — must
//!    be `#[non_exhaustive]`, unless [`DELIBERATELY_EXHAUSTIVE`] lists it.
//! 2. Every enum in [`DELIBERATELY_EXHAUSTIVE`] must exist and must **not** be
//!    `#[non_exhaustive]`. A stale entry fails, so the list cannot rot.
//!
//! Other enums may be marked too (`SealedPayloadV1`, `SurfaceTransport`, …);
//! the suffixes are the floor this census holds, not the whole policy.
//!
//! Structs are not censused: `#[non_exhaustive]` on a struct forbids building
//! it with a literal outside its crate, so whether to mark one depends on how
//! callers construct it, which a name cannot tell.

use std::fs;
use std::path::{Path, PathBuf};

use syn::{Attribute, Item, Meta, Visibility};

/// Name endings that mark an enum as a vocabulary designed to grow.
const GROWTH_SUFFIXES: &[&str] = &[
    "Error",
    "Refusal",
    "Violation",
    "Kind",
    "Event",
    "Status",
    "Capability",
    "Reason",
    "Code",
];

/// Published crates whose types are not a library API, so the census skips
/// them. `(crate, reason)`.
const NOT_A_LIBRARY_API: &[(&str, &str)] = &[(
    "vtc-service",
    "published as a binary: no crate depends on it and release-plz runs no semver check on it",
)];

/// Enums that are exhaustive on purpose: every arm must be considered, so a
/// downstream wildcard would be the bug. `(file, enum, reason)`, file relative
/// to the workspace root.
const DELIBERATELY_EXHAUSTIVE: &[(&str, &str, &str)] = &[
    (
        "vta-sdk/src/sealed_transfer/verify.rs",
        "VerifiedAssertion",
        "typestate: callers match every arm, and `AttestedNeedsNitroCheck` demands a follow-up check",
    ),
    (
        "vta-sdk/src/sealed_transfer/bundle.rs",
        "AssertionProof",
        "the producer-assertion kinds; a new one is a security decision every opener must make",
    ),
    (
        "vta-sdk/src/acl.rs",
        "ActScope",
        "ACL act scope: unrestricted vs listed vs nowhere must each be handled (#746, #769, #770)",
    ),
    (
        "vta-sdk/src/acl.rs",
        "ApproveScope",
        "ACL approve scope, the confer axis beside `ActScope`; same reason",
    ),
    (
        "vta-sdk/src/acl.rs",
        "ContextDirection",
        "which ACL entries touch a context (#770): a filter that guesses a direction answers the wrong question",
    ),
    (
        "vta-sdk/src/protocols/key_management/sign.rs",
        "SigningDomain",
        "signing-domain separation; a domain a signer does not know must not be signed in",
    ),
    (
        "vta-sdk/src/session.rs",
        "TokenStatus",
        "a cached token is valid, expired or absent; there is no fourth state",
    ),
    (
        "vti-common/src/acl/mod.rs",
        "Role",
        "VTA roles decide privilege; a new role must be weighed at every match, not defaulted",
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vta-sdk sits inside the workspace")
        .to_path_buf()
}

/// The `[workspace] members` of the root manifest.
fn workspace_members(root: &Path) -> Vec<String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    let start = manifest
        .find("members = [")
        .expect("the workspace manifest lists its members");
    let rest = &manifest[start + "members = [".len()..];
    let list = &rest[..rest.find(']').expect("the members list closes")];
    list.lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(|line| line.split(','))
        .map(|m| m.trim().trim_matches('"').to_string())
        .filter(|m| !m.is_empty())
        .collect()
}

/// A member that crates.io receives and that has a library target.
fn is_published_library(root: &Path, member: &str) -> bool {
    let dir = root.join(member);
    let Ok(manifest) = fs::read_to_string(dir.join("Cargo.toml")) else {
        return false;
    };
    let unpublished = manifest
        .lines()
        .any(|l| l.split('#').next().unwrap_or_default().replace(' ', "") == "publish=false");
    !unpublished && dir.join("src/lib.rs").is_file()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory is readable") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && matches!(&attr.meta, Meta::List(l) if l.tokens.to_string().contains("test"))
    })
}

struct PubEnum {
    file: String,
    name: String,
    non_exhaustive: bool,
}

fn walk(items: &[Item], file: &str, out: &mut Vec<PubEnum>) {
    for item in items {
        match item {
            Item::Enum(e) if matches!(e.vis, Visibility::Public(_)) && !is_cfg_test(&e.attrs) => {
                out.push(PubEnum {
                    file: file.to_string(),
                    name: e.ident.to_string(),
                    non_exhaustive: has_attr(&e.attrs, "non_exhaustive"),
                });
            }
            Item::Mod(m) if !is_cfg_test(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    walk(inner, file, out);
                }
            }
            _ => {}
        }
    }
}

fn census() -> Vec<PubEnum> {
    let root = workspace_root();
    let mut found = Vec::new();
    for member in workspace_members(&root) {
        if !is_published_library(&root, &member)
            || NOT_A_LIBRARY_API.iter().any(|(c, _)| *c == member)
        {
            continue;
        }
        let mut files = Vec::new();
        rust_sources(&root.join(&member).join("src"), &mut files);
        for path in files {
            let text = fs::read_to_string(&path).expect("source is readable");
            let parsed = syn::parse_file(&text)
                .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
            let rel = path
                .strip_prefix(&root)
                .expect("inside the workspace")
                .to_string_lossy()
                .replace('\\', "/");
            walk(&parsed.items, &rel, &mut found);
        }
    }
    found
}

fn is_growth_name(name: &str) -> bool {
    GROWTH_SUFFIXES.iter().any(|s| name.ends_with(s))
}

#[test]
fn growth_enums_in_published_crates_are_non_exhaustive() {
    let found = census();
    assert!(
        found.len() > 100,
        "the census found only {} public enums — is it reading the published crates?",
        found.len()
    );
    let missing: Vec<String> = found
        .iter()
        .filter(|e| is_growth_name(&e.name) && !e.non_exhaustive)
        .filter(|e| {
            !DELIBERATELY_EXHAUSTIVE
                .iter()
                .any(|(f, n, _)| *f == e.file && *n == e.name)
        })
        .map(|e| format!("  {} — pub enum {}", e.file, e.name))
        .collect();
    assert!(
        missing.is_empty(),
        "these public enums in published crates are vocabularies designed to grow, so a new \
         variant would be a breaking change. Mark each `#[non_exhaustive]` (and give \
         downstream matches a `_ =>` arm), or — if every arm truly must be handled — list it \
         in DELIBERATELY_EXHAUSTIVE with the reason:\n{}",
        missing.join("\n")
    );
}

#[test]
fn deliberately_exhaustive_enums_stay_exhaustive() {
    let found = census();
    let mut problems = Vec::new();
    for (file, name, _) in DELIBERATELY_EXHAUSTIVE {
        match found.iter().find(|e| e.file == *file && e.name == *name) {
            None => problems.push(format!(
                "  {file} — pub enum {name} is gone; remove its DELIBERATELY_EXHAUSTIVE entry"
            )),
            Some(e) if e.non_exhaustive => problems.push(format!(
                "  {file} — pub enum {name} is listed as deliberately exhaustive but is \
                 `#[non_exhaustive]`; a wildcard arm downstream would defeat it"
            )),
            Some(_) => {}
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_rules_read_names_and_attributes_the_way_a_reader_does() {
    let src = r#"
        #[derive(Debug)]
        #[non_exhaustive]
        pub enum MarkedError { A }
        pub enum BareKind { A }
        enum PrivateError { A }
        pub(crate) enum CrateStatus { A }
        pub mod inner { pub enum InnerEvent { A } }
        #[cfg(test)]
        mod tests { pub enum TestError { A } }
    "#;
    let file = syn::parse_file(src).unwrap();
    let mut out = Vec::new();
    walk(&file.items, "x.rs", &mut out);
    let names: Vec<(&str, bool)> = out
        .iter()
        .map(|e| (e.name.as_str(), e.non_exhaustive))
        .collect();
    assert_eq!(
        names,
        vec![
            ("MarkedError", true),
            ("BareKind", false),
            ("InnerEvent", false)
        ]
    );
    assert!(is_growth_name("BareKind") && is_growth_name("InnerEvent"));
    assert!(!is_growth_name("ActScope"));
}
