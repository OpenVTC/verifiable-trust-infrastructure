//! Census: no two `ToSchema` types that can reach this service's OpenAPI
//! document share a schema name.
//!
//! ## Why this exists
//!
//! utoipa keys `components.schemas` by the **bare type name**, and
//! `OpenApiRouter::routes` merges each route's schemas with a plain map
//! `extend` — so two types called `RevokeResponse` in two route modules do not
//! fail anything. The last one registered wins, and every `$ref` to the name
//! describes that one. When #1697 was filed, seven names collided this way and
//! the document was wrong, not just untidy:
//!
//! - `GET /v1/admin/passkeys` described `{consoleKeys: [...]}`, the console-key
//!   list that arrived in #1692 as a second `ListResponse`;
//! - `/auth/challenge` returns vta-sdk's `ChallengeResponse` and was described
//!   as the personhood challenge, a different type with the same name;
//! - five `RevokeResponse`s were all described as the endorsement one.
//!
//! `admin-ui/src/lib/wire.ts` is generated from that document, so a collision
//! ships a console whose types describe another endpoint — and `tsc` passes,
//! because generated types are self-consistent whether or not they describe the
//! daemon. It was found by eye, while consuming a generated alias; this census
//! makes the class a test failure instead.
//!
//! ## Why a source scan
//!
//! The collision is gone by the time anything could query it: the merged
//! document holds one schema per name and does not record which Rust type
//! produced it, and the per-route schema lists that *did* differ are consumed
//! inside `OpenApiRouter::routes`. So the definitions are read as text — the
//! same technique, for the same reason, as `openapi_response_census.rs`.
//!
//! ## What counts as the document's inputs
//!
//! This crate plus every workspace crate it depends on by path, read from its
//! own `Cargo.toml`: vta-sdk and vti-common put their wire types into this
//! document under their `openapi` features, and a vtc type named like one of
//! theirs collides exactly as two vtc types do. A clash is resolved with
//! `#[schema(as = DistinctName)]` on the service-side type, or, where the
//! service type is a copy of the dependency's, by deleting the copy.
//!
//! `vta-service/tests/openapi_schema_names.rs` holds the same rule for the VTA's
//! document.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[test]
fn every_schema_name_in_the_document_inputs_is_defined_once() {
    let mut defs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for krate in document_inputs() {
        for file in rust_sources(&krate.join("src")) {
            let src = std::fs::read_to_string(&file).expect("source is readable");
            let rel = file
                .strip_prefix(workspace_root())
                .unwrap_or(&file)
                .display()
                .to_string();
            for (name, line) in schema_names(&src) {
                defs.entry(name).or_default().push(format!("{rel}:{line}"));
            }
        }
    }

    let clashes: Vec<String> = defs
        .iter()
        .filter(|(_, at)| at.len() > 1)
        .map(|(name, at)| format!("  {name}\n      {}", at.join("\n      ")))
        .collect();

    assert!(
        clashes.is_empty(),
        "{} OpenAPI schema name(s) are defined by more than one type:\n\n{}\n\n\
         utoipa keys components by bare type name and the last registration wins, \
         so every `$ref` to a clashing name describes whichever type happened to be \
         registered last — and `admin-ui/src/lib/wire.ts` is generated from that. \
         Give the service-side type a distinct name with `#[schema(as = …)]`, or \
         delete it if it copies the dependency's type.",
        clashes.len(),
        clashes.join("\n")
    );

    // A scanner that finds nothing passes vacuously. The document has well
    // over a hundred named schemas; if the scan stops seeing them, say so.
    assert!(
        defs.len() > 100,
        "the scan found only {} schema names — the scanner has stopped recognising \
         `ToSchema` definitions, so the census above proves nothing",
        defs.len()
    );
}

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_dir()
        .parent()
        .expect("crate sits in the workspace")
        .to_path_buf()
}

/// This crate plus every workspace crate named under a (non-dev, non-build)
/// `dependencies` table with a `path = "../…"`.
fn document_inputs() -> Vec<PathBuf> {
    let manifest =
        std::fs::read_to_string(crate_dir().join("Cargo.toml")).expect("Cargo.toml is readable");
    let mut out = vec![crate_dir()];
    let mut in_deps = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_deps = line.ends_with("dependencies]")
                && !line.ends_with("dev-dependencies]")
                && !line.ends_with("build-dependencies]");
            continue;
        }
        if !in_deps {
            continue;
        }
        if let Some(at) = line.find("path = \"../") {
            let rest = &line[at + "path = \"../".len()..];
            let name = &rest[..rest.find('"').expect("closing quote")];
            let dir = workspace_root().join(name);
            if !out.contains(&dir) {
                out.push(dir);
            }
        }
    }
    assert!(
        out.iter().any(|d| d.ends_with("vta-sdk")),
        "vta-sdk not found among the path dependencies — the manifest parse is broken"
    );
    out
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The schema name and 1-based line of every `ToSchema` type in one file:
/// derived (`derive(…ToSchema…)`, including inside `cfg_attr`), honouring a
/// `#[schema(as = …)]` rename, or implemented by hand (`impl ToSchema for X`).
fn schema_names(src: &str) -> Vec<(String, usize)> {
    // Comment lines are dropped (blanked, to keep line numbers) so a doc
    // comment quoting `#[derive(ToSchema)]` is not read as a definition.
    let code: String = src
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let line_of = |at: usize| code[..at].matches('\n').count() + 1;
    let mut out = Vec::new();

    let mut at = 0;
    while let Some(found) = code[at..].find("derive(") {
        let open = at + found + "derive".len();
        at = open;
        let Some(close) = code[open..].find(')').map(|c| open + c) else {
            break;
        };
        if !code[open..close]
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|word| word == "ToSchema")
        {
            continue;
        }
        let Some((item, name)) = next_item_name(&code, close) else {
            continue;
        };
        let name = schema_as(&code[close..item]).unwrap_or(name);
        out.push((name, line_of(open)));
    }

    for prefix in ["impl ToSchema for ", "impl utoipa::ToSchema for "] {
        let mut at = 0;
        while let Some(found) = code[at..].find(prefix) {
            let start = at + found + prefix.len();
            at = start;
            let name = ident(&code[start..]);
            if !name.is_empty() {
                out.push((name, line_of(start)));
            }
        }
    }
    out
}

/// The next `struct`/`enum` after `from`: its byte offset and name.
fn next_item_name(code: &str, from: usize) -> Option<(usize, String)> {
    let mut at = from;
    loop {
        let rest = &code[at..];
        let (off, kw) = ["struct ", "enum "]
            .iter()
            .filter_map(|kw| rest.find(kw).map(|o| (o, *kw)))
            .min_by_key(|(o, _)| *o)?;
        let pos = at + off;
        let preceded_by_word = code[..pos]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !preceded_by_word {
            return Some((pos, ident(&code[pos + kw.len()..])));
        }
        at = pos + kw.len();
    }
}

/// The name a `#[schema(as = a::b::Name)]` gives the schema, as utoipa renders
/// it: path segments joined with `.`.
fn schema_as(attrs: &str) -> Option<String> {
    let at = attrs.find("schema(")?;
    let body = &attrs[at..];
    let body = &body[..body.find(")]").unwrap_or(body.len())];
    let as_at = body.match_indices("as").map(|(i, _)| i).find(|&i| {
        let before = body[..i].chars().next_back();
        let after = body[i + 2..].trim_start();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_') && after.starts_with('=')
    })?;
    let value = body[as_at + 2..].trim_start()[1..].trim_start();
    let path: String = value
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
        .collect();
    Some(path.replace("::", "."))
}

fn ident(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}
