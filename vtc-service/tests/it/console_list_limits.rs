//! The admin console's pinned listing page-size maxima agree with the
//! specifications.
//!
//! A listing's specification caps its `limit` with a JSON Schema `maximum`,
//! and the spine refuses a document over it. The console has no schema
//! package, so it pins the maxima it relies on in
//! `admin-ui/src/lib/list-limits.json`; its vitest census
//! (`list-limits.test.ts`) holds every page size it sends to that table, and
//! its signer refuses an over-limit page before signing. This test is the
//! other half: the table must say what `trust_tasks_rs::schema_index` says, and
//! must cover every listing the console names whose schema caps `limit`. The
//! admission-criteria page asked for 200 against a maximum of 50 and read
//! nothing (#1921); with the table drifting from the schemas, the census would
//! check against the wrong number.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

const TABLE: &str = include_str!("../../admin-ui/src/lib/list-limits.json");

/// The `limit` maximum `type_uri`'s payload schema declares, if any.
fn schema_maximum(type_uri: &str) -> Option<u64> {
    let schema: Value = serde_json::from_str(trust_tasks_rs::schema_index::schema_for(type_uri)?)
        .expect("a generated schema is JSON");
    schema
        .pointer("/properties/limit/maximum")
        .and_then(Value::as_u64)
}

/// Every Trust Task type URI written in the console's (non-test) source.
fn console_type_uris() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("admin-ui/src is readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let source = name.ends_with(".ts") || name.ends_with(".tsx");
            if !source || name.contains(".test.") || name == "wire.ts" {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source is UTF-8");
            let mut rest = text.as_str();
            while let Some(at) = rest.find("https://trusttasks.org/spec/") {
                let tail = &rest[at..];
                let end = tail
                    .find(|c: char| !(c.is_ascii_alphanumeric() || "/:._-".contains(c)))
                    .unwrap_or(tail.len());
                out.push(tail[..end].to_string());
                rest = &tail[end..];
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("admin-ui/src"),
        &mut out,
    );
    out.sort();
    out.dedup();
    out
}

#[test]
fn console_list_limits_match_the_specifications() {
    let table: BTreeMap<String, u64> =
        serde_json::from_str(TABLE).expect("list-limits.json is a map of URI to maximum");
    assert!(!table.is_empty(), "the console pins no listing maxima");
    for (uri, pinned) in &table {
        let spec = schema_maximum(uri)
            .unwrap_or_else(|| panic!("{uri} is pinned but its schema declares no limit maximum"));
        assert_eq!(
            *pinned, spec,
            "list-limits.json pins {uri} at {pinned}; its specification says {spec}"
        );
    }
}

#[test]
fn console_list_limits_cover_every_listing_the_console_names() {
    let table: BTreeMap<String, u64> = serde_json::from_str(TABLE).expect("list-limits.json");
    let uris = console_type_uris();
    assert!(
        uris.len() > 20,
        "found only {} type URIs in the console — is the walk looking in the right place?",
        uris.len()
    );
    let missing: Vec<String> = uris
        .iter()
        .filter_map(|uri| {
            let max = schema_maximum(uri)?;
            (!table.contains_key(uri)).then(|| format!("{uri} (maximum {max})"))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "the console names listings whose `limit` is capped but which \
         admin-ui/src/lib/list-limits.json does not pin: {missing:#?}"
    );
}
