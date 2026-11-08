//! Every Type URI this workspace serves, sends or names as a `TASK_*` constant
//! is a version `vti-specs` pins — or a listed, explained exception.
//!
//! The index `vti_specs::schema_index` answers only for the versions the
//! `vti-specs-*` crates' `trust-tasks.lock` files pin. A Type URI that is not
//! pinned answers `None`, and every gate that reads `None` as "no schema, skip
//! validation" (`validate_payload`, `spec_policy_for`, the size bounds) then
//! fails *open* for it — silently. A wire type built from a generated
//! `Payload::TYPE_URI` cannot be unpinned (it would not compile); a Type URI
//! written as a string can. This census holds the string ones.
//!
//! Three sources, because no one of them sees every string:
//!
//! 1. What this VTA dispatches — the dispatch table, the REST-routed set and
//!    the feature-gated allowlist (the sets the reverse parity harness reads).
//! 2. Every `TASK_*` constant in `vta_sdk::trust_tasks`, read from the source
//!    so a constant missing from `ALL_URIS` is still counted.
//! 3. Every string constant holding a `trusttasks.org/spec/<slug>/<M.N>` URI in the non-test
//!    source of every workspace member: the strings this workspace sends.
//!
//! The VTC's dispatched set has its own census in `vtc-service`
//! (`trust_tasks::spec_pin_census`), because this crate cannot see it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use vti_specs::schema_index;

/// String Type URIs, found by the source scan, that are not pinned on purpose
/// (an entry covers its `#response` URI too). Each says why. A URI here must still be found by the scan and must not be
/// pinned, so the list can only shrink.
const NOT_PINNED: &[(&str, &str)] = &[
    (
        "https://trusttasks.org/spec/provision/integration/0.1",
        "historical wire form `ProvisionSpecVersion::V0_1` still names (public API); never sent — `CURRENT` is 0.3",
    ),
    (
        "https://trusttasks.org/spec/provision/integration/0.2",
        "historical wire form `ProvisionSpecVersion::V0_2` still names (public API); never sent — `CURRENT` is 0.3",
    ),
    (
        "https://trusttasks.org/spec/git-ns/right/grant/0.1",
        "the `framework` label a projected right carries (git_ns::projection::FRAMEWORK), not a task this workspace sends or serves",
    ),
];

fn is_framework(uri: &str) -> bool {
    uri.strip_prefix("https://trusttasks.org/spec/")
        .is_some_and(|rest| rest.starts_with("trust-task-") || rest.starts_with("trust-ceremony-"))
}

/// Pinned, as itself — a `#response` URI is pinned only if the version
/// defines a response.
fn pinned(uri: &str) -> bool {
    schema_index::is_pinned(uri)
}

#[test]
fn every_dispatched_uri_is_pinned_or_tracked_debt() {
    let mut served: BTreeSet<&str> = super::dispatched_uris().into_iter().collect();
    served.extend(super::REST_ROUTED);
    served.extend(super::KNOWN_FEATURE_GATED_URIS);

    let unpinned: Vec<&str> = served
        .iter()
        .copied()
        .filter(|uri| {
            !is_framework(uri) && !pinned(uri) && !super::UNSPECCED_DISPATCHED_URIS.contains(uri)
        })
        .collect();
    assert!(
        unpinned.is_empty(),
        "this VTA serves Type URIs no `vti-specs-*` crate pins, so the dispatch \
         spine would validate nothing for them:\n  {}\n\n\
         Pin each with `trust-tasks -C vti-specs-<crate> add <slug>/<M.N>` and \
         commit the lock and the bundle (CLAUDE.md, \"Pinning a task version\").",
        unpinned.join("\n  ")
    );
    for uri in super::UNSPECCED_DISPATCHED_URIS {
        assert!(
            !pinned(uri),
            "`{uri}` is pinned now — remove it from UNSPECCED_DISPATCHED_URIS"
        );
    }
}

/// Every `pub const TASK_*: &str = "…"` in `vta_sdk::trust_tasks`.
fn task_constants() -> BTreeMap<String, String> {
    let src = include_str!("../../../vta-sdk/src/trust_tasks.rs");
    string_constants(src)
        .into_iter()
        .filter(|(name, _)| name.starts_with("TASK_"))
        .collect()
}

/// `const NAME: &str = "value"` (or `&'static str`), every one in `src`, as
/// `(NAME, value)`. Written out rather than with a regex crate: this crate has
/// none, and the grammar is small.
fn string_constants(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("const ") {
        rest = &rest[at + "const ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let after = rest[name.len()..].trim_start();
        let Some(after) = after.strip_prefix(':') else {
            continue;
        };
        let after = after.trim_start();
        let Some(after) = after.strip_prefix('&') else {
            continue;
        };
        let after = after.trim_start();
        let after = after.strip_prefix("'static").unwrap_or(after).trim_start();
        let Some(after) = after.strip_prefix("str") else {
            continue;
        };
        let Some(after) = after.trim_start().strip_prefix('=') else {
            continue;
        };
        let Some(after) = after.trim_start().strip_prefix('"') else {
            continue;
        };
        let Some(end) = after.find('"') else {
            continue;
        };
        out.push((name, after[..end].to_string()));
    }
    out
}

/// A Type URI: `https://trusttasks.org/spec/<slug>/<M.N>`, optionally
/// `#response`. A prefix (`…/spec/vtc/`) or a `_shared` body type is not one.
fn is_type_uri(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://trusttasks.org/spec/") else {
        return false;
    };
    let rest = rest.strip_suffix("#response").unwrap_or(rest);
    let Some((slug, version)) = rest.rsplit_once('/') else {
        return false;
    };
    let mut parts = version.split('.');
    let numeric =
        |p: Option<&str>| p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    !slug.is_empty()
        && !slug.contains("/_")
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_none()
}

/// Where a file's test module starts, if it has one.
fn test_module_start(text: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = text[from..].find("#[cfg(test)]") {
        let start = from + at;
        let after = text[start + "#[cfg(test)]".len()..].trim_start();
        let after = after
            .strip_prefix("pub(crate)")
            .or_else(|| after.strip_prefix("pub(super)"))
            .or_else(|| after.strip_prefix("pub"))
            .unwrap_or(after)
            .trim_start();
        if after.starts_with("mod ") {
            return Some(start);
        }
        from = start + 1;
    }
    None
}

#[test]
fn every_task_constant_is_pinned_or_tracked_debt() {
    // The constants written as a string literal, read from the source so one
    // missing from `ALL_URIS` still counts; the rest are a generated
    // `Payload::TYPE_URI`, pinned by construction, and `ALL_URIS` carries
    // their values.
    let literal = task_constants();
    assert!(
        literal.len() > 150,
        "found {} TASK_* string constants — the scan is broken, not the code",
        literal.len()
    );
    let mut all: BTreeMap<String, String> = literal;
    for uri in vta_sdk::trust_tasks::ALL_URIS {
        all.entry(format!("ALL_URIS[{uri}]"))
            .or_insert_with(|| uri.to_string());
    }
    let unpinned: Vec<String> = all
        .iter()
        .filter(|(_, uri)| {
            !is_framework(uri)
                && !pinned(uri)
                && !super::UNSPECCED_DISPATCHED_URIS.contains(&uri.as_str())
        })
        .map(|(name, uri)| format!("{name} = {uri}"))
        .collect();
    assert!(
        unpinned.is_empty(),
        "TASK_* constants name versions no `vti-specs-*` crate pins:\n  {}\n\n\
         Pin each with `trust-tasks -C vti-specs-<crate> add <slug>/<M.N>`.",
        unpinned.join("\n  ")
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// The workspace members, from the root manifest's `members` list.
fn members(root: &Path) -> Vec<PathBuf> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root Cargo.toml");
    let start = manifest.find("\nmembers = [").expect("a members list");
    let end = start
        + manifest[start..]
            .find("\n]")
            .expect("the end of the members list");
    manifest[start..end]
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('"'))
        .filter_map(|l| l.split('"').nth(1))
        .map(|m| root.join(m))
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every Type URI constant (see [`is_type_uri`]) outside a file's test
/// module, as `uri -> ["path:NAME", …]`. The `#response` fragment is kept: a
/// response URI is pinned only when the version defines a response.
fn sent_constants() -> BTreeMap<String, Vec<String>> {
    let root = workspace_root();
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for member in members(&root) {
        let mut files = Vec::new();
        rust_files(&member.join("src"), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            let text = &text[..test_module_start(&text).unwrap_or(text.len())];
            let rel = file
                .strip_prefix(&root)
                .unwrap_or(&file)
                .display()
                .to_string();
            for (name, value) in string_constants(text) {
                if is_type_uri(&value) {
                    found
                        .entry(value)
                        .or_default()
                        .push(format!("{rel}:{name}"));
                }
            }
        }
    }
    found
}

#[test]
fn every_type_uri_constant_in_the_workspace_is_pinned_or_listed() {
    let found = sent_constants();
    assert!(
        found.len() > 200,
        "found {} Type URI constants — the scan is broken, not the code",
        found.len()
    );
    let listed: BTreeSet<&str> = NOT_PINNED.iter().map(|(uri, _)| *uri).collect();
    let unpinned: Vec<String> = found
        .iter()
        .filter(|(uri, _)| {
            !is_framework(uri)
                && !pinned(uri)
                && !listed.contains(uri.trim_end_matches("#response"))
                && !super::UNSPECCED_DISPATCHED_URIS.contains(&uri.as_str())
        })
        .map(|(uri, at)| format!("{uri}  ({})", at.join(", ")))
        .collect();
    assert!(
        unpinned.is_empty(),
        "these Type URI constants name versions no `vti-specs-*` crate pins:\n  {}\n\n\
         Pin a version this workspace sends or serves with \
         `trust-tasks -C vti-specs-<crate> add <slug>/<M.N>`; a string that is \
         not a task this workspace speaks goes in NOT_PINNED with its reason.",
        unpinned.join("\n  ")
    );
    for (uri, reason) in NOT_PINNED {
        assert!(
            !pinned(uri),
            "`{uri}` is pinned now — remove it from NOT_PINNED ({reason})"
        );
        assert!(
            found.contains_key(*uri),
            "`{uri}` is in NOT_PINNED but no constant names it any more — remove the stale entry"
        );
    }
}
