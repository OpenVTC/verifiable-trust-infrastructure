//! Every production call site that touches the raw master seed is listed here,
//! with the reason it may.
//!
//! # What this is guarding
//!
//! Every key the VTA holds is a pure function of the seed and a derivation
//! path. So code that loads the seed, or builds a BIP-32 root from it, can
//! reach *every* key, not just the one it meant to. FTL-29904 and the holes
//! found beside it were all reachable-by-a-network-caller code doing exactly
//! that with an authorization check that asked the wrong question:
//! `keys/create` deriving at a caller-chosen path, `keys/derive-and-sign`
//! signing as any path, and vault signing loading a key a caller named.
//!
//! `vta_keys::custody` (and `vta_service::operations::key_custody` above it) is
//! the door that asks the right questions: whose context owns this path, does
//! this record's path lie in its context, is this key in the resource's scope.
//! The raw primitives (`load_seed_bytes`, `SeedStore::get`,
//! `ExtendedSigningKey::from_seed`) stay public because boot, setup, rotation,
//! backup and the offline CLIs need the whole seed. This census makes each use
//! a reviewed decision rather than a habit.
//!
//! # When it fails
//!
//! - **A count went up / a file appeared:** you added a raw seed access. If the
//!   caller is network-reachable, don't. Go through `key_custody` (or add a
//!   door there). If it is genuinely boot / setup / offline, add or bump the
//!   entry below with a reason that says why no caller-chosen path or key id
//!   can reach it.
//! - **A count went down:** thank you. Lower the entry so it cannot silently
//!   grow back.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `(file, raw call sites, why this file may touch the seed)`.
const ALLOWED: &[(&str, usize, &str)] = &[
    // ── The primitives and the custody doors themselves ──────────────────
    (
        "vta-keys/src/seeds.rs",
        1,
        "defines load_seed_bytes; its one call is the external store read inside it",
    ),
    (
        "vta-keys/src/custody.rs",
        2,
        "the custody door: loads the seed for an authorized record, holds the root privately",
    ),
    (
        "vta-service/src/operations/key_custody.rs",
        2,
        "the delegated-identity door: derives only after authorize_delegated_identity_path",
    ),
    (
        "vta-keys/src/derivation.rs",
        5,
        "derivation helpers taking a seed their caller already loaded; paths come from allocate_path under a caller-supplied base",
    ),
    (
        "vta-keys/src/lib.rs",
        5,
        "entity-key derivation helpers taking a caller-loaded seed at VTA-allocated bases",
    ),
    // ── Seed-wide operations, gated on instance authority ────────────────
    (
        "vta-service/src/operations/seeds.rs",
        2,
        "seed rotation: old and new seed to re-encrypt imported keys; gated by require_instance_authority",
    ),
    // ── Network-reachable, but no caller-chosen path or key id ───────────
    (
        "vta-service/src/operations/keys.rs",
        6,
        "create_key (path authorized by authorize_explicit_key_path or allocated under the context base), import_key, and the imported-key KEK in get_key_secret / get_key_secret_internal / sign_payload; derived keys go through derive_record_key",
    ),
    (
        "vta-service/src/operations/did_webvh/mod.rs",
        4,
        "imported-key KEK in load_key_as_secret, and fresh DID keys allocated under the target context's base (entity keys, sealed-transfer, pre-rotation)",
    ),
    (
        "vta-service/src/operations/did_webvh/update/keys.rs",
        4,
        "webvh update keys at allocate/peek paths under the DID's base, and re-derivation from a VTA-written WebvhKeyHandle",
    ),
    (
        "vta-service/src/operations/did_webvh/update/rotate.rs",
        2,
        "rotate-keys: replacement method keys at paths allocated under the DID's own context base; no caller-chosen path or key id",
    ),
    (
        "vta-service/src/operations/provision_integration/mint.rs",
        1,
        "integration DID keys minted at paths allocated under the target context's base",
    ),
    (
        "vta-service/src/did_key.rs",
        1,
        "did:key mint at a path allocated under the context's base",
    ),
    // ── Boot, setup, status, offline CLIs: no network caller ─────────────
    (
        "vta-service/src/server.rs",
        2,
        "boot: re-derives the VTA's own identity secrets from its own key record",
    ),
    (
        "vta-service/src/status.rs",
        2,
        "offline `vta status`: re-derives the VTA's own #key-0 to check it matches the DID document",
    ),
    (
        "vta-service/src/setup/from_toml.rs",
        2,
        "first-boot setup (no daemon running): mints the VTA's own keys",
    ),
    (
        "vta-service/src/main.rs",
        5,
        "offline operator commands, daemon stopped: apply a staged restore at boot, `vta auth sign-challenge`, and admin-credential reconstruction",
    ),
    (
        "vta-service/src/keys_cli.rs",
        2,
        "offline `vta keys` CLI, daemon stopped, operator on the host",
    ),
    (
        "vta-service/src/did_webvh.rs",
        2,
        "offline `vta did-webvh` CLI, daemon stopped, operator on the host",
    ),
    (
        "vta-tee/src/did_autogen.rs",
        1,
        "TEE first boot: autogenerates the VTA's own DID inside the enclave",
    ),
    (
        "vta-enclave/src/main.rs",
        1,
        "enclave boot, non-KMS fallback: applies a staged backup restore before anything reads the store",
    ),
];

/// The raw primitives. `seed_store.get()` is matched by receiver name, which is
/// how every call site in the workspace spells it.
const PATTERNS: &[&str] = &[
    "load_seed_bytes(",
    "ExtendedSigningKey::from_seed(",
    "seed_store.get()",
];

/// Crates whose production code can reach the seed, relative to the workspace.
const CRATES: &[&str] = &[
    "vta-service/src",
    "vta-keys/src",
    "vta-tee/src",
    "vta-enclave/src",
    "vta-backup/src",
    "vta-support/src",
];

#[test]
fn every_raw_seed_access_is_listed_with_its_reason() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    for krate in CRATES {
        let dir = workspace.join(krate);
        if !dir.exists() {
            continue;
        }
        for file in rust_files(&dir) {
            let rel = file
                .strip_prefix(workspace)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.ends_with("test_support.rs") || rel.contains("/test_support/") {
                continue;
            }
            let text = production_part(&std::fs::read_to_string(&file).unwrap());
            let n: usize = PATTERNS.iter().map(|p| count_calls(&text, p)).sum();
            if n > 0 {
                actual.insert(rel, n);
            }
        }
    }

    let allowed: BTreeMap<&str, usize> = ALLOWED.iter().map(|(f, n, _)| (*f, *n)).collect();
    let mut problems = Vec::new();
    for (file, n) in &actual {
        match allowed.get(file.as_str()) {
            None => problems.push(format!("  NEW   {file}: {n} raw seed access(es)")),
            Some(a) if n > a => problems.push(format!("  GREW  {file}: {a} -> {n}")),
            Some(a) if n < a => problems.push(format!("  SHRANK {file}: {a} -> {n} (lower it)")),
            _ => {}
        }
    }
    for (file, a) in &allowed {
        if !actual.contains_key(*file) {
            problems.push(format!("  GONE  {file}: {a} -> 0 (remove the entry)"));
        }
    }
    assert!(
        problems.is_empty(),
        "raw seed access census changed. Read the module documentation of \
         tests/key_custody_census.rs before updating ALLOWED:\n{}\n\ncurrent:\n{}",
        problems.join("\n"),
        actual
            .iter()
            .map(|(f, n)| format!("    (\"{f}\", {n}, \"\"),"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn every_allowed_entry_states_a_reason() {
    for (file, _, reason) in ALLOWED {
        assert!(
            reason.len() >= 20,
            "{file}: a raw seed access needs a reason a reviewer can check"
        );
    }
}

/// Source with `#[cfg(test)]` modules removed. Test code builds roots from
/// fixed seeds all the time, and none of it ships.
fn production_part(text: &str) -> String {
    let mut out = String::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "#[cfg(test)]"
            && lines
                .peek()
                .is_some_and(|next| next.trim_start().starts_with("mod "))
        {
            // Skip the module: track braces from its opening line.
            let mut depth = 0i32;
            let mut opened = false;
            for inner in lines.by_ref() {
                for c in inner.chars() {
                    match c {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if opened && depth <= 0 {
                    break;
                }
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Occurrences of `pattern` outside `//` comments.
fn count_calls(text: &str, pattern: &str) -> usize {
    text.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .map(|code| code.matches(pattern).count())
        .sum()
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}
