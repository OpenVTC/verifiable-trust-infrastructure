//! Every workspace member must be copied into the enclave image.
//!
//! `Dockerfile.nitro` copies a hand-maintained list of member directories rather than
//! `COPY . .`, so that an edit to `deploy/nitro/config.toml` does not invalidate the Rust
//! build layer. The cost of that trade is this list, and a member missing from it is not a
//! missing file — cargo-chef's skeleton stub stays in place, and the build fails six
//! minutes later with
//!
//! ```text
//! error: failed to select a version for the requirement `vti-common = "^0.0.1"`
//! required by package `room-host v0.0.1 (/build/room-host)`
//! ```
//!
//! which says nothing about the actual cause. That is how the `vti-rooms` and `room-host`
//! members broke the nitro image: both were added to `members`, neither to the COPY list,
//! and every other check in CI stayed green.
//!
//! This turns that into a one-second failure that names the line to add. It is a census in
//! the same sense as the keyspace and `retry_safety` censuses — a list that must not drift
//! from the thing it describes, pinned by a test rather than by remembering.
//!
//! `Dockerfile` (the ordinary image) uses `COPY . .` and needs no equivalent.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The workspace root, from this crate's manifest directory (`tests/e2e`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tests/e2e is two levels below the workspace root")
        .to_path_buf()
}

/// Workspace members, reduced to the top-level directory the Dockerfile would copy.
///
/// `tests/e2e` is copied as `tests/`, so a member path is truncated at its first
/// component — which is what the COPY list actually names.
fn members() -> BTreeSet<String> {
    let manifest = std::fs::read_to_string(workspace_root().join("Cargo.toml"))
        .expect("read the workspace manifest");
    let list = manifest
        .split_once("members = [")
        .expect("the workspace manifest declares members")
        .1
        .split_once(']')
        .expect("the members array is closed")
        .0;

    list.lines()
        .filter_map(|line| {
            let line = line.trim().trim_end_matches(',');
            let inner = line.strip_prefix('"')?.strip_suffix('"')?;
            inner.split('/').next().map(str::to_string)
        })
        .collect()
}

/// Directories `Dockerfile.nitro` copies, from its `COPY <dir>/ <dir>/` lines.
fn copied() -> BTreeSet<String> {
    let dockerfile = std::fs::read_to_string(workspace_root().join("Dockerfile.nitro"))
        .expect("read Dockerfile.nitro");

    dockerfile
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("COPY ")?;
            // `COPY --from=…` is a stage copy, not a source directory.
            if rest.starts_with("--") {
                return None;
            }
            let first = rest.split_whitespace().next()?;
            first.strip_suffix('/').map(str::to_string)
        })
        .collect()
}

#[test]
fn every_workspace_member_is_copied_into_the_enclave_image() {
    let missing: Vec<_> = members().difference(&copied()).cloned().collect();

    assert!(
        missing.is_empty(),
        "these workspace members are not copied into the nitro image, so cargo-chef's \
         0.0.1 skeleton stub survives into the real build and `cargo build -p vta-enclave` \
         fails to resolve their path dependencies:\n\n{}\n\nAdd a line for each to \
         Dockerfile.nitro's source-copy block:\n\n{}\n",
        missing.join(", "),
        missing
            .iter()
            .map(|m| format!("COPY {m}/ {m}/"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// The reverse drift: a directory copied after the member that needed it is gone. Harmless
/// to the build, but it invalidates the layer for a path nothing reads, which is the exact
/// cost the hand-maintained list exists to avoid paying.
#[test]
fn nothing_is_copied_that_is_no_longer_a_member() {
    let stale: Vec<_> = copied().difference(&members()).cloned().collect();

    assert!(
        stale.is_empty(),
        "Dockerfile.nitro copies directories that are not workspace members any more: {}. \
         Remove those COPY lines — they invalidate the build layer for sources nothing \
         compiles.",
        stale.join(", "),
    );
}
