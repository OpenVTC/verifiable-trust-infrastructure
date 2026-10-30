//! VTI's Trust Task wire types, generated at build time from the versions VTI
//! pins, and one Type URI index over all of them.
//!
//! The Trust Task specifications are normative; `trust-tasks-build` turns each
//! version a `trust-tasks.lock` pins into the same `Payload` / `Response` types
//! the deprecated prebuilt `trust_tasks_rs::specs` modules carried, at the same
//! module paths (`vtc::members::list::v0_2`). The versions live in four
//! generated crates, so no consumer compiles one huge unit and the light ones
//! compile only what they use:
//!
//! | Crate | Families |
//! |---|---|
//! | `vti-specs-rooms` | `rooms/*` — alone, so `vti-rooms-wasm` builds nothing else |
//! | `vti-specs-vta` | `vta/*` |
//! | `vti-specs-vtc` | `vtc/*` |
//! | `vti-specs-core` | every other family VTI speaks |
//!
//! Each version is generated in exactly one of them, so a type is the same type
//! everywhere in the workspace. This crate re-exports every family at the path
//! `trust_tasks_rs::specs` gave it — `vta_sdk::specs` re-exports this crate —
//! and merges the four indexes in [`schema_index`].
//!
//! To pin a new version: `trust-tasks -C vti-specs-<crate> add <slug>/<M.N>`,
//! then commit `trust-tasks.toml`, `trust-tasks.lock` and the bundle under
//! `trust-tasks/` (the workspace CLAUDE.md has the details).
//!
//! The framework's own specifications (`trust-task-error`,
//! `trust-task-discovery`, …) cannot be locked: they stay in `trust_tasks_rs`.

#![forbid(unsafe_code)]

pub use vti_specs_core::{
    acl, audit, auth, backup, config, consent, credential_exchange, device, did_management,
    external, git_ns, git_trust, governance, keys, messaging, persona, policy, provision, push,
    registry, task_consent, vault, vetting, voting, witness,
};
pub use vti_specs_rooms::rooms;
pub use vti_specs_vta::vta;
pub use vti_specs_vtc::vtc;

// The framework's own specifications cannot be pinned: the runtime always
// carries them, and they are not deprecated. Re-exported so this crate is a
// complete drop-in for `trust_tasks_rs::specs`.
pub use trust_tasks_rs::specs::{
    trust_ceremony_receipt, trust_task_control, trust_task_discovery, trust_task_next_step,
    trust_task_ok,
};

/// Every locked version's `extends` declaration (SPEC §5.2), across the four
/// generated crates.
///
/// Nothing in VTI routes a newer version to an older handler today, so nothing
/// calls this; it is here so that turning forward-minor routing on is one call
/// at start-up rather than four.
pub fn declare_extends() {
    vti_specs_core::declare_extends();
    vti_specs_rooms::declare_extends();
    vti_specs_vta::declare_extends();
    vti_specs_vtc::declare_extends();
}

/// Type URI → payload schema and consumer policy, for exactly the versions VTI
/// pins: a drop-in for `trust_tasks_rs::schema_index`.
///
/// Each function answers as its namesake in `trust_tasks_rs::schema_index`
/// does — a bare Type URI for the request, one suffixed `#response` for the
/// response. A framework specification (`trust-task-*`, `trust-ceremony-*`)
/// is answered by `trust_tasks_rs::schema_index`, which always carries them.
///
/// **`None` means "not pinned", and is a real answer.** A caller that reads it
/// as "no schema, skip validation" fails open for exactly the versions VTI has
/// not pinned — which is why the census tests in `vta-service` and
/// `vtc-service` hold every dispatched and sent Type URI to [`is_pinned`].
pub mod schema_index {
    use trust_tasks_rs::type_index::{self, IndexEntry};
    use trust_tasks_rs::{DeclaredErrorCode, SpecPolicy};

    /// The four generated crates' tables. Disjoint: each version is generated
    /// in exactly one crate.
    pub static INDEXES: &[&[IndexEntry]] = &[
        vti_specs_core::schema_index::INDEX,
        vti_specs_rooms::schema_index::INDEX,
        vti_specs_vta::schema_index::INDEX,
        vti_specs_vtc::schema_index::INDEX,
    ];

    /// Every pinned Type URI — each version's bare request URI and its
    /// `#response` URI where it defines one.
    pub fn type_uris() -> impl Iterator<Item = &'static str> {
        INDEXES.iter().flat_map(|t| t.iter().map(|e| e.type_uri))
    }

    /// The index entry for `type_uri`, or `None` when no pinned version has it.
    /// Framework specifications are not here (see the module docs).
    pub fn entry(type_uri: &str) -> Option<&'static IndexEntry> {
        type_index::lookup(INDEXES, type_uri)
    }

    /// Whether `type_uri` (bare, or `#response`) is a version VTI pins.
    pub fn is_pinned(type_uri: &str) -> bool {
        entry(type_uri).is_some()
    }

    /// A framework specification — not lockable, carried by the runtime.
    fn is_framework(type_uri: &str) -> bool {
        type_uri
            .strip_prefix("https://trusttasks.org/spec/")
            .is_some_and(|rest| {
                rest.starts_with("trust-task-") || rest.starts_with("trust-ceremony-")
            })
    }

    /// The payload schema for `type_uri`. See
    /// `trust_tasks_rs::schema_index::schema_for`.
    pub fn schema_for(type_uri: &str) -> Option<&'static str> {
        if is_framework(type_uri) {
            return trust_tasks_rs::schema_index::schema_for(type_uri);
        }
        entry(type_uri).and_then(|e| e.schema)
    }

    /// The consumer policy (SPEC §7.2) of the version behind the bare request
    /// Type URI `type_uri`. See `trust_tasks_rs::schema_index::spec_policy_for`.
    pub fn spec_policy_for(type_uri: &str) -> Option<SpecPolicy> {
        if is_framework(type_uri) {
            return trust_tasks_rs::schema_index::spec_policy_for(type_uri);
        }
        entry(type_uri).and_then(|e| e.policy)
    }

    /// The error codes the version behind the bare request Type URI declares,
    /// `Some(&[])` when it declares none. See
    /// `trust_tasks_rs::schema_index::error_codes_for`.
    pub fn error_codes_for(type_uri: &str) -> Option<&'static [DeclaredErrorCode]> {
        if is_framework(type_uri) {
            return trust_tasks_rs::schema_index::error_codes_for(type_uri);
        }
        entry(type_uri).and_then(|e| e.error_codes)
    }

    /// The document size bound the version behind `type_uri` declares for that
    /// side. See `trust_tasks_rs::schema_index::max_document_bytes_for`.
    pub fn max_document_bytes_for(type_uri: &str) -> Option<usize> {
        if is_framework(type_uri) {
            return trust_tasks_rs::schema_index::max_document_bytes_for(type_uri);
        }
        entry(type_uri).and_then(|e| e.max_document_bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashSet;

        /// Each version is generated in exactly one crate, so no URI may sit in
        /// two tables: `lookup` would answer from the first and hide the second.
        #[test]
        fn the_generated_tables_are_disjoint() {
            let mut seen = HashSet::new();
            for uri in type_uris() {
                assert!(seen.insert(uri), "{uri} is generated in two crates");
            }
        }

        #[test]
        fn a_pinned_version_answers_and_an_unpinned_one_does_not() {
            let uri =
                <crate::vta::contexts::delete::v1_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            assert!(is_pinned(uri));
            assert!(spec_policy_for(uri).is_some());
            assert!(schema_for(uri).is_some());
            assert!(!is_pinned(
                "https://trusttasks.org/spec/vta/contexts/delete/9.9"
            ));
            assert!(schema_for("https://trusttasks.org/spec/vta/contexts/delete/9.9").is_none());
        }

        #[test]
        fn a_framework_specification_falls_through_to_the_runtime() {
            let uri = "https://trusttasks.org/spec/trust-task-discovery/0.3";
            assert!(!is_pinned(uri));
            assert_eq!(
                spec_policy_for(uri),
                trust_tasks_rs::schema_index::spec_policy_for(uri)
            );
        }
    }
}
