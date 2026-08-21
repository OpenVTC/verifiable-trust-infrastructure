//! The seam between what the **agent serializes** and what the **client
//! deserializes**, for the call sites where those are still two different
//! types.
//!
//! # Why this file exists
//!
//! `pnm contexts create` failed in production with `trust-task response decode:
//! missing field base_path` while every test was green, because three layers of
//! coverage each stopped one step short of the join:
//!
//! - The conformance harness (`vta-service`) checks the agent's response against
//!   the *published schema*. It passed — its witness correctly said `basePath`.
//! - The SDK's client tests check the client against a *hand-written mock*. They
//!   passed too — the mock said `base_path`, which the agent had stopped
//!   emitting.
//! - Nothing compared those two fixtures, so they disagreed for days.
//!
//! # Most of what this file used to hold is gone, and that is the point
//!
//! It opened with nine cases covering the types #1033 repaired with `serde`
//! aliases. #1035 then collapsed each of those onto the agent's own body type,
//! so the client and the agent no longer have separate structs to disagree
//! about. Serializing one of them and decoding it back would now assert that
//! `serde` round-trips a type through itself — true of every type everywhere,
//! and no longer a fact about this codebase. They were deleted rather than kept
//! as reassurance.
//!
//! What is left is the genuine article: response types that really are a
//! *different shape* from the agent's, by design.
//!
//! # What a failure here means
//!
//! A red test in this file is a *live outage* for the named CLI command against
//! any current agent — not a stylistic complaint. Fix the types; do not adjust
//! the test to agree with them.
//!
//! `trust_task_decode_census.rs` is what keeps this file honest: it refuses any
//! new client-private decode type that does not appear here.

// The decode targets under test live behind `client`; without it there is no
// client half of the seam to check.
#![cfg(feature = "client")]

use chrono::{TimeZone, Utc};

use vta_sdk::client::{AclEntryResponse, AclListResponse, ContextResponse, RenameKeyResponse};
use vta_sdk::protocols::acl_management::entry::AclEntry;
use vta_sdk::protocols::acl_management::list::ListAclResultBody;

/// Serialize what the agent returns, then decode it as the client does.
///
/// The panic message names the CLI surface that breaks, because that is the
/// fact a reader needs first — `missing field base_path` on its own sent a real
/// investigation to the network layer.
#[track_caller]
fn agent_to_client<S, C>(surface: &str, agent_body: &S) -> C
where
    S: serde::Serialize,
    C: serde::de::DeserializeOwned,
{
    let wire = serde_json::to_string(agent_body).expect("agent body must serialize");
    match serde_json::from_str::<C>(&wire) {
        Ok(decoded) => decoded,
        Err(e) => panic!(
            "{surface} is BROKEN against a current agent.\n\
             \n  agent emitted: {wire}\n  client decode: {e}\n\
             \n\
             The client's decode type disagrees with the body the agent \
             serializes. Fix the type in vta-sdk/src/client/types.rs — best by \
             re-exporting the agent's body (#1035) rather than mirroring it. Do \
             not change this test.",
            surface = surface,
        ),
    }
}

fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 19, 9, 0, 0).unwrap()
}

// ── ACL ─────────────────────────────────────────────────────────────
//
// The one family where two types is the right answer. `AclEntryResponse` is not
// a mirror of `AclEntry` — it renames `subject` to `did` and `scopes` to
// `allowed_contexts`, and converts RFC 3339 to the epoch seconds the rest of the
// CLI speaks. That conversion is the reason it exists, and the reason it cannot
// simply be re-exported the way the others were.
//
// Which also makes it the one that most needs checking: an adapter with real
// logic can be wrong in ways a mirror cannot.

/// A representative entry, with every optional member **set**.
///
/// A fixture that leaves optionals unset would serialize without them (they all
/// carry `skip_serializing_if`), and a member absent from the wire is exactly a
/// member this seam cannot check. `allowed_keys` is `Some(vec![])` on purpose:
/// `None` and `Some(∅)` are opposite grants on this type, and the empty vec is
/// the one that must survive as `"allowedKeys": []`.
fn agent_acl_entry() -> AclEntry {
    AclEntry {
        subject: "did:key:z6MkSubject".into(),
        role: "admin".into(),
        scopes: vec!["personal".into()],
        allowed_keys: Some(vec![]),
        label: Some("laptop".into()),
        created_at: Some(ts()),
        created_by: Some("did:key:z6MkAdmin".into()),
        updated_at: Some(ts()),
        updated_by: Some("did:key:z6MkAdmin".into()),
        expires_at: Some(ts()),
        step_up: None,
        approve: None,
    }
}

/// `pnm acl show` / `grant` / `update` / `change-role`.
///
/// These decode a `pub(crate)` `{ entry }` envelope, which a `tests/` file
/// cannot name — and which cannot drift anyway, its one member being
/// single-word. The seam that *can* drift is the entry inside it, so that is
/// what is asserted.
///
/// #1033's audit classified this pair safe by reading the attributes on both
/// types. That reading was right — and it is the same kind of reasoning that
/// classified `client/types.rs` as REST bodies, so it is a check now.
#[test]
fn acl_entry_decodes() {
    let got: AclEntryResponse =
        agent_to_client("pnm acl grant / show / update", &agent_acl_entry());
    assert_eq!(got.did, "did:key:z6MkSubject", "subject renames to did");
    assert_eq!(
        got.allowed_contexts,
        vec!["personal".to_string()],
        "scopes renames to allowed_contexts"
    );
    assert_eq!(
        got.allowed_keys,
        Some(vec![]),
        "Some(empty) is the narrowest grant and must not decode as None"
    );
    assert_eq!(got.label.as_deref(), Some("laptop"));
    assert_ne!(got.created_at, 0, "RFC 3339 must convert to epoch seconds");
    assert!(got.expires_at.is_some());
}

/// `pnm acl list`, including its elements.
#[test]
fn acl_list_decodes_including_its_elements() {
    let agent = ListAclResultBody {
        entries: vec![agent_acl_entry()],
        truncated: false,
        cursor: None,
        redacted_fields: vec![],
    };
    let got: AclListResponse = agent_to_client("pnm acl list", &agent);
    assert_eq!(got.entries.len(), 1, "the element must survive the decode");
    assert_eq!(got.entries[0].did, "did:key:z6MkSubject");
    assert_ne!(got.entries[0].created_at, 0);
}

// ── The other direction ─────────────────────────────────────────────

/// An agent from **before** #1000 still decodes.
///
/// camelCase is what a current agent sends; snake_case is what one running an
/// older release sends, and the `alias` attributes on the agent's bodies are
/// what accept it. The fixtures in `client_rest.rs` used to be the only thing
/// covering that half, and re-cutting them to camelCase in #1033 would have
/// retired the coverage silently — the failure mode #1019 called out when it
/// annotated the last such case.
///
/// So it is asserted here, where the name says why it exists. This is the one
/// place a JSON literal is correct in this file: no current type *serializes*
/// the retired spelling, so there is nothing to derive it from.
///
/// Still meaningful after #1035 — arguably more so. These now exercise the
/// aliases on the **agent's** types, which is where every consumer's backward
/// compatibility comes from, not just this client's.
#[test]
fn a_legacy_agent_snake_case_response_still_decodes() {
    let legacy = serde_json::json!({
        "id": "personal",
        "name": "Personal",
        "did": null,
        "description": null,
        "base_path": "m/26'/2'/0'",
        "created_at": "2026-08-19T09:00:00Z",
        "updated_at": "2026-08-19T09:00:00Z"
    });
    let got: ContextResponse = serde_json::from_value(legacy)
        .expect("a pre-#1000 agent's snake_case response must still decode");
    assert_eq!(got.base_path, "m/26'/2'/0'");
    assert_eq!(got.created_at, ts());

    let legacy_key = serde_json::json!({ "key_id": "key-1", "updated_at": "2026-08-19T09:00:00Z" });
    let got: RenameKeyResponse =
        serde_json::from_value(legacy_key).expect("legacy key body must still decode");
    assert_eq!(got.key_id, "key-1");
}

// ── The exclusion, recorded ─────────────────────────────────────────

/// Why almost every Trust-Task call site is absent from this file.
///
/// They decode the **same struct** the agent serializes, so a casing change
/// moves both ends at once and this class of drift is structurally impossible —
/// not merely untested. After #1035 that is true of nearly all of them, the ACL
/// adapter above being the deliberate exception.
///
/// This exists so a reader counting call sites finds the reason here rather than
/// assuming the coverage was simply incomplete. If a future change gives one of
/// those sites its own decode type, the census will demand it appear here.
#[test]
fn same_type_sites_cannot_drift() {
    // `ContextResponse` IS the agent's body type now, not a copy of it. Naming
    // both spellings in one signature only compiles if they are the same type,
    // which is the property #1035 established.
    fn assert_same_type(
        _: vta_sdk::protocols::context_management::create::CreateContextResultBody,
    ) {
    }
    let _: fn(ContextResponse) = assert_same_type;
}
