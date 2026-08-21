//! The seam nothing tested: does what the **agent serializes** decode into what
//! the **client deserializes**?
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
//! Both fixtures were hand-written, and only one was maintained. This file takes
//! the fixtures out of the loop: it constructs the **agent's own body type**,
//! serializes it exactly as the agent would, and requires the **client's own
//! decode type** to accept the bytes. No JSON literal appears anywhere below, so
//! there is no third spelling to drift.
//!
//! # What a failure here means
//!
//! A red test in this file is a *live outage* for the named CLI command against
//! any current agent — not a stylistic complaint. Fix the types; do not adjust
//! the test to agree with them.
//!
//! # Scope, stated honestly
//!
//! This covers the 11 Trust-Task call sites whose client decode type differs
//! from the agent's serialize type (all in `client/types.rs`). The other 50
//! decode the *same* struct both ends and cannot drift this way — that is a
//! property of the type graph, and `same_type_sites_cannot_drift` below records
//! why they are excluded rather than leaving the omission to look like an
//! oversight.

// The decode targets under test live behind `client`; without it there is no
// client half of the seam to check.
#![cfg(feature = "client")]

use chrono::{TimeZone, Utc};

use vta_sdk::client::{
    AclEntryResponse, AclListResponse, ContextListResponse, ContextResponse, GetKeySecretResponse,
    InvalidateKeyResponse, ListSeedsResponse, RenameKeyResponse, RotateSeedResponse, SignResponse,
};
use vta_sdk::keys::{KeyStatus, KeyType};
use vta_sdk::protocols::acl_management::entry::AclEntry;
use vta_sdk::protocols::acl_management::list::ListAclResultBody;
use vta_sdk::protocols::context_management::create::CreateContextResultBody;
use vta_sdk::protocols::context_management::list::ListContextsResultBody;
use vta_sdk::protocols::key_management::rename::RenameKeyResultBody;
use vta_sdk::protocols::key_management::revoke::RevokeKeyResultBody;
use vta_sdk::protocols::key_management::secret::GetKeySecretResultBody;
use vta_sdk::protocols::key_management::sign::{SignAlgorithm, SignResultBody};
use vta_sdk::protocols::seed_management::list::{ListSeedsResultBody, SeedInfo};
use vta_sdk::protocols::seed_management::rotate::RotateSeedResultBody;

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
             serializes. Add the missing `#[serde(alias = \"...\")]` in \
             vta-sdk/src/client/types.rs — do not change this test.",
            surface = surface,
        ),
    }
}

fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 19, 9, 0, 0).unwrap()
}

fn agent_context() -> CreateContextResultBody {
    CreateContextResultBody {
        id: "personal".into(),
        name: "Personal".into(),
        did: None,
        description: None,
        parent: None,
        base_path: "m/26'/2'/0'".into(),
        created_at: ts(),
        updated_at: ts(),
    }
}

// ── Contexts ────────────────────────────────────────────────────────

/// `pnm contexts create` — the one a user actually hit.
#[test]
fn contexts_create_decodes() {
    let got: ContextResponse = agent_to_client("pnm contexts create", &agent_context());
    assert_eq!(got.base_path, "m/26'/2'/0'");
    assert_eq!(got.created_at, ts());
    assert_eq!(got.updated_at, ts());
}

/// `contexts/get` and `contexts/update{,-did}` return the same body type, so one
/// case covers the decode for all three call sites.
#[test]
fn contexts_get_and_update_decode() {
    let got: ContextResponse = agent_to_client("pnm contexts show / update", &agent_context());
    assert_eq!(got.id, "personal");
}

/// `pnm contexts list` — the nested case. The outer struct has only a
/// single-word member, so the break lives one level down; decoding the outer
/// alone would pass while the element still failed.
#[test]
fn contexts_list_decodes_including_its_elements() {
    let agent = ListContextsResultBody {
        contexts: vec![agent_context()],
    };
    let got: ContextListResponse = agent_to_client("pnm contexts list", &agent);
    assert_eq!(got.contexts.len(), 1, "the element must survive the decode");
    assert_eq!(got.contexts[0].base_path, "m/26'/2'/0'");
}

// ── Keys ────────────────────────────────────────────────────────────

#[test]
fn keys_sign_decodes() {
    let agent = SignResultBody {
        key_id: "key-1".into(),
        signature: "z3sig".into(),
        algorithm: SignAlgorithm::EdDSA,
    };
    let got: SignResponse = agent_to_client("pnm keys sign", &agent);
    assert_eq!(got.key_id, "key-1");
}

#[test]
fn keys_rename_decodes() {
    let agent = RenameKeyResultBody {
        key_id: "key-1".into(),
        updated_at: ts(),
    };
    let got: RenameKeyResponse = agent_to_client("pnm keys rename", &agent);
    assert_eq!(got.key_id, "key-1");
    assert_eq!(got.updated_at, ts());
}

#[test]
fn keys_revoke_decodes() {
    let agent = RevokeKeyResultBody {
        key_id: "key-1".into(),
        status: KeyStatus::Revoked,
        updated_at: ts(),
    };
    let got: InvalidateKeyResponse = agent_to_client("pnm keys revoke", &agent);
    assert_eq!(got.key_id, "key-1");
    assert_eq!(got.updated_at, ts());
}

#[test]
fn keys_get_secret_decodes() {
    let agent = GetKeySecretResultBody {
        key_id: "key-1".into(),
        key_type: KeyType::Ed25519,
        public_key_multibase: "z6Mkpub".into(),
        private_key_multibase: "z3priv".into(),
    };
    let got: GetKeySecretResponse = agent_to_client("pnm keys export-secret", &agent);
    assert_eq!(got.key_id, "key-1");
    assert_eq!(got.public_key_multibase, "z6Mkpub");
    assert_eq!(got.private_key_multibase, "z3priv");
}

// ── Seeds ───────────────────────────────────────────────────────────

#[test]
fn seeds_rotate_decodes() {
    let agent = RotateSeedResultBody {
        previous_seed_id: 1,
        new_seed_id: 2,
    };
    let got: RotateSeedResponse = agent_to_client("pnm seeds rotate", &agent);
    assert_eq!(got.previous_seed_id, 1);
    assert_eq!(got.new_seed_id, 2);
}

/// `seeds/list` is the asymmetric one: the outer body carries `rename_all`, the
/// nested `SeedInfo` does not. Asserting the nested timestamp as well as the
/// outer id is what keeps this honest if `SeedInfo` is folded later.
#[test]
fn seeds_list_decodes_including_its_elements() {
    let agent = ListSeedsResultBody {
        seeds: vec![SeedInfo {
            id: 1,
            status: "active".into(),
            created_at: ts(),
            retired_at: None,
        }],
        active_seed_id: 1,
    };
    let got: ListSeedsResponse = agent_to_client("pnm seeds list", &agent);
    assert_eq!(got.active_seed_id, 1);
    assert_eq!(got.seeds.len(), 1, "the element must survive the decode");
    assert_eq!(got.seeds[0].created_at, ts());
}

// ── ACL ─────────────────────────────────────────────────────────────

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
/// what is asserted: the agent's `AclEntry` into the client's
/// `AclEntryResponse`, which renames `subject`→`did` and `scopes`→
/// `allowed_contexts` and converts RFC 3339 to epoch seconds.
///
/// The audit for #1033 classified this pair safe by reading the attributes on
/// both types. That reading was right — and it is the same kind of reasoning
/// that classified `client/types.rs` as REST bodies, so it is a check now.
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
/// The aliases are Postel's rule: camelCase is what a current agent sends, and
/// snake_case is what one running an older release sends. The fixtures in
/// `client_rest.rs` used to be the only thing covering the snake_case half, and
/// re-cutting them to camelCase would have retired that coverage silently — the
/// failure mode #1019 called out when it annotated the last such case.
///
/// So it is asserted here explicitly, where the name says why it exists. This is
/// the one place a JSON literal is correct in this file: no current type
/// *serializes* the retired spelling, so there is nothing to derive it from.
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

/// Why the other 50 Trust-Task call sites are absent.
///
/// They decode the **same struct** the agent serializes (`protocols::**`), so a
/// casing change moves both ends at once and this class of drift is structurally
/// impossible — not merely untested. Re-serializing a shared type through itself
/// would assert that `serde` round-trips, which is not a property of this
/// codebase.
///
/// This exists so a reader counting call sites finds the reason here rather than
/// assuming the coverage was simply incomplete. If a future change gives one of
/// those sites its own decode type, it belongs in this file.
#[test]
fn same_type_sites_cannot_drift() {
    // A representative of the safe shape: the client's `create_key` decodes
    // `CreateKeyResponseBody`, which is the very type the agent's handler
    // returns. One type, one spelling, nothing to disagree about.
    fn assert_same<T>(_: std::marker::PhantomData<T>) {}
    assert_same::<vta_sdk::protocols::key_management::create::CreateKeyResponseBody>(
        std::marker::PhantomData,
    );
}
