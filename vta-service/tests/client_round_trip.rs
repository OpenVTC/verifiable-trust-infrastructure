//! Round-trip contract tests: the **real `VtaClient`** against the **real
//! router**, over a real socket.
//!
//! # Why this file exists
//!
//! Every other test in the workspace exercises one side of the wire and mocks
//! the other:
//!
//! - `vta-sdk/tests/client_rest.rs` drives the real client against a wiremock,
//!   so it proves the client agrees with a **hand-written fixture**.
//! - `tests/e2e/tests/client_didcomm.rs` drives the real client against a
//!   mocked responder — same shape, different transport.
//! - `vta-service/tests/api_integration.rs` drives the real router with
//!   hand-written JSON, so it proves the server agrees with **another
//!   hand-written fixture**.
//!
//! Nothing compares the two *real* implementations. When a wire type is
//! reshaped, both sides can be updated to disagree with each other and every
//! test still passes, because each is measured against its own fixture. That is
//! not hypothetical: folding the ACL surface onto canonical `acl/*` (#840 phase
//! A) changed the server's responses while the SDK client still parsed the old
//! shape. Nothing failed. The CLI would have broken in production, and the
//! defect was found by reading rather than by testing.
//!
//! These tests close that gap for the surfaces that fold has already reshaped.
//! **When you reshape a wire type, add a case here** — it is the only place a
//! client/server mismatch is a test failure rather than a runtime surprise.
//!
//! # What "round trip" means here
//!
//! Both directions, end to end:
//!
//! 1. the client **serialises** a request the server can deserialise, and
//! 2. the server **serialises** a response the client can deserialise,
//! 3. with the values intact in both directions.
//!
//! Step 3 is the part a smoke test misses. `create` returning `Ok` proves the
//! shapes are compatible; it does not prove `scopes` survived, and a dropped
//! scope list on an admin entry is a **permanent super-admin**.

use vta_service::test_support::MockVta;

use vta_sdk::client::{CreateAclRequest, UpdateAclRequest, VtaClient};

/// A client authenticated as an unrestricted admin against a live mock VTA.
async fn admin_client(mock: &MockVta) -> VtaClient {
    let token = mock
        .ctx
        .mint_token("did:key:z6MkRoundTripAdmin", "admin", vec![])
        .await;
    let client = VtaClient::new(mock.base_url());
    client.set_token_async(token).await;
    client
}

// ── ACL ─────────────────────────────────────────────────────────────

/// The full ACL lifecycle through the real client: grant, show, list, update,
/// revoke.
///
/// Each step asserts the *values*, not just that the call succeeded. The fold
/// renamed `did`→`subject` and `allowedContexts`→`scopes` and moved expiry from
/// epoch seconds to RFC 3339; a mismatch on any of those deserialises to a
/// default rather than an error, so only checking the value catches it.
#[tokio::test]
async fn acl_lifecycle_round_trips_through_the_real_client() {
    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;
    let subject = "did:key:z6MkRoundTripSubject";

    // ── grant ───────────────────────────────────────────────────────
    let created = client
        .create_acl(
            CreateAclRequest::new(subject, "application")
                .label("round trip")
                .contexts(vec!["ctx1".into()]),
        )
        .await
        .expect("grant round-trips");

    assert_eq!(created.did, subject);
    assert_eq!(created.role, "application");
    assert_eq!(
        created.allowed_contexts,
        vec!["ctx1".to_string()],
        "a dropped scope list on an admin entry is a permanent super-admin, so \
         the scopes must survive the round trip rather than defaulting to empty"
    );
    assert_eq!(created.label.as_deref(), Some("round trip"));

    // ── show ────────────────────────────────────────────────────────
    let fetched = client.get_acl(subject).await.expect("show round-trips");
    assert_eq!(fetched.did, subject);
    assert_eq!(fetched.allowed_contexts, vec!["ctx1".to_string()]);
    assert_eq!(
        fetched.role, created.role,
        "show and grant must describe the same entry"
    );

    // ── list ────────────────────────────────────────────────────────
    let listed = client.list_acl(None).await.expect("list round-trips");
    let found = listed
        .entries
        .iter()
        .find(|e| e.did == subject)
        .expect("the granted entry appears in the listing");
    assert_eq!(found.allowed_contexts, vec!["ctx1".to_string()]);

    // ── update ──────────────────────────────────────────────────────
    let updated = client
        .update_acl(
            subject,
            UpdateAclRequest {
                label: Some("renamed".into()),
                allowed_contexts: None,
                step_up_approver: None,
                step_up_require: None,
                approve_scope: None,
                allowed_keys: None,
            },
        )
        .await
        .expect("update round-trips");
    assert_eq!(updated.label.as_deref(), Some("renamed"));
    assert_eq!(
        updated.allowed_contexts,
        vec!["ctx1".to_string()],
        "an omitted member must leave the stored value alone, not clear it"
    );

    // ── revoke ──────────────────────────────────────────────────────
    client
        .delete_acl(subject)
        .await
        .expect("revoke round-trips");
    assert!(
        client.get_acl(subject).await.is_err(),
        "the entry is gone after revocation"
    );
}

/// Expiry crosses the wire as RFC 3339 and comes back as the same instant.
///
/// The fold changed this member's *representation* while leaving its Rust type
/// as epoch seconds, so a broken conversion yields `0` or `None` rather than a
/// parse error — a silent failure that would quietly make a time-boxed grant
/// permanent, or expire it immediately.
#[tokio::test]
async fn acl_expiry_survives_the_epoch_rfc3339_conversion() {
    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;
    let subject = "did:key:z6MkExpiringSubject";
    let expires_at = 1_800_000_000u64;

    let created = client
        .create_acl(
            CreateAclRequest::new(subject, "application")
                .contexts(vec!["ctx1".into()])
                .expires_at(expires_at),
        )
        .await
        .expect("grant with expiry round-trips");

    assert_eq!(
        created.expires_at,
        Some(expires_at),
        "expiry must survive epoch → RFC 3339 → epoch unchanged; a broken \
         conversion reads as permanent or already-expired rather than failing"
    );

    let fetched = client.get_acl(subject).await.expect("show round-trips");
    assert_eq!(fetched.expires_at, Some(expires_at));
}

/// The step-up and approve members survive the round trip through their
/// canonical nesting.
///
/// These moved from five flat members into `stepUp{}` and `approve{}`. Both are
/// authority-bearing: a dropped `approve` silently confers nothing (safe but
/// wrong), and a dropped `stepUp.approver` removes the delegated approver a
/// policy may depend on.
#[tokio::test]
async fn acl_step_up_and_approve_survive_their_canonical_nesting() {
    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;
    let subject = "did:key:z6MkNestedSubject";

    let created = client
        .create_acl(
            CreateAclRequest::new(subject, "application")
                .contexts(vec!["ctx1".into()])
                .step_up_approver("did:key:z6MkTheApprover")
                .step_up_require("delegated"),
        )
        .await
        .expect("grant with step-up round-trips");

    assert_eq!(
        created.step_up_approver(),
        Some("did:key:z6MkTheApprover"),
        "the delegated approver must survive the nesting"
    );
    assert_eq!(created.step_up_require(), Some("delegated"));

    // And again on the read path, which is a different response type.
    let fetched = client.get_acl(subject).await.expect("show round-trips");
    assert_eq!(fetched.step_up_approver(), Some("did:key:z6MkTheApprover"));
    assert_eq!(fetched.step_up_require(), Some("delegated"));
}

// ── Config ──────────────────────────────────────────────────────────

/// The config registry round-trips, and identity is readable but not writable.
///
/// `config/*` moved from three named typed fields to a key registry in the same
/// phase, so it has the same client/server mismatch exposure as ACL.
#[tokio::test]
async fn config_registry_round_trips_and_identity_stays_read_only() {
    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;

    // ── read ────────────────────────────────────────────────────────
    let cfg = client.get_config().await.expect("config/show round-trips");
    assert!(
        cfg.vta_did().is_some(),
        "the VTA DID must remain readable — nothing else exposes it, which is \
         why it is a registry key marked immutable rather than absent"
    );

    // ── patch a mutable key ─────────────────────────────────────────
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("vta_name".to_string(), serde_json::json!("round tripped"));
    let patched = client
        .update_config(vta_sdk::client::UpdateConfigRequest {
            patch: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody {
                overrides,
            },
        })
        .await
        .expect("config/patch round-trips");
    assert_eq!(patched.applied, vec!["vta_name".to_string()]);
    assert!(patched.rejected.is_empty(), "{patched:?}");

    // …and the change is visible on the read path.
    let cfg = client.get_config().await.expect("config/show round-trips");
    assert_eq!(cfg.vta_name(), Some("round tripped"));

    // ── identity is refused, through the real client ────────────────
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "vta_did".to_string(),
        serde_json::json!("did:key:z6MkAttacker"),
    );
    let patched = client
        .update_config(vta_sdk::client::UpdateConfigRequest {
            patch: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody {
                overrides,
            },
        })
        .await
        .expect("a rejected key is a reported rejection, not a transport error");

    assert!(
        patched.applied.is_empty(),
        "identity must never be applied: {patched:?}"
    );
    assert_eq!(patched.rejected.len(), 1);
    assert_eq!(patched.rejected[0].key, "vta_did");
    assert!(
        !patched.rejected[0].reason.is_empty(),
        "the rejection must explain itself — an operator learns the rule, not \
         just the refusal"
    );
}

// ── Audit ───────────────────────────────────────────────────────────

/// Audit list through the real client: the canonical envelope survives
/// the trip, and cursor pagination actually advances.
///
/// The failure this catches is quiet in both directions. The stored row
/// keeps its snake_case storage shape (`id`, `timestamp`) while the wire
/// carries the canonical camelCase envelope (`eventId`, `recordedAt`),
/// so a mapping that drops a field yields `None`, not an error — the
/// client parses a row full of nulls and the CLI prints em-dashes. And
/// a cursor the client fails to send back is not an error either; the
/// server simply returns page one again, so a caller walking the log
/// loops forever on the newest entries and never sees the tail.
#[tokio::test]
async fn audit_list_round_trips_through_the_real_client() {
    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;

    // Generate audit rows by doing auditable work through the client.
    for i in 0..5 {
        client
            .create_acl(
                CreateAclRequest::new(format!("did:key:z6MkAuditSubject{i}"), "application")
                    .contexts(vec!["ctx1".into()]),
            )
            .await
            .expect("grant round-trips");
    }

    let params = vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
        page_size: Some(2),
        ..Default::default()
    };
    let first = client
        .list_audit_logs(&params)
        .await
        .expect("audit/list round-trips");

    assert_eq!(first.entries.len(), 2, "pageSize must be honoured");
    assert!(
        first.truncated && first.cursor.is_some(),
        "more entries exist, so the page must be marked truncated with a cursor"
    );

    // The envelope arrives populated — not a shape-compatible row of
    // nulls.
    let entry = &first.entries[0];
    assert!(
        !entry.event_id.is_empty(),
        "eventId must survive: {entry:?}"
    );
    assert!(
        chrono::DateTime::parse_from_rfc3339(&entry.recorded_at).is_ok(),
        "recordedAt must be RFC 3339, got {:?}",
        entry.recorded_at
    );
    assert!(!entry.action.is_empty(), "action must survive: {entry:?}");
    assert!(
        entry.actor.is_some(),
        "actor must survive — 'who did this' is the question a log answers: {entry:?}"
    );

    // Page two is *different* entries, not the same page again.
    let next = client
        .list_audit_logs(
            &vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
                cursor: first.cursor.clone(),
                ..params.clone()
            },
        )
        .await
        .expect("continuation round-trips");

    let first_ids: Vec<&str> = first.entries.iter().map(|e| e.event_id.as_str()).collect();
    for entry in &next.entries {
        assert!(
            !first_ids.contains(&entry.event_id.as_str()),
            "the cursor must advance past page one, but {} repeated",
            entry.event_id
        );
    }
    assert!(!next.entries.is_empty(), "page two should hold entries");
}

/// The filters are bound into the cursor, so resuming a page under a
/// different filter set is refused rather than silently answered from a
/// position that belonged to another query.
#[tokio::test]
async fn audit_cursor_is_bound_to_its_filters() {
    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;

    for i in 0..5 {
        client
            .create_acl(
                CreateAclRequest::new(format!("did:key:z6MkBoundSubject{i}"), "application")
                    .contexts(vec!["ctx1".into()]),
            )
            .await
            .expect("grant round-trips");
    }

    let first = client
        .list_audit_logs(
            &vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
                page_size: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("audit/list round-trips");
    let cursor = first.cursor.expect("more entries remain");

    let err = client
        .list_audit_logs(
            &vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
                page_size: Some(1),
                cursor: Some(cursor),
                // A filter that was not in force when the cursor was minted.
                action: Some("acl.create".into()),
                ..Default::default()
            },
        )
        .await;

    assert!(
        err.is_err(),
        "changing the filters while resuming must be refused, got {err:?}"
    );
}

// ── WebVH DID get ───────────────────────────────────────────────────

/// Both legacy client methods still work after `dids/get-log` folded
/// into `dids/get`.
///
/// This is the compatibility claim the fold rests on, and it is exactly
/// the kind that fails silently. The merged response flattens the
/// record and adds an optional `log`, making it a superset of both old
/// shapes — but "superset" only helps because neither client type sets
/// `deny_unknown_fields`. If either did, or if the flatten were dropped
/// for a nested `record` object, both calls would fail at runtime while
/// every mocked test stayed green.
#[tokio::test]
async fn webvh_get_did_round_trips_after_the_get_log_fold() {
    use vta_sdk::webvh::WebvhDidRecord;

    let mock = MockVta::start().await;
    let token = mock
        .ctx
        .mint_token("did:key:z6MkRoundTripAdmin", "admin", vec![])
        .await;
    let client = VtaClient::new(mock.base_url());
    client.set_token_async(token.clone()).await;

    let did = "did:webvh:example.com:round-trip";
    let record = WebvhDidRecord {
        did: did.to_string(),
        server_id: "serverless".into(),
        mnemonic: "slot-one".into(),
        scid: "scid-round-trip".into(),
        context_id: "ctx1".into(),
        portable: false,
        log_entry_count: 1,
        pre_rotation_count: 0,
        next_fragment_id: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    vta_service::webvh_store::store_did(&mock.ctx.webvh_ks, &record)
        .await
        .expect("seed DID record");
    vta_service::webvh_store::store_did_log(&mock.ctx.webvh_ks, did, "{\"state\":{}}")
        .await
        .expect("seed DID log");

    // The record read: values must survive, not merely parse.
    let got = client
        .get_did_webvh(did)
        .await
        .expect("get_did_webvh round-trips");
    assert_eq!(got.did, did);
    assert_eq!(got.scid, "scid-round-trip");
    assert_eq!(got.context_id, "ctx1");

    // The new flag: the log is present only when asked for. If
    // `includeLog` failed to bind, the log would come back on every
    // record read — the fold would look like it worked while quietly
    // making every `dids/get` pay for the log.
    let raw = |qs: &str| {
        // Colons are legal path characters (RFC 3986 pchar), so the DID
        // needs no escaping here.
        let url = format!("{}/webvh/dids/{}{}", mock.base_url(), did, qs);
        let token = token.clone();
        async move {
            reqwest::Client::new()
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .expect("request")
                .json::<serde_json::Value>()
                .await
                .expect("json")
        }
    };
    let without = raw("").await;
    assert_eq!(without["did"], did);
    assert!(
        without.get("log").is_none(),
        "the log must be omitted unless requested: {without}"
    );
    let with = raw("?includeLog=true").await;
    assert_eq!(
        with["log"], "{\"state\":{}}",
        "includeLog=true must return the log: {with}"
    );

    // The log read, through the path whose Trust Task folded away.
    let log = client
        .get_did_webvh_log(did)
        .await
        .expect("get_did_webvh_log round-trips");
    assert_eq!(log.did, did);
    assert_eq!(
        log.log.as_deref(),
        Some("{\"state\":{}}"),
        "the log must survive the merge into the flattened record"
    );
}

// ── WebVH server registration ───────────────────────────────────────

/// The merged `servers/register` behaves correctly on every path the
/// two tasks it replaces used to cover, through the real client.
///
/// The one that matters is the last: an upsert keyed only on `id`
/// would happily re-point an existing registration at a different
/// host. That silently redirects every DID resolving through it, and
/// unwinding it needs coordinated teardown on the old host — so the
/// merge has to refuse it rather than treat it as an update.
#[tokio::test]
async fn webvh_server_register_upserts_but_refuses_a_repoint() {
    use vta_sdk::client::{AddWebvhServerRequest, UpdateWebvhServerRequest};

    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;

    let host_did = "did:web:host-one.example";
    mock.seed_webvh_server("host1", host_did).await;

    // Label-only update, the path that was `servers/update`.
    let updated = client
        .update_webvh_server(
            "host1",
            UpdateWebvhServerRequest {
                label: Some("renamed".into()),
            },
        )
        .await
        .expect("relabel round-trips");
    assert_eq!(updated.label.as_deref(), Some("renamed"));
    assert_eq!(updated.did, host_did, "a relabel must not touch the DID");

    // Re-registering the same host is idempotent rather than a conflict.
    let again = client
        .add_webvh_server(AddWebvhServerRequest {
            id: "host1".into(),
            did: host_did.into(),
            label: Some("same host".into()),
        })
        .await
        .expect("re-registering an identical host is idempotent");
    assert_eq!(again.did, host_did);
    assert_eq!(again.label.as_deref(), Some("same host"));

    // Re-pointing at a different host is refused.
    let repoint = client
        .add_webvh_server(AddWebvhServerRequest {
            id: "host1".into(),
            did: "did:web:host-two.example".into(),
            label: None,
        })
        .await;
    assert!(
        repoint.is_err(),
        "re-pointing a registration at a different DID must be refused, got {repoint:?}"
    );

    // …and the stored record is untouched by the refused attempt.
    let servers = client.list_webvh_servers().await.expect("list round-trips");
    let host1 = servers
        .servers
        .iter()
        .find(|s| s.id == "host1")
        .expect("host1 still registered");
    assert_eq!(
        host1.did, host_did,
        "a refused re-point must leave the registration alone"
    );

    // A label-only patch against an unknown id is still NotFound, not a
    // silent registration.
    let missing = client
        .update_webvh_server(
            "nope",
            UpdateWebvhServerRequest {
                label: Some("x".into()),
            },
        )
        .await;
    assert!(
        missing.is_err(),
        "patching an unregistered server must fail, got {missing:?}"
    );
}

// ── ACL change-role ─────────────────────────────────────────────────

/// The role transition is compare-and-swapped, through the real client.
///
/// The defect this exists to prevent: two admins acting on the same
/// stale read — one demoting, one promoting — both "succeed" under a
/// blind write, and whichever lands second silently wins. The loser's
/// intent disappears with no error anywhere, which on a *demotion*
/// means someone stays an admin who was meant to be removed.
#[tokio::test]
async fn acl_change_role_compare_and_swaps() {
    use vta_sdk::client::ChangeAclRoleRequest;

    let mock = MockVta::start().await;
    let client = admin_client(&mock).await;
    let subject = "did:key:z6MkChangeRoleSubject";

    client
        .create_acl(CreateAclRequest::new(subject, "reader").contexts(vec!["ctx1".into()]))
        .await
        .expect("grant round-trips");

    // A transition from the role they actually hold succeeds.
    let changed = client
        .change_acl_role(
            subject,
            ChangeAclRoleRequest {
                from_role: "reader".into(),
                to_role: "application".into(),
                reason: Some("promoted for the integration".into()),
            },
        )
        .await
        .expect("change-role round-trips");
    assert_eq!(
        changed.role, "application",
        "the new role must come back on the entry: {changed:?}"
    );

    // A transition declaring a stale `from` is refused — this is the
    // whole point of the split.
    let stale = client
        .change_acl_role(
            subject,
            ChangeAclRoleRequest {
                // They are `application` now, not `reader`.
                from_role: "reader".into(),
                to_role: "admin".into(),
                reason: None,
            },
        )
        .await;
    assert!(
        stale.is_err(),
        "a stale fromRole must be refused, got {stale:?}"
    );

    // …and the refusal left the entry alone.
    let after = client.get_acl(subject).await.expect("show round-trips");
    assert_eq!(
        after.role, "application",
        "a refused change must not modify the entry"
    );

    // An unrecognized role is a caller error, not a 500.
    let bogus = client
        .change_acl_role(
            subject,
            ChangeAclRoleRequest {
                from_role: "application".into(),
                to_role: "superuser".into(),
                reason: None,
            },
        )
        .await;
    assert!(bogus.is_err(), "an unknown role must be refused");

    // `acl/update` no longer carries a role at all, so the only way to
    // move one is through the checked path above.
    let updated = client
        .update_acl(
            subject,
            vta_sdk::client::UpdateAclRequest {
                label: Some("still an application".into()),
                allowed_contexts: None,
                step_up_approver: None,
                step_up_require: None,
                approve_scope: None,
                allowed_keys: None,
            },
        )
        .await
        .expect("update round-trips");
    assert_eq!(
        updated.role, "application",
        "update must leave the role untouched"
    );
}
