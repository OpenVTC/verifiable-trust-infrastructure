//! Integration coverage for `/v1/community/profile`, and its edit as the
//! signed `vtc/community/profile/update/0.1` document.
//!
//! Exercises the full router stack — Trust-Task header → auth
//! extractor → handler → community keyspace — through
//! `Router::oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vti_common::auth::session::now_epoch;
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::community::{CommunityProfile, store_profile};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

const PROFILE_TASK: &str = "https://trusttasks.org/spec/vtc/community/profile/show/0.1";
const PROFILE_UPDATE_TASK: &str = "https://trusttasks.org/spec/vtc/community/profile/update/0.1";

struct Fixture {
    router: axum::Router,
    state: AppState,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

/// Fixture with an `AuditWriter` wired — required for any PUT that
/// actually changes a field (audit is fail-closed).
async fn build_with_audit() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

async fn token_for(fix: &Fixture, role: &str) -> String {
    fix.vtc.token("did:key:z6MkAdmin", role, vec![]).await
}

async fn body_value(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, v)
}

async fn seed_profile(fix: &Fixture) -> CommunityProfile {
    let p = CommunityProfile::new("did:webvh:vtc.example.com:abc", "Example Community");
    store_profile(&fix.state.community_ks, &p).await.unwrap();
    p
}

// ──────────────────────── GET ────────────────────────

/// `vtc/community/profile/show/0.1`, signed by `from`: the reply's status and
/// document.
async fn show(fix: &Fixture, from: &Party) -> (StatusCode, Value) {
    let doc = crate::common::signed::signed(from, PROFILE_TASK, json!({})).await;
    crate::common::signed::post(&fix.vtc, &doc).await
}

#[tokio::test]
async fn show_is_not_found_when_not_initialised() {
    let fix = build().await;
    let admin = signer(&fix, VtcRole::Admin).await;
    let (_, doc) = show(&fix, &admin).await;
    assert_eq!(doc["payload"]["code"], "taskFailed", "{doc}");
    assert_eq!(doc["payload"]["details"]["reason"], "not_found", "{doc}");
}

#[tokio::test]
async fn show_returns_profile_when_initialised() {
    let fix = build().await;
    seed_profile(&fix).await;
    // Any entry may read it, as any session could.
    let member = signer(&fix, VtcRole::Member).await;
    let (status, doc) = show(&fix, &member).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    crate::common::signed::assert_conforms(PROFILE_TASK, &doc);
    // `show` nests the profile under `profile` (#1094).
    let body = &doc["payload"]["profile"];
    assert_eq!(body["name"], "Example Community");
    assert_eq!(body["communityDid"], "did:webvh:vtc.example.com:abc");
    assert_eq!(body["language"], "en");
    // M3.2: registryStatus surfaces on the response. No registry URL
    // configured → reads `degraded`.
    assert_eq!(body["registryStatus"], "degraded");
}

#[tokio::test]
async fn show_requires_a_known_signer() {
    let fix = build().await;
    seed_profile(&fix).await;
    let (_, doc) = show(&fix, &Party::new()).await;
    assert_eq!(doc["payload"]["code"], "permissionDenied", "{doc}");
}

// ──────────────────────── Update (signed document) ────────────────────────
//
// The edit has no REST route: it is `vtc/community/profile/update/0.1`, a
// signed document at `POST /v1/trust-tasks`, authorized by the signer's ACL
// row.

/// A party holding an ACL row of `role`, to sign as.
async fn signer(fix: &Fixture, role: VtcRole) -> Party {
    let who = Party::new();
    store_acl_entry(
        &fix.state.acl_ks,
        &VtcAclEntry {
            did: who.did.clone(),
            admin: role.implied_authority(),
            delegated_by: None,
            role,
            label: None,
            created_at: now_epoch(),
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
    who
}

/// Send `payload` as a signed profile update from `from`; the reply's status
/// and payload.
async fn update(fix: &Fixture, from: &Party, payload: Value) -> (StatusCode, Value) {
    let mut doc = vta_sdk::trust_task_sign::build_unsigned(
        PROFILE_UPDATE_TASK,
        payload,
        &from.did,
        vtc_service::test_support::TEST_VTC_DID,
    )
    .unwrap();
    let key = vta_sdk::trust_task_sign::HolderKey::from_did_key(&from.did, &from.secret_multibase)
        .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/trust-tasks")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let (status, body) = body_value(fix.router.clone().oneshot(req).await.unwrap()).await;
    (status, body["payload"].clone())
}

#[tokio::test]
async fn an_update_requires_an_admin_signer() {
    let fix = build().await;
    seed_profile(&fix).await;
    let member = signer(&fix, VtcRole::Member).await;
    let (status, payload) = update(&fix, &member, json!({ "name": "Renamed" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{payload}");
}

#[tokio::test]
async fn an_update_changes_the_profile_and_lists_changed_fields() {
    let fix = build_with_audit().await;
    seed_profile(&fix).await;
    let admin = signer(&fix, VtcRole::Admin).await;
    let (status, body) = update(
        &fix,
        &admin,
        json!({ "name": "Renamed", "description": "new", "logoUrl": "https://x/y.png" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let changed = body["fieldsChanged"].as_array().unwrap();
    let names: Vec<&str> = changed.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(names.contains(&"name"));
    assert!(names.contains(&"description"));
    assert!(names.contains(&"logoUrl"));
    assert_eq!(body["profile"]["name"], "Renamed");
    assert_eq!(body["profile"]["logoUrl"], "https://x/y.png");
}

#[tokio::test]
async fn an_update_to_the_same_value_is_an_empty_changeset_and_needs_no_audit_writer() {
    // A no-op emits no audit, so it must not be refused without a writer.
    let fix = build().await;
    seed_profile(&fix).await;
    let admin = signer(&fix, VtcRole::Admin).await;
    let (status, body) = update(&fix, &admin, json!({ "name": "Example Community" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["fieldsChanged"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn an_update_before_the_profile_exists_is_refused() {
    let fix = build().await;
    let admin = signer(&fix, VtcRole::Admin).await;
    let (status, payload) = update(&fix, &admin, json!({ "name": "Renamed" })).await;
    assert!(!status.is_success(), "{payload}");
    assert!(payload["code"].is_string(), "{payload}");
}

#[tokio::test]
async fn an_update_with_oversized_extensions_is_refused() {
    let fix = build().await;
    seed_profile(&fix).await;
    let admin = signer(&fix, VtcRole::Admin).await;
    // ~32 KiB — well inside the document limit, over the extensions cap.
    let (status, payload) = update(
        &fix,
        &admin,
        json!({ "extensions": { "k": "a".repeat(32 * 1024) } }),
    )
    .await;
    assert!(status.is_client_error(), "{status}: {payload}");
}

/// `communityDid` is no member of the update payload, whose schema admits no
/// others, so a document naming it is refused and changes nothing.
#[tokio::test]
async fn an_update_naming_the_community_did_is_refused() {
    let fix = build_with_audit().await;
    seed_profile(&fix).await;
    let admin = signer(&fix, VtcRole::Admin).await;
    let (status, payload) = update(
        &fix,
        &admin,
        json!({ "name": "Renamed", "communityDid": "did:webvh:attacker:steal" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}");
    let stored = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.community_did, "did:webvh:vtc.example.com:abc");
    assert_eq!(stored.name, "Example Community");
}

#[tokio::test]
async fn an_update_is_audited_under_the_signer() {
    use vti_common::audit::{AuditEnvelope, AuditEvent};

    let fix = build_with_audit().await;
    seed_profile(&fix).await;
    let admin = signer(&fix, VtcRole::Admin).await;
    let (status, body) = update(
        &fix,
        &admin,
        json!({ "name": "Renamed", "description": "new" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();
    let updated: Vec<&AuditEnvelope> = envelopes
        .iter()
        .filter(|e| matches!(e.event, AuditEvent::CommunityProfileUpdated(_)))
        .collect();
    assert_eq!(updated.len(), 1, "one CommunityProfileUpdated envelope");
    let env = updated[0];
    assert_eq!(env.actor_did_plain.as_deref(), Some(admin.did.as_str()));
    let AuditEvent::CommunityProfileUpdated(data) = &env.event else {
        unreachable!()
    };
    assert!(data.fields_changed.contains(&"name".to_string()));
    assert!(data.fields_changed.contains(&"description".to_string()));
}

#[tokio::test]
async fn an_update_that_cannot_be_audited_is_refused() {
    // Fail-closed: a profile change that can't be audited is refused.
    let fix = build().await; // no AuditWriter
    seed_profile(&fix).await;
    let admin = signer(&fix, VtcRole::Admin).await;
    let (status, payload) = update(&fix, &admin, json!({ "name": "Renamed" })).await;
    assert!(status.is_server_error(), "{status}: {payload}");
    let stored = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.name, "Example Community",
        "an unaudited change must not land"
    );
}

/// The edit has no REST route.
#[tokio::test]
async fn there_is_no_rest_update() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"Renamed"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    // Refused at the read's mount (its task or its method), and nothing moved.
    assert!(
        [
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        ]
        .contains(&resp.status()),
        "{}",
        resp.status()
    );
    let stored = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.name, "Example Community");
}

// ──────────────────────── Public profile (unauth) ─────────────

#[tokio::test]
async fn public_profile_returns_curated_subset_unauthenticated() {
    // Drives the default public website. Trust-Task-exempt and
    // unauthenticated — neither header is set on the request.
    let fix = build().await;
    seed_profile(&fix).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/public-profile")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Example Community");
    assert_eq!(body["communityDid"], "did:webvh:vtc.example.com:abc");
    assert_eq!(body["language"], "en");
    // Curated subset — operational + opaque fields stay private.
    assert!(body.get("registryStatus").is_none());
    assert!(body.get("extensions").is_none());
    // The transport view is always present, even when empty (see below), so a
    // consumer can tell "this VTC reports no transports" from "this response
    // predates the field".
    assert!(
        body.get("transports").is_some_and(|t| t.is_array()),
        "public profile must always carry a transports array: {body}"
    );
}

/// A VTC whose own DID cannot be resolved reports transports as **unknown**
/// (an empty array), never as "advertises nothing".
///
/// The distinction matters to a visitor: "no way in" is actionable and would be
/// a lie here. This fixture has no DID resolver wired, which is the same
/// observable state as a resolution failure.
#[tokio::test]
async fn public_profile_reports_unknown_transports_when_the_did_does_not_resolve() {
    let fix = build().await;
    seed_profile(&fix).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/public-profile")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["transports"].as_array().map(Vec::len),
        Some(0),
        "unresolvable DID must yield an empty (unknown) transport list, not a \
         fabricated one: {body}"
    );
}

/// The public endpoint must not leak build configuration. The operator-facing
/// remediation text in `transport_capability::Finding` names feature flags and
/// rebuild commands on purpose — for `vtc status` and the daemon log. None of
/// it may ride out on an unauthenticated response.
#[tokio::test]
async fn public_profile_leaks_no_build_configuration() {
    let fix = build().await;
    seed_profile(&fix).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/public-profile")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let serialised = body.to_string();
    for leak in ["--features", "cargo", "rebuild", "feature"] {
        assert!(
            !serialised.contains(leak),
            "public profile must not mention {leak:?}: {serialised}"
        );
    }
}

#[tokio::test]
async fn public_profile_returns_404_when_not_initialised() {
    let fix = build().await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/public-profile")
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// #1600 — the code `vtc/community/profile/update/0.1` declares, read from the
// generated bindings.
// ---------------------------------------------------------------------------

const PROFILE_UPDATE_ERR_VALIDATION_FAILED: &str =
    trust_tasks_rs::specs::vtc::community::profile::update::v0_1::error_codes::VALIDATION_FAILED
        .code;

/// The error code carried by a `trust-task-error` payload.
fn tt_error_code(payload: &Value) -> &str {
    payload["code"].as_str().unwrap_or_default()
}

/// A field that fails validation — a `logoUrl` that is not http(s) — is
/// `validationFailed`, and the stored profile is untouched.
#[tokio::test]
async fn a_profile_field_failing_validation_is_the_declared_validation_failed() {
    let fix = build().await;
    let before = seed_profile(&fix).await;
    let admin = signer(&fix, VtcRole::Admin).await;

    let (status, payload) = update(&fix, &admin, json!({ "logoUrl": "javascript:alert(1)" })).await;
    assert!(status.is_client_error(), "{status}: {payload}");
    assert_eq!(
        tt_error_code(&payload),
        PROFILE_UPDATE_ERR_VALIDATION_FAILED,
        "{payload}"
    );

    let after = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after, before, "a refused update must not write");
}
