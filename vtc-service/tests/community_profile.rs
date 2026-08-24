//! Integration coverage for `/v1/community/profile`.
//!
//! Exercises the full router stack — Trust-Task header → auth
//! extractor → handler → community keyspace — through
//! `Router::oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

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

#[tokio::test]
async fn get_returns_404_when_not_initialised() {
    let fix = build().await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_returns_profile_when_initialised() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    // `show` nests the profile under `profile` (#1094).
    let body = &body["profile"];
    assert_eq!(body["name"], "Example Community");
    assert_eq!(body["communityDid"], "did:webvh:vtc.example.com:abc");
    assert_eq!(body["language"], "en");
    // M3.2: registryStatus surfaces on the GET response. No
    // registry URL configured → reads `degraded`.
    assert_eq!(body["registryStatus"], "degraded");
}

#[tokio::test]
async fn get_requires_authentication() {
    let fix = build().await;
    seed_profile(&fix).await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_TASK)
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ──────────────────────── PUT ────────────────────────

#[tokio::test]
async fn put_requires_admin_role() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "reader").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"Renamed"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_updates_profile_and_lists_changed_fields() {
    let fix = build_with_audit().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"name":"Renamed","description":"new","logoUrl":"https://x/y.png"}"#,
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    let changed = body["fieldsChanged"].as_array().unwrap();
    let names: Vec<&str> = changed.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(names.contains(&"name"));
    assert!(names.contains(&"description"));
    assert!(names.contains(&"logoUrl"));
    assert_eq!(body["profile"]["name"], "Renamed");
    assert_eq!(body["profile"]["logoUrl"], "https://x/y.png");
}

#[tokio::test]
async fn put_idempotent_noop_returns_empty_changeset() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let body = r#"{"name":"Example Community"}"#; // already the value
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["fieldsChanged"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn put_returns_404_when_profile_not_initialised() {
    let fix = build().await;
    // No seed_profile call — store is empty.
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
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_rejects_oversized_extensions() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;

    // Build a clearly-too-large extensions value (~32 KiB).
    let mut huge_value = String::new();
    huge_value.push('"');
    huge_value.push_str(&"a".repeat(32 * 1024));
    huge_value.push('"');
    let body = format!(r#"{{"extensions":{{"k":{huge_value}}}}}"#);

    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_does_not_accept_community_did_in_request() {
    let fix = build_with_audit().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;

    // `communityDid` is not a field on the update DTO; serde_json
    // with `additionalProperties = no` would reject it, but our
    // CommunityProfileUpdate has no such guard at the type level
    // (serde silently ignores extra fields by default). The
    // important property is that it never reaches the stored
    // profile.
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"name":"Renamed","communityDid":"did:webvh:attacker:steal"}"#,
        ))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    // Profile's communityDid is unchanged.
    assert_eq!(
        body["profile"]["communityDid"],
        "did:webvh:vtc.example.com:abc"
    );
    // Only `name` made it into the changeset.
    let changed = body["fieldsChanged"].as_array().unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0], "name");
}

#[tokio::test]
async fn put_emits_profile_updated_audit_with_real_actor() {
    use vti_common::audit::{AuditEnvelope, AuditEvent};

    let fix = build_with_audit().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"Renamed","description":"new"}"#))
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);

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
    assert_eq!(env.actor_did_plain.as_deref(), Some("did:key:z6MkAdmin"));
    let AuditEvent::CommunityProfileUpdated(data) = &env.event else {
        unreachable!()
    };
    assert!(data.fields_changed.contains(&"name".to_string()));
    assert!(data.fields_changed.contains(&"description".to_string()));
}

#[tokio::test]
async fn put_503_when_audit_writer_missing() {
    // Fail-closed: a profile change that can't be audited is refused.
    let fix = build().await; // no AuditWriter
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
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn put_idempotent_noop_does_not_need_audit_writer() {
    // A no-op PUT emits no audit, so it must not 503 without a writer.
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/community/profile")
        .header("Trust-Task", PROFILE_UPDATE_TASK)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"Example Community"}"#)) // already the value
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, body) = body_value(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["fieldsChanged"].as_array().unwrap().is_empty());
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

// ──────────────────────── Trust-Task gate ────────────────────────

#[tokio::test]
async fn get_with_wrong_trust_task_returns_415() {
    let fix = build().await;
    seed_profile(&fix).await;
    let token = token_for(&fix, "admin").await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/community/profile")
        .header("Trust-Task", "https://trusttasks.org/spec/acl/list/0.1")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = fix.router.clone().oneshot(req).await.unwrap();
    let (status, _body) = body_value(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
