//! Integration coverage for the cross-community recognise flow.
//!
//! The HTTP `/v1/auth/recognise` route hard-wires a live
//! `DIDCacheClient` for foreign-issuer key resolution, which
//! is impractical to fake in a unit test. We exercise
//! `routes::recognise::mint_recognised_session` directly —
//! it takes an already-`VerifiedForeignCredential` (typestate
//! proof of "this passed the four hardening checks") and is
//! the load-bearing route-level surface. The M3.9 verifier
//! itself has 9 unit tests in `recognition::verify::tests` that
//! cover the four fail-closed checks against
//! mock/stub-backed credentials.
//!
//! Phase 3 M3.10.

use axum::Json;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;

use vtc_service::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
use vtc_service::recognition::VerifiedForeignCredential;
use vtc_service::routes::recognise::{RecogniseResponse, mint_recognised_session};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

struct Fixture {
    state: AppState,
    // Owns the temp data dir + backs `state`; must outlive it.
    _vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().build().await;
    Fixture {
        state: vtc.state.clone(),
        _vtc: vtc,
    }
}

async fn install_cross_community_policy(state: &AppState, source: &str) {
    use sha2::{Digest, Sha256};
    let sha: [u8; 32] = Sha256::digest(source.as_bytes()).into();
    let id = uuid::Uuid::new_v4();
    let policy = Policy {
        id,
        purpose: PolicyPurpose::CrossCommunityRoles,
        rego_source: source.into(),
        sha256: sha,
        activated_at: Some(Utc::now()),
        author_did: "did:key:test".into(),
        created_at: Utc::now(),
        version: 1,
    };
    store_policy(&state.policies_ks, &policy).await.unwrap();
    set_active_policy_id(
        &state.active_policies_ks,
        PolicyPurpose::CrossCommunityRoles,
        id,
    )
    .await
    .unwrap();
}

fn verified(
    issuer: &str,
    subject: &str,
    foreign_role: &str,
    valid_minutes: i64,
) -> VerifiedForeignCredential {
    VerifiedForeignCredential {
        foreign_issuer_did: issuer.into(),
        subject_did: subject.into(),
        foreign_role: foreign_role.into(),
        earliest_valid_until: Utc::now() + Duration::minutes(valid_minutes),
    }
}

async fn body_value(resp: Json<RecogniseResponse>) -> RecogniseResponse {
    resp.0
}

#[tokio::test]
async fn default_deny_policy_rejects_every_mapping() {
    let fix = build().await;
    // Default policy: allow := false, no mapped_role rule.
    let src = "\
package vtc.cross_community_roles
import rego.v1
default allow := false
";
    install_cross_community_policy(&fix.state, src).await;

    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("default deny must reject");
    let resp = err.into_response();
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = resp.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn permissive_policy_mints_session_with_mapped_role() {
    let fix = build().await;
    // Map every foreign role to local `monitor`.
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    let v = verified("did:webvh:peer.example", "did:key:zSub", "admin", 60);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;
    assert!(resp.session_id.starts_with("xc-"));
    assert_eq!(resp.data.mapped_role, "monitor");
    assert_eq!(resp.data.foreign_issuer_did, "did:webvh:peer.example");
    assert!(!resp.data.access_token.is_empty());
}

#[tokio::test]
async fn ttl_clamps_to_credentials_when_shorter_than_default() {
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    // Default access_token_expiry = 900s (15m); credentials
    // only valid for 5 more minutes → clamp to credentials.
    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 5);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;
    let now_secs = chrono::Utc::now().timestamp() as u64;
    let ttl = resp.data.access_expires_at - now_secs;
    assert!(
        (260..=305).contains(&ttl),
        "TTL ({ttl}s) should be ~300s (clamped to 5-min credential window)"
    );
}

#[tokio::test]
async fn ttl_clamps_to_default_when_credentials_longer() {
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    // Credentials valid 1 hour; default expiry 15 min →
    // clamp to default.
    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;
    let now_secs = chrono::Utc::now().timestamp() as u64;
    let ttl = resp.data.access_expires_at - now_secs;
    assert!(
        (880..=905).contains(&ttl),
        "TTL ({ttl}s) should be ~900s (default access_token_expiry)"
    );
}

#[tokio::test]
async fn expired_credentials_rejected_with_zero_window() {
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    // earliest_valid_until in the past → 0 window → reject.
    let v = VerifiedForeignCredential {
        foreign_issuer_did: "did:webvh:peer.example".into(),
        subject_did: "did:key:zSub".into(),
        foreign_role: "moderator".into(),
        earliest_valid_until: Utc::now() - Duration::seconds(1),
    };
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("expired credentials must reject");
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.contains("expire") || body.contains("validity"),
        "error body should mention expiry: {body}"
    );
}

#[tokio::test]
async fn allow_true_but_no_mapped_role_is_treated_as_deny() {
    let fix = build().await;
    // Operator typo: allows but forgets to set mapped_role.
    // Fail-closed per spec wording.
    let src = "\
package vtc.cross_community_roles
import rego.v1
default allow := true
";
    install_cross_community_policy(&fix.state, src).await;

    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("missing mapped_role must reject even when allow=true");
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_row_is_persisted_with_xc_prefix() {
    use vti_common::auth::session::{get_session, list_sessions};
    let fix = build().await;
    let src = r#"
package vtc.cross_community_roles
import rego.v1
default allow := true
mapped_role := "monitor"
"#;
    install_cross_community_policy(&fix.state, src).await;

    let subject = "did:key:zSessionTest";
    let v = verified("did:webvh:peer.example", subject, "moderator", 60);
    let resp = mint_recognised_session(&fix.state, v).await.expect("mint");
    let resp = body_value(resp).await;

    // Direct read-back: confirm the session row landed in fjall
    // with the xc- prefix and no refresh token.
    let session = get_session(&fix.state.sessions_ks, &resp.session_id)
        .await
        .unwrap()
        .expect("session row");
    assert_eq!(session.did, subject);
    assert!(session.session_id.starts_with("xc-"));
    assert!(session.refresh_token.is_none(), "no refresh token");
    // Total sessions in the keyspace should also be 1.
    let all = list_sessions(&fix.state.sessions_ks).await.unwrap();
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn missing_active_policy_surfaces_as_internal_error() {
    // No cross_community_roles policy installed at all.
    let fix = build().await;
    let v = verified("did:webvh:peer.example", "did:key:zSub", "moderator", 60);
    let err = mint_recognised_session(&fix.state, v)
        .await
        .expect_err("no active policy must reject");
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let resp = err.into_response();
    // No active policy = 500: this is a misconfigured-daemon
    // path (M2.5 should have installed the default), not a
    // caller-fixable input.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
