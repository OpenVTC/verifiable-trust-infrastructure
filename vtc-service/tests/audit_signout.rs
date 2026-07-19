//! `POST /v1/auth/sign-out` must leave an audit trail (#537 tier 1).
//!
//! Sign-out ends a session, and "when did this principal's access
//! stop" is a question the audit log has to be able to answer. It was
//! the one session-lifecycle mutation still writing only an `info!`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use vti_common::audit::{AuditEnvelope, AuditEvent};

use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

// The router enforces the canonical cross-service task URI here, not
// the openvtc-scoped one `trust-tasks/index.json` lists for this route.
const SIGN_OUT_TASK: &str = "https://trusttasks.org/spec/auth/revoke-session/0.1";
const MEMBER_DID: &str = "did:key:z6MkSignsOut";

struct Fixture {
    router: axum::Router,
    state: AppState,
    vtc: TestVtc,
}

async fn build() -> Fixture {
    let vtc = TestVtc::builder().with_audit(true).build().await;
    Fixture {
        router: vtc.router.clone(),
        state: vtc.state.clone(),
        vtc,
    }
}

async fn sign_out(fix: &Fixture, token: &str) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/sign-out")
        .header("Trust-Task", SIGN_OUT_TASK)
        .header("Authorization", format!("Bearer {token}"))
        // Sign-out takes no body, but the router's content-type gate
        // still applies to POST — without this it 415s before the
        // handler runs.
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    fix.router.clone().oneshot(req).await.unwrap().status()
}

/// Every `SignedOut` envelope in the store.
async fn signed_out_events(fix: &Fixture) -> Vec<AuditEnvelope> {
    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    raw.iter()
        .filter_map(|(_, v)| serde_json::from_slice::<AuditEnvelope>(v).ok())
        .filter(|e| matches!(e.event, AuditEvent::SignedOut(_)))
        .collect()
}

#[tokio::test]
async fn sign_out_emits_a_signed_out_envelope() {
    let fix = build().await;
    // `TestVtc::token` persists the session row it mints, so this
    // exercises the "session existed" arm.
    let token = fix.vtc.token(MEMBER_DID, "application", vec![]).await;

    assert_eq!(sign_out(&fix, &token).await, StatusCode::NO_CONTENT);

    let events = signed_out_events(&fix).await;
    assert_eq!(events.len(), 1, "exactly one SignedOut envelope");
    let env = &events[0];

    // Actor and target are both the caller — this is a self-initiated
    // action, which is precisely what distinguishes it from a revoke.
    assert_eq!(env.actor_did_plain.as_deref(), Some(MEMBER_DID));
    assert_eq!(env.target_did_plain.as_deref(), Some(MEMBER_DID));

    let AuditEvent::SignedOut(data) = &env.event else {
        unreachable!()
    };
    assert!(!data.session_id.is_empty(), "session id is recorded");
}

#[tokio::test]
async fn sign_out_is_distinct_from_session_revoked() {
    // The whole point of a separate variant: a SIEM rule counting
    // forced revocations must not pick up voluntary sign-outs.
    let fix = build().await;
    let token = fix.vtc.token(MEMBER_DID, "application", vec![]).await;
    assert_eq!(sign_out(&fix, &token).await, StatusCode::NO_CONTENT);

    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap();
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .filter_map(|(_, v)| serde_json::from_slice(v).ok())
        .collect();

    assert!(
        envelopes
            .iter()
            .any(|e| matches!(e.event, AuditEvent::SignedOut(_))),
        "a SignedOut envelope was written"
    );
    assert!(
        !envelopes
            .iter()
            .any(|e| matches!(e.event, AuditEvent::SessionRevoked(_))),
        "sign-out must not masquerade as an admin revocation"
    );
}

#[tokio::test]
async fn a_second_sign_out_is_rejected_and_not_audited_twice() {
    // Sign-out deletes the session row, and `AuthClaims` refuses a
    // token whose session is gone — so the same token cannot sign out
    // twice. This is why `SignedOutData` carries no "did it exist"
    // flag: the handler only ever runs against a live session.
    let fix = build().await;
    let token = fix.vtc.token(MEMBER_DID, "application", vec![]).await;

    assert_eq!(sign_out(&fix, &token).await, StatusCode::NO_CONTENT);
    assert_eq!(
        sign_out(&fix, &token).await,
        StatusCode::UNAUTHORIZED,
        "the token dies with its session"
    );

    assert_eq!(
        signed_out_events(&fix).await.len(),
        1,
        "the rejected retry must not add a second envelope"
    );
}
