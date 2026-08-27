//! Integration test for `auth/revoke-session/0.1` — signing a session out over
//! the trust-task dispatcher (bearer-authed).
//!
//! The interesting behaviour is not the happy path; it is what the caller is
//! told when nothing is revoked. The spec pulls in two directions at once:
//! `revokedCount: 0` is a documented success ("the named sessionId was already
//! revoked", and producers "SHOULD treat zero as 'the post-state is what you
//! asked for', not as an error"), while the `notOwner` error code carries "The
//! auth service MUST NOT reveal whether the session exists at all when the
//! producer is not its owner."
//!
//! Both hold only if a session that is not there and a session that is not
//! yours answer identically. These tests pin that: same status, same payload,
//! byte for byte.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, get_session, now_epoch, store_session};

/// The caller's signing seed. `auth/revoke-session/0.1` declares `proof`
/// REQUIRED, so the DID and the key behind it have to come from one place —
/// item 6 rejects a document whose issuer disagrees with the identity its token
/// authenticates.
const CALLER_SEED: u8 = 0x70;

fn caller() -> String {
    vta_service::test_support::did_for_seed(CALLER_SEED).0
}
const STRANGER: &str = "did:key:z6MkRevokeStranger";

async fn seed_session(ctx: &TestAppContext, session_id: &str, did: &str) {
    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some(format!("rt-{session_id}")),
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();
}

/// Dispatch a `revoke-session` for `target`, authenticated as `caller().as_str()` on
/// `caller_session` with `role`. Returns `(status, response document)`.
async fn revoke(
    router: &axum::Router,
    ctx: &TestAppContext,
    caller_session: &str,
    role: &str,
    target: &str,
    doc_id: &str,
) -> (StatusCode, Value) {
    let claims = ctx.jwt_keys.new_claims(
        caller(),
        caller_session.into(),
        role.into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{doc_id}"),
        "type": "https://trusttasks.org/spec/auth/revoke-session/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": &caller(),
        "recipient": "did:key:z6MkTestVTA",
        "payload": { "sessionId": target },
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as(CALLER_SEED, &mut typed);
    let doc = serde_json::to_value(&typed).expect("envelope serialises");
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The happy path, and then the retry of it.
#[tokio::test]
async fn revoking_own_session_counts_one_then_zero() {
    let (router, ctx) = build_test_app().await;
    seed_session(&ctx, "sess-here", &caller()).await;
    seed_session(&ctx, "sess-other-device", caller().as_str()).await;

    let (status, v) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-other-device",
        "revoke-1",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["payload"]["revokedCount"], 1, "{v}");
    assert!(
        get_session(&ctx.sessions_ks, "sess-other-device")
            .await
            .unwrap()
            .is_none(),
        "the session must actually be gone, not merely reported gone"
    );

    // The retry. `vta-sdk`'s `retry_safety` table calls this task `RetrySafe`,
    // and the response schema names this exact case — "Zero is a valid outcome
    // (e.g. the named sessionId was already revoked)". It used to reject.
    let (status, v) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-other-device",
        "revoke-2",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a retried revoke is not an error: {v}"
    );
    assert_eq!(v["payload"]["revokedCount"], 0, "{v}");
}

/// The disclosure rule, which is the whole reason zero is ambiguous: a session
/// belonging to someone else must be indistinguishable from one that was never
/// there.
#[tokio::test]
async fn a_stranger_session_and_a_missing_one_answer_identically() {
    let (router, ctx) = build_test_app().await;
    seed_session(&ctx, "sess-here", &caller()).await;
    seed_session(&ctx, "sess-not-yours", STRANGER).await;

    let (exists_status, exists) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-not-yours",
        "revoke-3",
    )
    .await;
    let (absent_status, absent) = revoke(
        &router,
        &ctx,
        "sess-here",
        "reader",
        "sess-never-existed",
        "revoke-4",
    )
    .await;

    assert_eq!(exists_status, absent_status, "status must not disclose");
    assert_eq!(
        exists["payload"], absent["payload"],
        "payload must not disclose: a caller who is not the owner learns \
         nothing about whether the session exists"
    );
    assert_eq!(exists["payload"]["revokedCount"], 0, "{exists}");

    // And the stranger's session is untouched — non-disclosure is not a licence
    // to revoke it.
    assert!(
        get_session(&ctx.sessions_ks, "sess-not-yours")
            .await
            .unwrap()
            .is_some(),
        "answering zero must not have deleted a session the caller cannot touch"
    );
}

/// An admin does reach another subject's session — the authorisation rule is
/// unchanged, only what a *refusal* discloses.
#[tokio::test]
async fn an_admin_revokes_another_subjects_session() {
    let (router, ctx) = build_test_app().await;
    seed_session(&ctx, "sess-here", &caller()).await;
    seed_session(&ctx, "sess-not-yours", STRANGER).await;

    let (status, v) = revoke(
        &router,
        &ctx,
        "sess-here",
        "admin",
        "sess-not-yours",
        "revoke-5",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["payload"]["revokedCount"], 1, "{v}");
    assert!(
        get_session(&ctx.sessions_ks, "sess-not-yours")
            .await
            .unwrap()
            .is_none()
    );
}
