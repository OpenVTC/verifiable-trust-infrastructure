//! Integration test for **refresh via an `auth/refresh/0.1` Trust Task over
//! REST** — the transport-agnostic refresh path that completes the mobile REST
//! auth loop (login lands in `authenticate_trust_task.rs`).
//!
//! Refresh carries **no proof**: the opaque refresh token in the payload is the
//! bearer credential (OAuth2 §10.4), verified server-side by the rotating
//! reverse-index. So this exercises route → `TrustTask` parse → canonical
//! `handle_refresh` → token rotation, with no signing ceremony.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{
    Session, SessionState, now_epoch, store_refresh_index, store_session,
};

async fn seed_admin_acl(ctx: &TestAppContext, did: &str) {
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");
}

/// Seed an authenticated session with a live refresh token + its reverse index.
async fn seed_authenticated_session(
    ctx: &TestAppContext,
    did: &str,
    refresh_token: &str,
) -> String {
    let session_id = format!("sess-{}", uuid::Uuid::new_v4());
    let session = Session {
        session_id: session_id.clone(),
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some(refresh_token.to_string()),
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session)
        .await
        .expect("store session");
    store_refresh_index(&ctx.sessions_ks, refresh_token, &session_id)
        .await
        .expect("store refresh index");
    session_id
}

fn refresh_doc(refresh_token: &str) -> Vec<u8> {
    json!({
        "id": "urn:uuid:refresh-itest-1",
        "type": "https://trusttasks.org/spec/auth/refresh/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": "did:key:z6MkRefresher",
        "recipient": "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD",
        "payload": { "refreshToken": refresh_token },
    })
    .to_string()
    .into_bytes()
}

fn post(uri: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.9")
        .body(Body::from(body))
        .unwrap()
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("request");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes).to_string()}));
    (status, v)
}

#[tokio::test]
async fn trust_task_refresh_rotates_tokens() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkRefresher";
    let old_token = "refresh-tok-itest-aaaa";
    seed_admin_acl(&ctx, did).await;
    seed_authenticated_session(&ctx, did, old_token).await;

    let (status, body) = send(&router, post("/auth/refresh", refresh_doc(old_token))).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Trust Task refresh must succeed: {body}"
    );
    // TT request → TT `#response` doc (tokens + session under `payload`).
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|t| t.ends_with("/auth/refresh/0.1#response")),
        "response is a TT #response doc: {body}"
    );
    assert_eq!(body["payload"]["session"]["subject"], did, "{body}");
    assert!(
        body["payload"]["tokens"]["accessToken"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "a fresh access token is issued: {body}"
    );
    // RFC 6749 §10.4 rotation: a new refresh token, different from the old one.
    let new_token = body["payload"]["tokens"]["refreshToken"]
        .as_str()
        .expect("rotated refresh token");
    assert_ne!(new_token, old_token, "refresh token must rotate: {body}");

    // The presented token never yields a *second, parallel* chain — which is
    // the property rotation exists to guarantee. It is not simply refused
    // here, though:
    // an immediate replay falls inside `refresh_reuse_grace` with the
    // replacement still unspent, which is the shape of a client retrying a
    // rotation response it never received, so it is answered idempotently
    // with the same pair. Replay once that window has closed, or once the
    // chain has moved on, is reuse — see
    // `refresh_token_reuse_is_detected_and_revokes_the_whole_session`.
    let (replay_status, replay_body) =
        send(&router, post("/auth/refresh", refresh_doc(old_token))).await;
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "an immediate retry is a lost response, not a compromise: {replay_body}"
    );
    assert_eq!(
        replay_body["payload"]["tokens"]["refreshToken"]
            .as_str()
            .expect("replayed refresh token"),
        new_token,
        "the retry must replay the same token, never mint a second live one",
    );
}

#[tokio::test]
async fn trust_task_refresh_rejects_unknown_token() {
    let (router, _ctx) = build_test_app().await;
    let (status, _) = send(
        &router,
        post("/auth/refresh", refresh_doc("refresh-tok-never-issued")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unknown refresh token must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Refresh-token reuse detection (RFC 9700 §4.14.2)
// ---------------------------------------------------------------------------

/// Pull the rotated refresh token out of a `#response` doc.
fn rotated_token(body: &Value) -> String {
    body["payload"]["tokens"]["refreshToken"]
        .as_str()
        .unwrap_or_else(|| panic!("rotated refresh token in {body}"))
        .to_string()
}

/// Reuse detection, end to end against the real router and keyspace.
///
/// The attacker's token and the victim's are the same chain, so once the
/// victim rotates past the stolen token, replaying it is unambiguous reuse.
/// No clock manipulation is needed — the successor has been spent, which
/// closes the retry window on its own.
///
/// Detection must revoke the *session*, not just refuse the replay: the
/// currently-live token has to die with it, or the attacker (or the victim)
/// would keep a working chain.
#[tokio::test]
async fn refresh_token_reuse_is_detected_and_revokes_the_whole_session() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkRefresher";
    let stolen = "refresh-tok-itest-reuse";
    seed_admin_acl(&ctx, did).await;
    seed_authenticated_session(&ctx, did, stolen).await;

    // The victim refreshes twice, so the chain moves past the stolen token.
    let (s1, b1) = send(&router, post("/auth/refresh", refresh_doc(stolen))).await;
    assert_eq!(s1, StatusCode::OK, "{b1}");
    let second = rotated_token(&b1);

    let (s2, b2) = send(&router, post("/auth/refresh", refresh_doc(&second))).await;
    assert_eq!(s2, StatusCode::OK, "{b2}");
    let live = rotated_token(&b2);

    // The attacker replays the token they stole earlier.
    let (replay, _) = send(&router, post("/auth/refresh", refresh_doc(stolen))).await;
    assert_eq!(
        replay,
        StatusCode::UNAUTHORIZED,
        "a replayed refresh token must be refused",
    );

    // …and that must have taken the session down with it.
    let (after, _) = send(&router, post("/auth/refresh", refresh_doc(&live))).await;
    assert_eq!(
        after,
        StatusCode::UNAUTHORIZED,
        "detection must revoke the session, killing the still-live token too",
    );
}

/// The non-attack the grace window exists for: the client never received the
/// rotation response, so it retries with the only token it has. It must get
/// the same pair back and stay signed in — a dropped connection is not a
/// compromise, and signing the user out on one would make the common network
/// fault indistinguishable from theft.
#[tokio::test]
async fn an_immediate_refresh_retry_replays_the_same_tokens_and_keeps_the_session() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkRefresher";
    let token = "refresh-tok-itest-retry";
    seed_admin_acl(&ctx, did).await;
    seed_authenticated_session(&ctx, did, token).await;

    // The response to this one is "lost in flight".
    let (s1, lost) = send(&router, post("/auth/refresh", refresh_doc(token))).await;
    assert_eq!(s1, StatusCode::OK, "{lost}");

    // The client retries with the same (only) token it holds.
    let (s2, retried) = send(&router, post("/auth/refresh", refresh_doc(token))).await;
    assert_eq!(
        s2,
        StatusCode::OK,
        "a retry inside the grace window must succeed: {retried}",
    );
    assert_eq!(
        rotated_token(&retried),
        rotated_token(&lost),
        "the retry must replay the same pair, not rotate again",
    );

    // The session is intact and the replayed token still works.
    let (s3, b3) = send(
        &router,
        post("/auth/refresh", refresh_doc(&rotated_token(&retried))),
    )
    .await;
    assert_eq!(s3, StatusCode::OK, "the client stays signed in: {b3}");
}

/// A token this node never issued is refused without collateral damage — it
/// must not be mistaken for a replay and revoke an unrelated live session.
#[tokio::test]
async fn an_unknown_token_does_not_revoke_a_live_session() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkRefresher";
    let token = "refresh-tok-itest-bystander";
    seed_admin_acl(&ctx, did).await;
    seed_authenticated_session(&ctx, did, token).await;

    let (status, _) = send(
        &router,
        post("/auth/refresh", refresh_doc("refresh-tok-never-issued")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (after, body) = send(&router, post("/auth/refresh", refresh_doc(token))).await;
    assert_eq!(
        after,
        StatusCode::OK,
        "an unrecognised token must not disturb a live session: {body}",
    );
}
