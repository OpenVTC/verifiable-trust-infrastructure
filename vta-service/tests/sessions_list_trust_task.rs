//! Integration test for `auth/sessions/list/0.1` — the multi-device session
//! enumeration over the trust-task dispatcher (bearer-authed).
//!
//! Companion to whoami: lists every **active** session for the **caller's own**
//! subject. Verifies scoping (a caller never sees another subject's sessions)
//! and the active filter (expired sessions are omitted).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

#[allow(clippy::too_many_arguments)]
async fn seed_session(
    ctx: &TestAppContext,
    session_id: &str,
    did: &str,
    acr: &str,
    amr: Vec<String>,
    refresh_expires_at: Option<u64>,
) {
    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: Some(format!("rt-{session_id}")),
        refresh_expires_at,
        tee_attested: false,
        amr,
        acr: acr.into(),
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();
}

#[tokio::test]
async fn sessions_list_returns_only_callers_active_sessions() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkMultiDevice";
    let other = "did:key:z6MkSomeoneElse";
    let now = now_epoch();

    // Two active sessions for the caller (different devices / AALs)…
    seed_session(
        &ctx,
        "sess-a",
        did,
        "aal2",
        vec!["did".into(), "passkey".into()],
        Some(now + 86_400),
    )
    .await;
    seed_session(
        &ctx,
        "sess-b",
        did,
        "aal1",
        vec!["did".into()],
        Some(now + 3_600),
    )
    .await;
    // …one expired session for the caller (must be filtered out)…
    seed_session(
        &ctx,
        "sess-expired",
        did,
        "aal1",
        vec!["did".into()],
        Some(now - 10),
    )
    .await;
    // …and one belonging to a different subject (must never leak).
    seed_session(
        &ctx,
        "sess-other",
        other,
        "aal2",
        vec!["did".into()],
        Some(now + 86_400),
    )
    .await;

    // Bearer for the caller (its own session is sess-a).
    let claims = ctx.jwt_keys.new_claims(
        did.into(),
        "sess-a".into(),
        "admin".into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    let doc = json!({
        "id": "urn:uuid:sessions-list-itest-1",
        "type": "https://trusttasks.org/spec/auth/sessions/list/0.1",
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {},
    });
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
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(status, StatusCode::OK, "sessions/list must succeed: {v}");
    let sessions = v["payload"]["sessions"].as_array().expect("sessions array");

    // Exactly the caller's two active sessions — not the expired one, not the
    // other subject's.
    let ids: Vec<&str> = sessions.iter().filter_map(|s| s["id"].as_str()).collect();
    assert_eq!(sessions.len(), 2, "only the caller's active sessions: {v}");
    assert!(ids.contains(&"sess-a") && ids.contains(&"sess-b"), "{v}");
    assert!(
        !ids.contains(&"sess-expired"),
        "expired session must be omitted: {v}"
    );
    assert!(
        !ids.contains(&"sess-other"),
        "another subject must never leak: {v}"
    );

    // Each session carries the required fields; sess-a reflects its AAL2 state.
    for s in sessions {
        assert_eq!(s["subject"], did, "{v}");
        assert!(s["issuedAt"].as_str().is_some(), "{v}");
        assert!(s["expiresAt"].as_str().is_some(), "{v}");
        assert!(s["amr"].as_array().is_some_and(|a| !a.is_empty()), "{v}");
    }
    let sess_a = sessions.iter().find(|s| s["id"] == "sess-a").unwrap();
    assert_eq!(sess_a["acr"], "aal2", "{v}");
    assert!(
        sess_a["amr"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "passkey"),
        "{v}"
    );
}

#[tokio::test]
async fn sessions_list_without_bearer_is_unauthorized() {
    let (router, _ctx) = build_test_app().await;
    let doc = json!({
        "id": "urn:uuid:sessions-list-itest-2",
        "type": "https://trusttasks.org/spec/auth/sessions/list/0.1",
        "issuer": "did:key:z6MkAnon",
        "recipient": "did:key:z6MkTestVTA",
        "payload": {},
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK, "requires a bearer token");
}
