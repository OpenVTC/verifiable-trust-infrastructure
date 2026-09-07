//! Integration test for `auth/whoami/0.1` — session introspection over the
//! trust-task dispatcher (bearer-authed, like revoke-session).
//!
//! The point of whoami is to surface the **live** session state: a bearer
//! token minted at AAL1 keeps saying `acr=aal1` until it's refreshed, but if
//! the session was stepped up to AAL2 in the meantime, whoami reports the
//! current `acr` (read from the session, not the stale token) plus
//! freshly-resolved roles, scopes and capabilities — without re-issuing any
//! token.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

async fn seed_admin_acl(ctx: &TestAppContext, did: &str, contexts: Vec<String>) {
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_contexts(contexts)
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");
}

#[tokio::test]
async fn whoami_reports_live_session_acr_not_stale_token() {
    let (router, ctx) = build_test_app().await;
    // Seeded: `auth/whoami/0.1` declares `proof` REQUIRED, so the subject needs
    // a key, and item 6 needs it to be the same identity the token names.
    const SUBJECT_SEED: u8 = 0xB0;
    let did = vta_service::test_support::did_for_seed(SUBJECT_SEED).0;
    let did = did.as_str();
    let session_id = "sess-whoami-1";
    seed_admin_acl(&ctx, did, vec!["ctx1".into()]).await;

    // The session has been stepped up to AAL2 (e.g. via approve-response).
    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into(), "passkey".into()],
        acr: "aal2".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    // The bearer token, however, was minted BEFORE the step-up: no `with_aal`,
    // so its `acr` is stale (empty / AAL1).
    let claims = ctx.jwt_keys.new_claims(
        did.into(),
        session_id.into(),
        "admin".into(),
        vec![],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": "urn:uuid:whoami-itest-1",
        "type": "https://trusttasks.org/spec/auth/whoami/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {},
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as(SUBJECT_SEED, &mut typed);
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
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(status, StatusCode::OK, "whoami must succeed: {v}");
    let s = &v["payload"]["session"];
    assert_eq!(s["subject"], did, "{v}");
    assert_eq!(s["id"], session_id, "{v}");
    // The live session acr (aal2) — NOT the stale token's (aal1/empty).
    assert_eq!(
        s["acr"], "aal2",
        "whoami must report the session's current acr, not the token's: {v}"
    );
    assert!(
        s["amr"].as_array().unwrap().iter().any(|m| m == "passkey"),
        "live amr should include the step-up factor: {v}"
    );
    // Freshly-resolved authority from the ACL.
    assert!(
        v["payload"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "admin"),
        "{v}"
    );
    assert!(
        v["payload"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "ctx:ctx1"),
        "scopes mirror the access-token `ctx:<id>` form: {v}"
    );
    // issuedAt / expiresAt are present timestamps.
    assert!(s["issuedAt"].as_str().is_some(), "{v}");
    assert!(s["expiresAt"].as_str().is_some(), "{v}");
}

/// The capability set whoami reports is the **effective** one, and the
/// difference is the whole reason the member exists.
///
/// An entry that narrows nothing is the commonest entry there is, and its
/// stored list is empty. Reporting the stored list would answer "what has this
/// entry been narrowed to" — a question almost nobody is asking — and read as
/// "you may do nothing" for a full administrator.
///
/// The additive capabilities make it sharper still: no role derives
/// `persona-holder`, so a consumer computing a role's own set would never see a
/// grant of it, which is exactly the case the console could not previously tell
/// apart from an absence of authority.
#[tokio::test]
async fn whoami_reports_effective_capabilities_including_an_additive_grant() {
    let (router, ctx) = build_test_app().await;
    const SUBJECT_SEED: u8 = 0xB3;
    let did = vta_service::test_support::did_for_seed(SUBJECT_SEED).0;
    let did = did.as_str();
    let session_id = "sess-whoami-caps";

    // A context-SCOPED admin, granted holder authority by name. Before
    // `persona-holder` existed this shape could not be expressed at all: the
    // pool was reachable only by an admin with no context restriction.
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_contexts(vec!["ctx1".to_string()])
        .with_capabilities(vec![vti_common::acl::Capability::PersonaHolder])
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed scoped admin with a holder grant");

    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    let claims = ctx.jwt_keys.new_claims(
        did.into(),
        session_id.into(),
        "admin".into(),
        vec!["ctx1".to_string()],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": "urn:uuid:whoami-caps-1",
        "type": "https://trusttasks.org/spec/auth/whoami/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {},
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as(SUBJECT_SEED, &mut typed);
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
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(status, StatusCode::OK, "whoami must succeed: {v}");
    let caps = v["payload"]["capabilities"]
        .as_array()
        .unwrap_or_else(|| panic!("capabilities must be reported: {v}"));

    // The grant, in the kebab-case the wire uses.
    assert!(
        caps.iter().any(|c| c == "persona-holder"),
        "a capability granted by name must be visible, or a client cannot tell \
         it apart from an absence of authority: {v}"
    );
    // And the role's own set rides alongside it — an additive grant narrows
    // nothing, and a client reading this to decide what to offer needs both.
    assert!(
        caps.iter().any(|c| c == "vault-read"),
        "the role's derived capabilities must still be reported: {v}"
    );
    // The grant is not a promotion: the entry is still scoped to one context.
    assert!(
        v["payload"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "ctx:ctx1"),
        "holder authority must not widen the entry's context scope: {v}"
    );
}

/// An ungranted entry reports its role's set and nothing more — the other half
/// of the pair, without which the test above would pass against a handler that
/// reported every capability that exists.
#[tokio::test]
async fn whoami_does_not_invent_a_capability_nobody_granted() {
    let (router, ctx) = build_test_app().await;
    const SUBJECT_SEED: u8 = 0xB4;
    let did = vta_service::test_support::did_for_seed(SUBJECT_SEED).0;
    let did = did.as_str();
    let session_id = "sess-whoami-nocaps";
    seed_admin_acl(&ctx, did, vec!["ctx1".into()]).await;

    let session = Session {
        session_id: session_id.into(),
        did: did.into(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: None,
        refresh_expires_at: Some(now_epoch() + 86_400),
        tee_attested: false,
        amr: vec!["did".into()],
        acr: "aal1".into(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    let claims = ctx.jwt_keys.new_claims(
        did.into(),
        session_id.into(),
        "admin".into(),
        vec!["ctx1".to_string()],
        900,
        false,
    );
    let token = ctx.jwt_keys.encode(&claims).unwrap();

    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": "urn:uuid:whoami-caps-2",
        "type": "https://trusttasks.org/spec/auth/whoami/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": did,
        "recipient": "did:key:z6MkTestVTA",
        "payload": {},
    }))
    .expect("envelope deserialises");
    vta_service::test_support::sign_as(SUBJECT_SEED, &mut typed);
    let doc = serde_json::to_value(&typed).expect("envelope serialises");
    let req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    let caps = v["payload"]["capabilities"].as_array().expect("reported");
    assert!(
        !caps.iter().any(|c| c == "persona-holder"),
        "no role derives holder authority, so an ungranted entry must not report \
         it — this is the assertion that makes the granted case mean something: {v}"
    );
    assert!(caps.iter().any(|c| c == "vault-read"), "{v}");
}

#[tokio::test]
async fn whoami_without_bearer_is_unauthorized() {
    let (router, _ctx) = build_test_app().await;
    let doc = json!({
        "id": "urn:uuid:whoami-itest-2",
        "type": "https://trusttasks.org/spec/auth/whoami/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "whoami requires a bearer token (the dispatcher is authed)"
    );
}
