//! Integration tests for the deferred-presentation approval surface over the
//! trust-task dispatcher (`credential-exchange/pending-{list,approve,deny}/1.0`).
//!
//! These exercise the **wire plumbing**: dispatch, the super-admin gate, and
//! the list/deny/approve handlers end to end through the real router. A
//! `pending-present:` record is seeded directly (the defer half is already
//! wired in `messaging::handlers::handle_credential_query`); the full
//! re-present with a real held credential is covered at the operations layer
//! (`operations::credential_exchange::defer_then_approve_presents_*`, where the
//! holder fixture lives).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::operations::credential_exchange::pending;
use vta_service::test_support::{TestAppContext, build_test_app};
use vti_common::auth::session::{Session, SessionState, now_epoch, store_session};

/// Seed an ACL entry + an authenticated session and mint a matching bearer
/// token. `contexts` empty ⇒ super-admin; non-empty ⇒ context-scoped admin.
async fn seed_admin_and_token(
    ctx: &TestAppContext,
    did: &str,
    session_id: &str,
    contexts: Vec<String>,
) -> String {
    let entry = vti_common::acl::AclEntry::new(did, vti_common::acl::Role::Admin, "test")
        .with_contexts(contexts.clone())
        .with_created_at(1);
    vti_common::acl::store_acl_entry(&ctx.acl_ks, &entry)
        .await
        .expect("seed admin ACL");

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
        acr: String::new(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&ctx.sessions_ks, &session).await.unwrap();

    let claims = ctx.jwt_keys.new_claims(
        did.into(),
        session_id.into(),
        "admin".into(),
        contexts,
        900,
        false,
    );
    ctx.jwt_keys.encode(&claims).unwrap()
}

/// A `Pending`, far-from-expiry deferral record, built by deserialization so
/// the test needs no direct `DcqlQuery` dependency.
fn seed_record_json(id: &str) -> Value {
    json!({
        "id": id,
        "verifier_did": "did:web:stranger.example",
        "requested": [{
            "credential_query_id": "membership",
            "credential_id": "urn:cred:1",
            "claims": ["givenName"]
        }],
        "purpose": "join the Acme community",
        "query": {
            "dcql_query": {
                "credentials": [{
                    "id": "membership",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["https://openvtc.org/credentials/MembershipCredential"] }
                }]
            },
            "nonce": "n-1",
            "purpose": "join the Acme community"
        },
        "status": "pending",
        "created_at": "2026-06-12T00:00:00Z",
        "expires_at": "2126-06-12T00:00:00Z"
    })
}

async fn put_pending(ctx: &TestAppContext, id: &str) {
    let record: pending::PendingPresentation =
        serde_json::from_value(seed_record_json(id)).expect("deserialize pending record");
    pending::put(&ctx.vault_ks, &record)
        .await
        .expect("seed pending record");
}

fn tt(id: &str, type_uri: &str, issuer: &str, payload: Value) -> Value {
    json!({
        "id": id,
        "type": type_uri,
        "issuer": issuer,
        "recipient": "did:key:z6MkTestVTA",
        "payload": payload,
    })
}

async fn post_tt(router: &axum::Router, token: Option<&str>, doc: &Value) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn list_then_deny_over_the_wire_deletes_the_record() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkPendingAdmin";
    let token = seed_admin_and_token(&ctx, did, "sess-pending-1", vec![]).await;
    put_pending(&ctx, "req-wire-1").await;

    // List: the seeded deferral shows up with its approver-facing fields.
    let (status, v) = post_tt(
        &router,
        Some(&token),
        &tt(
            "urn:uuid:pend-list-1",
            "https://trusttasks.org/spec/credential-exchange/pending-list/1.0",
            did,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list must succeed: {v}");
    let items = v["payload"]["pending"].as_array().expect("pending array");
    assert_eq!(items.len(), 1, "{v}");
    assert_eq!(items[0]["id"], "req-wire-1", "{v}");
    assert_eq!(items[0]["verifier_did"], "did:web:stranger.example", "{v}");
    assert_eq!(items[0]["requested"][0]["claims"][0], "givenName", "{v}");
    // The internal full query is NOT leaked in the summary.
    assert!(
        items[0].get("query").is_none(),
        "summary omits the query: {v}"
    );

    // Deny: succeeds and removes the record (delete-on-terminal).
    let (status, v) = post_tt(
        &router,
        Some(&token),
        &tt(
            "urn:uuid:pend-deny-1",
            "https://trusttasks.org/spec/credential-exchange/pending-deny/1.0",
            did,
            json!({ "id": "req-wire-1" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deny must succeed: {v}");
    assert_eq!(v["payload"]["status"], "denied", "{v}");
    assert!(
        pending::get(&ctx.vault_ks, "req-wire-1")
            .await
            .unwrap()
            .is_none(),
        "denied record is deleted"
    );

    // A follow-up list is now empty.
    let (status, v) = post_tt(
        &router,
        Some(&token),
        &tt(
            "urn:uuid:pend-list-2",
            "https://trusttasks.org/spec/credential-exchange/pending-list/1.0",
            did,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["payload"]["pending"].as_array().unwrap().len(), 0, "{v}");
}

#[tokio::test]
async fn pending_surface_requires_super_admin() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkContextAdmin";
    // Context-scoped admin (non-empty contexts) ⇒ NOT super-admin.
    let token = seed_admin_and_token(&ctx, did, "sess-pending-2", vec!["ctx1".into()]).await;
    put_pending(&ctx, "req-wire-2").await;

    for (op, payload) in [
        ("pending-list", json!({})),
        ("pending-approve", json!({ "id": "req-wire-2" })),
        ("pending-deny", json!({ "id": "req-wire-2" })),
    ] {
        let (status, v) = post_tt(
            &router,
            Some(&token),
            &tt(
                &format!("urn:uuid:pend-gate-{op}"),
                &format!("https://trusttasks.org/spec/credential-exchange/{op}/1.0"),
                did,
                payload,
            ),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "{op} must reject a non-super-admin: {v}"
        );
    }

    // The record is untouched by the rejected calls.
    assert!(
        pending::get(&ctx.vault_ks, "req-wire-2")
            .await
            .unwrap()
            .is_some(),
        "a rejected deny must not delete the record"
    );
}

#[tokio::test]
async fn approve_without_a_held_credential_fails_but_dispatches() {
    let (router, ctx) = build_test_app().await;
    let did = "did:key:z6MkPendingAdmin3";
    let token = seed_admin_and_token(&ctx, did, "sess-pending-3", vec![]).await;
    // A deferral whose query matches no held credential (empty vault).
    put_pending(&ctx, "req-wire-3").await;

    let (status, v) = post_tt(
        &router,
        Some(&token),
        &tt(
            "urn:uuid:pend-approve-1",
            "https://trusttasks.org/spec/credential-exchange/pending-approve/1.0",
            did,
            json!({ "id": "req-wire-3" }),
        ),
    )
    .await;
    // The approve handler ran (super-admin gate passed, op invoked) and the op
    // refused because nothing in the vault satisfies the deferred query.
    assert_ne!(
        status,
        StatusCode::OK,
        "approve with no held credential must fail: {v}"
    );
}

#[tokio::test]
async fn pending_surface_requires_a_bearer_token() {
    let (router, _ctx) = build_test_app().await;
    let (status, _v) = post_tt(
        &router,
        None,
        &tt(
            "urn:uuid:pend-anon",
            "https://trusttasks.org/spec/credential-exchange/pending-list/1.0",
            "did:key:z6MkAnon",
            json!({}),
        ),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the dispatcher is authed — no bearer, no access"
    );
}
