//! The record of accepted document identifiers — **VTI-OPS-025 … 027**, SPEC
//! §7.2 item 11 — measured on the VTA through `POST /trust-tasks`.
//!
//! Like `idempotency_trust_task`, every assertion that matters is on the number
//! of keys that exist afterwards, not on the status a second call returned: a
//! `keys/create` executed twice answers `200` twice.
//!
//! The record was a process-local `InMemoryReplayGuard` until it moved into the
//! `accepted_ids` keyspace, and two things were wrong with that which these
//! tests hold:
//!
//! - **It was lost on restart** (VTI-OPS-026). A document accepted before a
//!   restart is still inside its acceptance window after it, and its replay
//!   executed again.
//! - **A document refused after its claim kept its `id` spent.** The spine
//!   settled the claim only on its last line, so a refusal returned early
//!   (schema, spec policy, proof) left the `id` "in flight" for the window, and
//!   the corrected resend under the same `id` was answered `202` and never ran.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, TestAppOptions, build_test_app_with};

const KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";
const KEYS_LIST: &str = "https://trusttasks.org/spec/keys/list/0.2";
const CALLER_SEED: u8 = 0x42;
const CONTEXT: &str = "test";
const RECIPIENT: &str = "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD";

fn caller() -> String {
    vta_service::test_support::did_for_seed(CALLER_SEED).0
}

/// The app over `dir` (a fresh store when `None`), the `test` context in place,
/// and an admin token for [`caller`].
async fn app_at(dir: Option<&std::path::Path>) -> (axum::Router, TestAppContext, String) {
    let (router, ctx) = build_test_app_with(TestAppOptions {
        data_dir: dir.map(std::path::Path::to_path_buf),
        ..Default::default()
    })
    .await;
    if vta_service::contexts::get_context(&ctx.contexts_ks, CONTEXT)
        .await
        .expect("read context")
        .is_none()
    {
        vta_service::contexts::create_context(&ctx.contexts_ks, CONTEXT, "Accepted-id tests")
            .await
            .expect("context");
    }
    let token = ctx.mint_token(caller().as_str(), "admin", vec![]).await;
    (router, ctx, token)
}

/// A signed `keys/create` document under `id`, with `payload` as its payload.
fn signed(id: &str, payload: Value) -> Value {
    let doc = json!({
        "id": id,
        "type": KEYS_CREATE,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": caller(),
        "recipient": RECIPIENT,
        "payload": payload,
    });
    let mut typed: trust_tasks_rs::TrustTask<Value> =
        serde_json::from_value(doc).expect("envelope deserialises");
    vta_service::test_support::sign_as(CALLER_SEED, &mut typed);
    serde_json::to_value(&typed).expect("envelope serialises")
}

fn create_payload(label: &str) -> Value {
    json!({
        "keyType": "ed25519",
        "derivationPath": "",
        "label": label,
        "contextId": CONTEXT,
    })
}

async fn post(router: &axum::Router, token: &str, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn key_count(router: &axum::Router, token: &str, id: &str) -> usize {
    let doc = json!({
        "id": id,
        "type": KEYS_LIST,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": caller(),
        "recipient": RECIPIENT,
        "payload": { "contextId": CONTEXT },
    });
    let (status, body) = post(router, token, &doc).await;
    assert_eq!(status, StatusCode::OK, "keys/list must succeed: {body}");
    body["payload"]["keys"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default()
}

/// **VTI-OPS-026** across a restart: the same signed document, presented again
/// after the VTA restarted but inside its acceptance window, is a duplicate —
/// not a second key. The control is the fresh document at the end, which still
/// performs, so the refusal is the record's doing and not `keys/create`
/// failing after a restart.
#[tokio::test]
async fn vti_ops_026_a_document_replayed_after_a_restart_is_not_executed_again() {
    let dir = tempfile::tempdir().expect("temp dir");
    let doc = signed("urn:uuid:accepted-restart-1", create_payload("once"));

    let (router, ctx, token) = app_at(Some(dir.path())).await;
    let (s, first) = post(&router, &token, &doc).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    assert_eq!(key_count(&router, &token, "urn:uuid:list-1").await, 1);
    drop(router);
    drop(ctx);

    let (router, _ctx, token) = app_at(Some(dir.path())).await;
    let (s, replay) = post(&router, &token, &doc).await;
    assert!(
        s.is_success(),
        "a duplicate is answered, never refused (§7.2): {s} {replay}"
    );
    if s == StatusCode::OK {
        assert_eq!(
            replay["payload"]["key"]["keyId"], first["payload"]["key"]["keyId"],
            "a duplicate answered with a body is answered with the first result"
        );
    }
    assert_eq!(
        key_count(&router, &token, "urn:uuid:list-2").await,
        1,
        "the replay after the restart must not mint a second key"
    );

    let (s, b) = post(
        &router,
        &token,
        &signed("urn:uuid:accepted-restart-2", create_payload("control")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        key_count(&router, &token, "urn:uuid:list-3").await,
        2,
        "a new document still performs: the control"
    );
}

/// A document refused **after** its `id` was claimed gives the `id` back, so
/// the corrected document under the same `id` runs. Refused here by its
/// payload schema (an unknown member), which the spine checks after the claim.
#[tokio::test]
async fn a_document_refused_after_its_claim_does_not_spend_its_id() {
    let (router, _ctx, token) = app_at(None).await;
    const ID: &str = "urn:uuid:accepted-corrected";

    let mut bad = create_payload("corrected");
    bad["notAMember"] = json!(true);
    let (s, refused) = post(&router, &token, &signed(ID, bad)).await;
    assert!(
        s.is_client_error(),
        "the malformed document is refused: {s} {refused}"
    );
    assert_eq!(key_count(&router, &token, "urn:uuid:list-a").await, 0);

    let (s, ran) = post(&router, &token, &signed(ID, create_payload("corrected"))).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the corrected resend under the same id runs: {ran}"
    );
    assert_eq!(key_count(&router, &token, "urn:uuid:list-b").await, 1);
}

/// **VTI-OPS-025**: a different document under an `id` already accepted is
/// `idConflict`, and executes nothing.
#[tokio::test]
async fn vti_ops_025_a_different_document_under_an_accepted_id_is_a_conflict() {
    let (router, _ctx, token) = app_at(None).await;
    const ID: &str = "urn:uuid:accepted-conflict";

    let (s, b) = post(&router, &token, &signed(ID, create_payload("first"))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, conflict) = post(&router, &token, &signed(ID, create_payload("second"))).await;
    assert_ne!(s, StatusCode::OK, "{conflict}");
    assert!(conflict.to_string().contains("idConflict"), "{conflict}");
    assert_eq!(
        key_count(&router, &token, "urn:uuid:list-c").await,
        1,
        "the conflicting document made nothing"
    );
}
