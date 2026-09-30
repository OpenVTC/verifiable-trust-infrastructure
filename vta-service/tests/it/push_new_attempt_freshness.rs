//! A push that outlives its document's acceptance window is re-issued as a new
//! attempt (`vti_common::trust_task_push::new_attempt`), and the consuming VTA
//! performs it **once and only once**.
//!
//! # What is being held
//!
//! The push engine signs a document once and may deliver it much later — an
//! escalation an hour in, a hop the mediator refused for twenty minutes, a copy
//! collected when the recipient reconnects. The VTA refuses a document older
//! than `ACCEPTANCE_WINDOW` (+ skew) as `expired` (VTI-OPS-024), so the engine
//! replaces it with a new attempt: fresh `id`, fresh `issuedAt`, signed again,
//! the same `idempotencyKey`.
//!
//! These tests hold the consumer end of that contract, against the real
//! dispatch spine, counting what actually exists afterwards rather than
//! trusting status codes (two successful creates both answer `200`):
//!
//! - the stale original is refused, and performs nothing;
//! - the new attempt is performed;
//! - a replay of the new attempt, byte for byte, performs nothing (§7.2 item
//!   11, keyed on the document `id`);
//! - a *further* new attempt — the engine escalated again — performs nothing,
//!   because every attempt carries one idempotency key (VTI-OPS-064);
//! - re-signing under the **same** `id` — the fix this deliberately is not —
//!   is refused as `idConflict` (SPEC §8.4), which is why the engine mints a
//!   fresh one.
//!
//! `keys/create` stands in for the pushed task because it is `Keyed` (a second
//! execution mints a second key) and countable over the public surface.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use trust_tasks_rs::TrustTask;
use vta_service::test_support::build_test_app;
use vti_common::trust_task::ACCEPTANCE_WINDOW;
use vti_common::trust_task_push::new_attempt;

const KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";
const KEYS_LIST: &str = "https://trusttasks.org/spec/keys/list/0.1";
const RECIPIENT: &str = "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD";
const SEED: u8 = 0x52;
const CONTEXT: &str = "test";

fn producer() -> String {
    vta_service::test_support::did_for_seed(SEED).0
}

async fn app() -> (axum::Router, String) {
    let (router, ctx) = build_test_app().await;
    vta_service::contexts::create_context(&ctx.contexts_ks, CONTEXT, "Push freshness tests")
        .await
        .expect("context");
    let token = ctx.mint_token(&producer(), "admin", vec![]).await;
    (router, token)
}

fn sign(doc: Value) -> Value {
    let mut typed: TrustTask<Value> = serde_json::from_value(doc).expect("a document");
    vta_service::test_support::sign_as(SEED, &mut typed);
    serde_json::to_value(&typed).expect("serialises")
}

/// A signed `keys/create`, issued at `issued_at`, optionally keyed.
fn create_doc(id: &str, issued_at: chrono::DateTime<chrono::Utc>, key: Option<&str>) -> Value {
    let mut doc = json!({
        "id": format!("urn:uuid:{id}"),
        "type": KEYS_CREATE,
        "issuedAt": issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": producer(),
        "recipient": RECIPIENT,
        "payload": {
            "keyType": "ed25519",
            "derivationPath": "",
            "label": "pushed",
            "contextId": CONTEXT,
        },
    });
    if let Some(k) = key {
        doc["idempotencyKey"] = json!(k);
    }
    sign(doc)
}

/// What the engine does to a stale document: a new attempt, signed again.
fn engine_new_attempt(previous: &Value) -> Value {
    sign(new_attempt(previous, chrono::Utc::now()).expect("a new attempt"))
}

/// A document past the window: issued the window plus the skew tolerance plus
/// a minute ago.
fn stale_time() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
        - ACCEPTANCE_WINDOW
        - trust_tasks_rs::DEFAULT_SKEW
        - chrono::TimeDelta::minutes(1)
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

async fn key_count(router: &axum::Router, token: &str) -> usize {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let doc = sign(json!({
        "id": format!("urn:uuid:list-{}", N.fetch_add(1, Ordering::Relaxed)),
        "type": KEYS_LIST,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": producer(),
        "recipient": RECIPIENT,
        "payload": { "contextId": CONTEXT },
    }));
    let (status, body) = post(router, token, &doc).await;
    assert_eq!(status, StatusCode::OK, "keys/list must succeed: {body}");
    body["payload"]["keys"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default()
}

fn error_code(body: &Value) -> Option<&str> {
    body["payload"]["code"].as_str()
}

/// The whole contract, in the order a push lives it.
#[tokio::test]
async fn a_push_re_issued_after_the_freshness_window_is_performed_once_and_only_once() {
    let (router, token) = app().await;
    let before = key_count(&router, &token).await;
    let key = "urn:uuid:push-freshness-once";

    // The document as signed when the push began, delivered past the window.
    let stale = create_doc("push-original", stale_time(), Some(key));
    let (status, body) = post(&router, &token, &stale).await;
    assert_eq!(
        error_code(&body),
        Some("expired"),
        "the original, delivered late, is refused as expired ({status}): {body}"
    );
    assert_eq!(
        key_count(&router, &token).await,
        before,
        "and performs nothing"
    );

    // The engine's new attempt: fresh id, fresh issuedAt, same key.
    let first = engine_new_attempt(&stale);
    assert_ne!(first["id"], stale["id"]);
    let (status, body) = post(&router, &token, &first).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the new attempt is performed: {body}"
    );
    assert_eq!(key_count(&router, &token).await, before + 1);

    // The same new attempt again, byte for byte — a transport redelivery, or
    // the copy an escalation sent on the next transport.
    let (status, body) = post(&router, &token, &first).await;
    assert!(
        status.is_success(),
        "a duplicate is not a failure (SPEC §7.2): {status} {body}"
    );
    assert_eq!(
        key_count(&router, &token).await,
        before + 1,
        "a replayed identical document is not performed again"
    );

    // A further new attempt — the engine re-issued again, say on escalation.
    let second = engine_new_attempt(&first);
    assert_ne!(second["id"], first["id"]);
    let (status, body) = post(&router, &token, &second).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "answered from the first attempt's result: {body}"
    );
    assert_eq!(
        key_count(&router, &token).await,
        before + 1,
        "one idempotency key across every attempt: performed once"
    );
}

/// Re-signing the accepted document under its **same** `id` with a fresh
/// `issuedAt` is a different document reusing an `id` (SPEC §8.4), refused as
/// `idConflict` (§7.2 item 11). That is why the engine mints a fresh `id`
/// rather than re-stamping the old one.
#[tokio::test]
async fn re_signing_under_the_same_id_is_refused_as_an_id_conflict() {
    let (router, token) = app().await;
    let doc = create_doc(
        "push-same-id",
        chrono::Utc::now() - chrono::TimeDelta::minutes(2),
        Some("urn:uuid:push-same-id"),
    );
    let (status, body) = post(&router, &token, &doc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = key_count(&router, &token).await;

    let mut restamped = doc.clone();
    restamped["issuedAt"] =
        json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    restamped.as_object_mut().unwrap().remove("proof");
    let restamped = sign(restamped);
    let (_, body) = post(&router, &token, &restamped).await;
    assert_eq!(error_code(&body), Some("idConflict"), "{body}");
    assert_eq!(key_count(&router, &token).await, before);
}

/// The control: without a key, two new attempts at one push are two
/// operations. This is what the key is measured against — and why a push whose
/// repeat leaves a second artefact must carry one.
#[tokio::test]
async fn without_a_key_each_new_attempt_is_performed() {
    let (router, token) = app().await;
    let before = key_count(&router, &token).await;
    let stale = create_doc("push-unkeyed", stale_time(), None);

    for attempt in [engine_new_attempt(&stale), engine_new_attempt(&stale)] {
        let (status, body) = post(&router, &token, &attempt).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(key_count(&router, &token).await, before + 2);
}
