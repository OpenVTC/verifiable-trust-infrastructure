//! Keyring VTI-09 and VTI-23 over the HTTPS binding (`POST /trust-tasks`)
//! and the legacy `POST /keys` route.
//!
//! The DIDComm and TSP halves live beside the bindings they test
//! (`messaging::router::keyring_vti_09_27`, `messaging::tsp_inbound::
//! keyring_vti_09_27`); the three together are what "the same document
//! requirements on every transport" (VTI-OPS-021) means in practice. The
//! end-to-end run over a real mediator is `tests/e2e/tests/keyring_vti_23_27.rs`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{TestAppContext, build_test_app, did_for_seed, sign_as};

const KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";

async fn post(router: &axum::Router, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A signed `keys/create` document from the identity `seed` names, deriving in
/// `ctx1` (which `build_test_app` seeds).
fn keys_create(ctx: &TestAppContext, seed: u8) -> Value {
    let (did, _) = did_for_seed(seed);
    let mut doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:vti-23-{seed}-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "type": KEYS_CREATE,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": did,
        "recipient": ctx.vta_did,
        "payload": { "keyType": "ed25519", "contextId": "ctx1", "label": "persona" },
    }))
    .expect("a well-formed document");
    sign_as(seed, &mut doc);
    serde_json::to_value(doc).unwrap()
}

/// VTI-09: a bare payload posted to the HTTPS binding is refused with the
/// `malformedRequest` the VTC gives — the same answer DIDComm and TSP give.
#[tokio::test]
async fn vti_09_a_bare_payload_over_https_is_refused_as_malformed() {
    let (router, ctx) = build_test_app().await;
    let (did, _) = did_for_seed(0x51);
    let token = ctx.mint_token(&did, "admin", vec![]).await;

    let (status, body) = post(
        &router,
        "/trust-tasks",
        &token,
        &json!({ "keyType": "ed25519", "contextId": "ctx1" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["type"]
            .as_str()
            .is_some_and(|t| t.starts_with("https://trusttasks.org/spec/trust-task-error/")),
        "{body}"
    );
    assert_eq!(body["payload"]["code"], "malformedRequest", "{body}");
    assert!(
        body["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("missing field `id`")),
        "{body}"
    );
}

/// VTI-23: an `initiator` scoped to a context carries `key-mint`, so
/// `keys/create` succeeds for it over HTTPS; a `reader` does not, and is refused
/// naming the capability.
#[tokio::test]
async fn vti_23_keys_create_over_https_needs_key_mint_not_admin() {
    let (router, ctx) = build_test_app().await;

    let (manager, _) = did_for_seed(0x52);
    let token = ctx
        .mint_token(&manager, "initiator", vec!["ctx1".into()])
        .await;
    let (status, body) = post(&router, "/trust-tasks", &token, &keys_create(&ctx, 0x52)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an initiator derives key-mint: {body}"
    );
    // Derived under `ctx1`'s base path (`m/26'/2'/0'`, seeded by the harness).
    assert!(
        body["payload"]["key"]["derivationPath"]
            .as_str()
            .is_some_and(|p| p.starts_with("m/26'/2'/0'/")),
        "{body}"
    );

    let (reader, _) = did_for_seed(0x53);
    let token = ctx.mint_token(&reader, "reader", vec!["ctx1".into()]).await;
    let (status, body) = post(&router, "/trust-tasks", &token, &keys_create(&ctx, 0x53)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["payload"]["code"], "permissionDenied", "{body}");
    assert!(
        body["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("key-mint")),
        "{body}"
    );
}

/// VTI-23 on the legacy route: `POST /keys` was deleted outright (see the
/// `deprecation` module docs — the REST routes over `acl`/`audit`/`config`/
/// `contexts`/`did_templates`/`keys` went in one pass, no shim, no counter).
/// The only root-level fallback left is the did:webvh wildcard GET route
/// (`setup` → `webvh`, on by default), so a POST here 405s rather than
/// 404ing, and never reaches a handler. Assert the route stays gone.
#[tokio::test]
async fn vti_23_post_keys_needs_key_mint_not_admin() {
    let (router, ctx) = build_test_app().await;
    let request = json!({ "key_type": "ed25519", "context_id": "ctx1", "label": "persona" });

    let (manager, _) = did_for_seed(0x54);
    let token = ctx
        .mint_token(&manager, "initiator", vec!["ctx1".into()])
        .await;
    let (status, body) = post(&router, "/keys", &token, &request).await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "the retired /keys REST route must stay gone: {body}"
    );
}
