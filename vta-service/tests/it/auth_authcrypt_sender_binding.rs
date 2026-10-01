//! DIDComm authcrypt sender binding: the skid/apu battery that used to drive
//! the retired `/auth/` and `/auth/refresh` REST handlers directly.
//!
//! An authcrypt JWE names its sender key twice: `skid` (the key a recipient
//! resolves for the key agreement) and `apu` (the PartyUInfo the derivation is
//! bound to, which the unpack metadata reports as `encrypted_from_kid`). A
//! conforming packer writes one key id into both. `vti_common::auth::
//! bind_authcrypt_sender` requires that no sender is trusted for anybody but
//! the holder of the key actually used.
//!
//! **The forged/genuine-envelope battery against the auth family is gone, not
//! merely moved.** It drove the old `/auth/` and `/auth/refresh` REST
//! handlers' own inline `atm.unpack` + `bind_authcrypt_sender` call directly
//! with a crafted envelope — a synchronous, offline-testable entry point.
//! `POST /trust-tasks` has no equivalent: it only ever reads a plain JSON
//! Trust-Task envelope (`ceremony::peek_type_uri`), never calls `atm.unpack`,
//! and a DIDComm-transported Trust Task (the auth family included) now runs
//! through the generic mediator-relay inbound pipeline
//! (`messaging::service::{inbound_gate, handle_didcomm}`), which authenticates
//! on the transport's own `verified`/`sender` flags rather than
//! `bind_authcrypt_sender`, and which has no offline/in-process entry point
//! here — see `auth_flow`'s module doc for the full accounting.
//!
//! What is NOT gone:
//! - `bind_authcrypt_sender` itself keeps its own unit tests
//!   (`vti_common::auth::didcomm`), skid/apu split, missing headers, wrong
//!   wrapping and `from`-mismatch included.
//! - Its one remaining direct-unpack caller, vault unseal, is exercised right
//!   here (`vault_unseal_refuses_forged_apu_sender`, below) and in
//!   `vault_unseal_authcrypt.rs`.
//! - The DIDComm transport's own forged/anoncrypt/plaintext-sender refusal —
//!   which now covers every Trust Task, the auth family included — is
//!   unit-tested in `messaging::service` (`keyring_vti_27_gate` and the
//!   `inbound_gate` tests).
//! - A live-mediator authcrypt sign-in round trip lives in the e2e suite.
//!
//! So this file pins two things: the retired REST entry points stay gone, and
//! the one surviving direct-unpack caller (vault unseal) still refuses a
//! forged sender.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::build_test_app;
use vti_common::auth::authcrypt_test_support::{
    DidKeyParty, forge_authcrypt, genuine_authcrypt, offline_atm_with,
};

async fn request(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("request failed");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&body).to_string()}));
    (status, json)
}

fn post(uri: &str, content_type: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", content_type)
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::from(body))
        .unwrap()
}

/// The retired `/auth/` REST route — the authcrypt-envelope entry point the
/// forged/genuine battery used to drive — stays gone: any body posted there
/// (a JWE included) hits nothing but the did:webvh wildcard GET route
/// (`setup` → `webvh`, on by default) and 405s, never reaching any auth logic.
#[tokio::test]
async fn auth_route_stays_gone_for_a_didcomm_envelope() {
    let (router, _ctx) = build_test_app().await;
    let (status, body) = request(&router, post("/auth/", "text/plain", "irrelevant".into())).await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "the retired /auth/ REST route must stay gone: {body}"
    );
}

/// Same for `/auth/refresh`.
#[tokio::test]
async fn auth_refresh_route_stays_gone_for_a_didcomm_envelope() {
    let (router, _ctx) = build_test_app().await;
    let (status, body) = request(
        &router,
        post("/auth/refresh", "text/plain", "irrelevant".into()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "the retired /auth/refresh REST route must stay gone: {body}"
    );
}

/// Vault unseal (`vault/upsert` with a `didcomm-authcrypt` sealed secret)
/// refuses a secret sealed with the attacker's key while naming the caller in
/// `apu` and `from`.
#[tokio::test]
async fn vault_unseal_refuses_forged_apu_sender() {
    use vta_service::operations::vault::upsert::{UnsealError, unseal_secret};

    let vta = DidKeyParty::from_seed([0x54; 32]);
    let caller = DidKeyParty::from_seed([0x55; 32]);
    let attacker = DidKeyParty::from_seed([0x56; 32]);
    let atm = offline_atm_with(std::slice::from_ref(&vta.key_agreement)).await;
    let vta_pub = vta.public();
    let plaintext = vti_common::auth::authcrypt_test_support::plaintext_message(
        "https://trusttasks.org/spec/vault/_shared/0.1/vault-secret",
        &caller.did,
        &vta.did,
        json!({ "secret": "s3cr3t" }),
    );
    let forged = forge_authcrypt(&plaintext, &attacker, &caller.kid, (&vta.kid, &vta_pub));
    match unseal_secret(&atm, &caller.did, &forged).await {
        Err(UnsealError::UnpackFailed(msg)) => assert!(
            msg.contains("authcrypt sender key binding failed"),
            "expected the sender-binding refusal, got: {msg}"
        ),
        Ok(_) => panic!("a forged sealed secret must not open"),
        Err(_) => panic!("a forged sealed secret must be refused by the sender binding"),
    }

    // The caller's own sealed secret still opens.
    let genuine = genuine_authcrypt(&plaintext, &caller, (&vta.kid, &vta_pub));
    match unseal_secret(&atm, &caller.did, &genuine).await {
        Err(UnsealError::UnpackFailed(msg)) => {
            panic!("the genuine sealed secret must pass the sender binding: {msg}")
        }
        Err(UnsealError::SenderMismatch { .. }) => {
            panic!("the genuine sealed secret must bind to its caller")
        }
        // Opened, or reached body deserialisation: past the binding either way.
        _ => {}
    }
}
