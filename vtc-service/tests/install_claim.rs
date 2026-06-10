//! End-to-end coverage for `POST /v1/install/claim/{start,finish}`.
//!
//! Drives the full install ceremony through `Router::oneshot`,
//! using the soft EdDSA authenticator harness (`tests/common`) to
//! produce real WebAuthn responses and the install module's own
//! signer/store to mint and consume install tokens.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use vtc_service::install::{InstallTokenSigner, InstallTokenStore, mint_install_token};
use vtc_service::test_support::TestVtc;

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const START_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/start/1.0";
const FINISH_TASK: &str = "https://trusttasks.org/openvtc/vtc/install/claim/finish/1.0";

struct Fixture {
    router: axum::Router,
    install_signer: Arc<InstallTokenSigner>,
    install_store: InstallTokenStore,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture(public_url: Option<&str>, with_install_signer: bool) -> Fixture {
    // 64 bytes of test entropy mirror what production loads from the secret
    // store (32 Ed25519 + 32 X25519); HKDF only cares about length. The
    // same signer is injected into the AppState so tokens minted here verify.
    let install_signer = if with_install_signer {
        Some(Arc::new(
            InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
    } else {
        None
    };

    let mut builder = TestVtc::builder();
    if let Some(u) = public_url {
        builder = builder.with_public_url(u);
    }
    if let Some(sig) = &install_signer {
        builder = builder.with_install_signer(sig.clone());
    }
    let vtc = builder.build().await;

    let install_store = vtc.state.install_store.clone();

    Fixture {
        router: vtc.router.clone(),
        // When the AppState signer is absent (testing the 503 path), the
        // fixture still needs *a* signer to mint tokens with — a throwaway.
        install_signer: install_signer.unwrap_or_else(|| {
            Arc::new(InstallTokenSigner::from_master_seed(&[0xCD; 64]).unwrap())
        }),
        install_store,
        _vtc: vtc,
    }
}

async fn mint_token_and_record(fix: &Fixture, ttl_seconds: u64) -> (String, Uuid) {
    mint_token_and_record_with_secret(fix, ttl_seconds, None).await
}

async fn mint_token_and_record_with_secret(
    fix: &Fixture,
    ttl_seconds: u64,
    claim_secret_hash: Option<String>,
) -> (String, Uuid) {
    let minted = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        ttl_seconds,
    )
    .expect("mint install token");
    let exp = Utc::now() + ChronoDuration::seconds(ttl_seconds as i64);
    fix.install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
            claim_secret_hash,
            Some("did:key:z6MkAdmin".into()),
        )
        .await
        .expect("record_issued");
    (minted.jwt, minted.jti)
}

async fn post_json(
    router: &axum::Router,
    path: &str,
    trust_task: &str,
    body: Value,
) -> (StatusCode, Value) {
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("Trust-Task", trust_task)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn parse_ccr(body: &Value) -> CreationChallengeResponse {
    serde_json::from_value(body.get("options").cloned().expect("options field"))
        .expect("CreationChallengeResponse parses")
}

// ---------------------------------------------------------------------------
// Happy-path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_ceremony_completes_end_to_end() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    // -- start ---------------------------------------------------------
    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");

    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let ccr = parse_ccr(&body);

    // -- harness produces the registration response --------------------
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

    // -- finish --------------------------------------------------------
    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": registration_id,
            "webauthn_response": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {body}");
    let admin_did = body["adminDid"].as_str().unwrap();
    assert!(admin_did.starts_with("did:key:z"));
    assert!(!body["setupSessionToken"].as_str().unwrap().is_empty());

    // -- replay finish: must fail (token is now Consumed) --------------
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": registration_id,
            "webauthn_response": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Claim-secret paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_secret_happy_path_completes_ceremony() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let secret = "ABCDEFGHJK";
    let hash = vtc_service::install::claim_secret::hash(secret).unwrap();
    let (token, _jti) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token, "claim_secret": secret }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start with correct secret: {body}");
    assert!(body["registrationId"].as_str().is_some());
}

#[tokio::test]
async fn claim_secret_missing_returns_required_code() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let hash = vtc_service::install::claim_secret::hash("WHATEVER12").unwrap();
    let (token, _) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(
        body["error"].as_str(),
        Some("claim_secret_required"),
        "discriminated error code; got {body}"
    );
}

#[tokio::test]
async fn claim_secret_wrong_returns_invalid_code() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let hash = vtc_service::install::claim_secret::hash("CORRECT123").unwrap();
    let (token, _) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token, "claim_secret": "WRONGWRONG" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(
        body["error"].as_str(),
        Some("claim_secret_invalid"),
        "discriminated error code; got {body}"
    );
}

// ---------------------------------------------------------------------------
// 503 paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_returns_503_when_install_signer_missing() {
    let fix = build_fixture(Some(RP_ORIGIN), false).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": "bogus" }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn start_returns_503_when_webauthn_missing() {
    let fix = build_fixture(None, true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// Failure modes — auth + ceremony state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_rejects_unsigned_token() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": "not.a.real.jwt" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn start_rejects_unknown_jti() {
    // Mint a valid token but never call `record_issued` — the install
    // store has no state for the jti and `start_claim` must fail.
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let minted = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        600,
    )
    .unwrap();
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": minted.jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn second_concurrent_start_within_window_is_conflict() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    let (status1, _) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": &token }),
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    let (status2, _) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": &token }),
    )
    .await;
    assert_eq!(status2, StatusCode::CONFLICT);
}

#[tokio::test]
async fn finish_rejects_mismatched_registration_id() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    let (_status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    let ccr = parse_ccr(&body);
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _pub) = authenticator.register(&ccr, RP_ORIGIN);

    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": Uuid::new_v4().to_string(),
            "webauthn_response": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn finish_without_start_fails() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, jti) = mint_token_and_record(&fix, 600).await;

    // Skip start. Fabricate a registration_id and a placeholder
    // webauthn_response — finish must refuse because no
    // registration state exists for this jti.
    let dummy_cred = json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": {
            "attestationObject": "AA",
            "clientDataJSON": "AA"
        },
        "type": "public-key"
    });

    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "install_token": token,
            "registration_id": jti.to_string(),
            "webauthn_response": dummy_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Trust-Task gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_trust_task_header_returns_400() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/install/claim/start")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"install_token":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_trust_task_header_returns_415() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        FINISH_TASK, // start endpoint with finish task
        json!({ "install_token": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
