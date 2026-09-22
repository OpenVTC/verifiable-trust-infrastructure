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
const START_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/start/0.2";
const FINISH_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/finish/0.2";

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
        json!({ "installToken": token }),
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
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {body}");
    let admin_did = body["adminDid"].as_str().unwrap().to_string();
    assert!(admin_did.starts_with("did:key:z"));
    assert!(!body["setupSessionToken"].as_str().unwrap().is_empty());

    // -- replay finish: idempotent (P3.12) -----------------------------
    // A dropped response / crash between consume-and-return must not
    // strand the operator. Replaying the same finish against the now-
    // `Consumed` token re-issues a usable setup-session token for the
    // same admin DID rather than hard-rejecting.
    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "idempotent replay: {body}");
    assert_eq!(body["adminDid"].as_str().unwrap(), admin_did);
    assert!(!body["setupSessionToken"].as_str().unwrap().is_empty());

    // -- start after finish: still rejected ----------------------------
    // Idempotent finish must not reopen the ceremony: a fresh `start`
    // against the consumed token requires `Issued` and is refused.
    let (status, _body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "installToken": token }),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "start after finish must be rejected"
    );
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
        json!({ "installToken": token, "claimSecret": secret }),
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
        json!({ "installToken": token }),
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
        json!({ "installToken": token, "claimSecret": "WRONGWRONG" }),
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
        json!({ "installToken": "bogus" }),
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
        json!({ "installToken": token }),
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
        json!({ "installToken": "not.a.real.jwt" }),
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
        json!({ "installToken": minted.jwt }),
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
        json!({ "installToken": &token }),
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    let (status2, _) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "installToken": &token }),
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
        json!({ "installToken": token }),
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
            "installToken": token,
            "registrationId": Uuid::new_v4().to_string(),
            "webauthnResponse": register_cred,
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
            "installToken": token,
            "registrationId": jti.to_string(),
            "webauthnResponse": dummy_cred,
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
                .body(Body::from(r#"{"installToken":"x"}"#))
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
        json!({ "installToken": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---------------------------------------------------------------------------
// #1600 — the codes `vtc/install/claim/{start,finish}/0.2` declare, read from
// the generated bindings.
// ---------------------------------------------------------------------------

use trust_tasks_rs::specs::vtc::install::claim as claim_spec;

const START_ERR_INVALID_TOKEN: &str = claim_spec::start::v0_2::error_codes::INVALID_TOKEN.code;
const FINISH_ERR_INVALID_TOKEN: &str = claim_spec::finish::v0_2::error_codes::INVALID_TOKEN.code;
const FINISH_ERR_REGISTRATION_MISMATCH: &str =
    claim_spec::finish::v0_2::error_codes::REGISTRATION_MISMATCH.code;
const FINISH_ERR_BINDING_INVALID: &str =
    claim_spec::finish::v0_2::error_codes::BINDING_INVALID.code;

/// The extended error code carried by a REST error body (`{"error", "code"}`).
fn rest_error_code(body: &Value) -> &str {
    body["code"].as_str().unwrap_or_default()
}

/// A token that is not ours, one we never recorded, and one already consumed
/// are each `invalidToken` (401, unchanged). A missing claim secret is not a
/// token fault and keeps its own undeclared `claim_secret_required`, and a
/// second concurrent start stays the undeclared 409.
#[tokio::test]
async fn the_claim_start_task_answers_with_the_code_its_spec_declares() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let start = |token: String| {
        let router = fix.router.clone();
        async move {
            post_json(
                &router,
                "/v1/install/claim/start",
                START_TASK,
                json!({ "installToken": token }),
            )
            .await
        }
    };

    let (status, body) = start("not.a.real.jwt".into()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(rest_error_code(&body), START_ERR_INVALID_TOKEN, "{body}");

    let unrecorded = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        600,
    )
    .unwrap();
    let (status, body) = start(unrecorded.jwt).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(rest_error_code(&body), START_ERR_INVALID_TOKEN, "{body}");

    // Consumed: run the whole ceremony, then start again.
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, body) = start(token.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _pub) = authenticator.register(&parse_ccr(&body), RP_ORIGIN);
    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/finish",
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = start(token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(rest_error_code(&body), START_ERR_INVALID_TOKEN, "{body}");

    // A concurrent-ceremony lock is not a token fault.
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, _) = start(token.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = start(token).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(rest_error_code(&body), "", "{body}");
}

/// Finish distinguishes the token (`invalidToken`), the enrolment it names
/// (`registrationMismatch`) and the WebAuthn attestation (`bindingInvalid`).
/// Every status is the 401 it was.
#[tokio::test]
async fn the_claim_finish_task_answers_with_the_codes_its_spec_declares() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let dummy_cred = json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": { "attestationObject": "AA", "clientDataJSON": "AA" },
        "type": "public-key"
    });
    let finish = |token: String, registration_id: String, cred: Value| {
        let router = fix.router.clone();
        async move {
            post_json(
                &router,
                "/v1/install/claim/finish",
                FINISH_TASK,
                json!({
                    "installToken": token,
                    "registrationId": registration_id,
                    "webauthnResponse": cred,
                }),
            )
            .await
        }
    };

    // invalidToken: not a token this community signed.
    let (status, body) = finish(
        "not.a.real.jwt".into(),
        Uuid::new_v4().to_string(),
        dummy_cred.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(rest_error_code(&body), FINISH_ERR_INVALID_TOKEN, "{body}");

    // registrationMismatch: no enrolment was ever opened for this token.
    let (token, jti) = mint_token_and_record(&fix, 600).await;
    let (status, body) = finish(token.clone(), jti.to_string(), dummy_cred.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        rest_error_code(&body),
        FINISH_ERR_REGISTRATION_MISMATCH,
        "{body}"
    );

    // Open the enrolment, then name a different one, and one that is not an id.
    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "installToken": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ccr = parse_ccr(&body);
    for other in [Uuid::new_v4().to_string(), "not-a-registration".to_string()] {
        let (status, body) = finish(token.clone(), other.clone(), dummy_cred.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{other}: {body}");
        assert_eq!(
            rest_error_code(&body),
            FINISH_ERR_REGISTRATION_MISMATCH,
            "{other}: {body}"
        );
    }

    // bindingInvalid: an attestation made for another origin.
    let mut authenticator = SoftEd25519Authenticator::new();
    let (wrong_origin, _pub) = authenticator.register(&ccr, "https://evil.example.com");
    let (status, body) = finish(
        token,
        jti.to_string(),
        serde_json::to_value(&wrong_origin).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(rest_error_code(&body), FINISH_ERR_BINDING_INVALID, "{body}");
}
