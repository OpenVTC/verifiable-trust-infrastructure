//! End-to-end coverage for `vtc/install/claim/{start,finish}/0.2`.
//!
//! Drives the full install ceremony through `Router::oneshot`, posting signed
//! -- unsigned, rather: install/claim carries no proof requirement, the
//! install token itself is the credential -- documents to the shared
//! `POST /v1/trust-tasks` door (`trust_tasks::install_tasks`), using the soft
//! EdDSA authenticator harness (`tests/common`) to produce real WebAuthn
//! responses and the install module's own signer/store to mint and consume
//! install tokens.
//!
//! Every refusal here is a framework `trust-task-error` document. A
//! **declared** code (`vtc/install/claim/{start,finish}:*`) is an *extended*
//! code and so always answers `422` (`trust-tasks-https::status_for_code`);
//! an **undeclared** one falls through `app_error_to_reject`'s generic
//! taxonomy, which also lands on `422` for a `Conflict`/`NotFound` (mapped to
//! the standard `taskFailed` code, discriminated by `payload.details.reason`)
//! and `500` for anything else (including the old bespoke `503`s this ported
//! from — `AppError::ServiceError` has no dedicated arm in that taxonomy).

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

/// Every declared code, and the app-level `Conflict`/`NotFound` taxonomy fall
/// through to, is an extended or standard code the HTTPS binding buckets at
/// `422 Unprocessable Entity` — see the module doc.
const REJECTED: StatusCode = StatusCode::UNPROCESSABLE_ENTITY;

struct Fixture {
    router: axum::Router,
    install_signer: Arc<InstallTokenSigner>,
    install_store: InstallTokenStore,
    recipient: String,
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
    let recipient = vtc
        .state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .expect("the test VTC has a DID");

    Fixture {
        router: vtc.router.clone(),
        // When the AppState signer is absent (testing the missing-signer
        // path), the fixture still needs *a* signer to mint tokens with — a
        // throwaway.
        install_signer: install_signer.unwrap_or_else(|| {
            Arc::new(InstallTokenSigner::from_master_seed(&[0xCD; 64]).unwrap())
        }),
        install_store,
        recipient,
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

/// Post `payload` as an unsigned `type_uri` document (install/claim carries no
/// proof requirement — the install token itself is the credential) to the
/// shared document endpoint, and return its status and the response
/// document's `payload`.
async fn post_json(fix: &Fixture, type_uri: &str, payload: Value) -> (StatusCode, Value) {
    let doc = json!({
        "id": format!("urn:uuid:{}", Uuid::new_v4()),
        "type": type_uri,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "recipient": fix.recipient,
        "issuer": "did:key:z6MkAnonymousInstallCaller",
        "payload": payload,
    });
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/trust-tasks")
                .header("content-type", "application/json")
                .body(Body::from(doc.to_string()))
                .unwrap(),
        )
        .await
        .expect("oneshot");
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body["payload"].clone())
}

fn parse_ccr(payload: &Value) -> CreationChallengeResponse {
    serde_json::from_value(payload.get("options").cloned().expect("options field"))
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
    let (status, payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::OK, "start: {payload}");

    let registration_id = payload["registrationId"].as_str().unwrap().to_string();
    let ccr = parse_ccr(&payload);

    // -- harness produces the registration response --------------------
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

    // -- finish --------------------------------------------------------
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {payload}");
    let admin_did = payload["adminDid"].as_str().unwrap().to_string();
    assert!(admin_did.starts_with("did:key:z"));
    assert!(!payload["setupSessionToken"].as_str().unwrap().is_empty());

    // -- replay finish: idempotent (P3.12) -----------------------------
    // A dropped response / crash between consume-and-return must not
    // strand the operator. Replaying the same finish against the now-
    // `Consumed` token re-issues a usable setup-session token for the
    // same admin DID rather than hard-rejecting.
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "idempotent replay: {payload}");
    assert_eq!(payload["adminDid"].as_str().unwrap(), admin_did);
    assert!(!payload["setupSessionToken"].as_str().unwrap().is_empty());

    // -- start after finish: still rejected ----------------------------
    // Idempotent finish must not reopen the ceremony: a fresh `start`
    // against the consumed token requires `Issued` and is refused.
    let (status, _payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
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

    let (status, payload) = post_json(
        &fix,
        START_TASK,
        json!({ "installToken": token, "claimSecret": secret }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "start with correct secret: {payload}"
    );
    assert!(payload["registrationId"].as_str().is_some());
}

#[tokio::test]
async fn claim_secret_missing_returns_required_code() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let hash = vtc_service::install::claim_secret::hash("WHATEVER12").unwrap();
    let (token, _) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, REJECTED, "payload: {payload}");
    assert_eq!(payload["code"], START_ERR_INVALID_TOKEN, "{payload}");
    assert!(
        payload["message"]
            .as_str()
            .is_some_and(|m| m.contains("claim_secret_required")),
        "discriminating message prefix; got {payload}"
    );
}

#[tokio::test]
async fn claim_secret_wrong_returns_invalid_code() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let hash = vtc_service::install::claim_secret::hash("CORRECT123").unwrap();
    let (token, _) = mint_token_and_record_with_secret(&fix, 600, Some(hash)).await;

    let (status, payload) = post_json(
        &fix,
        START_TASK,
        json!({ "installToken": token, "claimSecret": "WRONGWRONG" }),
    )
    .await;
    assert_eq!(status, REJECTED, "payload: {payload}");
    assert_eq!(payload["code"], START_ERR_INVALID_TOKEN, "{payload}");
    assert!(
        payload["message"]
            .as_str()
            .is_some_and(|m| m.contains("claim_secret_invalid")),
        "discriminating message prefix; got {payload}"
    );
}

// ---------------------------------------------------------------------------
// Unavailable paths (missing signer / WebAuthn config)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_is_refused_when_install_signer_missing() {
    let fix = build_fixture(Some(RP_ORIGIN), false).await;
    let (status, _payload) = post_json(&fix, START_TASK, json!({ "installToken": "bogus" })).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn start_is_refused_when_webauthn_missing() {
    let fix = build_fixture(None, true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, _payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

// ---------------------------------------------------------------------------
// Failure modes — auth + ceremony state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_rejects_unsigned_token() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (status, payload) = post_json(
        &fix,
        START_TASK,
        json!({ "installToken": "not.a.real.jwt" }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], START_ERR_INVALID_TOKEN, "{payload}");
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
    let (status, payload) =
        post_json(&fix, START_TASK, json!({ "installToken": minted.jwt })).await;
    assert_eq!(status, REJECTED, "{payload}");
}

#[tokio::test]
async fn second_concurrent_start_within_window_is_conflict() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    let (status1, _) = post_json(&fix, START_TASK, json!({ "installToken": &token })).await;
    assert_eq!(status1, StatusCode::OK);

    let (status2, payload) = post_json(&fix, START_TASK, json!({ "installToken": &token })).await;
    assert_eq!(status2, REJECTED, "{payload}");
    assert_eq!(payload["details"]["reason"], "conflict", "{payload}");
}

#[tokio::test]
async fn finish_rejects_mismatched_registration_id() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _jti) = mint_token_and_record(&fix, 600).await;

    let (_status, payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    let ccr = parse_ccr(&payload);
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _pub) = authenticator.register(&ccr, RP_ORIGIN);

    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": Uuid::new_v4().to_string(),
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        payload["code"], FINISH_ERR_REGISTRATION_MISMATCH,
        "{payload}"
    );
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

    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": jti.to_string(),
            "webauthnResponse": dummy_cred,
        }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
}

// ---------------------------------------------------------------------------
// Unknown document type
// ---------------------------------------------------------------------------

/// A document naming a type this spine does not serve is `unsupportedType` —
/// the property the retired REST mount's `Trust-Task` header gate (missing →
/// 400, mismatched → 415) used to enforce is now the framework's generic
/// dispatch gate, shared by every verb on this door.
#[tokio::test]
async fn an_unknown_document_type_is_unsupported() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (status, payload) = post_json(
        &fix,
        "https://trusttasks.org/spec/vtc/install/claim/nope/0.1",
        json!({ "installToken": "x" }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], "unsupportedType", "{payload}");
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

/// A token that is not ours, one we never recorded, and one already consumed
/// are each `invalidToken` (unchanged code, now a `422` status). A missing
/// claim secret keeps the same declared code with a discriminating message
/// prefix, and a second concurrent start stays the undeclared conflict.
#[tokio::test]
async fn the_claim_start_task_answers_with_the_code_its_spec_declares() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let start = |token: String| {
        let fix = &fix;
        async move { post_json(fix, START_TASK, json!({ "installToken": token })).await }
    };

    let (status, payload) = start("not.a.real.jwt".into()).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], START_ERR_INVALID_TOKEN, "{payload}");

    let unrecorded = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        600,
    )
    .unwrap();
    let (status, payload) = start(unrecorded.jwt).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], START_ERR_INVALID_TOKEN, "{payload}");

    // Consumed: run the whole ceremony, then start again.
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, payload) = start(token.clone()).await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let registration_id = payload["registrationId"].as_str().unwrap().to_string();
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _pub) = authenticator.register(&parse_ccr(&payload), RP_ORIGIN);
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let (status, payload) = start(token).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], START_ERR_INVALID_TOKEN, "{payload}");

    // A concurrent-ceremony lock is not a token fault.
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, _) = start(token.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, payload) = start(token).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["details"]["reason"], "conflict", "{payload}");
}

/// Finish distinguishes the token (`invalidToken`), the enrolment it names
/// (`registrationMismatch`) and the WebAuthn attestation (`bindingInvalid`).
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
        let fix = &fix;
        async move {
            post_json(
                fix,
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
    let (status, payload) = finish(
        "not.a.real.jwt".into(),
        Uuid::new_v4().to_string(),
        dummy_cred.clone(),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], FINISH_ERR_INVALID_TOKEN, "{payload}");

    // registrationMismatch: no enrolment was ever opened for this token.
    let (token, jti) = mint_token_and_record(&fix, 600).await;
    let (status, payload) = finish(token.clone(), jti.to_string(), dummy_cred.clone()).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        payload["code"], FINISH_ERR_REGISTRATION_MISMATCH,
        "{payload}"
    );

    // Open the enrolment, then name a different one, and one that is not an id.
    let (status, payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let ccr = parse_ccr(&payload);
    for other in [Uuid::new_v4().to_string(), "not-a-registration".to_string()] {
        let (status, payload) = finish(token.clone(), other.clone(), dummy_cred.clone()).await;
        assert_eq!(status, REJECTED, "{other}: {payload}");
        assert_eq!(
            payload["code"], FINISH_ERR_REGISTRATION_MISMATCH,
            "{other}: {payload}"
        );
    }

    // bindingInvalid: an attestation made for another origin.
    let mut authenticator = SoftEd25519Authenticator::new();
    let (wrong_origin, _pub) = authenticator.register(&ccr, "https://evil.example.com");
    let (status, payload) = finish(
        token,
        jti.to_string(),
        serde_json::to_value(&wrong_origin).unwrap(),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], FINISH_ERR_BINDING_INVALID, "{payload}");
}
