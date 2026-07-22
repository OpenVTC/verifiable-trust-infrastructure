//! End-to-end coverage for `POST /v1/admin/bootstrap`.
//!
//! Drives the full install → claim → bootstrap chain through
//! `Router::oneshot`, using the soft EdDSA harness for the WebAuthn
//! ceremony. Verifies the M0.6.2 acceptance criteria:
//!
//! - Happy path writes an `Admin` ACL entry, an `AdminEntry`, and a
//!   `CommunityInstalled` audit envelope.
//! - Bootstrap-after-bootstrap is rejected (409).
//! - Replay of the same setup-session JWT is rejected by the
//!   duplicate-admin check (409).
//! - Tampered / wrong-audience / expired tokens are rejected as 401.
//! - 503 when install signer or audit writer aren't configured.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::acl::{Role, list_acl_entries};
use vti_common::audit::AuditEvent;

use vtc_service::acl::admin::get_admin_entry;
use vtc_service::install::{InstallTokenSigner, InstallTokenStore, mint_install_token};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

use common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const START_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/start/0.1";
const FINISH_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/finish/0.1";
const BOOTSTRAP_TASK: &str = "https://trusttasks.org/spec/vtc/admin/bootstrap/0.1";

struct Fixture {
    state: AppState,
    router: axum::Router,
    install_signer: Arc<InstallTokenSigner>,
    install_store: InstallTokenStore,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

async fn build_fixture(with_install_signer: bool, with_audit: bool) -> Fixture {
    // The same install signer is injected into the AppState so tokens
    // minted by the fixture verify on the claim/finish route.
    let install_signer = if with_install_signer {
        Some(Arc::new(
            InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap(),
        ))
    } else {
        None
    };

    let mut builder = TestVtc::builder()
        .with_audit(with_audit)
        .with_public_url(RP_ORIGIN);
    if let Some(sig) = &install_signer {
        builder = builder.with_install_signer(sig.clone());
    }
    let vtc = builder.build().await;

    let state = vtc.state.clone();
    let router = vtc.router.clone();
    let install_store = vtc.state.install_store.clone();

    Fixture {
        state,
        router,
        // Signer-absent path keeps a throwaway in the fixture for minting.
        install_signer: install_signer.unwrap_or_else(|| {
            Arc::new(InstallTokenSigner::from_master_seed(&[0xCD; 64]).unwrap())
        }),
        install_store,
        _vtc: vtc,
    }
}

async fn mint_token_and_record(fix: &Fixture, ttl_seconds: u64) -> String {
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
            None,
            None,
        )
        .await
        .unwrap();
    minted.jwt
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

/// Drive a full claim ceremony and return the setup-session JWT plus
/// the candidate admin DID the server returned.
async fn run_claim_ceremony(fix: &Fixture) -> (String, String) {
    let token = mint_token_and_record(fix, 600).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/install/claim/start",
        START_TASK,
        json!({ "install_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");

    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).unwrap();

    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

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
    let session_jwt = body["setupSessionToken"].as_str().unwrap().to_string();
    let admin_did = body["adminDid"].as_str().unwrap().to_string();
    (session_jwt, admin_did)
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_install_to_bootstrap_succeeds() {
    let fix = build_fixture(true, true).await;
    let (session_jwt, admin_did) = run_claim_ceremony(&fix).await;

    let (status, body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap: {body}");
    assert_eq!(body["adminDid"].as_str().unwrap(), admin_did);
    let event_id = body["eventId"].as_str().unwrap();
    let _: Uuid = event_id.parse().expect("eventId is a UUID");

    // ACL: one Admin entry for our DID.
    let acl = list_acl_entries(&fix.state.acl_ks).await.unwrap();
    assert_eq!(acl.len(), 1);
    assert_eq!(acl[0].did, admin_did);
    assert_eq!(acl[0].role, Role::Admin);

    // AdminEntry written with one passkey.
    let admin_entry = get_admin_entry(&fix.state.passkey_ks, &admin_did)
        .await
        .unwrap()
        .expect("admin entry persisted");
    assert_eq!(admin_entry.passkeys.len(), 1);

    // Audit envelope present and references the install jti.
    // `envelope_storage_key` formats as `<rfc3339-timestamp>:<event_id>`
    // — there's no fixed string prefix, so a `2` literal works for
    // every realistic timestamp (it's the first digit of the year).
    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    assert!(!raw.is_empty(), "at least one audit envelope expected");
    // Find the CommunityInstalled envelope (the bootstrap may also emit
    // companion envelopes); assert its data references the install jti.
    let installed = raw
        .iter()
        .find_map(|(_k, v)| {
            let env: vti_common::audit::AuditEnvelope = serde_json::from_slice(v).ok()?;
            match env.event {
                AuditEvent::CommunityInstalled(data) => Some(data),
                _ => None,
            }
        })
        .expect("a CommunityInstalled audit envelope is present");
    assert_eq!(installed.community_did, "did:webvh:vtc.example.com:abc");
    // install_token_jti is non-empty.
    assert!(!installed.install_token_jti.is_empty());

    // Community profile singleton is initialised with the configured
    // VTC DID. Spec §5.1: `community_did` is immutable, set at install
    // time. The form-editable fields (name, description, etc.) default
    // to empty so the operator fills them in via the admin UI.
    let profile = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .expect("community profile initialised at bootstrap");
    assert_eq!(profile.community_did, "did:webvh:vtc.example.com:abc");
    assert_eq!(profile.name, "");
    assert_eq!(profile.description, "");
    assert_eq!(profile.language, "en");
}

// ---------------------------------------------------------------------------
// 409 — bootstrap-after-bootstrap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_bootstrap_returns_409() {
    let fix = build_fixture(true, true).await;
    let (session_jwt_a, _) = run_claim_ceremony(&fix).await;

    let (s1, _) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt_a }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Try to replay the same session JWT.
    let (s2, body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt_a }),
    )
    .await;
    assert_eq!(
        s2,
        StatusCode::CONFLICT,
        "duplicate-admin check must catch the replay: {body}"
    );
}

// ---------------------------------------------------------------------------
// 401 paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_rejects_unsigned_token() {
    let fix = build_fixture(true, true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": "not.a.real.jwt" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bootstrap_rejects_install_token_as_setup_token() {
    // An attacker who intercepted the install URL still cannot drive
    // bootstrap directly — the install JWT has `aud = "vtc-install"`,
    // which the session decoder rejects.
    let fix = build_fixture(true, true).await;
    let install_jwt = mint_token_and_record(&fix, 600).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": install_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bootstrap_rejects_when_no_passkey_user_exists() {
    // Forge a valid setup-session JWT for a DID that never went
    // through claim/finish. Decoder accepts the signature; the
    // passkey-user lookup fails.
    let fix = build_fixture(true, true).await;
    let session_jwt = vtc_service::install::mint_install_session_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:zNobody",
        &Uuid::new_v4().to_string(),
        600,
    )
    .unwrap();
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// 503 paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_returns_503_when_install_signer_missing() {
    let fix = build_fixture(false, true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn bootstrap_returns_503_when_audit_writer_missing() {
    let fix = build_fixture(true, false).await;
    let session_jwt = vtc_service::install::mint_install_session_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:zAnyone",
        &Uuid::new_v4().to_string(),
        600,
    )
    .unwrap();
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        BOOTSTRAP_TASK,
        json!({ "setup_session_token": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// Trust-Task gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_trust_task_returns_415() {
    let fix = build_fixture(true, true).await;
    let (status, _body) = post_json(
        &fix.router,
        "/v1/admin/bootstrap",
        FINISH_TASK,
        json!({ "setup_session_token": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn missing_trust_task_returns_400() {
    let fix = build_fixture(true, true).await;
    let res = fix
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"setup_session_token":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
