//! End-to-end coverage for `vtc/admin/bootstrap/0.1`.
//!
//! Drives the full install → claim → bootstrap chain through
//! `Router::oneshot`, using the soft EdDSA harness for the WebAuthn
//! ceremony, posting unsigned documents to the shared `POST /v1/trust-tasks`
//! door (`trust_tasks::install_tasks`) — install/claim/bootstrap carry no
//! proof requirement; each verb's own bearer artifact is the credential.
//! Verifies the M0.6.2 acceptance criteria:
//!
//! - Happy path writes an `Admin` ACL entry, an `AdminEntry`, and a
//!   `CommunityInstalled` audit envelope.
//! - Bootstrap-after-bootstrap is rejected (`alreadyBootstrapped`).
//! - Replay of the same setup-session JWT is rejected by the
//!   duplicate-admin check (`alreadyBootstrapped`).
//! - Tampered / wrong-audience / expired tokens are rejected as `invalidToken`.
//! - Refused (`500`, this port's equivalent of the old bespoke `503`s — see
//!   `install_claim.rs`'s module doc) when install signer or audit writer
//!   aren't configured.
//!
//! Every refusal is a framework `trust-task-error` document; a **declared**
//! code is an *extended* code and so always answers `422`
//! (`trust-tasks-https::status_for_code`), except the app-level
//! `Conflict`/`NotFound` taxonomy, which also lands on `422` (the standard
//! `taskFailed` code, discriminated by `payload.details.reason`).

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
const START_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/start/0.2";
const FINISH_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/finish/0.2";
const BOOTSTRAP_TASK: &str = "https://trusttasks.org/spec/vtc/admin/bootstrap/0.1";

/// Every declared code, and the app-level `Conflict`/`NotFound` taxonomy fall
/// through to, is bucketed at `422 Unprocessable Entity` — see the module doc.
const REJECTED: StatusCode = StatusCode::UNPROCESSABLE_ENTITY;

struct Fixture {
    state: AppState,
    router: axum::Router,
    install_signer: Arc<InstallTokenSigner>,
    install_store: InstallTokenStore,
    recipient: String,
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
    let recipient = vtc
        .state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .expect("the test VTC has a DID");

    Fixture {
        state,
        router,
        // Signer-absent path keeps a throwaway in the fixture for minting.
        install_signer: install_signer.unwrap_or_else(|| {
            Arc::new(InstallTokenSigner::from_master_seed(&[0xCD; 64]).unwrap())
        }),
        install_store,
        recipient,
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

/// Post `payload` as an unsigned `type_uri` document to the shared document
/// endpoint, and return its status and the response document's `payload`.
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

/// The identifier a refusal's payload names — the error-code census's textual
/// witness scan looks for this exact call name.
fn tt_error_code(payload: &Value) -> Option<&str> {
    payload["code"].as_str()
}

/// Drive a full claim ceremony and return the setup-session JWT plus
/// the candidate admin DID the server returned.
async fn run_claim_ceremony(fix: &Fixture) -> (String, String) {
    let token = mint_token_and_record(fix, 600).await;

    let (status, payload) = post_json(fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::OK, "start: {payload}");

    let registration_id = payload["registrationId"].as_str().unwrap().to_string();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(payload["options"].clone()).unwrap();

    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

    let (status, payload) = post_json(
        fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish: {payload}");
    let session_jwt = payload["setupSessionToken"].as_str().unwrap().to_string();
    let admin_did = payload["adminDid"].as_str().unwrap().to_string();
    (session_jwt, admin_did)
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_install_to_bootstrap_succeeds() {
    let fix = build_fixture(true, true).await;
    let (session_jwt, admin_did) = run_claim_ceremony(&fix).await;

    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap: {payload}");
    assert_eq!(payload["adminDid"].as_str().unwrap(), admin_did);
    let event_id = payload["eventId"].as_str().unwrap();
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
// alreadyBootstrapped — bootstrap-after-bootstrap
// ---------------------------------------------------------------------------

/// VTI-APV-014: the co-admin `vtc setup` was given is installed beside the
/// first admin, both unrestricted, so the community can make a third
/// unrestricted admin remotely from its first day. The record is spent.
#[tokio::test]
async fn vti_apv_014_the_bootstrap_installs_the_co_admin_beside_the_first() {
    let fix = build_fixture(true, true).await;
    const CO_ADMIN: &str = "did:key:z6MkCoAdmin";
    fix.install_store.record_co_admin(CO_ADMIN).await.unwrap();
    let (session_jwt, admin_did) = run_claim_ceremony(&fix).await;

    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap: {payload}");

    let acl = list_acl_entries(&fix.state.acl_ks).await.unwrap();
    assert_eq!(acl.len(), 2, "{acl:?}");
    for did in [admin_did.as_str(), CO_ADMIN] {
        let entry = acl
            .iter()
            .find(|e| e.did == did)
            .unwrap_or_else(|| panic!("{did} installed: {acl:?}"));
        assert_eq!(entry.role, Role::Admin);
        assert!(entry.is_super_admin(), "{did} is unrestricted");
    }
    // The co-admin can enrol a passkey later; it needs none to consent.
    let co_entry = get_admin_entry(&fix.state.passkey_ks, CO_ADMIN)
        .await
        .unwrap()
        .expect("co-admin sister record");
    assert!(co_entry.passkeys.is_empty());

    assert!(
        fix.install_store.take_co_admin().await.unwrap().is_none(),
        "the record is spent by the bootstrap"
    );
}

/// A co-admin record naming the first admin installs nobody extra.
#[tokio::test]
async fn a_co_admin_that_is_the_first_admin_installs_nothing_extra() {
    let fix = build_fixture(true, true).await;
    let (session_jwt, admin_did) = run_claim_ceremony(&fix).await;
    fix.install_store.record_co_admin(&admin_did).await.unwrap();

    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap: {payload}");
    assert_eq!(list_acl_entries(&fix.state.acl_ks).await.unwrap().len(), 1);
}

#[tokio::test]
async fn second_bootstrap_is_already_bootstrapped() {
    let fix = build_fixture(true, true).await;
    let (session_jwt_a, _) = run_claim_ceremony(&fix).await;

    let (s1, _) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt_a }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Try to replay the same session JWT.
    let (s2, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt_a }),
    )
    .await;
    assert_eq!(
        s2, REJECTED,
        "duplicate-admin check must catch the replay: {payload}"
    );
    assert_eq!(
        payload["code"], BOOTSTRAP_ERR_ALREADY_BOOTSTRAPPED,
        "{payload}"
    );
}

// ---------------------------------------------------------------------------
// invalidToken paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_rejects_unsigned_token() {
    let fix = build_fixture(true, true).await;
    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": "not.a.real.jwt" }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], BOOTSTRAP_ERR_INVALID_TOKEN, "{payload}");
}

#[tokio::test]
async fn bootstrap_rejects_install_token_as_setup_token() {
    // An attacker who intercepted the install URL still cannot drive
    // bootstrap directly — the install JWT has `aud = "vtc-install"`,
    // which the session decoder rejects.
    let fix = build_fixture(true, true).await;
    let install_jwt = mint_token_and_record(&fix, 600).await;
    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": install_jwt }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], BOOTSTRAP_ERR_INVALID_TOKEN, "{payload}");
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
    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt }),
    )
    .await;
    // Not `REJECTED` (a declared code, always 422 on the spine): a missing
    // passkey user is an undeclared `AppError::Forbidden`, which keeps its
    // ordinary REST status.
    assert_eq!(status, StatusCode::FORBIDDEN, "{payload}");
}

// ---------------------------------------------------------------------------
// Unavailable paths (missing signer / audit writer)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_is_refused_when_install_signer_missing() {
    let fix = build_fixture(false, true).await;
    let (status, _payload) =
        post_json(&fix, BOOTSTRAP_TASK, json!({ "setupSessionToken": "x" })).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn bootstrap_is_refused_when_audit_writer_missing() {
    let fix = build_fixture(true, false).await;
    let session_jwt = vtc_service::install::mint_install_session_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:zAnyone",
        &Uuid::new_v4().to_string(),
        600,
    )
    .unwrap();
    let (status, _payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
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
    let fix = build_fixture(true, true).await;
    let (status, payload) = post_json(
        &fix,
        "https://trusttasks.org/spec/vtc/admin/bootstrap/nope/0.1",
        json!({ "setupSessionToken": "x" }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["code"], "unsupportedType", "{payload}");
}

// ---------------------------------------------------------------------------
// #1600 — the codes `vtc/admin/bootstrap/0.1` declares, read from the
// generated bindings.
// ---------------------------------------------------------------------------

const BOOTSTRAP_ERR_INVALID_TOKEN: &str =
    trust_tasks_rs::specs::vtc::admin::bootstrap::v0_1::error_codes::INVALID_TOKEN.code;
const BOOTSTRAP_ERR_ALREADY_BOOTSTRAPPED: &str =
    trust_tasks_rs::specs::vtc::admin::bootstrap::v0_1::error_codes::ALREADY_BOOTSTRAPPED.code;

/// A token this community did not sign, or signed for another audience, is
/// `invalidToken`; a second bootstrap once an admin exists is
/// `alreadyBootstrapped`.
#[tokio::test]
async fn the_bootstrap_task_answers_with_the_codes_its_spec_declares() {
    let fix = build_fixture(true, true).await;

    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": "not.a.real.jwt" }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        tt_error_code(&payload),
        Some(BOOTSTRAP_ERR_INVALID_TOKEN),
        "{payload}"
    );

    // The install token itself has the wrong audience for this route.
    let install_jwt = mint_token_and_record(&fix, 600).await;
    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": install_jwt }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        tt_error_code(&payload),
        Some(BOOTSTRAP_ERR_INVALID_TOKEN),
        "{payload}"
    );

    let (session_jwt, _) = run_claim_ceremony(&fix).await;
    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt.clone() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let (status, payload) = post_json(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": session_jwt }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        payload["code"], BOOTSTRAP_ERR_ALREADY_BOOTSTRAPPED,
        "{payload}"
    );
}
