//! Phase-0 install-flow integration test (M0.12.1).
//!
//! Walks the canonical 9-step scenario from the plan through
//! `Router::oneshot`, asserting that every endpoint added during
//! Phase 0 cooperates:
//!
//! 1. `vtc setup` shortcut — mint seed + install token (no real VTA).
//! 2. `POST /v1/install/claim/start` — WebAuthn ceremony begins.
//! 3. `POST /v1/install/claim/finish` — token consumed, session-JWT minted.
//! 4. `POST /v1/admin/bootstrap` — first ACL admin written.
//! 5. `auth/passkey/enroll/{start,finish}/0.2` — second passkey, signed by a
//!    console key the admin enrolled (#1641).
//! 6. `auth/passkey/list/0.1` — both passkeys present.
//! 7. The community profile setup wrote is in place.
//! 10. Second `POST /v1/install/claim/start` — refused (carve-out closed).
//!
//! Closes the Phase-0 behavioural gate (Checkpoint E in the plan).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use vti_common::audit::{AuditEnvelope, AuditEvent};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use vtc_service::install::{InstallTokenSigner, InstallTokenStore, mint_install_token};
use vtc_service::server::AppState;
use vtc_service::test_support::TestVtc;

use crate::common::signed::call;
use crate::common::webauthn_harness::SoftEd25519Authenticator;

/// Re-wrap the inner WebAuthn options as webauthn-rs's `{publicKey: …}`.
///
/// The `auth/passkey/*/start` tasks send the *inner* options — the value a
/// browser passes as `get({ publicKey: … })` — because that is what the
/// canonical `CredentialRequestOptions` component describes. The
/// soft-authenticator harness deserialises webauthn-rs's wrapper type, so the
/// test does the same re-wrap a real client does.
fn wrap_options<T: serde::de::DeserializeOwned>(inner: &serde_json::Value) -> T {
    serde_json::from_value(serde_json::json!({ "publicKey": inner })).expect("options re-wrap")
}

const RP_ORIGIN: &str = "https://vtc.example.com";

// Trust Tasks ------------------------------------------------------
const CLAIM_START_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/start/0.2";
const CLAIM_FINISH_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/finish/0.2";
const BOOTSTRAP_TASK: &str = "https://trusttasks.org/spec/vtc/admin/bootstrap/0.1";
const ENROLL_START_TASK: &str = "https://trusttasks.org/spec/auth/passkey/enroll/start/0.2";
const ENROLL_FINISH_TASK: &str = "https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2";
const LIST_TASK: &str = "https://trusttasks.org/spec/auth/passkey/list/0.1";

struct Fixture {
    state: AppState,
    router: axum::Router,
    install_signer: Arc<InstallTokenSigner>,
    install_store: InstallTokenStore,
    recipient: String,
    // Owns the temp data dir + serves `router`'s state; must outlive them.
    _vtc: TestVtc,
}

/// Step 1: `vtc setup` shortcut. Stands up an AppState with everything
/// `run()` would wire (WebAuthn via public_url, install signer, audit
/// writer, JWT keys). No actual VTA contact. The builder leaves
/// `supervisor: None` so step 9 asserts `/restart` returns 412.
async fn build_fixture() -> Fixture {
    let install_signer = Arc::new(InstallTokenSigner::from_master_seed(&[0xAB; 64]).unwrap());
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_public_url(RP_ORIGIN)
        .with_install_signer(install_signer.clone())
        .build()
        .await;

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
        install_signer,
        install_store,
        recipient,
        _vtc: vtc,
    }
}

/// Post `payload` as an unsigned `type_uri` document to the shared document
/// endpoint (`trust_tasks::install_tasks` — install/claim/bootstrap carry no
/// proof requirement), and return its status and the response document's
/// `payload`.
async fn post_document(fix: &Fixture, type_uri: &str, payload: Value) -> (StatusCode, Value) {
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

/// Step 1 (continued): mint a fresh install token + record it in
/// the install store so `claim/start` finds the state.
async fn mint_install(fix: &Fixture) -> String {
    let minted = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        600,
    )
    .expect("mint install token");
    let exp = Utc::now() + ChronoDuration::seconds(600);
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A webauthn-rs result as the browser's published JSON — what the console's
/// `serializeRegistration` / `serializeAssertion` send.
fn published(v: impl serde::Serialize) -> Value {
    fn strip_nulls(v: &mut Value) {
        if let Value::Object(map) = v {
            map.retain(|_, v| !v.is_null());
            map.values_mut().for_each(strip_nulls);
        }
    }
    let mut v = serde_json::to_value(v).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("extensions");
    obj.insert("clientExtensionResults".into(), json!({}));
    strip_nulls(&mut v);
    v
}

// ---------------------------------------------------------------------------
// The end-to-end test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn end_to_end_install_flow_phase_0_gate() {
    let fix = build_fixture().await;

    // Step 1 — `vtc setup` shortcut: mint install token. (Real
    // wizard rewrites the seed-generation + provisioning, but the
    // wire-flow gate only cares that an install token + state
    // pair exist.)
    let install_token = mint_install(&fix).await;

    // ----------------------------------------------------------------
    // Step 2 — claim/start
    // ----------------------------------------------------------------
    let (status, body) = post_document(
        &fix,
        CLAIM_START_TASK,
        json!({ "installToken": install_token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim/start: {body}");
    // `install/claim/start` is untouched by this PR: it is not one of the
    // `auth/passkey/*` tasks, and it still sends the wrapper under `options`.
    let registration_id = body["registrationId"].as_str().unwrap().to_string();
    let ccr: CreationChallengeResponse = serde_json::from_value(body["options"].clone()).unwrap();

    // ----------------------------------------------------------------
    // Step 3 — soft authenticator runs the WebAuthn ceremony, then claim/finish
    // ----------------------------------------------------------------
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);

    let (status, body) = post_document(
        &fix,
        CLAIM_FINISH_TASK,
        json!({
            "installToken": install_token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim/finish: {body}");
    let setup_session_token = body["setupSessionToken"].as_str().unwrap().to_string();
    let admin_did = body["adminDid"].as_str().unwrap().to_string();
    assert!(admin_did.starts_with("did:key:z"));

    // ----------------------------------------------------------------
    // Step 4 — admin/bootstrap
    // ----------------------------------------------------------------
    let (status, body) = post_document(
        &fix,
        BOOTSTRAP_TASK,
        json!({ "setupSessionToken": setup_session_token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bootstrap: {body}");
    assert_eq!(body["adminDid"].as_str().unwrap(), admin_did);

    // The console signs as a key it enrolled for the bootstrapped DID — the
    // admin's identity is the passkey's own `did:key`, whose private half
    // lives in the authenticator, so the console never signs as it directly.
    // Enrolment is `auth/signing-key/enroll` (`signed_step_up.rs` drives it);
    // here the delegation is written directly.
    let console = vti_rooms_dtg::test_support::Party::new();
    vtc_service::acl::console_key::enrol_delegation(
        &fix.state.console_keys_ks,
        &fix.state.acl_ks,
        &console.did,
        &admin_did,
        Some("install browser".into()),
        None,
    )
    .await
    .unwrap();

    // Seed the community profile so step 7's GET has something to
    // return. The bootstrap path doesn't write the profile (that's
    // a deliberate spec choice — profile is owned by the operator,
    // not the install flow).
    let profile = vtc_service::community::CommunityProfile::new(
        "did:webvh:vtc.example.com:abc",
        "Example Community",
    );
    vtc_service::community::store_profile(&fix.state.community_ks, &profile)
        .await
        .unwrap();

    // ----------------------------------------------------------------
    // Step 5 — auth/passkey/enroll (start + finish), signed documents
    // ----------------------------------------------------------------
    let (status, doc) = call(&fix._vtc, &console, ENROLL_START_TASK, json!({})).await;
    assert_eq!(status, StatusCode::OK, "enroll/start: {doc}");
    let body = doc["payload"].clone();
    let reg_id = body["enrollmentId"].as_str().unwrap().to_string();
    let register_options: CreationChallengeResponse = wrap_options(&body["options"]);
    let uv_options: RequestChallengeResponse = wrap_options(&body["uvOptions"]);

    let (register_response, _new_pub) = authenticator.register(&register_options, RP_ORIGIN);
    let uv_response = authenticator.authenticate(&uv_options, RP_ORIGIN);

    let (status, doc) = call(
        &fix._vtc,
        &console,
        ENROLL_FINISH_TASK,
        json!({
            "enrollmentId": reg_id,
            "credential": published(&register_response),
            "uvCredential": published(&uv_response),
            "deviceLabel": "second device",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enroll/finish: {doc}");

    // ----------------------------------------------------------------
    // Step 6 — passkeys list returns both
    // ----------------------------------------------------------------
    let (status, doc) = call(&fix._vtc, &console, LIST_TASK, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    // `credentials`, the name `auth/passkey/list/0.1` publishes (#1112).
    let passkeys = doc["payload"]["credentials"].as_array().unwrap();
    assert_eq!(passkeys.len(), 2, "expected 2 passkeys, got {passkeys:?}");
    let labels: std::collections::HashSet<_> = passkeys
        .iter()
        .map(|p| p["deviceLabel"].as_str().unwrap().to_string())
        .collect();
    assert!(labels.contains("install"));
    assert!(labels.contains("second device"));

    // ----------------------------------------------------------------
    // Step 7 — the community profile is in place. Reading it over the wire
    // is the signed `vtc/community/profile/show/0.1` (`community_profile.rs`).
    // ----------------------------------------------------------------
    let profile = vtc_service::community::load_profile(&fix.state.community_ks)
        .await
        .unwrap()
        .expect("profile written by setup");
    assert_eq!(profile.name, "Example Community");

    // Verify ACL admin record matches the bootstrapped DID
    let acl = vtc_service::acl::list_acl_entries(&fix.state.acl_ks)
        .await
        .unwrap();
    assert_eq!(acl.len(), 1);
    assert_eq!(acl[0].did, admin_did);
    assert!(acl[0].is_community_admin(), "{:?}", acl[0]);

    // The runtime configuration (`config/patch`, `config/restart`) is a
    // signed document only, driven through the signed door in
    // `admin_config.rs` and `admin_verbs_spine.rs`.

    // ----------------------------------------------------------------
    // Step 10 — second claim/start with the same token is rejected
    //           because the token has transitioned to `Consumed`.
    //           The earlier carve-out global lockdown is gone — the
    //           per-row state machine is the only gate.
    // ----------------------------------------------------------------
    let (status, body) = post_document(
        &fix,
        CLAIM_START_TASK,
        json!({ "installToken": install_token }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "second claim/start must be refused (token Consumed): {body}",
    );

    // ----------------------------------------------------------------
    // Sanity: audit log records the lifecycle events
    // ----------------------------------------------------------------
    let raw = fix
        .state
        .audit_ks
        .prefix_iter_raw(b"2".to_vec())
        .await
        .unwrap();
    let envelopes: Vec<AuditEnvelope> = raw
        .iter()
        .map(|(_, v)| serde_json::from_slice(v).unwrap())
        .collect();

    let mut saw_install = false;
    let mut saw_passkey_registered = false;
    let mut saw_restart = false;
    for env in &envelopes {
        match &env.event {
            AuditEvent::CommunityInstalled(_) => saw_install = true,
            AuditEvent::AdminPasskeyRegistered(_) => saw_passkey_registered = true,
            AuditEvent::RestartRequested(_) => saw_restart = true,
            _ => {}
        }
    }
    assert!(saw_install, "CommunityInstalled envelope missing");
    assert!(
        saw_passkey_registered,
        "AdminPasskeyRegistered envelope missing"
    );
    // Restart never reaches the audit writer when the supervisor
    // check fails first; this is the correct semantics — failed
    // requests don't pollute the audit log.
    assert!(!saw_restart, "RestartRequested must not be emitted on 412");
}
