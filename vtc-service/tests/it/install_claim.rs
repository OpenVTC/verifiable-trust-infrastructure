//! End-to-end coverage for the passkey install,
//! `vtc/install/claim/passkey/{start,finish}/0.1` (trust-tasks-tf #976, #978).
//!
//! The administrator's DID is the `did:key` of the passkey's own key — Ed25519
//! or P-256 — never one the token names; finish proves possession with an
//! assertion over a second challenge before it grants anything; an invitation
//! on a community that already has an administrator writes the entry at finish.
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

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use vtc_service::install::{
    InstallTokenSigner, InstallTokenState, InstallTokenStore, InvitedAuthority, mint_install_token,
    mint_passkey_install_token,
};
use vtc_service::test_support::TestVtc;

use crate::common::webauthn_harness::SoftEd25519Authenticator;

const RP_ORIGIN: &str = "https://vtc.example.com";
const START_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/passkey/start/0.1";
const FINISH_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/passkey/finish/0.1";
const RETIRED_START_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/start/0.2";
const RETIRED_FINISH_TASK: &str = "https://trusttasks.org/spec/vtc/install/claim/finish/0.2";

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

    // The passkey finish's response is signed (its proof is REQUIRED).
    let mut builder = TestVtc::builder().with_credential_signer(Arc::new(
        vtc_service::credentials::LocalSigner::from_ed25519_seed(
            vtc_service::test_support::TEST_VTC_DID.to_string(),
            &[0x5A; 32],
        ),
    ));
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
    let minted = mint_passkey_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        ttl_seconds,
    )
    .expect("mint install token");
    let exp = Utc::now() + ChronoDuration::seconds(ttl_seconds as i64);
    fix.install_store
        .record_issued_passkey(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            exp,
            claim_secret_hash,
            InvitedAuthority::community_admin("test", "passkey invitation"),
        )
        .await
        .expect("record_issued_passkey");
    (minted.jwt, minted.jti)
}

/// Post `payload` as an unsigned `type_uri` document (install/claim carries no
/// proof requirement — the install token itself is the credential) to the
/// shared document endpoint, and return its status and the response
/// document's `payload`.
async fn post_json(fix: &Fixture, type_uri: &str, payload: Value) -> (StatusCode, Value) {
    let (status, doc) = post_doc(fix, type_uri, payload).await;
    (status, doc["payload"].clone())
}

/// As [`post_json`], answering the whole response document.
async fn post_doc(fix: &Fixture, type_uri: &str, payload: Value) -> (StatusCode, Value) {
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
    (status, body)
}

fn parse_ccr(payload: &Value) -> CreationChallengeResponse {
    serde_json::from_value(payload.get("options").cloned().expect("options field"))
        .expect("CreationChallengeResponse parses")
}

// ---------------------------------------------------------------------------
// Happy-path
// ---------------------------------------------------------------------------

/// The `did:key` an Ed25519 key names.
fn ed25519_did(public: &[u8; 32]) -> String {
    format!(
        "did:key:{}",
        multibase::encode(
            multibase::Base::Base58Btc,
            [&[0xed, 0x01][..], public].concat()
        )
    )
}

/// The `did:key` a P-256 key names, from its uncompressed SEC1 point: the
/// compressed point (`0x02` for an even `y`, `0x03` for odd, then `x`) under
/// multicodec `0x1200`.
fn p256_did(uncompressed: &[u8]) -> String {
    let prefix = if uncompressed[64].is_multiple_of(2) {
        0x02
    } else {
        0x03
    };
    let compressed = [&[prefix][..], &uncompressed[1..33]].concat();
    format!(
        "did:key:{}",
        multibase::encode(
            multibase::Base::Base58Btc,
            [&[0x80, 0x24][..], &compressed[..]].concat()
        )
    )
}

#[tokio::test]
async fn full_ceremony_completes_end_to_end() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, jti) = mint_token_and_record(&fix, 600).await;

    // -- start ---------------------------------------------------------
    let (status, payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::OK, "start: {payload}");

    let registration_id = payload["registrationId"].as_str().unwrap().to_string();
    assert_eq!(registration_id, jti.to_string());
    // start item 3: exactly EdDSA and ES256.
    let algs: Vec<i64> = payload["options"]["publicKey"]["pubKeyCredParams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["alg"].as_i64().unwrap())
        .collect();
    assert_eq!(algs, vec![-8, -7], "{payload}");
    // start item 5: no DID in the user members.
    let user = &payload["options"]["publicKey"]["user"];
    for member in ["name", "displayName"] {
        assert!(
            !user[member].as_str().unwrap().starts_with("did:"),
            "{user}"
        );
    }
    // start item 4: a second, distinct challenge, no allowCredentials.
    let assertion_options = &payload["assertionOptions"]["publicKey"];
    assert_ne!(
        assertion_options["challenge"], payload["options"]["publicKey"]["challenge"],
        "{payload}"
    );
    assert!(
        assertion_options.get("allowCredentials").is_none(),
        "{payload}"
    );
    assert_eq!(assertion_options["rpId"], "vtc.example.com", "{payload}");
    let ccr = parse_ccr(&payload);

    // -- the installer registers a passkey and proves they hold it ------
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, ed25519_pub) = authenticator.register(&ccr, RP_ORIGIN);
    let assertion = authenticator.install_assertion(&payload, &register_cred, RP_ORIGIN);

    // -- finish --------------------------------------------------------
    let finish_body = json!({
        "installToken": token,
        "registrationId": registration_id,
        "webauthnResponse": register_cred,
        "webauthnAssertion": assertion,
    });
    let (status, doc) = post_doc(&fix, FINISH_TASK, finish_body.clone()).await;
    assert_eq!(status, StatusCode::OK, "finish: {doc}");
    // finish item 5: the DID is the passkey's own key.
    let admin_did = doc["payload"]["adminDid"].as_str().unwrap().to_string();
    assert_eq!(admin_did, ed25519_did(&ed25519_pub));
    assert!(admin_did.starts_with("did:key:z6Mk"), "{admin_did}");
    assert!(
        !doc["payload"]["setupSessionToken"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    // finish item 8: the response carrying the bearer token is signed.
    assert_eq!(doc["proof"]["type"], "DataIntegrityProof", "{doc}");
    // The token is consumed for the derived DID.
    match fix.install_store.get_token(&jti).await.unwrap() {
        Some(InstallTokenState::Consumed { admin_did: d, .. }) => {
            assert_eq!(d.as_deref(), Some(admin_did.as_str()))
        }
        other => panic!("expected Consumed, got {other:?}"),
    }

    // -- replay finish: the token is consumed --------------------------
    // finish item 1: a consumed token is `invalidToken`. A replay never mints
    // a second setup-session token without a fresh assertion.
    let (status, payload) = post_json(&fix, FINISH_TASK, finish_body).await;
    assert_eq!(status, REJECTED, "replay: {payload}");
    assert_eq!(tt_error_code(&payload), Some(FINISH_ERR_INVALID_TOKEN));

    // -- start after finish: still rejected ----------------------------
    let (status, _payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "start after finish must be rejected"
    );
}

/// A P-256 passkey — what almost every platform authenticator creates — names
/// the administrator by its own `did:key:zDn…`, the compressed point under
/// multicodec 0x1200 (finish item 5).
#[tokio::test]
async fn a_p256_passkey_names_the_administrator_by_its_own_did_key() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, jti) = mint_token_and_record(&fix, 600).await;
    let (status, payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, point) = authenticator.register_p256(&parse_ccr(&payload), RP_ORIGIN);
    let assertion = authenticator.install_assertion(&payload, &register_cred, RP_ORIGIN);
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": jti.to_string(),
            "webauthnResponse": register_cred,
            "webauthnAssertion": assertion,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let admin_did = payload["adminDid"].as_str().unwrap();
    assert!(admin_did.starts_with("did:key:zDn"), "{admin_did}");
    assert_eq!(admin_did, p256_did(&point));
}

/// finish items 6–7 (trust-tasks-tf #978): a registration under the `none`
/// attestation format signs nothing, so possession is proven by an assertion
/// over start's second challenge, by the registered key — and until it is,
/// nothing is consumed, stored or minted.
#[tokio::test]
async fn possession_is_proven_before_any_authority() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, jti) = mint_token_and_record(&fix, 600).await;

    // Three ways to fail: an assertion over the wrong challenge, one by
    // another credential, and none at all.
    for case in ["wrong challenge", "another credential", "no assertion"] {
        let (status, payload) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{case}: start again at once: {payload}"
        );
        let mut authenticator = SoftEd25519Authenticator::new();
        let (register_cred, _) = authenticator.register(&parse_ccr(&payload), RP_ORIGIN);
        let assertion = match case {
            "wrong challenge" => serde_json::to_value(authenticator.assert_raw(
                register_cred.raw_id.as_ref(),
                "vtc.example.com",
                b"a challenge this community never issued",
                RP_ORIGIN,
                crate::common::webauthn_harness::FLAGS_UP_UV,
            ))
            .unwrap(),
            "another credential" => {
                // A key the installer does hold, but not the one registered.
                let mut other = SoftEd25519Authenticator::new();
                let (other_cred, _) = other.register_p256(&parse_ccr(&payload), RP_ORIGIN);
                other.install_assertion(&payload, &other_cred, RP_ORIGIN)
            }
            _ => json!({ "id": "AAAA", "rawId": "AAAA", "type": "public-key",
                         "response": { "authenticatorData": "AA", "clientDataJSON": "AA",
                                       "signature": "AA" } }),
        };
        let (status, payload) = post_json(
            &fix,
            FINISH_TASK,
            json!({
                "installToken": token,
                "registrationId": jti.to_string(),
                "webauthnResponse": register_cred,
                "webauthnAssertion": assertion,
            }),
        )
        .await;
        assert_eq!(status, REJECTED, "{case}: {payload}");
        assert_eq!(
            tt_error_code(&payload),
            Some(FINISH_ERR_POSSESSION_UNPROVEN),
            "{case}: {payload}"
        );
        // Item 7: nothing consumed, no passkey kept.
        assert!(
            matches!(
                fix.install_store.get_token(&jti).await.unwrap(),
                Some(InstallTokenState::Issued { .. })
            ),
            "{case}: the token is still open"
        );
        let cred_hex = hex::encode(register_cred.raw_id.as_ref() as &[u8]);
        assert!(
            vti_common::auth::passkey::store::get_passkey_user_by_cred(
                &fix._vtc.state.passkey_ks,
                &cred_hex
            )
            .await
            .unwrap()
            .is_none(),
            "{case}: no passkey was kept"
        );
    }
}

/// finish item 4: a key no `did:key` here can name is `unsupportedAlgorithm`,
/// consuming nothing — the registration stays open for a passkey that can be
/// named, and finish succeeds with one.
#[tokio::test]
async fn a_passkey_no_did_key_can_name_is_unsupported_algorithm() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, jti) = mint_token_and_record(&fix, 600).await;
    let (status, start) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::OK, "{start}");
    let ccr = parse_ccr(&start);
    let mut authenticator = SoftEd25519Authenticator::new();
    let rs256 = authenticator.register_rs256(&ccr, RP_ORIGIN);
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": jti.to_string(),
            "webauthnResponse": rs256,
            "webauthnAssertion": { "id": "AAAA", "type": "public-key" },
        }),
    )
    .await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        tt_error_code(&payload),
        Some(FINISH_ERR_UNSUPPORTED_ALGORITHM),
        "{payload}"
    );
    assert!(matches!(
        fix.install_store.get_token(&jti).await.unwrap(),
        Some(InstallTokenState::Issued { .. })
    ));

    // Nothing consumed: the same registration finishes with an Ed25519 key.
    let (register_cred, _) = authenticator.register(&ccr, RP_ORIGIN);
    let assertion = authenticator.install_assertion(&start, &register_cred, RP_ORIGIN);
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": jti.to_string(),
            "webauthnResponse": register_cred,
            "webauthnAssertion": assertion,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{payload}");
}

/// finish item 9: on a community that already has an administrator, the claim
/// is an invitation, and finish writes the derived DID's entry with the
/// authority the invitation was issued with — bootstrap, single-use, would
/// answer `alreadyBootstrapped`.
#[tokio::test]
async fn an_invitation_writes_the_derived_did_entry_at_finish() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    // An administrator already exists.
    let existing = vtc_service::acl::VtcAclEntry::new(
        "did:key:z6MkExistingAdministrator",
        vtc_service::acl::VtcRole::Admin,
        vtc_service::acl::AdminAuthority::community_admin(),
        "test",
    );
    vtc_service::acl::store_acl_entry(&fix._vtc.state.acl_ks, &existing)
        .await
        .unwrap();

    let (token, jti) = mint_token_and_record(&fix, 600).await;
    let (status, start) = post_json(&fix, START_TASK, json!({ "installToken": token })).await;
    assert_eq!(status, StatusCode::OK, "{start}");
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, point) = authenticator.register_p256(&parse_ccr(&start), RP_ORIGIN);
    let derived = p256_did(&point);
    // Nothing was written for it before the claim.
    assert!(
        vtc_service::acl::get_acl_entry(&fix._vtc.state.acl_ks, &derived)
            .await
            .unwrap()
            .is_none()
    );
    let assertion = authenticator.install_assertion(&start, &register_cred, RP_ORIGIN);
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": jti.to_string(),
            "webauthnResponse": register_cred,
            "webauthnAssertion": assertion,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    assert_eq!(payload["adminDid"], derived);
    let entry = vtc_service::acl::get_acl_entry(&fix._vtc.state.acl_ks, &derived)
        .await
        .unwrap()
        .expect("finish writes the invited administrator");
    assert!(entry.is_community_admin(), "{entry:?}");
    assert_eq!(entry.label.as_deref(), Some("passkey invitation"));
}

/// A token that names a DID was issued for the wallet ceremony (0.3), and a
/// passkey cannot claim it (start item 5).
#[tokio::test]
async fn a_token_that_names_a_did_is_not_a_passkey_invitation() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let minted = mint_install_token(
        &fix.install_signer,
        "did:webvh:vtc.example.com:abc",
        "did:key:z6MkAdmin",
        600,
    )
    .unwrap();
    fix.install_store
        .record_issued(
            &minted.jti,
            minted.cnonce_bytes,
            *minted.ephemeral_signing_key,
            Utc::now() + ChronoDuration::seconds(600),
            None,
            Some("did:key:z6MkAdmin".into()),
        )
        .await
        .unwrap();
    let (status, payload) =
        post_json(&fix, START_TASK, json!({ "installToken": minted.jwt })).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(tt_error_code(&payload), Some(START_ERR_INVALID_TOKEN));
}

/// `vtc/install/claim/{start,finish}/0.2` are retired (trust-tasks-tf #976)
/// and no longer served: the slug's served version is the wallet ceremony's
/// 0.3, so a 0.2 document is `unsupportedVersion`.
#[tokio::test]
async fn the_retired_0_2_ceremony_is_not_served() {
    let fix = build_fixture(Some(RP_ORIGIN), true).await;
    let (token, _) = mint_token_and_record(&fix, 600).await;
    for uri in [RETIRED_START_TASK, RETIRED_FINISH_TASK] {
        let (status, payload) = post_json(&fix, uri, json!({ "installToken": token })).await;
        assert_eq!(status, REJECTED, "{uri}: {payload}");
        assert_eq!(payload["code"], "unsupportedVersion", "{uri}: {payload}");
    }
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
    let minted =
        mint_passkey_install_token(&fix.install_signer, "did:webvh:vtc.example.com:abc", 600)
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
            "webauthnAssertion": { "id": "AAAA", "type": "public-key" },
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
            "webauthnAssertion": { "id": "AAAA", "type": "public-key" },
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
// #1600 — the codes `vtc/install/claim/passkey/{start,finish}/0.1` declare,
// read from the generated bindings.
// ---------------------------------------------------------------------------

use vti_specs::vtc::install::claim::passkey as claim_spec;

const START_ERR_INVALID_TOKEN: &str = claim_spec::start::v0_1::error_codes::INVALID_TOKEN.code;
const FINISH_ERR_INVALID_TOKEN: &str = claim_spec::finish::v0_1::error_codes::INVALID_TOKEN.code;
const FINISH_ERR_REGISTRATION_MISMATCH: &str =
    claim_spec::finish::v0_1::error_codes::REGISTRATION_MISMATCH.code;
const FINISH_ERR_BINDING_INVALID: &str =
    claim_spec::finish::v0_1::error_codes::BINDING_INVALID.code;
const FINISH_ERR_POSSESSION_UNPROVEN: &str =
    claim_spec::finish::v0_1::error_codes::POSSESSION_UNPROVEN.code;
const FINISH_ERR_UNSUPPORTED_ALGORITHM: &str =
    claim_spec::finish::v0_1::error_codes::UNSUPPORTED_ALGORITHM.code;

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
    assert_eq!(
        tt_error_code(&payload),
        Some(START_ERR_INVALID_TOKEN),
        "{payload}"
    );

    let unrecorded =
        mint_passkey_install_token(&fix.install_signer, "did:webvh:vtc.example.com:abc", 600)
            .unwrap();
    let (status, payload) = start(unrecorded.jwt).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        tt_error_code(&payload),
        Some(START_ERR_INVALID_TOKEN),
        "{payload}"
    );

    // Consumed: run the whole ceremony, then start again.
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, payload) = start(token.clone()).await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let registration_id = payload["registrationId"].as_str().unwrap().to_string();
    let mut authenticator = SoftEd25519Authenticator::new();
    let (register_cred, _pub) = authenticator.register(&parse_ccr(&payload), RP_ORIGIN);
    let assertion = authenticator.install_assertion(&payload, &register_cred, RP_ORIGIN);
    let (status, payload) = post_json(
        &fix,
        FINISH_TASK,
        json!({
            "installToken": token,
            "registrationId": registration_id,
            "webauthnResponse": register_cred,
            "webauthnAssertion": assertion,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{payload}");
    let (status, payload) = start(token).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(
        tt_error_code(&payload),
        Some(START_ERR_INVALID_TOKEN),
        "{payload}"
    );

    // A concurrent-ceremony lock is not a token fault.
    let (token, _jti) = mint_token_and_record(&fix, 600).await;
    let (status, _) = start(token.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, payload) = start(token).await;
    assert_eq!(status, REJECTED, "{payload}");
    assert_eq!(payload["details"]["reason"], "conflict", "{payload}");
}

/// Finish distinguishes the token (`invalidToken`), the enrolment it names
/// (`registrationMismatch`) and the WebAuthn registration (`bindingInvalid`).
/// `possessionUnproven` and `unsupportedAlgorithm` have tests of their own.
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
                    "webauthnAssertion": { "id": "AAAA", "type": "public-key" },
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
    assert_eq!(
        tt_error_code(&payload),
        Some(FINISH_ERR_BINDING_INVALID),
        "{payload}"
    );
}

/// The identifier a refusal's payload names — the error-code census's textual
/// witness scan looks for this exact call name.
fn tt_error_code(payload: &Value) -> Option<&str> {
    payload["code"].as_str()
}
