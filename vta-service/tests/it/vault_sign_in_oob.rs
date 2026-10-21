//! Wallet sign-in: the default VTA policy for `auth/oob/identify` and
//! `auth/oob/grant` through `vault/sign-trust-task` (base design §5 and §11;
//! sign-in trigger-link contract C5, C6 and C9).
//!
//! - `identify` is signed unattended, for `authentication`, but only in its
//!   exact shape, for an enrolled device, as the entry's principal and for a
//!   DID the entry targets.
//! - `grant` is signed for `assertionMethod` only on a `task-consent/decision`
//!   from the device's UV key approving the digest of exactly that unsigned
//!   grant — a raw hardware key (phone) or a WebAuthn passkey with UV (browser
//!   plugin) — and never twice for one grant `id`.
//! - A UV key is enrolled on `device/register` and replaced on
//!   `device/heartbeat`, both by the device's transport key.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::operations::vault::oob_sign_in::grant_digest;
use vta_service::test_support::{
    SoftAuthenticator, TestAppContext, build_test_app, did_for_seed, sign_as,
};
use vti_common::vault::{
    SecretKind, SiteTarget, StoredVaultEntry, VaultEntry, VaultSecret, VaultStatus,
    put_stored_vault_entry,
};

const DEVICE_SEED: u8 = 0x71;
const CONTEXT: &str = "wallet";
const ENTRY: &str = "persona-oob";
const VTC: &str = "did:web:vtc.example";
const SIGN_TT: &str = "https://trusttasks.org/spec/vault/sign-trust-task/0.2";
const KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";
const REGISTER: &str = "https://trusttasks.org/spec/device/register/0.2";
const HEARTBEAT: &str = "https://trusttasks.org/spec/device/heartbeat/0.2";
const IDENTIFY: &str = "https://trusttasks.org/spec/auth/oob/identify/0.1";
const GRANT: &str = "https://trusttasks.org/spec/auth/oob/grant/0.1";
const DECISION: &str = "https://trusttasks.org/spec/task-consent/decision/0.2";
const REQUEST_ID: &str = "q1w2e3r4t5y6u7i8o9p0aA";
const RP_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn k_a() -> String {
    did_for_seed(0x0a).0
}

fn k_b() -> String {
    did_for_seed(0x0b).0
}

struct App {
    router: axum::Router,
    token: String,
    principal: String,
    vta_did: String,
    ctx: TestAppContext,
}

fn signed_doc(seed: u8, type_uri: &str, payload: Value, vta: &str) -> Value {
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuedAt": now(),
        "issuer": did_for_seed(seed).0,
        "recipient": vta,
        "payload": payload,
    }))
    .expect("envelope deserialises");
    sign_as(seed, &mut typed);
    serde_json::to_value(&typed).expect("envelope serialises")
}

async fn post(app: &App, token: &str, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn call(app: &App, type_uri: &str, payload: Value) -> (StatusCode, Value) {
    let doc = signed_doc(DEVICE_SEED, type_uri, payload, &app.vta_did);
    post(app, &app.token, &doc).await
}

/// A persona entry targeting the VTC, and — when `uv_key` is `Some` — the
/// caller registered as a mobile device with that UV key enrolment
/// (`Some(Value::Null)` registers with no UV key; `None` does not register).
async fn app(uv_key: Option<Value>) -> App {
    let (router, ctx) = build_test_app().await;
    vta_service::contexts::create_context(&ctx.contexts_ks, CONTEXT, "Wallet personas")
        .await
        .expect("context");
    let token = ctx
        .mint_token(&did_for_seed(DEVICE_SEED).0, "admin", vec![])
        .await;
    let mut app = App {
        router,
        token,
        principal: String::new(),
        vta_did: ctx.vta_did.clone(),
        ctx,
    };

    let (status, body) = call(
        &app,
        KEYS_CREATE,
        json!({ "keyType": "ed25519", "derivationPath": "", "label": "persona", "contextId": CONTEXT }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "keys/create: {body}");
    let key = &body["payload"]["key"];
    let key_id = key["keyId"].as_str().expect("keyId").to_string();
    let principal = format!("did:key:{}", key["publicKey"].as_str().expect("publicKey"));

    let stamp = "2026-01-01T00:00:00Z".to_string();
    let entry = StoredVaultEntry {
        entry: VaultEntry {
            id: ENTRY.to_string(),
            context_id: CONTEXT.to_string(),
            targets: vec![SiteTarget::Did {
                did: VTC.to_string(),
            }],
            label: "Persona".to_string(),
            secret_kind: SecretKind::DidSelfIssued,
            tags: Vec::new(),
            notes: None,
            favicon: None,
            selectors: Vec::new(),
            custom_field_names: Vec::new(),
            attachments: Vec::new(),
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: stamp.clone(),
            created_by: None,
            updated_at: stamp,
            updated_by: None,
            last_used_at: None,
            version: 1,
            principal_did: Some(principal.clone()),
            status: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        },
        secret: VaultSecret::DidSelfIssued {
            did: principal.clone(),
            signing_key_id: key_id,
            secure_notes: None,
        },
    };
    put_stored_vault_entry(&app.ctx.vault_ks, &entry)
        .await
        .expect("seed the persona entry");
    app.principal = principal;

    if let Some(uv) = uv_key {
        let mut payload = json!({
            "consumerKind": { "kind": "companion", "formFactor": "mobile" },
            "displayName": "Test phone",
            "hpkePublicKey": "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
        });
        if !uv.is_null() {
            payload["ext"] = json!({ "org.openvtc.uv-key": uv });
        }
        let (status, body) = call(&app, REGISTER, payload).await;
        assert_eq!(status, StatusCode::OK, "device/register: {body}");
    }
    app
}

// ─── UV keys ────────────────────────────────────────────────────────────────

/// A P-256 hardware UV key (the Secure Enclave's curve), as a `did:key`.
fn hardware_key(seed: u8) -> (String, Secret) {
    let probe = Secret::generate_p256(None, Some(&[seed; 32])).expect("p256");
    let mb = probe.get_public_keymultibase().expect("multibase");
    let did = format!("did:key:{mb}");
    let secret = Secret::generate_p256(Some(&format!("{did}#{mb}")), Some(&[seed; 32])).unwrap();
    (did, secret)
}

/// An Ed25519 UV key the browser plugin holds sealed under its PRF passkey.
fn prf_sealed_key(seed: u8) -> (String, Secret) {
    let probe = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let mb = probe.get_public_keymultibase().expect("multibase");
    let did = format!("did:key:{mb}");
    let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(&[seed; 32]));
    (did, secret)
}

fn prf_sealed_enrolment(did: &str) -> Value {
    json!({ "kind": "prfSealedKey", "did": did, "hardwareBacked": false, "biometricGated": false })
}

fn hardware_enrolment(did: &str) -> Value {
    json!({ "kind": "hardwareKey", "did": did, "hardwareBacked": true, "biometricGated": true })
}

fn passkey_enrolment(auth: &SoftAuthenticator) -> Value {
    let reg = auth.register(RP_ID, ORIGIN, "AAAAAAAAAAAAAAAAAAAAAA");
    json!({
        "kind": "webauthn",
        "credentialId": reg.credential_id,
        "publicKeyMultibase": reg.public_key_multibase,
        "rpId": RP_ID,
        "origin": ORIGIN,
        "hardwareBacked": true,
        "biometricGated": false,
    })
}

/// The Ed25519 transport key of the device `seed` names.
fn transport_secret(seed: u8) -> Secret {
    let (_, vm) = did_for_seed(seed);
    Secret::generate_ed25519(Some(&vm), Some(&[seed; 32]))
}

// ─── Documents ──────────────────────────────────────────────────────────────

fn identify(app: &App) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": IDENTIFY,
        "issuer": app.principal,
        "recipient": VTC,
        "issuedAt": now(),
        "payload": { "requestId": REQUEST_ID, "approverKey": k_a(), "enteredNumber": "47" },
    })
}

fn grant(app: &App) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": GRANT,
        "issuer": app.principal,
        "recipient": VTC,
        "issuedAt": now(),
        "payload": {
            "requestId": REQUEST_ID,
            "decision": "approve",
            "sessionKey": k_b(),
            "approverKey": k_a(),
            "origin": "https://portal.vtc.example",
            "contextDigest": "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR",
            "notAfter": chrono::Utc::now().timestamp() + 3600,
        },
    })
}

/// A `task-consent/decision/0.2` approving `digest`, issued and signed by
/// `signer`, optionally carrying `evidence`.
async fn decision(
    app: &App,
    issuer: &str,
    signer: &Secret,
    digest: &str,
    evidence: Option<Value>,
) -> Value {
    let mut payload =
        json!({ "challenge": digest, "payloadDigest": digest, "decision": "approve" });
    if let Some(e) = evidence {
        payload["evidence"] = e;
    }
    let unsigned = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": DECISION,
        "issuer": issuer,
        "recipient": app.vta_did,
        "issuedAt": now(),
        "payload": payload,
    });
    let proof = DataIntegrityProof::sign(
        &unsigned,
        signer,
        SignOptions::new().with_proof_purpose("assertionMethod"),
    )
    .await
    .expect("sign the decision");
    let mut signed = unsigned;
    signed["proof"] = serde_json::to_value(proof).unwrap();
    signed
}

async fn hardware_decision(app: &App, uv: &(String, Secret), grant: &Value) -> Value {
    let digest = grant_digest(grant).unwrap();
    decision(app, &uv.0, &uv.1, &digest, None).await
}

async fn passkey_decision(
    app: &App,
    auth: &SoftAuthenticator,
    grant: &Value,
    user_verified: bool,
) -> Value {
    passkey_decision_by(app, DEVICE_SEED, auth, grant, user_verified).await
}

/// A passkey decision issued and signed by the transport key of `device`,
/// carrying `auth`'s assertion.
async fn passkey_decision_by(
    app: &App,
    device: u8,
    auth: &SoftAuthenticator,
    grant: &Value,
    user_verified: bool,
) -> Value {
    let digest = grant_digest(grant).unwrap();
    // Chrome signs an extension's assertion over SHA-256 of its origin
    // (`chrome-extension://<id>`), not of the bare id it passed as `rpId`.
    let a = auth.assert(
        ORIGIN,
        ORIGIN,
        &URL_SAFE_NO_PAD.encode(digest.as_bytes()),
        user_verified,
    );
    let evidence = json!({
        "kind": "webauthn",
        "assertion": {
            "id": a.credential_id,
            "rawId": a.credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": a.client_data_json,
                "authenticatorData": a.authenticator_data,
                "signature": a.signature,
            },
        },
    });
    decision(
        app,
        &did_for_seed(device).0,
        &transport_secret(device),
        &digest,
        Some(evidence),
    )
    .await
}

async fn sign(app: &App, envelope: &Value, decision: Option<Value>) -> (StatusCode, Value) {
    let mut payload = json!({ "entryId": ENTRY, "unsignedEnvelope": envelope });
    if let Some(d) = decision {
        payload["ext"] = json!({ "org.openvtc.uv-consent": { "decision": d } });
    }
    call(app, SIGN_TT, payload).await
}

fn assert_signed(status: StatusCode, body: &Value, purpose: &str) {
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["payload"]["signedEnvelope"]["proof"]["proofPurpose"], purpose,
        "{body}"
    );
}

fn assert_refused(status: StatusCode, body: &Value, code: &str) {
    let text = body.to_string();
    assert!(
        status != StatusCode::OK || !text.contains("signedEnvelope"),
        "expected a refusal: {text}"
    );
    assert!(
        text.contains(code) && !text.contains("signedEnvelope"),
        "expected {code}: {text}"
    );
}

// ─── identify ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn identify_is_signed_without_user_verification_for_authentication() {
    let app = app(Some(Value::Null)).await;
    let (status, body) = sign(&app, &identify(&app), None).await;
    assert_signed(status, &body, "authentication");
}

#[tokio::test]
async fn identify_must_match_the_schema_exactly() {
    let app = app(Some(Value::Null)).await;

    let mut extra = identify(&app);
    extra["payload"]["ext"] = json!({ "org.example": { "x": 1 } });
    let (s, b) = sign(&app, &extra, None).await;
    assert_refused(s, &b, "oobDocumentInvalid");

    let mut number = identify(&app);
    number["payload"]["enteredNumber"] = json!(47);
    let (s, b) = sign(&app, &number, None).await;
    assert_refused(s, &b, "oobDocumentInvalid");

    let mut member = identify(&app);
    member["ext"] = json!({ "org.example": {} });
    let (s, b) = sign(&app, &member, None).await;
    assert_refused(s, &b, "oobDocumentInvalid");

    let mut version = identify(&app);
    version["type"] = json!("https://trusttasks.org/spec/auth/oob/identify/0.2");
    let (s, b) = sign(&app, &version, None).await;
    assert_refused(s, &b, "oobUnsupportedType");
}

#[tokio::test]
async fn the_recipient_must_be_a_did_the_entry_targets() {
    let app = app(Some(Value::Null)).await;
    let mut doc = identify(&app);
    doc["recipient"] = json!("did:web:elsewhere.example");
    let (s, b) = sign(&app, &doc, None).await;
    assert_refused(s, &b, "oobRecipientNotTarget");
}

#[tokio::test]
async fn a_stale_document_is_refused() {
    let app = app(Some(Value::Null)).await;
    let mut doc = identify(&app);
    doc["issuedAt"] = json!("2026-01-01T00:00:00Z");
    let (s, b) = sign(&app, &doc, None).await;
    assert_refused(s, &b, "oobStale");
}

#[tokio::test]
async fn only_an_enrolled_device_gets_sign_in_documents_signed() {
    let app = app(None).await;
    let (s, b) = sign(&app, &identify(&app), None).await;
    assert_refused(s, &b, "oobNotEnrolledDevice");
}

// ─── grant ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_grant_needs_a_uv_decision_and_a_uv_key() {
    let app = app(Some(Value::Null)).await;
    let (s, b) = sign(&app, &grant(&app), None).await;
    assert_refused(s, &b, "oobNoUvKey");

    let uv = hardware_key(0x51);
    let app = app_with_hardware(&uv).await;
    let (s, b) = sign(&app, &grant(&app), None).await;
    assert_refused(s, &b, "oobUvRequired");
}

async fn app_with_hardware(uv: &(String, Secret)) -> App {
    app(Some(hardware_enrolment(&uv.0))).await
}

#[tokio::test]
async fn a_grant_approved_by_the_hardware_uv_key_is_signed_once() {
    let uv = hardware_key(0x52);
    let app = app_with_hardware(&uv).await;
    let g = grant(&app);
    let d = hardware_decision(&app, &uv, &g).await;
    let (s, b) = sign(&app, &g, Some(d.clone())).await;
    assert_signed(s, &b, "assertionMethod");

    // The same grant id is never signed twice, even with a fresh approval.
    let d2 = hardware_decision(&app, &uv, &g).await;
    let (s, b) = sign(&app, &g, Some(d2)).await;
    assert_refused(s, &b, "oobGrantReplayed");
}

#[tokio::test]
async fn a_decision_for_another_grant_or_by_another_key_is_refused() {
    let uv = hardware_key(0x53);
    let app = app_with_hardware(&uv).await;

    // Approves a different grant.
    let g = grant(&app);
    let other = grant(&app);
    let d = hardware_decision(&app, &uv, &other).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // Approves this grant, but not with the enrolled UV key.
    let impostor = hardware_key(0x54);
    let d = hardware_decision(&app, &impostor, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // A refusal does not burn the grant id: the real approval still works.
    let d = hardware_decision(&app, &uv, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");
}

#[tokio::test]
async fn a_grant_approved_by_the_prf_sealed_uv_key_is_signed_once() {
    let uv = prf_sealed_key(0x5a);
    let app = app(Some(prf_sealed_enrolment(&uv.0))).await;
    let g = grant(&app);
    let d = hardware_decision(&app, &uv, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");

    let d2 = hardware_decision(&app, &uv, &g).await;
    let (s, b) = sign(&app, &g, Some(d2)).await;
    assert_refused(s, &b, "oobGrantReplayed");
}

#[tokio::test]
async fn a_prf_sealed_decision_must_be_by_that_key_and_carry_no_evidence() {
    let uv = prf_sealed_key(0x5b);
    let app = app(Some(prf_sealed_enrolment(&uv.0))).await;
    let g = grant(&app);
    let digest = grant_digest(&g).unwrap();

    // Signed by the device's transport key, as a passkey decision is.
    let (device, _) = did_for_seed(DEVICE_SEED);
    let d = decision(&app, &device, &transport_secret(DEVICE_SEED), &digest, None).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // Signed by another key.
    let impostor = prf_sealed_key(0x5c);
    let d = hardware_decision(&app, &impostor, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // Carrying evidence it does not take.
    let d = decision(
        &app,
        &uv.0,
        &uv.1,
        &digest,
        Some(json!({ "kind": "webauthn", "assertion": {} })),
    )
    .await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // None of those burnt the grant id.
    let d = hardware_decision(&app, &uv, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");
}

#[tokio::test]
async fn a_tampered_grant_no_longer_matches_its_approval() {
    let uv = hardware_key(0x55);
    let app = app_with_hardware(&uv).await;
    let g = grant(&app);
    let d = hardware_decision(&app, &uv, &g).await;
    let mut swapped = g.clone();
    swapped["payload"]["sessionKey"] = json!(did_for_seed(0x0c).0);
    let (s, b) = sign(&app, &swapped, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");
}

#[tokio::test]
async fn a_grant_must_match_the_schema_exactly() {
    let uv = hardware_key(0x56);
    let app = app_with_hardware(&uv).await;
    for (field, bad) in [
        ("decision", json!("deny")),
        ("notAfter", json!(chrono::Utc::now().timestamp() - 10)),
        ("contextDigest", json!("sha-256:abc")),
        ("origin", json!("https://portal.vtc.example/members")),
        ("sessionKey", json!("did:web:browser.example")),
    ] {
        let mut g = grant(&app);
        g["payload"][field] = bad.clone();
        let d = hardware_decision(&app, &uv, &g).await;
        let (s, b) = sign(&app, &g, Some(d)).await;
        assert_refused(s, &b, "oobDocumentInvalid");
    }
}

#[tokio::test]
async fn a_grant_approved_with_the_passkey_and_uv_is_signed() {
    let auth = SoftAuthenticator::new(0x61);
    let app = app(Some(passkey_enrolment(&auth))).await;
    let g = grant(&app);
    let d = passkey_decision(&app, &auth, &g, true).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");
}

#[tokio::test]
async fn a_passkey_assertion_without_user_verification_is_refused() {
    let auth = SoftAuthenticator::new(0x62);
    let app = app(Some(passkey_enrolment(&auth))).await;
    let g = grant(&app);
    let d = passkey_decision(&app, &auth, &g, false).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // Another authenticator's assertion is refused too.
    let other = SoftAuthenticator::new(0x63);
    let d = passkey_decision(&app, &other, &g, true).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");
}

// ─── device/register and device/heartbeat ───────────────────────────────────

#[tokio::test]
async fn a_malformed_uv_key_refuses_the_registration() {
    let app = app(None).await;
    let (status, body) = call(
        &app,
        REGISTER,
        json!({
            "consumerKind": { "kind": "companion", "formFactor": "mobile" },
            "displayName": "Test phone",
            "hpkePublicKey": "did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            "ext": { "org.openvtc.uv-key": {
                "kind": "hardwareKey", "did": hardware_key(0x57).0,
                "hardwareBacked": true, "biometricGated": false } },
        }),
    )
    .await;
    assert!(
        status != StatusCode::OK || body.to_string().contains("uvKeyInvalid"),
        "{body}"
    );
    assert!(body.to_string().contains("uvKeyInvalid"), "{body}");
}

#[tokio::test]
async fn the_device_replaces_its_uv_key_on_heartbeat() {
    let old = hardware_key(0x58);
    let new = hardware_key(0x59);
    let app = app_with_hardware(&old).await;

    let (status, body) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-key": hardware_enrolment(&new.0) } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "heartbeat: {body}");

    let g = grant(&app);
    let d = hardware_decision(&app, &old, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    let d = hardware_decision(&app, &new, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");
}

// ─── Many devices, one member ───────────────────────────────────────────────
//
// A member signs in from several devices at once. Each is its own DID, its own
// ACL entry and its own binding — so its own `consumerKind`, form factor,
// transport key and UV key. The member's own administrative entry (the
// `DEVICE_SEED` caller `app` builds with, standing in for `pnm`) is not a
// device at all.

const BROWSER_A: u8 = 0x81;
const BROWSER_B: u8 = 0x82;
const PHONE: u8 = 0x83;
const DISABLE: &str = "https://trusttasks.org/spec/device/disable/0.1";
const WIPE: &str = "https://trusttasks.org/spec/device/wipe/0.2";
const LIST: &str = "https://trusttasks.org/spec/device/list/0.2";

/// One of the member's devices: an ACL entry of its own in the member's
/// context, as onboarding writes one for every wallet install.
struct Device {
    seed: u8,
    token: String,
    device_id: String,
}

impl Device {
    fn did(&self) -> String {
        did_for_seed(self.seed).0
    }
}

async fn call_as(
    app: &App,
    device: &Device,
    type_uri: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let doc = signed_doc(device.seed, type_uri, payload, &app.vta_did);
    post(app, &device.token, &doc).await
}

async fn sign_as_device(
    app: &App,
    device: &Device,
    envelope: &Value,
    decision: Option<Value>,
) -> (StatusCode, Value) {
    let mut payload = json!({ "entryId": ENTRY, "unsignedEnvelope": envelope });
    if let Some(d) = decision {
        payload["ext"] = json!({ "org.openvtc.uv-consent": { "decision": d } });
    }
    call_as(app, device, SIGN_TT, payload).await
}

/// Give `seed` an ACL entry confined to the member's context (what onboarding
/// writes for a wallet) and, unless `form_factor` is `None`, register it as a
/// companion of that form factor with `uv` as its UV key.
async fn device(
    app: &App,
    seed: u8,
    form_factor: Option<&str>,
    name: &str,
    uv: Option<Value>,
) -> Device {
    let token = app
        .ctx
        .mint_token(&did_for_seed(seed).0, "admin", vec![CONTEXT.to_string()])
        .await;
    let mut d = Device {
        seed,
        token,
        device_id: String::new(),
    };
    if let Some(ff) = form_factor {
        let mut payload = json!({
            "consumerKind": { "kind": "companion", "formFactor": ff },
            "displayName": name,
        });
        if let Some(uv) = uv {
            payload["ext"] = json!({ "org.openvtc.uv-key": uv });
        }
        let (status, body) = call_as(app, &d, REGISTER, payload).await;
        assert_eq!(status, StatusCode::OK, "device/register {name}: {body}");
        d.device_id = body["payload"]["binding"]["deviceId"]
            .as_str()
            .expect("deviceId")
            .to_string();
    }
    d
}

async fn acl_row(app: &App, did: &str) -> vti_common::acl::AclEntry {
    vti_common::acl::get_acl_entry(&app.ctx.acl_ks, did)
        .await
        .expect("read ACL")
        .expect("entry exists")
}

/// The stored row, for comparing before and after.
async fn acl_json(app: &App, did: &str) -> Value {
    serde_json::to_value(acl_row(app, did).await).expect("row serialises")
}

struct Member {
    app: App,
    browser_a: Device,
    auth_a: SoftAuthenticator,
    browser_b: Device,
    auth_b: SoftAuthenticator,
    phone: Device,
    phone_uv: (String, Secret),
}

/// Two browser installs with their own passkeys and a phone with a hardware
/// UV key, all one member's.
async fn member() -> Member {
    let app = app(None).await;
    let auth_a = SoftAuthenticator::new(0x91);
    let auth_b = SoftAuthenticator::new(0x92);
    let phone_uv = hardware_key(0x93);
    let browser_a = device(
        &app,
        BROWSER_A,
        Some("browser"),
        "Chrome on macOS",
        Some(passkey_enrolment(&auth_a)),
    )
    .await;
    let browser_b = device(
        &app,
        BROWSER_B,
        Some("browser"),
        "Firefox on Linux",
        Some(passkey_enrolment(&auth_b)),
    )
    .await;
    let phone = device(
        &app,
        PHONE,
        Some("mobile"),
        "Phone",
        Some(hardware_enrolment(&phone_uv.0)),
    )
    .await;
    Member {
        app,
        browser_a,
        auth_a,
        browser_b,
        auth_b,
        phone,
        phone_uv,
    }
}

/// Each device signs both documents with its own UV key.
async fn assert_device_signs_in(m: &Member, which: &Device) {
    let app = &m.app;
    let (s, b) = sign_as_device(app, which, &identify(app), None).await;
    assert_signed(s, &b, "authentication");
    let g = grant(app);
    let d = if which.seed == PHONE {
        hardware_decision(app, &m.phone_uv, &g).await
    } else {
        let auth = if which.seed == BROWSER_A {
            &m.auth_a
        } else {
            &m.auth_b
        };
        passkey_decision_by(app, which.seed, auth, &g, true).await
    };
    let (s, b) = sign_as_device(app, which, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");
}

#[tokio::test]
async fn two_browsers_and_a_phone_each_sign_in_on_their_own_binding() {
    let m = member().await;
    for d in [&m.browser_a, &m.browser_b, &m.phone] {
        assert_device_signs_in(&m, d).await;
    }

    // Three rows, three bindings, each with its own kind and form factor.
    let ids: std::collections::BTreeSet<_> = [&m.browser_a, &m.browser_b, &m.phone]
        .iter()
        .map(|d| d.device_id.clone())
        .collect();
    assert_eq!(ids.len(), 3, "every device has its own deviceId");
    use vti_common::acl::{CompanionFormFactor, ConsumerKind};
    for (d, ff) in [
        (&m.browser_a, CompanionFormFactor::Browser),
        (&m.browser_b, CompanionFormFactor::Browser),
        (&m.phone, CompanionFormFactor::Mobile),
    ] {
        let row = acl_row(&m.app, &d.did()).await;
        assert_eq!(row.kind, ConsumerKind::Companion { form_factor: ff });
        assert_eq!(row.device.expect("binding").device_id, d.device_id);
    }

    // The member's own administrative entry is not a device: registering three
    // devices left its kind and (absent) binding alone, and it cannot sign in.
    let admin = acl_row(&m.app, &did_for_seed(DEVICE_SEED).0).await;
    assert_eq!(admin.kind, ConsumerKind::default());
    assert!(admin.device.is_none());
    let (s, b) = sign(&m.app, &identify(&m.app), None).await;
    assert_refused(s, &b, "oobNotEnrolledDevice");

    // The member lists all three, each under its own DID.
    let (s, b) = call(&m.app, LIST, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let listed = b["payload"]["devices"].as_array().expect("devices");
    for d in [&m.browser_a, &m.browser_b, &m.phone] {
        let row = listed
            .iter()
            .find(|x| x["deviceId"] == d.device_id.as_str())
            .unwrap_or_else(|| panic!("{} listed: {b}", d.device_id));
        assert_eq!(row["consumerDid"], d.did().as_str());
        assert!(row["ext"]["org.openvtc"]["uvKey"].is_object(), "{row}");
    }
}

#[tokio::test]
async fn each_devices_uv_key_approves_grants_for_that_device_only() {
    let m = member().await;
    let app = &m.app;
    let g = grant(app);

    // Browser B sends browser A's passkey assertion, under B's own transport
    // key: A's credential is not B's.
    let d = passkey_decision_by(app, BROWSER_B, &m.auth_a, &g, true).await;
    let (s, b) = sign_as_device(app, &m.browser_b, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // Browser B relays browser A's whole decision, signed by A: a passkey
    // decision must be by the caller's own transport key.
    let d = passkey_decision_by(app, BROWSER_A, &m.auth_a, &g, true).await;
    let (s, b) = sign_as_device(app, &m.browser_b, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // Browser B relays the phone's hardware-key decision.
    let d = hardware_decision(app, &m.phone_uv, &g).await;
    let (s, b) = sign_as_device(app, &m.browser_b, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // The phone relays browser A's passkey decision.
    let d = passkey_decision_by(app, BROWSER_A, &m.auth_a, &g, true).await;
    let (s, b) = sign_as_device(app, &m.phone, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");

    // None of those burned the grant id: B's own approval signs it.
    let d = passkey_decision_by(app, BROWSER_B, &m.auth_b, &g, true).await;
    let (s, b) = sign_as_device(app, &m.browser_b, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");

    // Replacing B's UV key on heartbeat leaves A's and the phone's alone.
    let auth_b2 = SoftAuthenticator::new(0x94);
    let (s, b) = call_as(
        app,
        &m.browser_b,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-key": passkey_enrolment(&auth_b2) } }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_device_signs_in(&m, &m.browser_a).await;
    assert_device_signs_in(&m, &m.phone).await;
    let g = grant(app);
    let d = passkey_decision_by(app, BROWSER_B, &m.auth_b, &g, true).await;
    let (s, b) = sign_as_device(app, &m.browser_b, &g, Some(d)).await;
    assert_refused(s, &b, "oobUvInvalid");
    let d = passkey_decision_by(app, BROWSER_B, &auth_b2, &g, true).await;
    let (s, b) = sign_as_device(app, &m.browser_b, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");
}

#[tokio::test]
async fn disabling_or_wiping_one_device_leaves_the_others_signing_in() {
    let m = member().await;
    let app = &m.app;
    let before_b = acl_json(app, &m.browser_b.did()).await;
    let before_phone = acl_json(app, &m.phone.did()).await;

    // The member disables browser A.
    let (s, b) = call(app, DISABLE, json!({ "deviceId": m.browser_a.device_id })).await;
    assert_eq!(s, StatusCode::OK, "{b}");

    // A is refused — as disabled, not as unenrolled, so it does not try to
    // register again — for both documents, and may not re-key.
    let (s, b) = sign_as_device(app, &m.browser_a, &identify(app), None).await;
    assert_refused(s, &b, "oobDeviceDisabled");
    let g = grant(app);
    let d = passkey_decision_by(app, BROWSER_A, &m.auth_a, &g, true).await;
    let (s, b) = sign_as_device(app, &m.browser_a, &g, Some(d)).await;
    assert_refused(s, &b, "oobDeviceDisabled");
    let (s, b) = call_as(
        app,
        &m.browser_a,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-key": passkey_enrolment(&SoftAuthenticator::new(0x95)) } }),
    )
    .await;
    assert!(
        s != StatusCode::OK || b.to_string().contains("deviceDisabled"),
        "{b}"
    );
    assert!(b.to_string().contains("deviceDisabled"), "{b}");

    // The other two rows are untouched and sign in as before.
    assert_eq!(acl_json(app, &m.browser_b.did()).await, before_b);
    assert_eq!(acl_json(app, &m.phone.did()).await, before_phone);
    assert_device_signs_in(&m, &m.browser_b).await;
    assert_device_signs_in(&m, &m.phone).await;

    // Wiping the phone stops the phone, and only the phone.
    let (s, b) = call(
        app,
        WIPE,
        json!({ "deviceId": m.phone.device_id, "reason": "lost", "scope": "full" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, b) = sign_as_device(app, &m.phone, &identify(app), None).await;
    assert_refused(s, &b, "oobDeviceDisabled");
    assert_device_signs_in(&m, &m.browser_b).await;

    // Each device's state is its own in the listing.
    let (s, b) = call(
        app,
        LIST,
        json!({ "includeDisabled": true, "includeWiped": true }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let devices = b["payload"]["devices"].as_array().expect("devices");
    let state = |id: &str| {
        let row = devices
            .iter()
            .find(|x| x["deviceId"] == id)
            .unwrap_or_else(|| panic!("{id} listed: {b}"));
        (
            row.get("disabledAt").is_some(),
            row.get("wipedAt").is_some(),
        )
    };
    assert_eq!(state(&m.browser_a.device_id), (true, false));
    assert_eq!(state(&m.browser_b.device_id), (false, false));
    assert_eq!(state(&m.phone.device_id), (true, true));
}

#[tokio::test]
async fn a_device_registering_changes_only_its_own_row() {
    let app = app(None).await;
    let auth_a = SoftAuthenticator::new(0x96);
    let a = device(
        &app,
        BROWSER_A,
        Some("browser"),
        "Chrome on macOS",
        Some(passkey_enrolment(&auth_a)),
    )
    .await;
    let a_row = acl_json(&app, &a.did()).await;
    let admin_row = acl_json(&app, &did_for_seed(DEVICE_SEED).0).await;

    // A second install of the same browser registers, then a phone.
    let b = device(&app, BROWSER_B, Some("browser"), "Chrome on macOS", None).await;
    let _phone = device(&app, PHONE, Some("mobile"), "Phone", None).await;
    assert_ne!(a.device_id, b.device_id);
    assert_eq!(acl_json(&app, &a.did()).await, a_row);
    assert_eq!(
        acl_json(&app, &did_for_seed(DEVICE_SEED).0).await,
        admin_row
    );

    // Registering again is refused and changes nothing (the spec: rotate keys).
    let (s, body) = call_as(
        &app,
        &a,
        REGISTER,
        json!({ "consumerKind": { "kind": "companion", "formFactor": "desktop" }, "displayName": "again" }),
    )
    .await;
    assert!(body.to_string().contains("alreadyRegistered"), "{s} {body}");
    assert_eq!(acl_json(&app, &a.did()).await, a_row);
}

/// A device registered before UV keys existed — its stored binding has no
/// `uvKey`, and its row predates `version`, `capabilities` and the rest —
/// still loads, still signs `identify`, and enrols a passkey on heartbeat to
/// approve grants. No re-registration, no re-onboarding.
#[tokio::test]
async fn a_device_enrolled_before_this_change_keeps_signing_in() {
    let app = app(None).await;
    let did = did_for_seed(BROWSER_A).0;
    let legacy = json!({
        "did": did,
        "role": "admin",
        "label": "browser-plugin onboarding",
        "allowed_contexts": [CONTEXT],
        "created_at": 1_780_000_000u64,
        "created_by": did_for_seed(DEVICE_SEED).0,
        "kind": { "kind": "companion", "form-factor": "browser" },
        "device": {
            "deviceId": "dev-legacy",
            "displayName": "VTA Wallet browser extension",
            "registeredAt": "2026-06-01T00:00:00Z",
            "lastSeenAt": "2026-06-02T00:00:00Z",
        },
    });
    app.ctx
        .acl_ks
        .insert(format!("acl:{did}"), &legacy)
        .await
        .expect("write the legacy row");
    let token = app
        .ctx
        .mint_token(&did, "admin", vec![CONTEXT.to_string()])
        .await;
    let dev = Device {
        seed: BROWSER_A,
        token,
        device_id: "dev-legacy".into(),
    };

    let row = acl_row(&app, &did).await;
    assert!(row.device.as_ref().is_some_and(|b| b.uv_key.is_none()));

    let (s, b) = sign_as_device(&app, &dev, &identify(&app), None).await;
    assert_signed(s, &b, "authentication");
    let (s, b) = sign_as_device(&app, &dev, &grant(&app), None).await;
    assert_refused(s, &b, "oobNoUvKey");

    let auth = SoftAuthenticator::new(0x97);
    let (s, b) = call_as(
        &app,
        &dev,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-key": passkey_enrolment(&auth) } }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let g = grant(&app);
    let d = passkey_decision_by(&app, BROWSER_A, &auth, &g, true).await;
    let (s, b) = sign_as_device(&app, &dev, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");
    assert_eq!(
        acl_row(&app, &did).await.device.expect("binding").device_id,
        "dev-legacy",
        "the binding is the one it always had"
    );
}

// ─── vtaPin: a PIN the VTA checks, with a guess limit ───────────────────────
//
// For a browser with no PRF passkey. The browser enrols `K` (its PBKDF2 output)
// as the verifier and approves a grant with a decision signed by its transport
// key plus `pinProof = HMAC-SHA256(K, "org.openvtc.uv-pin/v1|" + D)`.

const PIN_K: [u8; 32] = [0x4b; 32];
const OTHER_K: [u8; 32] = [0x4c; 32];

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hmac(k: &[u8; 32], message: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(k).unwrap();
    mac.update(message.as_bytes());
    b64(&mac.finalize().into_bytes())
}

fn pin_enrolment(k: &[u8; 32]) -> Value {
    json!({
        "kind": "vtaPin",
        "salt": b64(&[0x5a; 16]),
        "iterations": 600_000,
        "verifier": b64(k),
        "hardwareBacked": false,
        "biometricGated": false,
    })
}

/// The device's PIN approval of `grant`: a decision by its transport key, and
/// the HMAC under `k` over the grant digest.
async fn pin_consent(app: &App, grant: &Value, k: &[u8; 32]) -> Value {
    let digest = grant_digest(grant).unwrap();
    let (device, _) = did_for_seed(DEVICE_SEED);
    let d = decision(app, &device, &transport_secret(DEVICE_SEED), &digest, None).await;
    json!({
        "decision": d,
        "pinProof": hmac(k, &format!("org.openvtc.uv-pin/v1|{digest}")),
    })
}

async fn sign_with_consent(app: &App, envelope: &Value, consent: Value) -> (StatusCode, Value) {
    call(
        app,
        SIGN_TT,
        json!({
            "entryId": ENTRY,
            "unsignedEnvelope": envelope,
            "ext": { "org.openvtc.uv-consent": consent },
        }),
    )
    .await
}

/// The first value under `key` anywhere in `v` — a refusal's `details` sit at
/// a depth the binding decides.
fn find<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(key).or_else(|| m.values().find_map(|x| find(x, key))),
        Value::Array(a) => a.iter().find_map(|x| find(x, key)),
        _ => None,
    }
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Move the device's PIN lock into the past, as waiting it out would.
async fn expire_pin_lock(app: &App) {
    let key = format!("uv-pin:{}", did_for_seed(DEVICE_SEED).0);
    let raw = app
        .ctx
        .acl_ks
        .get_raw(key.clone())
        .await
        .unwrap()
        .expect("a guard row");
    let mut guard: Value = serde_json::from_slice(&raw).unwrap();
    guard["lockedUntil"] = json!(now_secs() - 1);
    app.ctx.acl_ks.insert(key, &guard).await.unwrap();
}

#[tokio::test]
async fn a_grant_approved_with_the_vta_pin_is_signed_once() {
    let app = app(Some(pin_enrolment(&PIN_K))).await;
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_signed(s, &b, "assertionMethod");

    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_refused(s, &b, "oobGrantReplayed");
}

#[tokio::test]
async fn a_pin_decision_must_be_the_devices_own_and_carry_a_proof() {
    let app = app(Some(pin_enrolment(&PIN_K))).await;
    let g = grant(&app);
    let digest = grant_digest(&g).unwrap();

    // No pinProof.
    let mut c = pin_consent(&app, &g, &PIN_K).await;
    c.as_object_mut().unwrap().remove("pinProof");
    let (s, b) = sign_with_consent(&app, &g, c).await;
    assert_refused(s, &b, "oobUvInvalid");

    // A decision signed by another key.
    let other = prf_sealed_key(0x5d);
    let mut c = pin_consent(&app, &g, &PIN_K).await;
    c["decision"] = decision(&app, &other.0, &other.1, &digest, None).await;
    let (s, b) = sign_with_consent(&app, &g, c).await;
    assert_refused(s, &b, "oobUvInvalid");

    // A proof over another grant's digest is a wrong PIN, counted.
    let mut c = pin_consent(&app, &g, &PIN_K).await;
    c["pinProof"] = json!(hmac(&PIN_K, "org.openvtc.uv-pin/v1|zSomethingElse"));
    let (s, b) = sign_with_consent(&app, &g, c).await;
    assert_refused(s, &b, "oobUvPinWrong");

    // None of those burnt the grant id.
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_signed(s, &b, "assertionMethod");
}

#[tokio::test]
async fn a_wrong_pin_reports_attempts_remaining_and_a_right_one_resets_the_count() {
    let app = app(Some(pin_enrolment(&PIN_K))).await;
    for remaining in [4, 3] {
        let g = grant(&app);
        let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
        assert_refused(s, &b, "oobUvPinWrong");
        assert_eq!(
            find(&b, "attemptsRemaining"),
            Some(&json!(remaining)),
            "{b}"
        );
        assert!(find(&b, "lockedUntil").is_none(), "{b}");
    }
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_signed(s, &b, "assertionMethod");

    // The count started again.
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    assert_refused(s, &b, "oobUvPinWrong");
    assert_eq!(find(&b, "attemptsRemaining"), Some(&json!(4)), "{b}");
}

#[tokio::test]
async fn five_wrong_pins_lock_and_each_lock_after_one_expires_is_twice_as_long() {
    let app = app(Some(pin_enrolment(&PIN_K))).await;
    for _ in 0..4 {
        let g = grant(&app);
        let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
        assert_refused(s, &b, "oobUvPinWrong");
    }
    // The fifth locks for 15 minutes.
    let g = grant(&app);
    let before = now_secs();
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    assert_refused(s, &b, "oobUvPinWrong");
    assert_eq!(find(&b, "attemptsRemaining"), Some(&json!(0)), "{b}");
    let until = find(&b, "lockedUntil")
        .and_then(Value::as_i64)
        .expect("locked");
    assert!((before + 900..=now_secs() + 900).contains(&until), "{b}");

    // While locked even the right PIN is refused, unchecked.
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_refused(s, &b, "oobUvLocked");
    assert_eq!(find(&b, "lockedUntil"), Some(&json!(until)), "{b}");

    // Once it has expired, one wrong PIN locks again — for 30 minutes.
    expire_pin_lock(&app).await;
    let g = grant(&app);
    let before = now_secs();
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    assert_refused(s, &b, "oobUvPinWrong");
    let until = find(&b, "lockedUntil")
        .and_then(Value::as_i64)
        .expect("locked");
    assert!((before + 1800..=now_secs() + 1800).contains(&until), "{b}");

    // And then an hour.
    expire_pin_lock(&app).await;
    let g = grant(&app);
    let before = now_secs();
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    assert_refused(s, &b, "oobUvPinWrong");
    let until = find(&b, "lockedUntil")
        .and_then(Value::as_i64)
        .expect("locked");
    assert!((before + 3600..=now_secs() + 3600).contains(&until), "{b}");

    // The right PIN after the lock signs, and resets the doubling: the next
    // wrong PIN has the full five attempts again.
    expire_pin_lock(&app).await;
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_signed(s, &b, "assertionMethod");
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    assert_refused(s, &b, "oobUvPinWrong");
    assert_eq!(find(&b, "attemptsRemaining"), Some(&json!(4)), "{b}");
}

#[tokio::test]
async fn the_pin_verifier_never_leaves_the_vta() {
    let app = app(None).await;
    let verifier = b64(&PIN_K);

    // Register (its response carries the binding).
    let (s, register) = call(
        &app,
        REGISTER,
        json!({
            "consumerKind": { "kind": "companion", "formFactor": "browser" },
            "displayName": "Chromium on Linux",
            "ext": { "org.openvtc.uv-key": pin_enrolment(&PIN_K) },
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{register}");
    let summary = find(&register, "uvKey").expect("summary").clone();
    assert_eq!(summary["kind"], "vtaPin", "{summary}");
    assert_eq!(summary["salt"], b64(&[0x5a; 16]), "{summary}");
    assert_eq!(summary["iterations"], 600_000, "{summary}");
    assert_eq!(summary["failedAttempts"], 0, "{summary}");
    assert_eq!(summary["lockedUntil"], Value::Null, "{summary}");

    // One wrong PIN, so the failure is audited.
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    assert_refused(s, &b, "oobUvPinWrong");

    // The listing and the heartbeat show the count, never the verifier.
    let (s, list) = call(&app, LIST, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let listed = find(&list, "uvKey").expect("listed summary");
    assert_eq!(listed["failedAttempts"], 1, "{listed}");
    let (s, hb) = call(&app, HEARTBEAT, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{hb}");
    let own = find(&hb, "org.openvtc.uv-key").expect("own summary");
    assert_eq!(own["kind"], "vtaPin", "{hb}");
    assert_eq!(own["failedAttempts"], 1, "{hb}");

    let audit: String = app
        .ctx
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
        .collect();
    assert!(
        audit.contains("device.uv-key.enrol"),
        "the enrolment is audited"
    );
    assert!(
        audit.contains("device.uv-pin.failed"),
        "the failure is audited"
    );
    for (what, text) in [
        ("register", register.to_string()),
        ("list", list.to_string()),
        ("heartbeat", hb.to_string()),
        ("refusal", b.to_string()),
        ("audit", audit),
    ] {
        assert!(!text.contains(&verifier), "{what} leaks the verifier");
    }
}

#[tokio::test]
async fn replacing_a_pin_needs_the_current_pin() {
    let app = app(Some(pin_enrolment(&PIN_K))).await;
    let uv = prf_sealed_key(0x5e);
    let new_key = prf_sealed_enrolment(&uv.0);
    let change = |k: &[u8; 32]| {
        let canonical = serde_json_canonicalizer::to_string(&new_key).unwrap();
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes()));
        hmac(k, &format!("org.openvtc.uv-pin/v1|change|{digest}"))
    };

    // No proof.
    let (s, b) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-key": new_key } }),
    )
    .await;
    assert!(s != StatusCode::OK || b.to_string().contains("uvKeyChangeProofRequired"));
    assert!(b.to_string().contains("uvKeyChangeProofRequired"), "{b}");

    // The wrong PIN: counted against the same limit.
    let (s, b) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": {
            "org.openvtc.uv-key": new_key,
            "org.openvtc.uv-key-change": { "pinProof": change(&OTHER_K) },
        } }),
    )
    .await;
    assert!(s != StatusCode::OK || b.to_string().contains("device:uvPinWrong"));
    assert!(b.to_string().contains("device:uvPinWrong"), "{b}");
    assert_eq!(find(&b, "attemptsRemaining"), Some(&json!(4)), "{b}");
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    assert_refused(s, &b, "oobUvPinWrong");
    assert_eq!(
        find(&b, "attemptsRemaining"),
        Some(&json!(3)),
        "one limit: {b}"
    );

    // A proof for a different new key does not authorise this one.
    let (_, b) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": {
            "org.openvtc.uv-key": prf_sealed_enrolment(&prf_sealed_key(0x5f).0),
            "org.openvtc.uv-key-change": { "pinProof": change(&PIN_K) },
        } }),
    )
    .await;
    assert!(b.to_string().contains("device:uvPinWrong"), "{b}");

    // The PIN still approves: nothing was replaced.
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_signed(s, &b, "assertionMethod");

    // The right PIN replaces it.
    let (s, b) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": {
            "org.openvtc.uv-key": new_key,
            "org.openvtc.uv-key-change": { "pinProof": change(&PIN_K) },
        } }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, pin_consent(&app, &g, &PIN_K).await).await;
    assert_refused(s, &b, "oobUvInvalid");
    let d = hardware_decision(&app, &uv, &g).await;
    let (s, b) = sign(&app, &g, Some(d)).await;
    assert_signed(s, &b, "assertionMethod");

    // Replacing a key of another kind needs nothing extra, as before.
    let (s, b) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-key": pin_enrolment(&OTHER_K) } }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
}

#[tokio::test]
async fn a_locked_pin_cannot_be_replaced() {
    let app = app(Some(pin_enrolment(&PIN_K))).await;
    for _ in 0..5 {
        let g = grant(&app);
        let _ = sign_with_consent(&app, &g, pin_consent(&app, &g, &OTHER_K).await).await;
    }
    let new_key = pin_enrolment(&OTHER_K);
    let canonical = serde_json_canonicalizer::to_string(&new_key).unwrap();
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes()));
    let (_, b) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": {
            "org.openvtc.uv-key": new_key,
            "org.openvtc.uv-key-change": {
                "pinProof": hmac(&PIN_K, &format!("org.openvtc.uv-pin/v1|change|{digest}")),
            },
        } }),
    )
    .await;
    assert!(b.to_string().contains("device:uvKeyLocked"), "{b}");
    assert!(find(&b, "lockedUntil").is_some(), "{b}");
}

// ─── remoteApprover: approve on the phone ───────────────────────────────────
//
// The browser names the member's phone; the VTA pushes a VTA-signed
// `task-consent/request` to it and answers `oobUvPending` until the phone's
// `task-consent/decision/0.1` approves it.

const DECISION_0_1: &str = "https://trusttasks.org/spec/task-consent/decision/0.1";

fn remote_enrolment(approver: &str) -> Value {
    json!({ "kind": "remoteApprover", "approver": approver,
            "hardwareBacked": false, "biometricGated": false })
}

/// A member's browser (the `DEVICE_SEED` caller, registered as a browser
/// companion with no UV key) and their phone, an ACL entry as `pnm acl create`
/// writes one, named by the operator as the browser's step-up approver.
async fn browser_and_phone() -> (App, Device) {
    let app = app(None).await;
    let (s, b) = call(
        &app,
        REGISTER,
        json!({
            "consumerKind": { "kind": "companion", "formFactor": "browser" },
            "displayName": "Chromium on Linux",
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let phone = device(&app, PHONE, None, "Phone", None).await;
    let mut browser = acl_row(&app, &did_for_seed(DEVICE_SEED).0).await;
    browser.step_up_approver = Some(phone.did());
    vti_common::acl::store_acl_entry(&app.ctx.acl_ks, &browser)
        .await
        .unwrap();
    (app, phone)
}

async fn enrol_remote(app: &App, approver: &str) -> (StatusCode, Value) {
    call(
        app,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-key": remote_enrolment(approver) } }),
    )
    .await
}

/// The live request the VTA raised for the browser.
async fn raised(app: &App) -> Vec<vti_common::task_consent::PendingTaskConsent> {
    app.ctx
        .state
        .task_consent_ks
        .prefix_iter_raw("pending:")
        .await
        .unwrap()
        .into_iter()
        .map(|(_, v)| serde_json::from_slice(&v).unwrap())
        .collect()
}

/// The phone's `task-consent/decision/0.1`, as Cierge sends it.
async fn phone_decides(
    app: &App,
    by: &Device,
    pending: &vti_common::task_consent::PendingTaskConsent,
    answer: &str,
) -> (StatusCode, Value) {
    call_as(
        app,
        by,
        DECISION_0_1,
        json!({
            "challenge": pending.challenge,
            "payloadDigest": pending.wire_digest,
            "decision": answer,
        }),
    )
    .await
}

fn remote() -> Value {
    json!({ "remote": true })
}

#[tokio::test]
async fn a_remote_approver_must_be_a_phone_the_operator_named() {
    let (app, phone) = browser_and_phone().await;

    // Not itself.
    let (_, b) = enrol_remote(&app, &did_for_seed(DEVICE_SEED).0).await;
    assert!(b.to_string().contains("uvApproverNotPermitted"), "{b}");
    // Not a DID the VTA does not know.
    let (_, b) = enrol_remote(&app, &did_for_seed(0x99).0).await;
    assert!(b.to_string().contains("uvApproverNotPermitted"), "{b}");
    // Not a DID in the ACL that nobody designated (another browser).
    let other = device(&app, BROWSER_B, Some("browser"), "Firefox", None).await;
    let (_, b) = enrol_remote(&app, &other.did()).await;
    assert!(b.to_string().contains("uvApproverNotPermitted"), "{b}");
    // Not a malformed DID.
    let (_, b) = enrol_remote(&app, "phone").await;
    assert!(b.to_string().contains("uvKeyInvalid"), "{b}");
    // Not an entry the browser created itself, even one it designated.
    let minted = did_for_seed(0x9a).0;
    let mut own = vti_common::acl::AclEntry::new(
        &minted,
        vti_common::acl::Role::Reader,
        did_for_seed(DEVICE_SEED).0,
    );
    own.allowed_contexts = vec![CONTEXT.into()];
    vti_common::acl::store_acl_entry(&app.ctx.acl_ks, &own)
        .await
        .unwrap();
    let mut browser = acl_row(&app, &did_for_seed(DEVICE_SEED).0).await;
    browser.step_up_approver = Some(minted.clone());
    vti_common::acl::store_acl_entry(&app.ctx.acl_ks, &browser)
        .await
        .unwrap();
    let (_, b) = enrol_remote(&app, &minted).await;
    assert!(b.to_string().contains("uvApproverNotPermitted"), "{b}");
    browser.step_up_approver = Some(phone.did());
    vti_common::acl::store_acl_entry(&app.ctx.acl_ks, &browser)
        .await
        .unwrap();

    // The picker lists the phone, and only the phone.
    let (s, b) = call(
        &app,
        HEARTBEAT,
        json!({ "ext": { "org.openvtc.uv-approvers": {} } }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let approvers = find(&b, "approvers")
        .and_then(Value::as_array)
        .expect("approvers");
    assert_eq!(approvers.len(), 1, "{b}");
    assert_eq!(approvers[0]["did"], phone.did(), "{b}");

    // The phone enrols.
    let (s, b) = enrol_remote(&app, &phone.did()).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let own = find(&b, "org.openvtc.uv-key").expect("summary");
    assert_eq!(own["kind"], "remoteApprover", "{b}");
    assert_eq!(own["approver"], phone.did(), "{b}");
}

#[tokio::test]
async fn a_member_of_an_approver_set_may_be_named_too() {
    let (app, _) = browser_and_phone().await;
    let tablet = device(&app, 0x84, None, "Tablet", None).await;
    let (_, b) = enrol_remote(&app, &tablet.did()).await;
    assert!(b.to_string().contains("uvApproverNotPermitted"), "{b}");
    vta_service::policy::seed_declarative_approvals(
        &app.ctx.policy_ks,
        &[],
        &std::collections::HashMap::from([("phones".to_string(), vec![tablet.did()])]),
        &chrono::Utc::now().to_rfc3339(),
    )
    .await
    .unwrap();
    let (s, b) = enrol_remote(&app, &tablet.did()).await;
    assert_eq!(s, StatusCode::OK, "{b}");
}

#[tokio::test]
async fn a_grant_approved_on_the_phone_is_signed_once() {
    let (app, phone) = browser_and_phone().await;
    let (s, b) = enrol_remote(&app, &phone.did()).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let g = grant(&app);

    // The phone is asked once; polling re-reads the same request.
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_refused(s, &b, "oobUvPending");
    let code = find(&b, "matchCode")
        .and_then(Value::as_str)
        .expect("code")
        .to_string();
    let expires = find(&b, "expiresAt")
        .and_then(Value::as_u64)
        .expect("expiry");
    let now = now_secs() as u64;
    assert!(expires > now && expires <= now + 120, "{b}");
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_refused(s, &b, "oobUvPending");
    assert_eq!(find(&b, "matchCode"), Some(&json!(code)), "{b}");
    let pending = raised(&app).await;
    assert_eq!(pending.len(), 1, "one request, however often it is polled");
    let p = &pending[0];
    assert_eq!(p.bound_approver.as_deref(), Some(phone.did().as_str()));
    assert_eq!(p.requester_did, did_for_seed(DEVICE_SEED).0);
    assert_eq!(
        vta_sdk::task_consent::match_code(&p.wire_digest).unwrap(),
        code,
        "the browser shows the code the phone shows"
    );

    // A decision without the phone, or a PIN decision, does not stand in.
    let (s, b) = sign(&app, &g, None).await;
    assert_refused(s, &b, "oobUvRequired");

    // The phone approves; the browser's next poll signs.
    let (s, b) = phone_decides(&app, &phone, p, "approve").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(find(&b, "status"), Some(&json!("granted")), "{b}");
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_signed(s, &b, "assertionMethod");

    // Single use: the same grant again is refused, and nothing is re-asked.
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_refused(s, &b, "oobGrantReplayed");
    assert!(raised(&app).await.is_empty());

    // The signature is audited as the phone's approval.
    let audit: String = app
        .ctx
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
        .collect();
    assert!(audit.contains("remoteApprover"), "kind is audited");
    assert!(audit.contains(&phone.did()), "the approver is audited");
}

#[tokio::test]
async fn a_declined_or_lapsed_remote_approval_is_refused() {
    let (app, phone) = browser_and_phone().await;
    enrol_remote(&app, &phone.did()).await;

    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_refused(s, &b, "oobUvPending");
    let p = raised(&app).await.remove(0);
    let (s, b) = phone_decides(&app, &phone, &p, "deny").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    for _ in 0..2 {
        let (s, b) = sign_with_consent(&app, &g, remote()).await;
        assert_refused(s, &b, "oobUvDeclined");
    }
    assert!(raised(&app).await.is_empty(), "a decline does not re-ask");

    // A request nobody answered lapses.
    let g = grant(&app);
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_refused(s, &b, "oobUvPending");
    let mut p = raised(&app).await.remove(0);
    p.expires_at = now_secs() as u64 - 1;
    app.ctx
        .state
        .task_consent_ks
        .insert(format!("pending:{}", p.digest), &p)
        .await
        .unwrap();
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_refused(s, &b, "oobUvExpired");
    let (s, b) = phone_decides(&app, &phone, &p, "approve").await;
    assert!(b.to_string().contains("noPending"), "{s} {b}");
    let (s, b) = sign_with_consent(&app, &g, remote()).await;
    assert_refused(s, &b, "oobUvExpired");
}

#[tokio::test]
async fn only_the_named_phone_approving_this_grant_counts() {
    let (app, phone) = browser_and_phone().await;
    enrol_remote(&app, &phone.did()).await;
    let g1 = grant(&app);
    let g2 = grant(&app);
    let (s, b) = sign_with_consent(&app, &g1, remote()).await;
    assert_refused(s, &b, "oobUvPending");
    let (s, b) = sign_with_consent(&app, &g2, remote()).await;
    assert_refused(s, &b, "oobUvPending");
    let pending = raised(&app).await;
    assert_eq!(pending.len(), 2);

    // Another device in the ACL answers with the right challenge and digest:
    // it is not the approver this request is bound to.
    let intruder = device(&app, BROWSER_A, Some("browser"), "Other browser", None).await;
    for p in &pending {
        let (s, b) = phone_decides(&app, &intruder, p, "approve").await;
        assert!(
            s != StatusCode::OK && b.to_string().contains("not a member"),
            "{s} {b}"
        );
    }
    // The phone answers with a digest that names no request.
    let mut wrong = pending[0].clone();
    wrong.wire_digest = pending[0].digest.clone();
    let (s, b) = phone_decides(&app, &phone, &wrong, "approve").await;
    assert!(b.to_string().contains("noPending"), "{s} {b}");
    // …or with the other request's challenge.
    let mut crossed = pending[0].clone();
    crossed.challenge = pending[1].challenge.clone();
    let (s, b) = phone_decides(&app, &phone, &crossed, "approve").await;
    assert!(s != StatusCode::OK, "{b}");
    for g in [&g1, &g2] {
        let (s, b) = sign_with_consent(&app, g, remote()).await;
        assert_refused(s, &b, "oobUvPending");
    }

    // Approving one grant's request approves that grant and no other.
    let digest_of = |g: &Value| grant_digest(g).unwrap();
    let _ = digest_of;
    let (s, b) = phone_decides(&app, &phone, &pending[0], "approve").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let mut signed = 0;
    for g in [&g1, &g2] {
        let (s, b) = sign_with_consent(&app, g, remote()).await;
        if s == StatusCode::OK && b.to_string().contains("signedEnvelope") {
            signed += 1;
        } else {
            assert_refused(s, &b, "oobUvPending");
        }
    }
    assert_eq!(signed, 1, "exactly the approved grant is signed");
}
