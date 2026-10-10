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
use vta_service::test_support::{SoftAuthenticator, build_test_app, did_for_seed, sign_as};
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
}

fn signed_doc(type_uri: &str, payload: Value, vta: &str) -> Value {
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuedAt": now(),
        "issuer": did_for_seed(DEVICE_SEED).0,
        "recipient": vta,
        "payload": payload,
    }))
    .expect("envelope deserialises");
    sign_as(DEVICE_SEED, &mut typed);
    serde_json::to_value(&typed).expect("envelope serialises")
}

async fn post(app: &App, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("authorization", format!("Bearer {}", app.token))
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
    let doc = signed_doc(type_uri, payload, &app.vta_did);
    post(app, &doc).await
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
    put_stored_vault_entry(&ctx.vault_ks, &entry)
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

fn device_secret() -> Secret {
    let (_, vm) = did_for_seed(DEVICE_SEED);
    Secret::generate_ed25519(Some(&vm), Some(&[DEVICE_SEED; 32]))
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
    let digest = grant_digest(grant).unwrap();
    let a = auth.assert(
        RP_ID,
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
        &did_for_seed(DEVICE_SEED).0,
        &device_secret(),
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
