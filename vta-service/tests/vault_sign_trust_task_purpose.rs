//! `vault/sign-trust-task` signs for the purpose the document's type demands.
//!
//! VTI-KEY-022 and VTI-KEY-106: an operational Trust Task document is signed
//! for `authentication`; `assertionMethod` is only for the approver/attestation
//! types the registry names. The vault used to sign everything for
//! `assertionMethod`, so a relying party that (rightly) refuses
//! `assertionMethod` on operational tasks refused every document a wallet
//! session had the VTA sign for it.
//!
//! These tests sign through `/trust-tasks` with a real key held in the
//! entry's context, then check the proof: its declared purpose, and that it
//! verifies over the envelope under the principal's public key (so the purpose
//! is inside the signature, not pasted on afterwards). The refusal paths cover
//! a `type` that is not a Type URI and an envelope that already carries a
//! proof, whatever purpose that proof names.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use vta_service::test_support::{build_test_app, did_for_seed, sign_as};
use vti_common::vault::{
    SecretKind, SiteTarget, StoredVaultEntry, VaultEntry, VaultSecret, VaultStatus,
    put_stored_vault_entry,
};

const CALLER_SEED: u8 = 0x61;
const CONTEXT: &str = "wallet";
const ENTRY: &str = "persona-1";
const VTA: &str = "did:key:z6MkfMo6gxqdBhaHMNnmfhgZFBjpCDTkmJMJLoypsBZS9PwD";
const SIGN_TT: &str = "https://trusttasks.org/spec/vault/sign-trust-task/0.2";
const KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn signed_doc(type_uri: &str, payload: Value) -> Value {
    let mut typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuedAt": now(),
        "issuer": did_for_seed(CALLER_SEED).0,
        "recipient": VTA,
        "payload": payload,
    }))
    .expect("envelope deserialises");
    sign_as(CALLER_SEED, &mut typed);
    serde_json::to_value(&typed).expect("envelope serialises")
}

async fn post(router: &axum::Router, token: &str, doc: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(doc).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A signing-capable app: the entry's context, a key minted in it, and a
/// `did-self-issued` entry whose principal is that key's `did:key`.
/// Returns the router, a token, the principal DID and its raw public key.
async fn app() -> (axum::Router, String, String, Vec<u8>) {
    let (router, ctx) = build_test_app().await;
    vta_service::contexts::create_context(&ctx.contexts_ks, CONTEXT, "Wallet personas")
        .await
        .expect("context");
    let token = ctx
        .mint_token(&did_for_seed(CALLER_SEED).0, "admin", vec![])
        .await;

    let (status, body) = post(
        &router,
        &token,
        &signed_doc(
            KEYS_CREATE,
            json!({ "keyType": "ed25519", "derivationPath": "", "label": "persona", "contextId": CONTEXT }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "keys/create: {body}");
    let key = &body["payload"]["key"];
    let key_id = key["keyId"].as_str().expect("keyId").to_string();
    let public_key = key["publicKey"].as_str().expect("publicKey").to_string();
    let principal = format!("did:key:{public_key}");
    let (_, multicodec) = multibase::decode(&public_key).expect("multibase public key");
    assert_eq!(&multicodec[..2], &[0xed, 0x01], "an Ed25519 multikey");

    let stamp = "2026-01-01T00:00:00Z".to_string();
    let entry = StoredVaultEntry {
        entry: VaultEntry {
            id: ENTRY.to_string(),
            context_id: CONTEXT.to_string(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://rp.example".to_string(),
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
        .expect("seed the signing entry");
    (router, token, principal, multicodec[2..].to_vec())
}

fn unsigned(type_uri: &str, principal: &str) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": principal,
        "recipient": "did:web:rp.example",
        "issuedAt": now(),
        "payload": {},
    })
}

async fn sign(router: &axum::Router, token: &str, envelope: Value) -> (StatusCode, Value) {
    post(
        router,
        token,
        &signed_doc(
            SIGN_TT,
            json!({ "entryId": ENTRY, "unsignedEnvelope": envelope }),
        ),
    )
    .await
}

/// Sign `type_uri`, assert the proof names `purpose`, and verify it over the
/// envelope under the principal's key.
async fn assert_signed_for(type_uri: &str, purpose: &str) {
    let (router, token, principal, public_key) = app().await;
    let envelope = unsigned(type_uri, &principal);
    let (status, body) = sign(&router, &token, envelope.clone()).await;
    assert_eq!(status, StatusCode::OK, "{type_uri}: {body}");

    let signed = body["payload"]["signedEnvelope"].clone();
    assert_eq!(
        signed["proof"]["proofPurpose"], purpose,
        "{type_uri}: {signed}"
    );
    let mut stripped = signed.clone();
    let proof_value = stripped
        .as_object_mut()
        .expect("object")
        .remove("proof")
        .expect("a proof");
    assert_eq!(stripped, envelope, "every other member is unchanged");

    let proof: affinidi_data_integrity::DataIntegrityProof =
        serde_json::from_value(proof_value).expect("a Data Integrity proof");
    proof
        .verify_with_public_key(
            &stripped,
            &public_key,
            affinidi_data_integrity::VerifyOptions::new(),
        )
        .expect("the proof verifies over the envelope");

    // The declared purpose is covered by the signature: relabelling it breaks
    // verification, so no intermediary can turn one into the other.
    let mut relabelled = proof.clone();
    relabelled.proof_purpose = if purpose == "authentication" {
        "assertionMethod".into()
    } else {
        "authentication".into()
    };
    assert!(
        relabelled
            .verify_with_public_key(
                &stripped,
                &public_key,
                affinidi_data_integrity::VerifyOptions::new()
            )
            .is_err(),
        "a relabelled purpose must not verify"
    );
}

#[tokio::test]
async fn operational_documents_are_signed_for_authentication() {
    for type_uri in [
        "https://trusttasks.org/spec/acl/grant/0.1",
        "https://trusttasks.org/spec/did-management/did/list/0.2",
        "https://trusttasks.org/spec/auth/step-up/approve-request/0.3",
        // The executor's reply to a decision is an operational message too.
        "https://trusttasks.org/spec/task-consent/decision/0.1#response",
        // A private registry does not inherit the registry's attestation slugs.
        "https://registry.example/spec/auth/step-up/approve-response/0.5",
    ] {
        assert_signed_for(type_uri, "authentication").await;
    }
}

#[tokio::test]
async fn approver_decisions_are_signed_for_assertion_method() {
    for type_uri in [
        "https://trusttasks.org/spec/auth/step-up/approve-response/0.5",
        "https://trusttasks.org/spec/task-consent/decision/0.1",
        "https://trusttasks.org/spec/confirm/response/0.1",
    ] {
        assert_signed_for(type_uri, "assertionMethod").await;
    }
}

/// The purpose is decided by the type, so a type that is not a Type URI
/// cannot be signed for any purpose. A string that is not one is refused by the
/// handler as `envelopeInvalid`; a non-string never gets that far, because the
/// published schema types `type` as a string and the gate refuses it as
/// `malformedRequest`.
#[tokio::test]
async fn a_type_that_is_not_a_type_uri_is_refused() {
    let (router, token, principal, _) = app().await;
    for bad in [
        json!("approve-response"),
        json!("http://trusttasks.org/spec/acl/grant/0.1"),
        json!("https://trusttasks.org/spec/acl/grant/latest"),
        json!(42),
    ] {
        let mut envelope = unsigned("https://trusttasks.org/spec/acl/grant/0.1", &principal);
        envelope["type"] = bad.clone();
        let (status, body) = sign(&router, &token, envelope).await;
        assert_ne!(status, StatusCode::OK, "{bad}: {body}");
        let text = body.to_string();
        let expected = if bad.is_string() {
            "envelopeInvalid"
        } else {
            "malformedRequest"
        };
        assert!(
            text.contains(expected) && !text.contains("signedEnvelope"),
            "{bad} must be refused as {expected}: {text}"
        );
    }
}

/// A requester cannot pick the purpose by pre-filling a proof: an envelope
/// that carries one is refused, whatever purpose it names. The published
/// schema forbids `proof` on `unsignedEnvelope`, so the gate refuses it before
/// the handler's own `envelopeAlreadyProofed` check.
#[tokio::test]
async fn a_requester_supplied_proof_is_refused() {
    let (router, token, principal, _) = app().await;
    let mut envelope = unsigned("https://trusttasks.org/spec/acl/grant/0.1", &principal);
    envelope["proof"] = json!({ "type": "DataIntegrityProof", "proofPurpose": "assertionMethod" });
    let (status, body) = sign(&router, &token, envelope).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    let text = body.to_string();
    assert!(
        text.contains("malformedRequest") && !text.contains("signedEnvelope"),
        "refused before signing: {text}"
    );
}
