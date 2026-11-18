//! What the central signing operations produce for a key held in the VTA's own
//! store, pinned against references built here from the primitives alone.
//!
//! Ed25519 and ES256 (RFC 6979) signatures are deterministic, so a signature is
//! the same bytes whatever code made it. These tests fix a key, sign through the
//! real operations (ACL gates, custody, audit and all) and compare with the
//! signature the primitive makes over the bytes the specification defines. They
//! are the evidence that moving the byte building and the signing step into
//! `vta-signing` changed no output.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vta_sdk::keys::KeyType;
use vta_sdk::protocols::key_management::sign::{
    SignAlgorithm, SigningDomain, opaque_signing_input,
};
use vta_sdk::protocols::key_management::sign_sshsig::signed_data;

use crate::acl::Role;
use crate::operations::keys::{
    ImportKeyParams, import_key, sign_document, sign_jws, sign_payload, sign_sshsig,
};
use crate::operations::persona::PersonaStores;
use crate::operations::sign_formats::{
    JwsPayload, document_proof_config, eddsa_jcs_2022_hash_data, jws_signing_input,
};
use crate::test_support::build_signing_test_app_state;
use vti_common::auth::AuthClaims;

const ED25519_SEED: [u8; 32] = [0x11; 32];
const P256_SCALAR: [u8; 32] = [0x22; 32];
const CHANNEL: &str = "characterization";

fn admin() -> AuthClaims {
    AuthClaims {
        did: "did:key:z6MkCharacterizationAdmin".to_string(),
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        session_id: "s".into(),
        access_expires_at: 0,
        issued_at: 0,
        amr: Vec::new(),
        acr: String::new(),
    }
}

struct Fixture {
    state: crate::server::AppState,
    _dir: tempfile::TempDir,
    auth: AuthClaims,
    ed25519_key: String,
    ed25519_public: String,
    p256_key: String,
}

impl Fixture {
    async fn new() -> Self {
        let (state, dir) = build_signing_test_app_state().await;
        let auth = admin();
        let ed = import(
            &state,
            &auth,
            KeyType::Ed25519,
            ED25519_SEED.to_vec(),
            "ed-key",
        )
        .await;
        let p256 = import(
            &state,
            &auth,
            KeyType::P256,
            P256_SCALAR.to_vec(),
            "p256-key",
        )
        .await;
        Self {
            state,
            _dir: dir,
            auth,
            ed25519_key: ed.0,
            ed25519_public: ed.1,
            p256_key: p256.0,
        }
    }
}

async fn import(
    state: &crate::server::AppState,
    auth: &AuthClaims,
    key_type: KeyType,
    secret: Vec<u8>,
    label: &str,
) -> (String, String) {
    let created = import_key(
        &state.keys_ks,
        &state.imported_ks,
        &state.seed_store,
        &state.audit_sink,
        auth,
        ImportKeyParams {
            key_type,
            private_key_bytes: secret,
            label: Some(label.to_string()),
            context_id: None,
        },
        CHANNEL,
    )
    .await
    .expect("import");
    (created.key_id, created.public_key)
}

fn ed25519_sign(message: &[u8]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED)
        .sign(message)
        .to_bytes()
        .to_vec()
}

fn p256_sign(message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer as _;
    let key = p256::ecdsa::SigningKey::from_slice(&P256_SCALAR).expect("scalar");
    let signature: p256::ecdsa::Signature = key.sign(message);
    signature.to_bytes().to_vec()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn object(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn an_opaque_payload_is_signed_under_its_domain_tag_by_both_key_types() {
    let f = Fixture::new().await;
    let payload = b"caller bytes the vta cannot read";
    let s = &f.state;

    let ed = sign_payload(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        &f.auth,
        &f.ed25519_key,
        payload,
        &SignAlgorithm::EdDSA,
        SigningDomain::Opaque,
        CHANNEL,
    )
    .await
    .expect("ed25519");
    let p256 = sign_payload(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        &f.auth,
        &f.p256_key,
        payload,
        &SignAlgorithm::ES256,
        SigningDomain::Opaque,
        CHANNEL,
    )
    .await
    .expect("p256");

    let framed = opaque_signing_input(payload);
    assert_eq!(ed.signature, b64(&ed25519_sign(&framed)));
    assert_eq!(p256.signature, b64(&p256_sign(&framed)));
}

#[tokio::test]
async fn a_protocol_defined_payload_is_signed_exactly_as_presented() {
    let f = Fixture::new().await;
    let payload = b"bytes a specification already framed";
    let s = &f.state;

    let ed = sign_payload(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        &f.auth,
        &f.ed25519_key,
        payload,
        &SignAlgorithm::EdDSA,
        SigningDomain::ProtocolDefined,
        CHANNEL,
    )
    .await
    .expect("ed25519");

    assert_eq!(ed.signature, b64(&ed25519_sign(payload)));
}

#[tokio::test]
async fn a_jws_is_the_rfc_8785_signing_input_with_the_keys_own_signature() {
    let f = Fixture::new().await;
    let s = &f.state;
    let header = object(json!({ "typ": "at+jwt", "kid": "key-1" }));
    let payload = object(json!({ "sub": "agent", "n": 1, "a": { "z": 1, "b": 2 } }));

    let (ed_jws, ed_alg) = sign_jws(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        &f.auth,
        &f.ed25519_key,
        &header,
        JwsPayload::Json(&payload),
        CHANNEL,
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("ed25519 jws");
    let (p256_jws, p256_alg) = sign_jws(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        &f.auth,
        &f.p256_key,
        &header,
        JwsPayload::Json(&payload),
        CHANNEL,
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("p256 jws");

    assert_eq!((ed_alg, p256_alg), ("EdDSA", "ES256"));
    let ed_input = jws_signing_input("EdDSA", &header, JwsPayload::Json(&payload)).unwrap();
    let p256_input = jws_signing_input("ES256", &header, JwsPayload::Json(&payload)).unwrap();
    assert_eq!(
        ed_jws,
        format!("{ed_input}.{}", b64(&ed25519_sign(ed_input.as_bytes())))
    );
    assert_eq!(
        p256_jws,
        format!("{p256_input}.{}", b64(&p256_sign(p256_input.as_bytes())))
    );
}

#[tokio::test]
async fn a_base64url_jws_payload_is_signed_as_given() {
    let f = Fixture::new().await;
    let s = &f.state;
    let header = object(json!({ "typ": "JWT" }));
    let given = b64(br#"{"b":1,"a":2}"#);

    let (jws, _) = sign_jws(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        &f.auth,
        &f.ed25519_key,
        &header,
        JwsPayload::Base64Url(&given),
        CHANNEL,
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("jws");

    let input = jws_signing_input("EdDSA", &header, JwsPayload::Base64Url(&given)).unwrap();
    assert!(input.ends_with(&format!(".{given}")));
    assert_eq!(
        jws,
        format!("{input}.{}", b64(&ed25519_sign(input.as_bytes())))
    );
}

#[tokio::test]
async fn a_document_proof_is_the_eddsa_jcs_2022_signature_over_its_hash_data() {
    let f = Fixture::new().await;
    let s = &f.state;
    let signer = format!("did:key:{}", f.ed25519_public);
    let document = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": signer,
        "credentialSubject": { "id": "did:example:subject" }
    });
    let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let signed = sign_document(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        PersonaStores::from_state(s),
        None,
        &f.auth,
        &f.ed25519_key,
        &document,
        Some("assertionMethod"),
        Some(&created),
        Some("a-challenge"),
        Some("example.com"),
        CHANNEL,
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("signed document");

    assert_eq!(signed.signer_did, signer);
    let vm = format!("{signer}#{}", f.ed25519_public);
    let config = document_proof_config(
        &document,
        &vm,
        "assertionMethod",
        &created,
        Some("a-challenge"),
        Some("example.com"),
    );
    let hash_data = eddsa_jcs_2022_hash_data(&document, &config).unwrap();
    let mut expected = config;
    expected["proofValue"] =
        multibase::encode(multibase::Base::Base58Btc, ed25519_sign(&hash_data)).into();
    assert_eq!(signed.proof, expected);
    assert_eq!(signed.document["proof"], expected);
}

#[tokio::test]
async fn an_sshsig_signature_covers_the_rfc_4251_framed_statement() {
    let f = Fixture::new().await;
    let s = &f.state;
    let message_hash = Sha256::digest(b"a file to sign").to_vec();

    let signed = sign_sshsig(
        &s.keys_ks,
        &s.imported_ks,
        &s.internal_ks,
        &s.contexts_ks,
        &s.acl_ks,
        &s.seed_store,
        &s.audit_sink,
        &f.auth,
        &f.ed25519_key,
        &SignAlgorithm::EdDSA,
        "file",
        "sha256",
        32,
        &message_hash,
        CHANNEL,
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("sshsig");

    let statement = signed_data("file", "sha256", &message_hash);
    assert_eq!(signed.signature, b64(&ed25519_sign(&statement)));
}
