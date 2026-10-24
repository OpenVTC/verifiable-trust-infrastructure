//! A did:scid:vh:1 identity signs a Trust Task as itself (VTI-KEY-161 to
//! VTI-KEY-163).
//!
//! The holder names its key under the did:scid DID URL, `src` included, and
//! writes `issuer` in the same form; a verifier that has never seen the
//! identity resolves it through that `src` to the identity's own document, whose
//! keys are under the bare DID, and accepts the proof. Its own binary because
//! the log is served on loopback, which only a process-wide opt-in allows.

#![cfg(all(feature = "client", feature = "proof-verify", feature = "session"))]

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, network_resolvers::HostPolicy,
};
use didwebvh_rs::prelude::*;
use serde_json::{Value, json};
use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_value};
use vta_sdk::trust_task_sign::{HolderKey, build_signed_with};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A signed did:webvh log on the mock server's `/.well-known/did.jsonl`,
/// listing its did:scid alias. Returns the did:webvh DID and the signing key.
async fn serve_log(server: &MockServer) -> (String, String) {
    let port = server.address().port();
    let (_, signing_key) = didwebvh_rs::did_key::generate_did_key(KeyType::Ed25519).unwrap();
    let document = json!({
        "id": "{DID}",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": "{DID}#key-0",
            "type": "Multikey",
            "controller": "{DID}",
            "publicKeyMultibase": signing_key.get_public_keymultibase().unwrap(),
        }],
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"],
    });
    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            signing_key.get_public_keymultibase().unwrap(),
        )])),
        ..Default::default()
    };
    let config = CreateDIDConfig::builder()
        .address(format!("http://localhost:{port}/"))
        .authorization_key(signing_key.clone())
        .did_document(document)
        .parameters(parameters)
        .also_known_as_scid(true)
        .build()
        .unwrap();
    let created = create_did(config).await.unwrap();
    let log = format!("{}\n", serde_json::to_string(created.log_entry()).unwrap());
    Mock::given(method("GET"))
        .and(path("/.well-known/did.jsonl"))
        .respond_with(ResponseTemplate::new(200).set_body_string(log))
        .mount(server)
        .await;
    (
        created.did().to_string(),
        signing_key.get_private_keymultibase().unwrap(),
    )
}

/// A verifier with its own resolver — so its own did:scid sources — allowed to
/// reach loopback.
async fn verifier() -> TrustTaskVmResolver {
    vta_sdk::http::set_allow_private_endpoints(true);
    TrustTaskVmResolver::new(
        DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_host_policy(HostPolicy::AllowPrivate)
                .build(),
        )
        .await
        .unwrap(),
    )
}

async fn signed_as(vm: &str, private: &str) -> Value {
    let key = HolderKey::new(vm, private).unwrap();
    let doc = build_signed_with(
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_LIST_1_0,
        json!({}),
        &key,
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    )
    .await
    .unwrap();
    serde_json::from_str(&doc).unwrap()
}

#[tokio::test]
async fn a_did_scid_signs_as_itself_and_a_stranger_verifies() {
    let server = MockServer::start().await;
    let (webvh, private) = serve_log(&server).await;
    let (bare, url) = vta_sdk::did_scid::scid_forms(&webvh).unwrap();

    let doc = signed_as(&format!("{url}#key-0"), &private).await;
    // VTI-KEY-163: issuer and method in one form.
    assert_eq!(doc["issuer"], url.as_str(), "{doc}");
    assert_eq!(doc["proof"]["verificationMethod"], format!("{url}#key-0"));

    let signer = verify_trust_task_proof_value(&doc, &verifier().await)
        .await
        .expect("a stranger resolves the did:scid through its src and accepts the proof");
    assert_eq!(vta_sdk::did_scid::identity(&signer), bare);
}

#[tokio::test]
async fn a_bare_did_scid_needs_a_source_the_verifier_holds() {
    let server = MockServer::start().await;
    let (webvh, private) = serve_log(&server).await;
    let (bare, url) = vta_sdk::did_scid::scid_forms(&webvh).unwrap();
    let doc = signed_as(&format!("{bare}#key-0"), &private).await;

    // A stranger has no source for the bare DID.
    assert!(
        verify_trust_task_proof_value(&doc, &verifier().await)
            .await
            .is_err()
    );

    // One that has seen it through its src verifies the bare form too.
    let known = verifier().await;
    let first = signed_as(&format!("{url}#key-0"), &private).await;
    verify_trust_task_proof_value(&first, &known).await.unwrap();
    let signer = verify_trust_task_proof_value(&doc, &known)
        .await
        .expect("the bare did:scid resolves through the source seen");
    assert_eq!(signer, bare);
}

#[tokio::test]
async fn another_did_scid_cannot_borrow_the_key() {
    let server = MockServer::start().await;
    let (_webvh, private) = serve_log(&server).await;
    let port = server.address().port();
    // The right key under an identity whose log is not this one.
    let forged = format!("did:scid:vh:1:QmNotTheScid?src=localhost:{port}#key-0");
    let doc = signed_as(&forged, &private).await;
    assert!(
        verify_trust_task_proof_value(&doc, &verifier().await)
            .await
            .is_err()
    );
}
