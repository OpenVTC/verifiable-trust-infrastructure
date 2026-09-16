//! The SDK resolves a given DID over the network at most once per process
//! (within the resolver cache's TTL), however many entry points ask.
//!
//! Every `session::resolve_*` entry point, `VtaClient::resolve_did`, agent-name
//! lookup and `didcomm_light` used to build a throwaway resolver (or none), so
//! a single CLI command fetched the VTA's `did.jsonl` from scratch several
//! times — each an unauthenticated request from the same address as the
//! authentication that followed, against a VTA that may host its own log
//! behind a per-IP rate limiter. These tests serve a real signed `did:webvh`
//! log and count the fetches.
//!
//! Its own test binary because the server is on loopback, which the resolver
//! refuses unless private hosts are allowed process-wide — a switch that must
//! not leak into other suites' assertions about the default.

#![cfg(feature = "session")]

use std::sync::Arc;

use didwebvh_rs::prelude::*;
use serde_json::json;
use vta_sdk::didcomm_light::resolve_vta_keyagreement;
use vta_sdk::session::{VtaEndpoint, resolve_mediator_did, resolve_vta_endpoint, resolve_vta_url};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MEDIATOR: &str = "did:web:mediator.example";
const DID_JSONL: &str = "/.well-known/did.jsonl";
const X25519: [u8; 32] = [7u8; 32];

/// A signed genesis log for `did:webvh:{SCID}:localhost%3A{port}`, advertising
/// DIDComm (via [`MEDIATOR`]) and REST, with an X25519 key-agreement key.
async fn mint_log(port: u16) -> (String, String) {
    let (_, signing_key) = didwebvh_rs::did_key::generate_did_key(KeyType::Ed25519).unwrap();
    let mut x = vec![0xec, 0x01];
    x.extend_from_slice(&X25519);
    let x_multikey = multibase::encode(multibase::Base::Base58Btc, &x);
    let document = json!({
        "id": "{DID}",
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [
            {
                "id": "{DID}#key-0",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": signing_key.get_public_keymultibase().unwrap(),
            },
            {
                "id": "{DID}#key-1",
                "type": "Multikey",
                "controller": "{DID}",
                "publicKeyMultibase": x_multikey,
            },
        ],
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"],
        "keyAgreement": ["{DID}#key-1"],
        "service": [
            { "id": "{DID}#vta-didcomm", "type": "DIDCommMessaging", "serviceEndpoint": MEDIATOR },
            { "id": "{DID}#vta-rest", "type": "VTARest", "serviceEndpoint": format!("http://localhost:{port}") },
        ],
    });
    let parameters = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            signing_key.get_public_keymultibase().unwrap(),
        )])),
        ..Default::default()
    };
    let config = CreateDIDConfig::builder()
        .address(format!("http://localhost:{port}/"))
        .authorization_key(signing_key)
        .did_document(document)
        .parameters(parameters)
        .build()
        .unwrap();
    let created = create_did(config).await.unwrap();
    let log = format!("{}\n", serde_json::to_string(created.log_entry()).unwrap());
    (created.did().to_string(), log)
}

/// A server publishing a freshly minted DID; `unpublished_for` initial
/// requests get a 404 first.
async fn serve(unpublished_for: u64) -> (MockServer, String) {
    let server = MockServer::start().await;
    let (did, log) = mint_log(server.address().port()).await;
    if unpublished_for > 0 {
        Mock::given(method("GET"))
            .and(path(DID_JSONL))
            .respond_with(ResponseTemplate::new(404))
            .up_to_n_times(unpublished_for)
            .with_priority(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(DID_JSONL))
        .respond_with(ResponseTemplate::new(200).set_body_string(log))
        .mount(&server)
        .await;
    (server, did)
}

async fn log_fetches(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == DID_JSONL)
        .count()
}

fn allow_loopback() {
    vta_sdk::http::set_allow_private_endpoints(true);
}

#[tokio::test]
async fn every_entry_point_shares_one_fetch_of_the_same_did() {
    allow_loopback();
    let (server, did) = serve(0).await;

    // What one CLI command does before it authenticates — discover the
    // transport, find the mediator and the REST URL, find the key to pack to —
    // and then all of it again.
    for _ in 0..2 {
        let endpoint = resolve_vta_endpoint(&did).await.expect("endpoint");
        assert!(
            matches!(endpoint, VtaEndpoint::DIDComm { .. }),
            "the served document was used, not a URL guessed from the DID"
        );
        assert_eq!(
            resolve_mediator_did(&did)
                .await
                .expect("mediator")
                .as_deref(),
            Some(MEDIATOR)
        );
        resolve_vta_url(&did).await.expect("rest url");
        let (kid, x_pub) = resolve_vta_keyagreement(&did).await.expect("key agreement");
        assert_eq!((kid, x_pub), (format!("{did}#key-1"), X25519));
    }

    assert_eq!(
        log_fetches(&server).await,
        1,
        "eight resolutions of one DID must cost one fetch"
    );
}

#[tokio::test]
async fn a_failed_resolution_is_fetched_again() {
    allow_loopback();
    // Unpublished at first: nothing may be cached from a failure, or a VTA
    // that publishes a moment later stays unresolvable for the whole TTL.
    let (server, did) = serve(2).await;

    assert!(resolve_mediator_did(&did).await.is_err());
    assert!(resolve_mediator_did(&did).await.is_err());
    assert_eq!(log_fetches(&server).await, 2);

    for _ in 0..3 {
        assert_eq!(
            resolve_mediator_did(&did)
                .await
                .expect("published")
                .as_deref(),
            Some(MEDIATOR)
        );
    }
    assert_eq!(
        log_fetches(&server).await,
        3,
        "the first success is fetched, the repeats are not"
    );
}

/// A resolver is tied to the runtime that built it. A process that runs one
/// runtime after another must get a working resolver on the second, not a
/// client whose runtime is gone.
#[test]
fn a_later_runtime_gets_a_working_resolver() {
    allow_loopback();
    let server_rt = tokio::runtime::Runtime::new().unwrap();
    let (server, did) = server_rt.block_on(serve(0));

    for _ in 0..2 {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mediator = rt
            .block_on(resolve_mediator_did(&did))
            .expect("resolves on a fresh runtime");
        assert_eq!(mediator.as_deref(), Some(MEDIATOR));
        drop(rt);
    }
    // One fetch per runtime: the second runtime's resolver is its own.
    assert_eq!(server_rt.block_on(log_fetches(&server)), 2);

    vta_sdk::resolver::shutdown_shared_did_resolvers();
}
