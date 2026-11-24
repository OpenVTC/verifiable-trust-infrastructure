//! Coverage for `vta_sdk::didcomm_session::DIDCommSession` against a
//! live `TestMediator`. The session module is heavyweight — it sets up
//! a TDK runtime, resolves DIDs over a real cache, opens a WebSocket
//! to the mediator, and exchanges DIDComm messages. wiremock can't
//! stand in here, so these tests run against the embedded mediator.
//!
//! The success-direction round-trip (`send_and_wait` returning a
//! valid response) needs a live VTA-side responder, which is too
//! heavy for the harness; we cover that path via the timeout branch
//! and the unreachable-mediator branch instead. Together they
//! exercise the entire `connect` flow plus the `send_and_wait`
//! pack/send path up to the response-wait loop.

use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use ed25519_dalek::SigningKey;
use serde_json::json;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::didcomm_session::DIDCommSession;
use vta_sdk::error::VtaError;

mod common;
use common::test_vta_responder::{ResponderReply, TestVtaResponder};

/// Build a deterministic `did:key` + matching multibase private-key
/// string from a seed byte. Mirrors the helper used in the SDK's REST
/// test harnesses; kept inline here so this binary stays self-contained.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let priv_mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, priv_mb)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_via_live_mediator_succeeds() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);

    // Mediator must accept the client DID as a LOCAL account so the
    // WebSocket upgrade succeeds (matching the pattern used in
    // `transient_handshake.rs`).
    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let session = DIDCommSession::connect(&client_did, &client_priv, &vta_did, mediator.did())
        .await
        .expect("DIDComm session connects against live mediator");

    // Clean shutdown must not panic.
    session.shutdown().await;

    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_and_wait_times_out_when_no_responder() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let session = DIDCommSession::connect(&client_did, &client_priv, &vta_did, mediator.did())
        .await
        .expect("session connects");

    // No VTA listening on `vta_did`, so `send_and_wait` packs +
    // sends successfully but never sees a matching response.
    let timeout_secs = 2;
    let start = std::time::Instant::now();
    let result: Result<serde_json::Value, _> = session
        .send_and_wait(
            "https://example.com/protocols/test/1.0/ping",
            serde_json::json!({}),
            "https://example.com/protocols/test/1.0/pong",
            timeout_secs,
        )
        .await;
    let elapsed = start.elapsed();

    let err = result.expect_err("must time out");
    assert!(
        matches!(err, VtaError::DidcommTransport(ref msg) if msg.contains("timeout")),
        "expected DidcommTransport timeout, got {err:?}"
    );

    // The timeout should hit close to the requested duration, not
    // multiples of it (catching regressions in the wait loop's
    // deadline arithmetic).
    assert!(
        elapsed < Duration::from_secs(timeout_secs * 2 + 5),
        "send_and_wait honored timeout poorly: {elapsed:?}"
    );
    // The session counts it on its receive leg (#2753).
    assert_eq!(session.receive_health().consecutive_reply_timeouts, 1);
    assert!(
        session
            .clone()
            .receive_health()
            .since_last_timeout
            .is_some()
    );

    session.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_fails_when_mediator_did_unresolvable() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);

    // `did:peer:2.unresolvable` is syntactically valid but the cache
    // resolver rejects it before any network round-trip — same fixture
    // pattern used in `transient_handshake.rs`.
    let bogus_mediator = "did:peer:2.unresolvable";

    let result = DIDCommSession::connect(&client_did, &client_priv, &vta_did, bogus_mediator).await;
    assert!(
        result.is_err(),
        "connect against unresolvable mediator must fail"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_and_wait_round_trip_success() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (mediator, responder) =
        TestVtaResponder::spawn_with_mediator(vec![client_did.clone()], |msg_type, _body| {
            if msg_type.ends_with("/list-keys") {
                ResponderReply::ok(
                    format!("{msg_type}-result"),
                    json!({"keys": [], "total": 0}),
                )
            } else {
                ResponderReply::problem_report("e.p.msg.not-found", "no handler")
            }
        })
        .await
        .expect("responder spawns with mediator");

    let session =
        DIDCommSession::connect(&client_did, &client_priv, responder.did(), mediator.did())
            .await
            .expect("session connects");

    let resp: serde_json::Value = session
        .send_and_wait(
            "https://firstperson.network/protocols/key-management/1.0/list-keys",
            json!({"offset": 0, "limit": 10}),
            "https://firstperson.network/protocols/key-management/1.0/list-keys-result",
            10,
        )
        .await
        .expect("round-trip returns the responder's body");

    assert_eq!(resp["total"], 0);
    assert!(resp["keys"].as_array().unwrap().is_empty());

    session.shutdown().await;
    responder.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_and_wait_problem_report_maps_to_typed_error() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (mediator, responder) =
        TestVtaResponder::spawn_with_mediator(vec![client_did.clone()], |_msg_type, _body| {
            ResponderReply::problem_report("e.p.msg.conflict", "key already exists")
        })
        .await
        .expect("responder spawns");

    let session =
        DIDCommSession::connect(&client_did, &client_priv, responder.did(), mediator.did())
            .await
            .expect("session connects");

    let err = session
        .send_and_wait::<serde_json::Value>(
            "https://firstperson.network/protocols/key-management/1.0/create-key",
            json!({}),
            "https://firstperson.network/protocols/key-management/1.0/create-key-result",
            10,
        )
        .await
        .expect_err("problem report propagates");

    assert!(err.is_conflict(), "got {err:?}");
    // A problem report is still a reply: the receive leg works (#2753).
    let health = session.receive_health();
    assert_eq!(health.consecutive_reply_timeouts, 0);
    assert!(health.since_last_reply.is_some());

    session.shutdown().await;
    responder.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_and_wait_unknown_problem_code_lands_in_didcomm_remote() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (mediator, responder) =
        TestVtaResponder::spawn_with_mediator(vec![client_did.clone()], |_msg_type, _body| {
            ResponderReply::problem_report("e.custom.unique", "domain-specific failure")
        })
        .await
        .expect("responder spawns");

    let session =
        DIDCommSession::connect(&client_did, &client_priv, responder.did(), mediator.did())
            .await
            .expect("session connects");

    let err = session
        .send_and_wait::<serde_json::Value>(
            "https://firstperson.network/protocols/key-management/1.0/get-key",
            json!({"key_id": "x"}),
            "https://firstperson.network/protocols/key-management/1.0/get-key-result",
            10,
        )
        .await
        .expect_err("unknown problem code propagates");

    match err {
        VtaError::DidcommRemote { code, .. } => {
            assert_eq!(code, "e.custom.unique");
        }
        other => panic!("expected DidcommRemote, got {other:?}"),
    }

    session.shutdown().await;
    responder.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_and_wait_wrong_response_type_is_protocol_error() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (mediator, responder) =
        TestVtaResponder::spawn_with_mediator(vec![client_did.clone()], |_msg_type, _body| {
            ResponderReply::ok(
                "https://example.com/something/different/1.0/result",
                json!({"unexpected": true}),
            )
        })
        .await
        .expect("responder spawns");

    let session =
        DIDCommSession::connect(&client_did, &client_priv, responder.did(), mediator.did())
            .await
            .expect("session connects");

    let err = session
        .send_and_wait::<serde_json::Value>(
            "https://firstperson.network/protocols/key-management/1.0/list-keys",
            json!({}),
            "https://firstperson.network/protocols/key-management/1.0/list-keys-result",
            10,
        )
        .await
        .expect_err("wrong type triggers Protocol error");

    match err {
        VtaError::Protocol(msg) => assert!(
            msg.contains("unexpected response type"),
            "expected 'unexpected response type' guidance, got: {msg}"
        ),
        other => panic!("expected Protocol, got {other:?}"),
    }

    session.shutdown().await;
    responder.shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_fails_with_invalid_private_key() {
    common::init_tracing();

    // `did:key:` for the client but a private-key multibase that
    // doesn't decode to 32 bytes — caught by
    // `decode_private_key_multibase` before any network call.
    let (client_did, _) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let bogus_mediator_did = "did:peer:2.med";

    let result =
        DIDCommSession::connect(&client_did, "z2truncated", &vta_did, bogus_mediator_did).await;
    assert!(
        result.is_err(),
        "invalid private key must surface as an error"
    );
}
