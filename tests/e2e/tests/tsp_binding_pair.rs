//! The TSP binding, checked across the two crates that have to agree on it.
//!
//! ## Why a test that spans both sides
//!
//! `vta-service` started requiring the `trust-tasks-tsp` binding envelope on
//! inbound TSP frames while every client in this workspace kept sealing the
//! **bare document**, so the VTA refused each one:
//!
//! ```text
//! refused a TSP frame that is not a binding envelope
//!   reason=TSP payload is not a `…/binding/tsp/0.1/envelope` envelope
//!          (got `…/spec/messaging/ping/0.1`)
//! ```
//!
//! Nothing was red. `tsp_round_trip` and `tsp_dual_leg` send *and* receive
//! through `vta-sdk`, so a private dialect round-trips against itself perfectly;
//! `tsp_inbound`'s unit tests frame their fixtures with the service's own
//! wrapper, so they agree with themselves too. Each side was self-consistent and
//! the pair was broken — the same shape as the REST-auth client/server split,
//! and the reason this file exists at all: **the only way to test carriage is to
//! put bytes on a wire from one crate and hand them to the other.**
//!
//! So: a real `TspSession` seals and routes through a real mediator, the frame
//! is pulled off the recipient's pickup socket and unpacked exactly as the VTA's
//! delivery layer unpacks it, and the resulting payload goes into the VTA's own
//! `tsp_inbound::dispatch_one`. No fixture in the middle to encode an
//! assumption.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_test_mediator::TestMediator;
use affinidi_tdk::common::{TDKSharedState, config::TDKConfig};
use affinidi_tdk::messaging::{ATM, config::ATMConfig, profiles::ATMProfile};
// `insert` lives on the SecretsResolver trait — must be in scope.
use affinidi_tdk::secrets_resolver::SecretsResolver;
use ed25519_dalek::SigningKey;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::TspSession;
use vti_common::acl::{AclEntry, Role, store_acl_entry};

mod common;

/// Deterministic `did:key` + matching multibase private key from a seed byte.
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

/// A `messaging/ping/0.1` document — the task the failing log line named, and
/// the one probe that needs no session and no capability.
fn ping_document(issuer: &str, recipient: &str, id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "type": "https://trusttasks.org/spec/messaging/ping/0.1",
        "issuer": issuer,
        "recipient": recipient,
        "issuedAt": chrono::Utc::now().to_rfc3339(),
        "payload": { "nonce": id },
    }))
    .expect("serialize ping document")
}

/// Open a raw-TSP pickup socket for `did` and return everything needed to
/// unpack frames addressed to it — the VTA's side of the wire, minus the VTA.
async fn pickup_socket(
    did: &str,
    private_key_mb: &str,
    mediator_did: &str,
) -> (ATM, Arc<ATMProfile>) {
    let seed = vta_sdk::did_key::decode_private_key_multibase(private_key_mb).expect("seed");
    let secrets = vta_sdk::did_key::secrets_from_did_key(did, &seed).expect("secrets");
    let tdk = TDKSharedState::new(TDKConfig::builder().build().expect("tdk cfg"))
        .await
        .expect("tdk");
    tdk.secrets_resolver().insert(secrets.signing).await;
    tdk.secrets_resolver().insert(secrets.key_agreement).await;
    let atm = ATM::new(
        ATMConfig::builder().build().expect("atm cfg"),
        Arc::new(tdk),
    )
    .await
    .expect("atm");
    let profile = Arc::new(
        ATMProfile::new(&atm, None, did.to_string(), Some(mediator_did.to_string()))
            .await
            .expect("profile"),
    );
    // Registered so `graceful_shutdown` can stop it; an unregistered profile's
    // socket survives every teardown (vta-sdk #830).
    let profile = atm
        .profile_add(&profile, false)
        .await
        .expect("register pickup profile");
    atm.profile_enable_websocket(&profile)
        .await
        .expect("enable pickup websocket");
    (atm, profile)
}

/// **The pair.** What `vta-sdk` puts on the TSP wire is what `vta-service` takes
/// off it.
///
/// The assertion is deliberately about *carriage*, not about the ping: the reply
/// must not be the binding refusal. A `permissionDenied` would pass this test
/// and should — that answer is only reachable once the envelope has been opened,
/// which is the thing under test. (The sender is granted admin anyway, so the
/// ping is answered properly; the looser assertion is what keeps this test about
/// one thing.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_sdk_seals_is_what_the_vta_opens() {
    common::init_tracing();

    let (client_did, client_priv) = did_key_from_seed(0x41);
    let (vta_did, vta_priv) = did_key_from_seed(0x42);

    let mediator = TestMediator::builder()
        .local_did(client_did.clone())
        .local_did(vta_did.clone())
        .spawn()
        .await
        .expect("spawn test mediator");

    let (vta_atm, vta_profile) = pickup_socket(&vta_did, &vta_priv, mediator.did()).await;

    let client = TspSession::connect(&client_did, &client_priv, mediator.did())
        .await
        .expect("client TSP session connects");
    let id = "urn:uuid:binding-pair-probe";
    client
        .send_document(
            &vta_did,
            mediator.did(),
            &ping_document(&client_did, &vta_did, id),
        )
        .await
        .expect("send_document reports success");

    // Pull the frame off the VTA's socket and unpack it the way the delivery
    // layer does, so `payload` is byte-for-byte what `handle_tsp` would hand to
    // `dispatch_one`.
    let mut payload: Option<Vec<u8>> = None;
    for _ in 0..6 {
        let frame = vta_atm
            .message_pickup()
            .live_stream_next_frame(&vta_profile, Some(Duration::from_secs(5)), true)
            .await
            .expect("live_stream_next_frame must not error");
        let Some(affinidi_tdk::messaging::protocols::message_pickup::InboundFrame::Tsp(raw)) =
            frame
        else {
            continue; // a DIDComm pickup status frame, or nothing yet
        };
        // `unpack`, not `unpack_bytes`: the multiplexed pickup socket surfaces a
        // TSP frame as the **qb64** text (`-E…`), and `unpack_bytes` wants raw
        // qb2. This is the same pair of calls the delivery layer's
        // `tsp_to_inbound` documents, and picking the wrong one here would fail
        // as "missing -E envelope wrapper" — an unpack fault wearing the costume
        // of a binding fault, in the one test whose job is to tell them apart.
        let (bytes, _sender) = vta_atm
            .tsp()
            .unpack(&vta_profile, &raw)
            .await
            .expect("the VTA can unpack a frame sealed to it");
        payload = Some(bytes);
        break;
    }

    client.shutdown().await;
    vta_atm.graceful_shutdown().await;
    mediator.shutdown();
    mediator.join().await.expect("mediator joins cleanly");

    let payload = payload.expect("the client's TSP frame reached the VTA's socket");

    // The VTA's own receiver, on the bytes the SDK actually sent.
    let (app_state, _dir) = vta_service::test_support::build_signing_test_app_state().await;
    store_acl_entry(
        &app_state.acl_ks,
        &AclEntry::new(&client_did, Role::Admin, "tsp-binding-pair"),
    )
    .await
    .expect("grant the client an ACL entry");

    let reply =
        vta_service::messaging::tsp_inbound::dispatch_one(&app_state, &payload, &client_did).await;

    // The reply is sealed in the same binding, so the client's opener is the
    // right way to read it — the return leg of the same agreement.
    let document = vta_sdk::tsp_binding::open_envelope(&reply)
        .expect("the VTA's reply must be carriage the SDK can open");
    let document: serde_json::Value =
        serde_json::from_slice(&document).expect("the reply document is JSON");

    let code = document["payload"]["code"].as_str().unwrap_or_default();
    let message = document["payload"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("binding envelope") && !message.contains("binding/tsp"),
        "the VTA refused the SDK's carriage — the two sides disagree about the \
         TSP binding: code={code} message={message}"
    );
    assert_eq!(
        document["threadId"].as_str(),
        Some(id),
        "the reply must be threaded to the ping we sent: {document}"
    );
}
