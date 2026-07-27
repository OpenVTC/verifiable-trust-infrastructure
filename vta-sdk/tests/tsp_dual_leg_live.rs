//! Live dual-leg round trip against a **deployed** TSP-enabled VTA (#803).
//!
//! `tsp_discovery_live.rs` closes the discovery half and names what it cannot
//! reach: *"the correlated round-trip (`connect_tsp` → `TspSession::request` →
//! reply) … still wants a live exercise."* This is that exercise, for the shape
//! the deployment actually forces — a client holding a DIDComm session that also
//! needs TSP, on a VTA advertising **the same mediator** for both.
//!
//! What it proves that the hermetic tests cannot: the *deployed* VTA answers a
//! trust task that arrived over TSP on a socket it shares with DIDComm. The
//! hermetic suite (`tests/e2e/tests/tsp_dual_leg.rs`) uses a `TestMediator` and
//! a scripted responder, so it pins the client's plumbing but not the VTA's.
//!
//! **`#[ignore]`d**: resolves a `did:webvh` and opens a mediator connection over
//! the network. Run it deliberately:
//!
//! ```sh
//! cargo test -p vta-sdk --features session,provision-client,tsp \
//!     --test tsp_dual_leg_live -- --ignored --nocapture
//! ```
//!
//! Point it at a different deployment with `VTA_LIVE_TSP_DID`.
//!
//! ## What counts as a pass, and why it needs no credential
//!
//! The question is **transport**, not authorization: did a document we sent over
//! the multiplexed socket reach the VTA, and did *its* reply come back and
//! correlate to that request? A `permissionDenied` trust-task response answers
//! that with a yes — the VTA received the task, dispatched it, and routed a
//! reply to the right waiter. Only a *transport* failure (timeout, TSP error)
//! means the socket did not carry the exchange.
//!
//! So by default the test mints a throwaway `did:key` and asserts it got a
//! correlated **reply of either kind**. Set `VTA_LIVE_CLIENT_DID` +
//! `VTA_LIVE_CLIENT_KEY` to an ACL-granted identity and it tightens to
//! demanding a successful payload. Each test prints which mode it ran in, so a
//! green run never overstates what it checked.
//!
//! Every case is paired with a **DIDComm control over the same deployment**, so
//! a failure is attributable to the TSP leg rather than to the VTA being down or
//! the identity being rejected.

#![cfg(all(feature = "session", feature = "provision-client", feature = "tsp"))]

use vta_sdk::client::{SurfaceTransport, VtaClient};
use vta_sdk::error::VtaError;
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_sdk::session::{VtaEndpoint, resolve_vta_endpoint};

/// The deployment named in #803. Overridable so this does not rot into a test
/// that only ever proves one host was up.
fn target_did() -> String {
    std::env::var("VTA_LIVE_TSP_DID").unwrap_or_else(|_| {
        "did:webvh:QmWoJD2kpP6AJknNtj7UFERUstEen258ywj3ruHoh1ZAqr:webvh.storm.ws:glenn-vta"
            .to_string()
    })
}

/// The identity to run as: an ACL-granted one from the environment when
/// supplied, otherwise a freshly-minted throwaway.
fn client_identity() -> (String, String, bool) {
    match (
        std::env::var("VTA_LIVE_CLIENT_DID"),
        std::env::var("VTA_LIVE_CLIENT_KEY"),
    ) {
        (Ok(did), Ok(key)) if !did.is_empty() && !key.is_empty() => (did, key, true),
        _ => {
            let key = EphemeralSetupKey::generate().expect("mint an ephemeral did:key");
            let mb = key.private_key_multibase().to_string();
            (key.did, mb, false)
        }
    }
}

/// The VTA's `#tsp` + `#vta-didcomm` + `#vta-rest` advertisement, or a skip.
async fn dual_endpoint() -> (String, String, String, Option<String>) {
    let endpoint = resolve_vta_endpoint(&target_did())
        .await
        .expect("the target VTA's DID must resolve");
    let VtaEndpoint::Tsp {
        vta_did,
        mediator_did: tsp_mediator_did,
        didcomm_mediator_did,
        rest_url,
    } = endpoint
    else {
        panic!(
            "this test needs a VTA advertising `#tsp`; {} advertises something else",
            target_did()
        );
    };
    let didcomm_mediator_did = didcomm_mediator_did.expect(
        "this test needs a VTA advertising BOTH `#tsp` and `#vta-didcomm` — that pairing on \
         one mediator is the collision #803 is about",
    );
    (vta_did, didcomm_mediator_did, tsp_mediator_did, rest_url)
}

/// Did the VTA *answer*? A denial is an answer; a transport error is not.
///
/// This is the whole distinction the test turns on. `dispatch_trust_task`
/// surfaces a rejected task as [`VtaError::Protocol`] carrying the VTA's own
/// response document — which can only exist if the request arrived, was
/// dispatched, and its reply was routed back to this waiter. A
/// [`VtaError::TspTransport`] or a timeout is the opposite: nothing came back.
fn assert_vta_answered(result: Result<serde_json::Value, VtaError>, authorized: bool, over: &str) {
    match result {
        Ok(payload) => eprintln!("  ✅ {over}: authorized round trip — {payload}"),
        Err(VtaError::Protocol(msg)) if !authorized => {
            eprintln!("  ✅ {over}: the VTA answered (unauthorized identity) — {msg}");
        }
        Err(e) => panic!(
            "{over}: no correlated reply came back from the deployed VTA — the exchange did \
             not complete over the transport (set VTA_LIVE_CLIENT_DID/_KEY for an authorized \
             run): {e}"
        ),
    }
}

/// A `messaging/ping` dispatched through `client`, with a fresh nonce.
async fn ping(client: &VtaClient) -> Result<serde_json::Value, VtaError> {
    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_MESSAGING_PING_0_1,
            serde_json::json!({ "nonce": uuid::Uuid::new_v4().to_string() }),
            30,
        )
        .await
}

/// **The core case.** One client, one socket, both surfaces — against the real
/// deployment.
///
/// That deployment resolves `#tsp` and `#vta-didcomm` to the same mediator,
/// which is precisely why `connect_tsp` alongside a DIDComm session could not
/// work: the mediator permits one websocket per DID and evicts the second as
/// `duplicate-channel`. Here the TSP leg rides the DIDComm session's socket, so
/// there is only ever one — and the trust task still round-trips.
#[tokio::test]
#[ignore = "resolves a did:webvh and connects to a live mediator; run explicitly with --ignored"]
async fn a_deployed_vta_answers_a_trust_task_over_the_didcomm_sessions_socket() {
    let (vta_did, didcomm_mediator_did, tsp_mediator_did, rest_url) = dual_endpoint().await;
    let (client_did, client_key, authorized) = client_identity();

    eprintln!("  VTA:              {vta_did}");
    eprintln!("  DIDComm mediator: {didcomm_mediator_did}");
    eprintln!("  TSP mediator:     {tsp_mediator_did}");
    eprintln!("  client:           {client_did}");
    eprintln!(
        "  mode:             {}",
        if authorized {
            "authorized (expecting a successful payload)"
        } else {
            "throwaway identity (expecting any correlated reply)"
        }
    );
    assert_eq!(
        didcomm_mediator_did, tsp_mediator_did,
        "this deployment splits its TSP and DIDComm mediators, so it does not exercise the \
         one-socket-per-DID collision #803 is about"
    );

    let client = VtaClient::connect_didcomm_with_tsp(
        &client_did,
        &client_key,
        &vta_did,
        &didcomm_mediator_did,
        &tsp_mediator_did,
        rest_url,
    )
    .await
    .expect("connect DIDComm and put trust tasks on TSP");

    assert_eq!(client.trust_task_transport(), SurfaceTransport::Tsp);
    assert_eq!(
        client.protocol_message_transport(),
        SurfaceTransport::Didcomm
    );

    let result = ping(&client).await;
    client.shutdown().await;

    assert_vta_answered(result, authorized, "TSP on the DIDComm session's socket");
}

/// The same deployment over DIDComm alone, as a control. If the dual-leg test
/// fails while this passes, the fault is TSP-specific rather than the deployment
/// being down or the identity being rejected.
#[tokio::test]
#[ignore = "resolves a did:webvh and connects to a live mediator; run explicitly with --ignored"]
async fn didcomm_control_against_the_same_deployment() {
    let (vta_did, didcomm_mediator_did, _, rest_url) = dual_endpoint().await;
    let (client_did, client_key, authorized) = client_identity();

    let client = VtaClient::connect_didcomm(
        &client_did,
        &client_key,
        &vta_did,
        &didcomm_mediator_did,
        rest_url,
    )
    .await
    .expect("connect over DIDComm");

    assert_eq!(client.trust_task_transport(), SurfaceTransport::Didcomm);

    let result = ping(&client).await;
    client.shutdown().await;

    assert_vta_answered(result, authorized, "DIDComm");
}
