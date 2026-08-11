//! A join over **TSP** reaches the VTC's dispatcher and is recorded.
//!
//! The regression this pins is not a logic bug — it is a build that could not
//! serve the transport its DID document advertised. A VTC deployed advertising
//! `#tsp` (`TSPTransport`) and no `DIDCommMessaging`, compiled without
//! `--features tsp`, accepted every join and recorded none. The operator saw
//!
//! ```text
//! Error unpacking message: DidcommError("Cannot parse message as JSON",
//! "invalid number at line 1 column 2")
//! ```
//!
//! and the applicant saw success. Two `cfg` gates in the messaging SDK explain
//! the silence, and the outer one hides the inner: the websocket transport
//! classifies TSP frames only under its own `tsp` feature
//! (`force_packed = atm.tsp().is_tsp(..)`), so without it a CESR frame is never
//! tagged `Protocol::TSP` at all — it falls through to the DIDComm unpacker and
//! dies as a JSON parse error, below both the SDK's own "the `tsp` feature is
//! disabled" warning and the VTC's. CESR qb64 starts with `-`, which serde_json
//! reads as the start of a number, hence "invalid number at column 2".
//!
//! `vtc-service` compiled the TSP receive path long before this test existed
//! (`messaging::handle_tsp`), which is exactly the problem: compiling it proved
//! nothing about whether a frame could traverse it. This exercises the path
//! end-to-end over a real mediator — client seals and routes, mediator forwards,
//! the production listener unpacks, dispatches, and stores — so a build or
//! wiring change that re-breaks it fails here instead of in production.
//!
//! Requires `--features tsp,didcomm-harness`; CI runs it (see `ci.yml`).

#![cfg(all(feature = "tsp", feature = "didcomm-harness"))]

use std::time::Duration;

use serde_json::json;

use vtc_service::join::storage::list_join_requests;
use vtc_service::test_support::MockVtcDidcomm;
use vtc_service::transport_capability::{
    MessagingVerdict, NON_TSP_BUILD, TSP_BUILD, classify_against,
};

use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities};
use vta_sdk::protocols::join_requests::{JOIN_REQUEST_SUBMIT_TYPE, JoinRequestSubmitBody};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// Seed just enough ceremony state for `submit` to reach a verdict: the default
/// policy bundle (without it `join.rego` fails closed and nothing is stored)
/// and both status lists.
async fn seed_for_submit(mock: &MockVtcDidcomm) {
    let state = &mock.vtc.state;

    vtc_service::policy::default::install_defaults(&state.policies_ks, &state.active_policies_ks)
        .await
        .expect("install default policies");

    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        vtc_service::status_list::ensure_initial(
            &state.status_lists_ks,
            purpose,
            format!("https://vtc.test/v1/status-lists/{purpose}"),
        )
        .await
        .expect("ensure status list");
    }
}

/// Poll for the applicant's join request. TSP delivery is asynchronous and
/// correlated out of band — there is no `thid` to await on, and per R1.1 the
/// send returning `Ok` means "the mediator accepted it", never "the VTC
/// processed it". So the only honest assertion is on the VTC's own state, with
/// a bound generous enough for a real mediator round trip and short enough that
/// a genuine break fails rather than hangs.
async fn await_recorded_join(
    mock: &MockVtcDidcomm,
    applicant_did: &str,
) -> vtc_service::join::JoinRequest {
    const LIMIT: Duration = Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + LIMIT;
    while tokio::time::Instant::now() < deadline {
        let found = list_join_requests(&mock.vtc.state.join_requests_ks)
            .await
            .expect("list join requests")
            .into_iter()
            .find(|r| r.applicant_did == applicant_did);
        if let Some(request) = found {
            return request;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "no join request from {applicant_did} was recorded within {LIMIT:?}. The TSP frame did \
         not reach `dispatch_trust_task_core` — check whether it was classified as \
         `Protocol::TSP` at all (the `tsp` feature must be on for BOTH this crate and the \
         messaging SDK), or whether it died in the DIDComm unpacker as a JSON parse error."
    );
}

/// The whole point: a join submitted over TSP is dispatched and stored.
///
/// The applicant sends *only* over TSP — it never packs a DIDComm envelope — so
/// a recorded request can only have arrived through `messaging::handle_tsp`.
#[tokio::test]
async fn a_join_submitted_over_tsp_is_dispatched_and_recorded() {
    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    seed_for_submit(&mock).await;

    let vtc_did = mock.vtc_did().to_string();
    let applicant_did = mock.client.did().to_string();

    mock.client
        .send_tsp(
            &vtc_did,
            JOIN_REQUEST_SUBMIT_TYPE,
            serde_json::to_value(JoinRequestSubmitBody {
                vp: json!({ "type": "VerifiablePresentation", "holder": applicant_did }),
                registry_consent: false,
                extensions: json!({}),
            })
            .expect("serialise submit body"),
        )
        .await;

    let request = await_recorded_join(&mock, &applicant_did).await;

    // The applicant is bound to the TSP sender VID, which `atm.tsp().unpack`
    // cryptographically authenticated — not to anything the document claimed.
    // A mismatch here would mean the spine authorised on an unproven identity.
    assert_eq!(
        request.applicant_did, applicant_did,
        "the stored applicant must be the authenticated TSP sender VID"
    );

    mock.shutdown().await;
}

/// The harness's premise, asserted rather than assumed: the VTC's DID really
/// does advertise both transports, and a client's protocol matcher would
/// therefore *choose* TSP (preference order TSP > DIDComm > REST).
///
/// Without this, the test above could pass against a document advertising
/// nothing — proving the plumbing works but not that the advertisement is what
/// leads a client into it, which is the half that actually broke.
#[tokio::test]
async fn the_mock_advertises_tsp_and_didcomm_and_serves_both() {
    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;

    let resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    .expect("local DID cache");
    let resolved = resolver
        .resolve(mock.vtc_did())
        .await
        .expect("a did:peer resolves offline in any resolver");
    let doc = serde_json::to_value(&resolved.doc).expect("document serialises");
    let caps = ServiceCapabilities::from_did_document(&doc);

    assert_eq!(
        caps.advertised(),
        vec![Protocol::Tsp, Protocol::Didcomm],
        "expected both transports in preference order, got {caps:?}"
    );

    // This build serves everything it advertises...
    assert_eq!(classify_against(TSP_BUILD, &caps), MessagingVerdict::Ok);
    // ...and the same document in a build without `tsp` is a mismatch the
    // startup check reports rather than a silent drop. Degraded, not
    // Unreachable, because DIDComm is still advertised here — unlike the
    // deployed VTC, which offered TSP alone.
    assert!(
        matches!(
            classify_against(NON_TSP_BUILD, &caps),
            MessagingVerdict::Degraded(u) if u.len() == 1 && u[0].protocol == Protocol::Tsp
        ),
        "a non-tsp build must report the advertised TSP it cannot serve"
    );

    mock.shutdown().await;
}
