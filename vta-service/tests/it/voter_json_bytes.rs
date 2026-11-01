//! The SDK's `_json` voter methods carry the manifest byte for byte.
//!
//! The VTA digests the manifest it is given and the community digests the one it published;
//! the two must be the same bytes or the ticket is for another election. A community that
//! publishes `…T00:00:00.000Z` gets a typed round trip's `…T00:00:00Z` back, so a caller
//! carrying documents uses `pcs_voter_register_json` and friends.

use std::sync::Arc;

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vta_sdk::client::loopback::RecordingSink;
use vta_sdk::trust_tasks;

const OPENS: &str = "2027-01-02T00:00:00.000Z";

fn register_payload() -> Value {
    json!({
        "contextId": "member",
        "community": "did:webvh:QmCommunity:vtc.example.org",
        "parameters": { "suite": "ps-ddh-bls12381", "votingKey": "zKey" },
        "manifest": {
            "electionId": "agm-2027", "community": "did:webvh:QmCommunity:vtc.example.org",
            "questions": [{ "key": "budget", "type": "choice",
                "options": [{ "key": "yes" }, { "key": "no" }],
                "minSelections": 1, "maxSelections": 1, "optional": false }],
            "secrecy": "open", "roll": { "rule": "members" },
            "registrationOpensAt": "2027-01-01T00:00:00.000Z", "votingOpensAt": OPENS,
            "votingClosesAt": "2027-01-03T00:00:00.000Z", "revote": "replace",
            "board": { "visibility": "public", "auditors": [] },
            "ballotBox": "did:key:z6MkBallotBox",
            "binding": false, "allowEarlyClose": false, "resultsBeforeClose": false,
            "textReleaseThreshold": 10,
        },
    })
}

#[tokio::test]
async fn the_json_register_sends_the_manifest_as_given() {
    let sink = Arc::new(RecordingSink::new());
    let client = VtaClient::loopback(sink.clone());
    let sent = register_payload();

    let _ = client.pcs_voter_register_json(sent.clone()).await;

    let (uri, payload) = sink.recorded().pop().expect("one task was dispatched");
    assert_eq!(uri, trust_tasks::TASK_VTA_PCS_VOTER_REGISTER_0_2);
    assert_eq!(
        serde_json::to_string(&payload).unwrap(),
        serde_json::to_string(&sent).unwrap(),
        "the payload reaches the VTA exactly as the caller built it"
    );
    assert_eq!(payload["manifest"]["votingOpensAt"], OPENS);
}

/// Why the `_json` forms exist: the typed form does not carry the published bytes. When this
/// stops failing to round-trip, the typed forms are safe and the warnings on them can go.
#[tokio::test]
async fn the_typed_register_rewrites_the_manifest() {
    let sink = Arc::new(RecordingSink::new());
    let client = VtaClient::loopback(sink.clone());
    let typed: vta_sdk::specs::vta::pcs::voter::register::v0_2::Payload =
        serde_json::from_value(register_payload()).expect("the payload is the schema's");

    let _ = client.pcs_voter_register(&typed).await;

    let (_, payload) = sink.recorded().pop().expect("one task was dispatched");
    assert_ne!(
        payload["manifest"]["votingOpensAt"], OPENS,
        "the typed form now keeps the published timestamp; drop the `_json` warning"
    );
}
