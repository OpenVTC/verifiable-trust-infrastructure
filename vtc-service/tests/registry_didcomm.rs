//! A membership record reaches a trust registry over DIDComm, and the reply
//! completes the call.
//!
//! What this pins that the unit tests cannot: the unit tests assert the wire
//! shapes and the classification of a reply handed to them directly. They say
//! nothing about whether a document the VTC builds can *leave* — whether
//! transport selection finds a route, whether the send reaches a peer through
//! a real mediator, and whether the peer's answer gets back to the caller that
//! is blocked waiting for it.
//!
//! That last leg is the one that broke twice in this area. A send returning
//! `Ok` means "the mediator accepted it" and nothing more (R1.1), so the only
//! thing that can complete a registry write is a correlated reply — and the
//! reply arrives on a different code path from the send, through the inbound
//! demux. A demux that drops it looks exactly like a registry that never
//! answered: the call times out, the syncer backs off, and the queue grows
//! with no error anywhere naming the cause.
//!
//! The peer here is a real second DIDComm identity on the same mediator whose
//! `did:peer` advertises `DIDCommMessaging`, so the VTC has to resolve it and
//! choose a transport rather than be handed one.
//!
//! Requires `--features didcomm-harness`; CI runs it.

#![cfg(feature = "didcomm-harness")]

use std::time::Duration;

use serde_json::{Value, json};

use vtc_service::registry::{
    MessagingRegistryClient, RECOGNISE_ACTION, RegistryRecord, RegistryStatus,
    TRUST_GRAPH_RESOURCE, TrustRegistryClient,
};
use vtc_service::test_support::{MockVtcDidcomm, TestJoinClient};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// Build the client under test against `registry_did`, wired to the same
/// messaging handle, signer, resolver and reply demux the daemon wires at boot.
fn client_for(mock: &MockVtcDidcomm, registry_did: &str) -> MessagingRegistryClient {
    let state = &mock.vtc.state;
    MessagingRegistryClient::new(
        registry_did.to_string(),
        Some(mock.vtc_did().to_string()),
        state.didcomm.clone(),
        state
            .credential_signer
            .clone()
            .expect("harness builds a credential signer"),
        state.pending_replies.clone(),
        state.did_resolver.clone(),
        None,
    )
}

/// Stand in for the registry: await the VTC's task, hand it to `answer`, and
/// send whatever that returns back on the request's thread.
///
/// Returns the request document so the test can assert on what was actually
/// put on the wire — the bytes the registry would verify, not a re-serialised
/// copy of what we meant to send.
async fn serve_once(
    registry: &TestJoinClient,
    vtc_did: &str,
    answer: impl FnOnce(&Value) -> Value,
) -> Value {
    let request = registry
        .next_trust_task(Duration::from_secs(30))
        .await
        .expect("the VTC's task reached the registry peer");
    let mut reply = answer(&request);
    reply["threadId"] = json!(request["id"].as_str().expect("request carries an id"));
    registry.send_trust_task(vtc_did, reply).await;
    request
}

const RECORD_PUT: &str = "https://trusttasks.org/spec/registry/record/put/0.1";
const RECORD_QUERY: &str = "https://trusttasks.org/spec/registry/record/query/0.1";

/// The `#response` to `request_type`, carrying `payload`.
///
/// Takes the whole request URI rather than interpolating a slug into a
/// `trusttasks.org/spec/…` template: the canonical-task census scans source
/// for `spec/` literals and asserts each one is a task the registry actually
/// publishes, so a templated URI reads to it as a bound task named `{slug}`.
fn response(request_type: &str, payload: Value) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": format!("{request_type}#response"),
        "issuedAt": "2026-01-01T00:00:00Z",
        "payload": payload,
    })
}

/// A `trust-task-error` with `code`.
fn rejection(code: &str) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/trust-task-error/0.1",
        "issuedAt": "2026-01-01T00:00:00Z",
        "payload": { "code": code, "message": "not on the admin list" },
    })
}

#[tokio::test]
async fn a_member_record_reaches_the_registry_and_the_reply_completes_the_write() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let registry = mock.connect_registry_peer().await;
    let client = client_for(&mock, registry.did());

    let record = RegistryRecord::fresh_active("did:key:zMemberOne");
    let (result, request) = tokio::join!(
        client.publish_member(&record),
        serve_once(&registry, mock.vtc_did(), |_| response(
            RECORD_PUT,
            json!({ "ok": true, "created": true }),
        )),
    );

    result.expect("the write completes once the registry answers");

    // The document the registry actually received. `record/put` is a write, so
    // the registry requires a proof and the four-part key must be the tuple a
    // recognition query later looks up.
    assert_eq!(
        request["type"],
        "https://trusttasks.org/spec/registry/record/put/0.1"
    );
    assert_eq!(request["issuer"], mock.vtc_did());
    assert_eq!(request["recipient"], registry.did());
    assert!(
        request["proof"].is_object(),
        "a record write must be signed — the registry rejects it as `proofRequired` otherwise: \
         {request}",
    );
    let stored = &request["payload"]["record"];
    assert_eq!(stored["entity_id"], "did:key:zMemberOne");
    assert_eq!(stored["authority_id"], mock.vtc_did());
    assert_eq!(stored["action"], RECOGNISE_ACTION);
    assert_eq!(stored["resource"], TRUST_GRAPH_RESOURCE);
    assert_eq!(stored["recognized"], true);

    // What the diagnostics surface will report. It has to describe the call
    // that just happened, not the configuration that implies it: the whole
    // point of showing advertised *and* active is that an operator can tell a
    // registry we are talking to from one we merely have a DID for.
    let transport = client.transport();
    assert_eq!(transport.did.as_deref(), Some(registry.did()));
    assert_eq!(
        transport.advertised,
        vec!["didcomm".to_string()],
        "the peer's did:peer advertises DIDComm and nothing else",
    );
    assert_eq!(
        transport.active.as_deref(),
        Some("didcomm"),
        "the reported transport must be the one that carried the write",
    );
    assert_eq!(transport.error, None);

    registry.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn a_failed_selection_is_visible_on_the_transport_snapshot() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    // The applicant advertises no service block, so there is nothing to match.
    let client = client_for(&mock, mock.client.did());

    client.health().await.expect_err("no route to this peer");

    // The snapshot has to carry *why*, not just the absence of a transport —
    // "advertised nothing" is the actionable half, and it is the half a bare
    // `active: none` would drop.
    let transport = client.transport();
    assert_eq!(transport.active, None);
    assert!(transport.advertised.is_empty());
    let error = transport.error.expect("the failure is recorded");
    assert!(
        error.contains("no transport protocol in common"),
        "got {error}",
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn a_rejection_is_a_permanent_failure_not_a_retry_loop() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let registry = mock.connect_registry_peer().await;
    let client = client_for(&mock, registry.did());

    // `permissionDenied` is what a registry says when the VTC's DID is not on
    // its admin list. Retrying cannot fix that, so it must reach the syncer as
    // permanent — a retriable classification here is how a misconfiguration
    // turns into an ever-growing queue with no failed job to look at.
    let record = RegistryRecord::fresh_active("did:key:zMemberTwo");
    let (result, _) = tokio::join!(
        client.publish_member(&record),
        serve_once(&registry, mock.vtc_did(), |_| rejection("permissionDenied")),
    );

    let err = result.expect_err("a rejected write is a failure");
    assert!(!err.is_retriable(), "got {err:?}");
    assert!(err.to_string().contains("permissionDenied"), "got {err}");

    registry.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn health_follows_the_round_trip_not_a_url() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let registry = mock.connect_registry_peer().await;
    let client = client_for(&mock, registry.did());

    // A registry that answers is healthy. The probe is a read, so it carries
    // no proof — the registry serves it without consulting its admin list.
    let (result, request) = tokio::join!(
        client.health(),
        serve_once(&registry, mock.vtc_did(), |_| response(
            RECORD_QUERY,
            json!({ "records": [] }),
        )),
    );
    result.expect("a registry that answers is healthy");
    assert_eq!(
        request["type"],
        "https://trusttasks.org/spec/registry/record/query/0.1"
    );
    assert!(
        request["proof"].is_null(),
        "the health probe must not need a proof, or it stops working on a \
         registry that refuses our writes: {request}",
    );

    // A registry that *rejects* is still answering, and answering is what the
    // signal reports on.
    let (result, _) = tokio::join!(
        client.health(),
        serve_once(&registry, mock.vtc_did(), |_| rejection("permissionDenied")),
    );
    result.expect("a rejection still proves the registry is alive");

    registry.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn silence_is_unhealthy_and_retriable() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let registry = mock.connect_registry_peer().await;
    // Deliberately no `serve_once`: the peer is connected but never answers.
    // This is the case the old HTTP probe could not represent — the registry's
    // URL is up, its DID resolves, and it is still not doing its job.
    let client = client_for(&mock, registry.did()).with_reply_timeout(Duration::from_secs(2));

    let err = client
        .health()
        .await
        .expect_err("a registry that never answers is not healthy");
    assert!(err.is_retriable(), "silence is transient, got {err:?}");

    registry.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn a_member_record_round_trips_through_query() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    let registry = mock.connect_registry_peer().await;
    let client = client_for(&mock, registry.did());

    // Echo back the record shape the registry stores, and check the client
    // reconstructs the member from it — the pairing that decides whether boot
    // drift detection compares like with like.
    let (result, request) = tokio::join!(
        client.read_member("did:key:zMemberThree"),
        serve_once(&registry, mock.vtc_did(), |req| {
            let entity = req["payload"]["entity_id"].as_str().unwrap_or_default();
            response(
                RECORD_QUERY,
                json!({
                    "records": [{
                        "entity_id": entity,
                        "authority_id": req["payload"]["authority_id"],
                        "action": RECOGNISE_ACTION,
                        "resource": TRUST_GRAPH_RESOURCE,
                        "record_type": "recognition",
                        "recognized": true,
                        "context": { "status": "active", "activeFrom": "2026-08-01T00:00:00Z" },
                    }],
                }),
            )
        }),
    );

    let found = result
        .expect("query completes")
        .expect("the registry returned a record for this member");
    assert_eq!(found.member_did, "did:key:zMemberThree");
    assert_eq!(found.status, RegistryStatus::Active);
    // Not a fully-keyed fetch: all four parts make it an exact lookup that
    // errors on a miss, and "this member has no record" is a normal answer.
    assert!(
        request["payload"]["resource"].is_null(),
        "read_member must stay an enumeration: {request}",
    );

    registry.shutdown().await;
    mock.shutdown().await;
}

#[tokio::test]
async fn a_peer_advertising_no_transport_is_refused_by_name() {
    init_tracing();
    let mock = MockVtcDidcomm::start().await;
    // The applicant's `did:peer` carries no service block, so there is nothing
    // to match on. The point is that this fails as a *typed* refusal naming
    // both sides' advertised sets, rather than defaulting to DIDComm because
    // the peer happens to be reachable on the mediator — inferring transport
    // from reachability is precisely what the matcher exists to prevent.
    let client = client_for(&mock, mock.client.did());

    let err = client
        .health()
        .await
        .expect_err("a peer that advertises nothing cannot be routed to");
    assert!(!err.is_retriable(), "a config fault must not spin: {err:?}");
    // The message has to carry both sides' advertised sets, not just "failed":
    // an operator reading it should be able to tell which side to fix without
    // resolving the DID by hand.
    let message = err.to_string();
    assert!(
        message.contains("no transport protocol in common"),
        "the error should name the mismatch: {message}",
    );
    assert!(
        message.contains("we advertise") && message.contains("they advertise []"),
        "the error should quote both advertised sets: {message}",
    );

    mock.shutdown().await;
}
