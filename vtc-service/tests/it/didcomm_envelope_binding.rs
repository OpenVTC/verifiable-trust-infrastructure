//! A Trust Task in the DIDComm **binding envelope** reaches the dispatcher.
//!
//! ## The gap this closes
//!
//! This service has one dispatcher (`trust_tasks::dispatch_trust_task_core`) and
//! three ways in. REST and TSP each reach it in a single hop: TSP's inbound has
//! no type surface at all, it opens carriage and hands over bytes. DIDComm had a
//! hand-written router keyed on **task URIs**, so a verb was reachable there
//! only if somebody had also written it down in `messaging::route`.
//!
//! Thirteen of the twenty-four dispatched URIs had not been: every `rooms/*`
//! task and both `members/personhood/*` verbs. They dispatch over REST and TSP
//! and answered `unsupported message type` over DIDComm — not because the
//! service lacks them, but because the router is a second list that nobody
//! remembered to extend. The same class of omission had already shipped once
//! here: `rooms/records/curate` was dispatched and named in neither URI list, so
//! every version hint this service emitted was wrong.
//!
//! The binding envelope removes the second list. Its type says "a Trust Task is
//! inside" and nothing more, so one arm reaches everything the dispatcher
//! serves, and a new verb is reachable because it is *dispatched*.
//!
//! ## And then the first list went too (Keyring VTI-42)
//!
//! The task-typed arms stayed beside the envelope for a while, so the router
//! answered twelve verbs in either carriage and the rest in only one. A client
//! that sent `join-requests/withdraw` typed as itself got `unsupported message
//! type` for a verb this service plainly serves. The binding
//! (`bindings/didcomm/0.2` §2–§5) settles it: the envelope is the **only**
//! DIDComm carriage, and a consumer refuses any other type at the DIDComm
//! layer, with no `trust-task-error`. So the arms are gone, and every served
//! URI now behaves the same way in each carriage — which is what the two
//! parity tests below hold, driven by the dispatcher's own lists.
//!
//! ## Why these assertions and not tighter ones
//!
//! The claim under test is **reachability**, not authorization: that the
//! document reached the spine and the spine answered about the task. A
//! `permissionDenied` or a validation refusal is a pass — those are answers only
//! reachable past the router. What must not come back is the DIDComm
//! problem-report `unsupported message type`, which is the router saying it has
//! never heard of a verb this service implements.
//!
//! Requires `--features tsp,didcomm-harness` like its sibling `join_tsp`.

#![cfg(all(feature = "tsp", feature = "didcomm-harness"))]

use std::time::Duration;

use serde_json::json;

use vtc_service::test_support::{MockVtcDidcomm, ReplyOutcome, served_trust_task_uris};
use vti_common::capability_client::TRUST_TASK_ENVELOPE_TYPE;

const TIMEOUT: Duration = Duration::from_secs(20);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// Did the router refuse to recognise the verb at all?
fn is_unsupported_type(outcome: &ReplyOutcome) -> bool {
    match outcome {
        ReplyOutcome::Problem(p) => p.comment.contains("unsupported message type"),
        _ => false,
    }
}

/// **The case.** Every URI the dispatcher serves is reachable in the binding
/// envelope — answered by the spine (a refusal is fine: a `permissionDenied` or
/// a validation error is only reachable past the router), never by the router's
/// fallback, and never dropped.
#[tokio::test]
async fn every_served_uri_is_reachable_in_the_envelope() {
    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let vtc_did = mock.vtc_did().to_string();

    let mut failures = Vec::new();
    for uri in served_trust_task_uris() {
        let outcome = mock
            .client
            .try_request_enveloped(&vtc_did, uri, json!({}), TIMEOUT)
            .await;
        if is_unsupported_type(&outcome) || matches!(outcome, ReplyOutcome::Timeout) {
            failures.push(format!("{uri}: {outcome:?}"));
        }
    }

    mock.shutdown().await;

    assert!(
        failures.is_empty(),
        "an enveloped request for a dispatched URI must reach the dispatcher and be \
         answered — `unsupported message type` is the router disagreeing with the \
         dispatcher, a timeout is a silent drop:\n{}",
        failures.join("\n")
    );
}

/// The same URIs typed as themselves — the carriage the binding forbids — are
/// refused at the DIDComm layer with a problem-report that names the envelope,
/// threaded to the request (a reply this harness could not correlate would
/// surface as a timeout).
///
/// This used to assert the opposite for the verbs with a task-typed arm, and
/// "refused" only for the ones without. Read before changing: the binding
/// requires the refusal, and a verb that answers here has grown a second list
/// again.
#[tokio::test]
async fn every_served_uri_typed_as_itself_is_refused_naming_the_envelope() {
    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let vtc_did = mock.vtc_did().to_string();

    let mut failures = Vec::new();
    for uri in served_trust_task_uris() {
        let outcome = mock
            .client
            .try_request_task_typed(&vtc_did, uri, json!({}), TIMEOUT)
            .await;
        match &outcome {
            ReplyOutcome::Problem(p)
                if p.comment.contains(TRUST_TASK_ENVELOPE_TYPE)
                    // A DIDComm problem-report, not a `trust-task-error`: the
                    // document never entered the pipeline.
                    && p.body.get("payload").is_none() => {}
            other => failures.push(format!("{uri}: {other:?}")),
        }
    }

    mock.shutdown().await;

    assert!(
        failures.is_empty(),
        "a Trust Task typed as its own URI must get a DIDComm problem-report naming \
         `{TRUST_TASK_ENVELOPE_TYPE}`:\n{}",
        failures.join("\n")
    );
}
