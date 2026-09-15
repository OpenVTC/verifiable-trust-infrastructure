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

use vtc_service::test_support::{MockVtcDidcomm, ReplyOutcome};

const TIMEOUT: Duration = Duration::from_secs(20);

/// `members/personhood/challenge/0.1` — dispatched by the spine, absent from the
/// DIDComm router.
const PERSONHOOD_CHALLENGE: &str =
    "https://trusttasks.org/spec/vtc/members/personhood/challenge/0.1";

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

/// **The case.** A verb with no arm of its own in the DIDComm router is reachable
/// when it arrives in the binding envelope.
#[tokio::test]
async fn a_verb_absent_from_the_didcomm_router_is_reachable_in_the_envelope() {
    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let vtc_did = mock.vtc_did().to_string();

    let outcome = mock
        .client
        .try_request_enveloped(&vtc_did, PERSONHOOD_CHALLENGE, json!({}), TIMEOUT)
        .await;

    mock.shutdown().await;

    assert!(
        !is_unsupported_type(&outcome),
        "the envelope must reach the dispatcher, not the router's fallback. \
         `{PERSONHOOD_CHALLENGE}` is dispatched over REST and TSP, so an \
         `unsupported message type` here is the DIDComm router's second list \
         disagreeing with the dispatcher: {outcome:?}"
    );
    assert!(
        !matches!(outcome, ReplyOutcome::Timeout),
        "an enveloped request must be answered, not dropped — a silent drop is \
         what this arm exists to remove: {outcome:?}"
    );
}

/// The same verb sent the old way, so the test above cannot pass for a reason
/// that has nothing to do with the envelope.
///
/// This asserts today's behaviour, which is the defect: keyed on the task URI,
/// the router has no arm and refuses. When the legacy task-URI arms are
/// eventually retired this assertion flips — and it should be *read* then, not
/// deleted, because it is the record of why the envelope arm was added.
#[tokio::test]
async fn the_same_verb_typed_as_the_task_is_still_refused_by_the_router() {
    init_tracing();
    let mock = MockVtcDidcomm::start_with_tsp().await;
    let vtc_did = mock.vtc_did().to_string();

    let outcome = mock
        .client
        .try_request(&vtc_did, PERSONHOOD_CHALLENGE, json!({}), TIMEOUT)
        .await;

    mock.shutdown().await;

    assert!(
        is_unsupported_type(&outcome),
        "expected the task-URI router to refuse a verb it has no arm for — if \
         this now passes, the router learned the verb and this test should be \
         re-read rather than deleted: {outcome:?}"
    );
}
