//! The community's operation budgets on Trust Task work (VTI-TRN-029), charged on the
//! shared spine after the proof: a signer with a live access-control entry to its own
//! share and then the node's, a proven signer without one (a guest, VTI-EVT-154) to the
//! budget for signers without standing. The per-address HTTPS limit stays in front.
//!
//! Every budget here sits on a manual clock, so a refusal is followed by a resend after
//! the clock moves — the refused document was not recorded, so the resend is a retry
//! (VTI-OPS-026), not a duplicate.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;
use vtc_service::acl::VtcRole;
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};
use vti_rooms_dtg::test_support::Party;
use vti_trust_task_server::budget::BudgetClock;

use crate::common::signed::{error_code, party_with_role, post, signed_to};

/// A task any proven signer may send and that changes nothing: a guest withdrawing from
/// an event they never registered for answers `notRegistered`, a member `alreadyMember`
/// or the like — either way, the task ran, so the budget let it through.
const WITHDRAW: &str = "https://trusttasks.org/spec/vtc/events/guests/withdraw/0.1";

/// With a rate of one a second, every bucket's burst is the heaviest weight (10).
const BURST: usize = 10;

async fn send(vtc: &TestVtc, from: &Party) -> (StatusCode, Value, Value) {
    let doc = signed_to(
        from,
        TEST_VTC_DID,
        WITHDRAW,
        json!({ "eventId": "evt_NoSuchEvent0000000001" }),
    )
    .await;
    let (status, reply) = post(vtc, &doc).await;
    (status, reply, doc)
}

fn refused_by_budget(reply: &Value) -> bool {
    error_code(reply) == Some("unavailable")
}

/// Send from `from` until the budget refuses; the number let through.
async fn spend(vtc: &TestVtc, from: &Party) -> usize {
    for n in 0..BURST * 3 {
        let (_, reply, _) = send(vtc, from).await;
        if refused_by_budget(&reply) {
            return n;
        }
    }
    panic!("no budget refusal in {} documents", BURST * 3);
}

#[tokio::test]
async fn vti_trn_029_a_member_is_charged_to_its_own_share() {
    let clock = BudgetClock::manual();
    let vtc = TestVtc::builder()
        .with_operation_budget(1, 1, clock.clone())
        .build()
        .await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let other = party_with_role(&vtc, VtcRole::Member, &[]).await;

    assert_eq!(spend(&vtc, &member).await, BURST);
    // Another member's share is untouched, and so is the budget for signers without
    // standing: a guest is still let through.
    let (_, reply, _) = send(&vtc, &other).await;
    assert!(!refused_by_budget(&reply), "{reply}");
    let (_, reply, _) = send(&vtc, &Party::new()).await;
    assert!(!refused_by_budget(&reply), "{reply}");
}

#[tokio::test]
async fn vti_trn_029_members_together_are_bounded_by_the_node_budget() {
    let clock = BudgetClock::manual();
    let vtc = TestVtc::builder()
        .with_operation_budget(1000, 1000, clock.clone())
        .with_node_operation_budget(1, BURST as u32)
        .build()
        .await;
    let mut let_through = 0;
    let mut refused = false;
    for _ in 0..BURST * 2 {
        let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
        let (_, reply, _) = send(&vtc, &member).await;
        if refused_by_budget(&reply) {
            refused = true;
            break;
        }
        let_through += 1;
    }
    assert!(refused, "the node budget never refused");
    assert_eq!(let_through, BURST);
}

#[tokio::test]
async fn vti_evt_154_guests_are_charged_to_the_budget_without_standing() {
    let clock = BudgetClock::manual();
    let vtc = TestVtc::builder()
        .with_operation_budget(1, 1, clock.clone())
        .build()
        .await;

    // Strangers share one budget: ten different guests spend it…
    for _ in 0..BURST {
        let (_, reply, _) = send(&vtc, &Party::new()).await;
        assert!(!refused_by_budget(&reply), "{reply}");
    }
    let (status, reply, _) = send(&vtc, &Party::new()).await;
    assert!(refused_by_budget(&reply), "{status} {reply}");
    // …and never what members need.
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    let (_, reply, _) = send(&vtc, &member).await;
    assert!(!refused_by_budget(&reply), "{reply}");
}

#[tokio::test]
async fn vti_ops_026_a_refused_document_is_not_recorded_so_a_resend_is_a_retry() {
    let clock = BudgetClock::manual();
    let vtc = TestVtc::builder()
        .with_operation_budget(1, 1, clock.clone())
        .build()
        .await;
    let member = party_with_role(&vtc, VtcRole::Member, &[]).await;
    assert_eq!(spend(&vtc, &member).await, BURST);

    let doc = signed_to(
        &member,
        TEST_VTC_DID,
        WITHDRAW,
        json!({ "eventId": "evt_NoSuchEvent0000000001" }),
    )
    .await;
    let (_, reply) = post(&vtc, &doc).await;
    assert!(refused_by_budget(&reply), "{reply}");

    clock.advance(Duration::from_secs(2));
    // The same document, resent, runs: had the refusal been recorded against its `id`,
    // the duplicate-execution record would answer the resend with that refusal again.
    let (_, reply) = post(&vtc, &doc).await;
    assert!(!refused_by_budget(&reply), "{reply}");
    assert!(
        error_code(&reply).is_some_and(|c| c != "idConflict"),
        "{reply}"
    );
}

#[tokio::test]
async fn vti_trn_029_the_per_address_limit_stays_in_front() {
    // Budgets far above the per-address burst: one address is refused by the HTTPS
    // governor (429, `x-rate-limit-source`), never by the budget.
    let vtc = TestVtc::builder()
        .with_operation_budget(1000, 1000, BudgetClock::manual())
        .build()
        .await;
    let guest = Party::new();
    for _ in 0..40 {
        let doc = signed_to(
            &guest,
            TEST_VTC_DID,
            WITHDRAW,
            json!({ "eventId": "evt_NoSuchEvent0000000001" }),
        )
        .await;
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/trust-tasks")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&doc).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [10, 254, 0, 1],
                40_000,
            ))));
        let res = vtc.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let has_source = res.headers().contains_key("x-rate-limit-source");
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let reply: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert!(
            !refused_by_budget(&reply),
            "the budget refused first: {reply}"
        );
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert!(has_source, "a governor refusal names its source");
            return;
        }
    }
    panic!("no per-address refusal in 40 requests");
}
