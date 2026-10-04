//! Queue items on the wire (`docs/05-design-notes/vtc-action-list.md` §8.2):
//! a join referred for review reads, through the signed-document door, as a
//! `queue` action — no threshold, no expiry, a challenge for its decider —
//! held to the published `_shared` Action at 0.1 and 0.2, and decided with
//! `task-consent/decision/0.2` exactly as the Join requests page decides it.
//!
//! The lifecycle in depth is held in-crate (`admin_actions::queue_tests`,
//! `git_ns::tests::break_glass_queue`); this file holds the wire.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vti_rooms_dtg::test_support::Party;

use vtc_service::acl::{AdminAuthority, VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::join::{JoinRequest, JoinStatus, get_join_request, store_join_request};
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::{TEST_VTC_DID, TestVtc};

use crate::common::second_party::decide;
use crate::common::signed::{assert_conforms, post, signed};

const RP_ORIGIN: &str = "https://vtc.example.com";
const LIST: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.1";
const LIST_V0_2: &str = "https://trusttasks.org/spec/vtc/admin/actions/list/0.2";
const JOINS_LIST: &str = "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
const MEMBERS_LIST: &str = "https://trusttasks.org/spec/vtc/members/list/0.1";

async fn vtc() -> TestVtc {
    let vtc = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url(RP_ORIGIN)
        .with_signers(true)
        .with_audit(true)
        .build()
        .await;
    vtc_service::policy::default::install_defaults(
        &vtc.state.policies_ks,
        &vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        vtc_service::status_list::ensure_initial(
            &vtc.state.status_lists_ks,
            purpose,
            format!("{RP_ORIGIN}/v1/status-lists/{purpose}"),
        )
        .await
        .unwrap();
    }
    vtc
}

async fn administrator(vtc: &TestVtc) -> Party {
    let p = Party::new();
    let admin = AdminAuthority::community_admin();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: p.did.clone(),
            role: VtcRole::implied_by(admin.admin_role.as_ref()),
            label: None,
            admin,
            delegated_by: None,
            created_at: 0,
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
        },
    )
    .await
    .unwrap();
    store_member(&vtc.state.members_ks, &Member::fresh(p.did.clone()))
        .await
        .unwrap();
    p
}

/// A join request referred for review, its item raised by the sweeper as it
/// would be for one whose submit hook was lost.
async fn referred(vtc: &TestVtc) -> JoinRequest {
    let mut req = JoinRequest::new(Party::new().did, json!({ "vp": "x" }));
    req.status = JoinStatus::Pending;
    store_join_request(&vtc.state.join_requests_ks, &req)
        .await
        .unwrap();
    vtc_service::admin_actions::sweep_once(&vtc.state)
        .await
        .unwrap();
    req
}

async fn waiting(vtc: &TestVtc, who: &Party, uri: &str) -> Value {
    let (status, reply) = post(
        vtc,
        &signed(who, uri, json!({ "view": "waitingForMe" })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(uri, &reply);
    reply
}

#[tokio::test]
async fn a_join_review_is_a_queue_action_at_both_versions_and_decides_the_request() {
    let vtc = vtc().await;
    let admin = administrator(&vtc).await;
    let req = referred(&vtc).await;

    for uri in [LIST, LIST_V0_2] {
        let reply = waiting(&vtc, &admin, uri).await;
        let actions = reply["payload"]["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 1, "{reply}");
        let a = &actions[0];
        assert_eq!(a["category"], "queue");
        assert_eq!(a["kind"], "member.join.review");
        assert_eq!(a["payload"]["requestId"], json!(req.id.to_string()));
        assert!(
            a.get("threshold").is_none(),
            "a queue item has no threshold"
        );
        assert!(a.get("expiresAt").is_none(), "a queue item does not expire");
        assert_eq!(a["approversRemaining"], 1);
        assert!(a["challenge"].is_string(), "its decider may decide it now");
        assert_eq!(reply["payload"]["counts"]["waitingForMe"], 1);
    }

    let id = waiting(&vtc, &admin, LIST_V0_2).await["payload"]["actions"][0]["actionId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, ack) = decide(&vtc, &admin, &id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "granted");
    let stored = get_join_request(&vtc.state.join_requests_ks, req.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, JoinStatus::Approved);

    // Gone from Waiting for me; in History, decided.
    let reply = waiting(&vtc, &admin, LIST_V0_2).await;
    assert_eq!(reply["payload"]["actions"], json!([]));
    let (_, history) = post(
        &vtc,
        &signed(&admin, LIST_V0_2, json!({ "view": "history" })).await,
    )
    .await;
    assert_conforms(LIST_V0_2, &history);
    let closed = &history["payload"]["actions"][0];
    assert_eq!(closed["status"], "completed");
    assert_eq!(closed["closedReason"], "thresholdMet");
}

#[tokio::test]
async fn rejecting_a_join_review_rejects_the_request() {
    let vtc = vtc().await;
    let admin = administrator(&vtc).await;
    let req = referred(&vtc).await;
    let id = waiting(&vtc, &admin, LIST_V0_2).await["payload"]["actions"][0]["actionId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, ack) = decide(&vtc, &admin, &id, "deny").await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["payload"]["status"], "denied");
    let stored = get_join_request(&vtc.state.join_requests_ks, req.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, JoinStatus::Rejected);
}

/// `vtc/join-requests/list/0.1` and `vtc/members/list/0.1` fill
/// `totalEstimate`, so the console's badge is one `limit: 1` read.
#[tokio::test]
async fn the_listings_count_what_they_filter_in_one_page() {
    let vtc = vtc().await;
    let admin = administrator(&vtc).await;
    for _ in 0..3 {
        referred(&vtc).await;
    }
    let mut decided = JoinRequest::new(Party::new().did, json!({ "vp": "x" }));
    decided.status = JoinStatus::Rejected;
    store_join_request(&vtc.state.join_requests_ks, &decided)
        .await
        .unwrap();

    let (status, reply) = post(
        &vtc,
        &signed(
            &admin,
            JOINS_LIST,
            json!({ "status": "pending", "limit": 1 }),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(JOINS_LIST, &reply);
    assert_eq!(reply["payload"]["totalEstimate"], 3);
    assert_eq!(reply["payload"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(reply["payload"]["items"][0]["status"], "pending");

    let (status, reply) = post(
        &vtc,
        &signed(&admin, MEMBERS_LIST, json!({ "limit": 1 })).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_conforms(MEMBERS_LIST, &reply);
    assert_eq!(reply["payload"]["totalEstimate"], 1, "the administrator");
}
