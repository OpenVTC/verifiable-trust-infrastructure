//! Join review and vetting withdrawal review as action-list queue items, and
//! the two listings that filter before they page and count what they filter
//! (`docs/05-design-notes/vtc-action-list.md` §8.2; `vtc/join-requests/list`
//! and `vtc/members/list` `totalEstimate`).
//!
//! Break-glass ratification is held in `git_ns::tests::break_glass_queue`,
//! beside the fixtures that make a break-glass.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use vti_rooms_dtg::test_support::Party;

use super::queues::{decide_as, item, items_of_kind, join_changed};
use super::summary::{KIND_JOIN_REVIEW, KIND_VETTING_REVIEW};
use super::{Category, ClosedReason, Decided, DecisionError, Status};
use crate::acl::{AdminAuthority, AdminRole, VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry};
use crate::join::{JoinRequest, JoinStatus, get_join_request, store_join_request};
use crate::members::{Member, get_member, store_member};
use crate::server::AppState;
use crate::test_support::{TEST_VTC_DID, TestVtc};

const RP_ORIGIN: &str = "https://vtc.example.com";

async fn vtc() -> TestVtc {
    let vtc = TestVtc::builder()
        .vtc_did(TEST_VTC_DID)
        .with_public_url(RP_ORIGIN)
        .with_audit(true)
        .with_signers(true)
        .build()
        .await;
    crate::policy::default::install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .unwrap();
    // Approving issues a membership credential, which takes a status slot.
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        crate::status_list::ensure_initial(
            &vtc.state.status_lists_ks,
            purpose,
            format!("{RP_ORIGIN}/v1/status-lists/{purpose}"),
        )
        .await
        .unwrap();
    }
    vtc
}

async fn seed(state: &AppState, did: &str, admin: AdminAuthority) {
    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
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
            suspension: None,
        },
    )
    .await
    .unwrap();
    store_member(&state.members_ks, &Member::fresh(did))
        .await
        .unwrap();
}

async fn admin(state: &AppState) -> Party {
    let p = Party::new();
    seed(state, &p.did, AdminAuthority::community_admin()).await;
    p
}

/// A join request referred for review, as `realize_join_verdict` stores it
/// and then tells the action list.
async fn referred(state: &AppState) -> JoinRequest {
    let applicant = Party::new();
    let mut req = JoinRequest::new(applicant.did.clone(), json!({ "vp": "x" }));
    req.status = JoinStatus::Pending;
    store_join_request(&state.join_requests_ks, &req)
        .await
        .unwrap();
    join_changed(state, &req).await;
    req
}

async fn join_item(state: &AppState, req: &JoinRequest) -> super::ActionRecord {
    items_of_kind(state, KIND_JOIN_REVIEW)
        .await
        .into_iter()
        .find(|r| r.payload["requestId"] == json!(req.id.to_string()))
        .expect("a join review for the request")
}

// ─── join review ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_referred_join_raises_one_queue_item_for_the_join_deciders() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    // A vetting lead holds no vtc.join.decide: not a decider.
    let lead = Party::new();
    seed(
        &vtc.state,
        &lead.did,
        AdminAuthority::for_role(AdminRole::VettingLead),
    )
    .await;
    let req = referred(&vtc.state).await;
    // Told twice, raised once.
    join_changed(&vtc.state, &req).await;

    let items = items_of_kind(&vtc.state, KIND_JOIN_REVIEW).await;
    assert_eq!(items.len(), 1);
    let rec = &items[0];
    assert_eq!(rec.category, Category::Queue);
    assert_eq!(rec.threshold, 1);
    assert_eq!(rec.requester, req.applicant_did);
    let deciders: Vec<&str> = rec.approvers.iter().map(|s| s.did.as_str()).collect();
    assert_eq!(deciders, vec![a.did.as_str()]);
}

/// Single-administrator mode or not, a sole administrator holding
/// `vtc.join.decide` decides a queue item alone: it is a decision, not a
/// consent.
#[tokio::test]
async fn approving_the_join_item_admits_the_applicant() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    let req = referred(&vtc.state).await;
    let rec = join_item(&vtc.state, &req).await;

    let out = decide_as(&vtc.state, &a.did, &rec.id, true, None)
        .await
        .unwrap();
    assert!(
        matches!(
            out,
            Decided::Granted {
                completed: true,
                ..
            }
        ),
        "{out:?}"
    );
    let stored = get_join_request(&vtc.state.join_requests_ks, req.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, JoinStatus::Approved);
    assert!(
        get_member(&vtc.state.members_ks, &req.applicant_did)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        get_acl_entry(&vtc.state.acl_ks, &req.applicant_did)
            .await
            .unwrap()
            .is_some()
    );
    let done = item(&vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Completed);
    assert_eq!(done.closed_by.as_deref(), Some(a.did.as_str()));
}

#[tokio::test]
async fn rejecting_the_join_item_rejects_with_the_reason() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    let req = referred(&vtc.state).await;
    let rec = join_item(&vtc.state, &req).await;

    let out = decide_as(&vtc.state, &a.did, &rec.id, false, Some("incomplete"))
        .await
        .unwrap();
    assert!(matches!(out, Decided::Denied { .. }), "{out:?}");
    let stored = get_join_request(&vtc.state.join_requests_ks, req.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, JoinStatus::Rejected);
    assert_eq!(
        stored.decision.unwrap().reason.as_deref(),
        Some("incomplete")
    );
    let done = item(&vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Declined);
    assert_eq!(done.closed_reason, Some(ClosedReason::Declined));
}

#[tokio::test]
async fn deciding_on_the_join_requests_page_closes_the_item() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    let req = referred(&vtc.state).await;
    let rec = join_item(&vtc.state, &req).await;

    crate::routes::join_requests::decide::decide_inner(
        &vtc.state,
        &a.did,
        "rest",
        req.id,
        crate::routes::join_requests::decide::DecideBody {
            decision: crate::routes::join_requests::decide::Decision::Rejected,
            reason: None,
        },
    )
    .await
    .unwrap();
    let done = item(&vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Declined);
    assert_eq!(done.closed_by.as_deref(), Some(a.did.as_str()));
    assert!(matches!(
        decide_as(&vtc.state, &a.did, &rec.id, true, None).await,
        Err(DecisionError::NoPending)
    ));
}

#[tokio::test]
async fn a_request_decided_where_no_hook_reaches_closes_at_the_next_read() {
    let vtc = vtc().await;
    admin(&vtc.state).await;
    let req = referred(&vtc.state).await;
    let rec = join_item(&vtc.state, &req).await;
    // Withdrawn by the applicant, written without telling the list.
    let mut gone = req.clone();
    gone.status = JoinStatus::Withdrawn;
    store_join_request(&vtc.state.join_requests_ks, &gone)
        .await
        .unwrap();
    super::refresh_all(&vtc.state).await.unwrap();
    let done = item(&vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Cancelled);
    assert_eq!(done.closed_reason, Some(ClosedReason::Invalidated));
}

#[tokio::test]
async fn the_sweeper_raises_a_referred_join_whose_item_was_lost() {
    let vtc = vtc().await;
    admin(&vtc.state).await;
    // Stored, and the process died before the item was raised.
    let mut req = JoinRequest::new(Party::new().did, json!({ "vp": "x" }));
    req.status = JoinStatus::Pending;
    store_join_request(&vtc.state.join_requests_ks, &req)
        .await
        .unwrap();
    assert!(items_of_kind(&vtc.state, KIND_JOIN_REVIEW).await.is_empty());
    super::sweep_once(&vtc.state).await.unwrap();
    super::sweep_once(&vtc.state).await.unwrap();
    assert_eq!(items_of_kind(&vtc.state, KIND_JOIN_REVIEW).await.len(), 1);
}

#[tokio::test]
async fn queue_items_never_count_toward_the_action_limits() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    for _ in 0..60 {
        referred(&vtc.state).await;
    }
    // Over the community's 50 open actions in queue items alone, an
    // administrator can still raise an approval.
    super::check_limits(
        &vtc.state,
        crate::acl::admin_consent::Act::GrantUnrestricted,
        &a.did,
        "did:key:zSomeone",
    )
    .await
    .unwrap();
}

// ─── vetting withdrawal review ───────────────────────────────────────────

struct Withdrawal {
    vetter: Party,
    member: Party,
    request: Uuid,
}

/// A member admitted on a vetting statement, whose vetter then withdraws it
/// (`vtc/vetting/revoke-statement`): `needsReview`.
async fn withdrawn(state: &AppState) -> Withdrawal {
    let vetter = Party::new();
    let member = Party::new();
    seed(state, &vetter.did, AdminAuthority::none()).await;
    seed(state, &member.did, AdminAuthority::none()).await;
    let mut req = JoinRequest::new(member.did.clone(), json!({ "vp": "x" }));
    req.status = JoinStatus::Approved;
    store_join_request(&state.join_requests_ks, &req)
        .await
        .unwrap();
    let statement_id = "urn:uuid:9a7b6c5d-4e3f-4a2b-8c1d-0e9f8a7b6c5d";
    let facts = crate::vetting::VettingFacts {
        criterion_id: "vetted".into(),
        requirements_digest: "z".into(),
        applicant_digest_matches: true,
        statements: vec![crate::vetting::VettingStatementFact {
            id: Some(statement_id.into()),
            issuer: Some(vetter.did.clone()),
            verified: true,
            eligible: true,
            revoked: false,
            method: Some("inPerson".into()),
            declared_relationship: None,
            counted: true,
            failures: Vec::new(),
        }],
        distinct_counted_vetters: 1,
        by_method: Default::default(),
        commitments_consistent: true,
        independence_ok: true,
        invitation_required: false,
        satisfied: true,
        needs: Vec::new(),
    };
    crate::join::store_vetting_facts(&state.join_requests_ks, req.id, &facts, Utc::now())
        .await
        .unwrap();
    let body: vta_sdk::protocols::vetting::revoke_statement::v0_1::Payload =
        serde_json::from_value(json!({
            "statementId": statement_id,
            "statementDigestMultibase":
                dtg_credentials::digest_multibase_json(&json!({ "statement": 1 })).unwrap(),
            "reason": "mistake",
        }))
        .unwrap();
    crate::vetting::revocation::withdraw(state, &vetter.did, &body)
        .await
        .unwrap();
    Withdrawal {
        vetter,
        member,
        request: req.id,
    }
}

#[tokio::test]
async fn a_withdrawal_a_membership_rests_on_raises_a_review_for_vetting_managers() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    let w = withdrawn(&vtc.state).await;
    let items = items_of_kind(&vtc.state, KIND_VETTING_REVIEW).await;
    assert_eq!(items.len(), 1);
    let rec = &items[0];
    assert_eq!(rec.category, Category::Queue);
    assert_eq!(rec.subject, w.member.did);
    assert_eq!(rec.payload["issuer"], json!(w.vetter.did));
    assert_eq!(rec.payload["joinRequests"], json!([w.request.to_string()]));
    let deciders: Vec<&str> = rec.approvers.iter().map(|s| s.did.as_str()).collect();
    assert_eq!(deciders, vec![a.did.as_str()], "never the member");
}

#[tokio::test]
async fn keeping_the_member_closes_the_review_for_good() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    let w = withdrawn(&vtc.state).await;
    let rec = items_of_kind(&vtc.state, KIND_VETTING_REVIEW)
        .await
        .remove(0);

    let out = decide_as(&vtc.state, &a.did, &rec.id, true, None)
        .await
        .unwrap();
    assert!(matches!(
        out,
        Decided::Granted {
            completed: true,
            ..
        }
    ));
    assert_eq!(item(&vtc.state, &rec.id).await.status, Status::Completed);
    assert!(
        get_acl_entry(&vtc.state.acl_ks, &w.member.did)
            .await
            .unwrap()
            .is_some()
    );
    // The withdrawal still reads `needsReview`; the sweeper never raises it
    // again for this member.
    super::sweep_once(&vtc.state).await.unwrap();
    assert_eq!(
        items_of_kind(&vtc.state, KIND_VETTING_REVIEW).await.len(),
        1
    );
}

#[tokio::test]
async fn starting_removal_removes_the_member_through_admin_remove() {
    let vtc = vtc().await;
    let a = admin(&vtc.state).await;
    let w = withdrawn(&vtc.state).await;
    let rec = items_of_kind(&vtc.state, KIND_VETTING_REVIEW)
        .await
        .remove(0);

    let out = decide_as(
        &vtc.state,
        &a.did,
        &rec.id,
        false,
        Some("statement withdrawn"),
    )
    .await
    .unwrap();
    assert!(matches!(out, Decided::Denied { .. }), "{out:?}");
    assert!(
        get_acl_entry(&vtc.state.acl_ks, &w.member.did)
            .await
            .unwrap()
            .is_none(),
        "removed"
    );
    let done = item(&vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Declined);
    assert_eq!(done.closed_by.as_deref(), Some(a.did.as_str()));
}

#[tokio::test]
async fn a_removal_the_decider_may_not_start_leaves_the_review_open() {
    let vtc = vtc().await;
    // A vetting lead manages vetting but not members: they may keep the
    // member, and starting a removal is refused by admin-remove's own rule.
    let lead = Party::new();
    seed(
        &vtc.state,
        &lead.did,
        AdminAuthority::for_role(AdminRole::VettingLead),
    )
    .await;
    let w = withdrawn(&vtc.state).await;
    let rec = items_of_kind(&vtc.state, KIND_VETTING_REVIEW)
        .await
        .remove(0);
    assert!(rec.approvers.iter().any(|s| s.did == lead.did));

    let refused = decide_as(&vtc.state, &lead.did, &rec.id, false, None).await;
    assert!(
        matches!(&refused, Err(DecisionError::Refused(m)) if m.contains("vtc.members.manage")),
        "{refused:?}"
    );
    assert_eq!(item(&vtc.state, &rec.id).await.status, Status::Open);
    assert!(
        get_acl_entry(&vtc.state.acl_ks, &w.member.did)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_member_removed_elsewhere_closes_the_review() {
    let vtc = vtc().await;
    admin(&vtc.state).await;
    let w = withdrawn(&vtc.state).await;
    let rec = items_of_kind(&vtc.state, KIND_VETTING_REVIEW)
        .await
        .remove(0);
    let mut m = get_member(&vtc.state.members_ks, &w.member.did)
        .await
        .unwrap()
        .unwrap();
    m.removed_at = Some(Utc::now());
    store_member(&vtc.state.members_ks, &m).await.unwrap();
    super::refresh_all(&vtc.state).await.unwrap();
    assert_eq!(item(&vtc.state, &rec.id).await.status, Status::Cancelled);
}

// ─── filter before paging, and count ─────────────────────────────────────

fn request_with(id: u128, status: JoinStatus) -> JoinRequest {
    let mut r = JoinRequest::new(format!("did:key:zApplicant{id}"), json!({ "vp": "x" }));
    r.id = Uuid::from_u128(id);
    r.status = status;
    r
}

/// The status filter used to run on each page after it was cut, so the first
/// page of `pending` could come back empty while pending requests lay
/// further on. It runs first now: every page is full of matches, the cursor
/// walks only them, and `totalEstimate` counts them.
#[tokio::test]
async fn join_requests_filter_before_paging_and_count_the_matches() {
    use crate::routes::join_requests::read::{ListJoinRequestsQuery, list_join_requests_inner};
    let vtc = vtc().await;
    // Ten decided requests sort before the two pending ones.
    for i in 1..=10 {
        store_join_request(
            &vtc.state.join_requests_ks,
            &request_with(i, JoinStatus::Approved),
        )
        .await
        .unwrap();
    }
    for i in [u128::MAX - 1, u128::MAX] {
        store_join_request(
            &vtc.state.join_requests_ks,
            &request_with(i, JoinStatus::Pending),
        )
        .await
        .unwrap();
    }
    let page = |cursor: Option<String>| ListJoinRequestsQuery {
        status: None,
        cursor,
        limit: Some(1),
    };
    let first = list_join_requests_inner(&vtc.state, page(None))
        .await
        .unwrap();
    assert_eq!(
        first.items.len(),
        1,
        "the first page holds a pending request"
    );
    assert_eq!(first.items[0].status, JoinStatus::Pending);
    assert_eq!(first.total_estimate, Some(2));
    let second = list_join_requests_inner(&vtc.state, page(first.next_cursor.clone()))
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].status, JoinStatus::Pending);
    assert_ne!(second.items[0].id, first.items[0].id);
    assert!(
        second.next_cursor.is_none(),
        "no empty page after the last match"
    );

    let approved = list_join_requests_inner(
        &vtc.state,
        ListJoinRequestsQuery {
            status: Some(JoinStatus::Approved),
            cursor: None,
            limit: Some(200),
        },
    )
    .await
    .unwrap();
    assert_eq!(approved.items.len(), 10);
    assert_eq!(approved.total_estimate, Some(10));
}

#[tokio::test]
async fn members_filter_before_paging_and_count_the_matches() {
    use crate::routes::members::read::{ListMembersQuery, list_members_inner};
    let vtc = vtc().await;
    let mut members = Vec::new();
    for _ in 0..3 {
        let p = Party::new();
        seed(&vtc.state, &p.did, AdminAuthority::none()).await;
        members.push(p.did);
    }
    admin(&vtc.state).await;
    // A departed member's tombstone: a row, no ACL entry — never listed.
    let mut gone = Member::fresh("did:key:zDeparted");
    gone.removed_at = Some(Utc::now());
    store_member(&vtc.state.members_ks, &gone).await.unwrap();

    let all = list_members_inner(
        &vtc.state,
        ListMembersQuery {
            role: None,
            cursor: None,
            limit: Some(200),
        },
    )
    .await
    .unwrap();
    assert_eq!(all.items.len(), 4);
    assert_eq!(all.total_estimate, Some(4), "the tombstone is not counted");

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = list_members_inner(
            &vtc.state,
            ListMembersQuery {
                role: Some("member".into()),
                cursor: cursor.clone(),
                limit: Some(1),
            },
        )
        .await
        .unwrap();
        assert_eq!(page.total_estimate, Some(3));
        assert_eq!(page.items.len(), 1, "never an empty page");
        seen.push(page.items[0].did.clone());
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    seen.sort();
    members.sort();
    assert_eq!(seen, members);
}
