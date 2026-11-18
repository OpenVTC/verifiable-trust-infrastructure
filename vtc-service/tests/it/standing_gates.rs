//! Who may read as a member, and who may send a join query.
//!
//! - An `application` entry is never a membership (VTI-ACL-037): it reads
//!   nothing the community shows its members.
//! - A suspended entry may read the action list and nothing else
//!   (`vtc-action-list.md` §8.2, VTI-APV-019), so it reads no member's
//!   relationships, no groups and no badges either.
//! - `vtc/join-requests/query` queues a credential query the community signs to
//!   a DID the caller names: a write, gated on the capability that decides join
//!   requests, not on holding any administrative role.

use axum::http::StatusCode;
use serde_json::{Value, json};
use vtc_service::acl::{AdminAuthority, AdminRole, VtcAclEntry, VtcRole, store_acl_entry};
use vtc_service::members::{Member, store_member};
use vtc_service::test_support::TestVtc;
use vti_rooms_dtg::test_support::Party;

use crate::common::signed::{admin, call, error_code, party_with_role};

const RELATIONSHIPS_LIST: &str = "https://trusttasks.org/spec/vtc/relationships/list/0.3";
const GROUPS_LIST: &str = "https://trusttasks.org/spec/vtc/groups/list/0.2";
const BADGES_LIST: &str = "https://trusttasks.org/spec/vtc/badges/list/0.1";
const JOIN_QUERY: &str = "https://trusttasks.org/spec/vtc/join-requests/query/0.1";

async fn community() -> TestVtc {
    TestVtc::builder()
        .with_signers(true)
        .with_audit(true)
        .build()
        .await
}

/// An active member: an ACL row and a member record.
async fn member(vtc: &TestVtc) -> Party {
    let m = party_with_role(vtc, VtcRole::Member, &[]).await;
    store_member(&vtc.state.members_ks, &Member::fresh(&m.did))
        .await
        .unwrap();
    m
}

/// Put `did` under a cooling-off suspension that has not landed.
async fn suspend(vtc: &TestVtc, did: &str) {
    vtc_service::acl::storage::put_suspension(
        &vtc.state.acl_ks,
        did,
        &vtc_service::acl::Suspension {
            action_id: "act-test".into(),
            lands_at: u64::MAX,
            requester: "did:key:zRequester".into(),
        },
    )
    .await
    .unwrap();
}

/// An administrator holding `role` alone.
async fn with_admin_role(vtc: &TestVtc, role: AdminRole) -> Party {
    let party = Party::new();
    store_acl_entry(
        &vtc.state.acl_ks,
        &VtcAclEntry {
            did: party.did.clone(),
            admin: AdminAuthority::for_role(role),
            delegated_by: None,
            role: VtcRole::Member,
            label: None,
            created_at: 0,
            created_by: "did:key:vtc-install".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
            resource_grants: Vec::new(),
            group_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        },
    )
    .await
    .unwrap();
    party
}

fn refused(status: StatusCode, doc: &Value) {
    assert_ne!(status, StatusCode::OK, "{doc}");
    assert_eq!(error_code(doc), Some("permissionDenied"), "{doc}");
}

#[tokio::test]
async fn vti_acl_037_an_application_entry_reads_nothing_members_read() {
    let vtc = community().await;
    let subject = member(&vtc).await;
    let app = party_with_role(&vtc, VtcRole::Application, &[]).await;

    let (status, doc) = call(
        &vtc,
        &app,
        RELATIONSHIPS_LIST,
        json!({ "did": subject.did }),
    )
    .await;
    refused(status, &doc);
    let (status, doc) = call(&vtc, &app, BADGES_LIST, json!({})).await;
    refused(status, &doc);

    // The same reads by an active member are answered.
    let reader = member(&vtc).await;
    let (status, doc) = call(
        &vtc,
        &reader,
        RELATIONSHIPS_LIST,
        json!({ "did": subject.did }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
}

#[tokio::test]
async fn a_suspended_administrator_reads_no_relationships_groups_or_badges() {
    let vtc = community().await;
    let subject = member(&vtc).await;
    let suspended = admin(&vtc).await;

    // Before the suspension, each read is answered.
    let (status, doc) = call(
        &vtc,
        &suspended,
        RELATIONSHIPS_LIST,
        json!({ "did": subject.did }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let (status, doc) = call(&vtc, &suspended, GROUPS_LIST, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    suspend(&vtc, &suspended.did).await;

    let (status, doc) = call(
        &vtc,
        &suspended,
        RELATIONSHIPS_LIST,
        json!({ "did": subject.did }),
    )
    .await;
    refused(status, &doc);
    let (status, doc) = call(&vtc, &suspended, GROUPS_LIST, json!({})).await;
    refused(status, &doc);
    let (status, doc) = call(&vtc, &suspended, BADGES_LIST, json!({})).await;
    refused(status, &doc);
}

#[tokio::test]
async fn a_suspended_member_reads_no_badges() {
    let vtc = community().await;
    let m = member(&vtc).await;
    suspend(&vtc, &m.did).await;
    let (status, doc) = call(&vtc, &m, BADGES_LIST, json!({})).await;
    refused(status, &doc);
}

#[tokio::test]
async fn a_join_query_takes_the_join_decide_capability_not_any_administrative_role() {
    let vtc = community().await;
    // An auditor is an administrator, holding only `vtc.audit.read`.
    let auditor = with_admin_role(&vtc, AdminRole::Auditor).await;
    let (status, doc) = call(
        &vtc,
        &auditor,
        JOIN_QUERY,
        json!({ "holderDid": "did:key:zHolder", "criterionId": "membership" }),
    )
    .await;
    refused(status, &doc);

    // One holding `vtc.join.decide` passes the gate; this community has no
    // such criterion, which is the next thing it is told.
    let decider = admin(&vtc).await;
    let (_, doc) = call(
        &vtc,
        &decider,
        JOIN_QUERY,
        json!({ "holderDid": "did:key:zHolder", "criterionId": "membership" }),
    )
    .await;
    assert_ne!(error_code(&doc), Some("permissionDenied"), "{doc}");
}
