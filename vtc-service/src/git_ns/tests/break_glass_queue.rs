//! Break-glass ratification as an action-list queue item
//! (`docs/05-design-notes/vtc-action-list.md` §8.2, *Existing queues*): an
//! unratified break-glass raises an item for the other administrators of its
//! namespace, decided by Ratify (`git-ns/right/ratify`) or Revoke
//! (`git-ns/right/revoke`), never lapsing into acceptance, and closed however
//! the break-glass ends.

use super::*;
use crate::admin_actions::queues::{decide_as, item, items_of_kind};
use crate::admin_actions::summary::{BREAK_GLASS_REVIEW_URI, KIND_BREAK_GLASS_REVIEW};
use crate::admin_actions::{ActionRecord, Category, ClosedReason, Decided, DecisionError, Status};

const WIDGETS: &str = "github.com/acme/widgets";

/// Carol breaks the glass on widgets; the one ratification item it raised.
async fn carol_breaks_glass(f: &Fixture) -> (Value, ActionRecord) {
    let body = ok(&break_glass(f, &f.carol, "git.repo.own", WIDGETS).await);
    let at = body["right"]["breakGlass"]["at"].clone();
    let items = items_of_kind(&f.vtc.state, KIND_BREAK_GLASS_REVIEW).await;
    assert_eq!(items.len(), 1, "one ratification item per break-glass");
    (at, items.into_iter().next().unwrap())
}

fn row_of(snap: &Snapshot, subject: &str) -> Option<super::super::model::RightRow> {
    let scope = Scope::Repo(snap.repo_at(WIDGETS).unwrap().id.clone());
    snap.rows(&scope)
        .iter()
        .find(|r| r.subject == subject && r.break_glass.is_some())
        .cloned()
}

#[tokio::test]
async fn a_break_glass_raises_a_queue_item_for_the_other_administrators() {
    let f = carol_admin_fixture().await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    let (at, rec) = carol_breaks_glass(&f).await;

    assert_eq!(rec.category, Category::Queue);
    assert_eq!(rec.type_uri, BREAK_GLASS_REVIEW_URI);
    assert_eq!(rec.status, Status::Open);
    assert_eq!(rec.requester, f.carol.did, "shown to the one who broke it");
    assert_eq!(rec.payload["breakGlassAt"], at);
    assert_eq!(rec.payload["right"], json!("git.repo.own"));
    assert!(
        rec.payload["justification"]
            .as_str()
            .unwrap()
            .contains("CVE")
    );
    let mut deciders: Vec<&str> = rec.approvers.iter().map(|s| s.did.as_str()).collect();
    deciders.sort();
    let mut want = vec![f.admin.did.as_str(), dana.did.as_str()];
    want.sort();
    assert_eq!(
        deciders, want,
        "the administrators of the namespace — never its subject, never a plain owner"
    );

    // Every break-glass invariant still holds: the Critical row and the
    // notice were written, and the unratified record does not count toward
    // the last-owner invariant.
    let rows = bg_audit_rows(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event, "breakGlass");
    let out = send_ver(
        &f.vtc.state,
        &f.bob,
        "right/revoke",
        "0.3",
        json!({ "subject": f.bob.did, "right": "git.repo.own", "resource": WIDGETS }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:lastOwner");
}

#[tokio::test]
async fn it_never_lapses_into_acceptance_and_nobody_cancels_it() {
    let f = carol_admin_fixture().await;
    let (_, rec) = carol_breaks_glass(&f).await;
    assert!(
        rec.expires_at > crate::auth::session::now_epoch() + 365 * 24 * 3600,
        "a queue item does not expire"
    );
    // The one who broke the glass cannot withdraw the item asking about it.
    let refused = crate::admin_actions::cancel(&f.vtc.state, &f.carol.did, false, &rec.id, None)
        .await
        .unwrap_err();
    assert!(matches!(
        refused,
        crate::admin_actions::CancelError::NotRequester
    ));
    // Housekeeping leaves it open, and raises no second one.
    crate::admin_actions::sweep_once(&f.vtc.state)
        .await
        .unwrap();
    assert_eq!(item(&f.vtc.state, &rec.id).await.status, Status::Open);
    assert_eq!(
        items_of_kind(&f.vtc.state, KIND_BREAK_GLASS_REVIEW)
            .await
            .len(),
        1
    );
    // The subject never decides it.
    assert!(!rec.approvers.iter().any(|s| s.did == f.carol.did));
}

#[tokio::test]
async fn ratify_from_the_action_list_ratifies_it_as_git_ns_right_ratify_does() {
    let f = carol_admin_fixture().await;
    let (_, rec) = carol_breaks_glass(&f).await;

    let out = decide_as(
        &f.vtc.state,
        &f.admin.did,
        &rec.id,
        true,
        Some("confirmed by phone"),
    )
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

    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    let row = row_of(&snap, &f.carol.did).unwrap();
    assert_eq!(
        row.break_glass.unwrap().ratified_by.as_deref(),
        Some(f.admin.did.as_str())
    );
    let rows = bg_audit_rows(&f).await;
    let last = rows.last().unwrap();
    assert_eq!(last.event, "ratified");
    assert_eq!(last.statement.as_deref(), Some("confirmed by phone"));
    assert_eq!(
        vti_common::audit::AuditEvent::GitNsBreakGlass(last.clone()).severity(),
        vti_common::audit::AuditSeverity::Critical
    );

    let done = item(&f.vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Completed);
    assert_eq!(done.closed_reason, Some(ClosedReason::ThresholdMet));
    assert_eq!(done.closed_by.as_deref(), Some(f.admin.did.as_str()));
    assert_eq!(done.approvals.len(), 1);
}

#[tokio::test]
async fn revoke_from_the_action_list_takes_the_right_away() {
    let f = carol_admin_fixture().await;
    let (_, rec) = carol_breaks_glass(&f).await;

    let out = decide_as(
        &f.vtc.state,
        &f.admin.did,
        &rec.id,
        false,
        Some("not needed"),
    )
    .await
    .unwrap();
    assert!(matches!(out, Decided::Denied { .. }), "{out:?}");

    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    assert!(
        row_of(&snap, &f.carol.did).is_none(),
        "the break-glass right is gone"
    );
    assert_eq!(bg_audit_rows(&f).await.last().unwrap().event, "revoked");

    let done = item(&f.vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Declined);
    assert_eq!(done.closed_by.as_deref(), Some(f.admin.did.as_str()));
    assert_eq!(done.closed_message.as_deref(), Some("not needed"));
}

#[tokio::test]
async fn ratifying_through_git_ns_closes_the_item_naming_who_did() {
    let f = carol_admin_fixture().await;
    let (at, rec) = carol_breaks_glass(&f).await;
    ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "right/ratify",
        "0.1",
        json!({
            "subject": f.carol.did,
            "right": "git.repo.own",
            "resource": WIDGETS,
            "breakGlassAt": at,
        }),
    )
    .await);
    let done = item(&f.vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Completed);
    assert_eq!(done.closed_by.as_deref(), Some(f.admin.did.as_str()));
    // A decision now finds nothing open.
    assert!(matches!(
        decide_as(&f.vtc.state, &f.admin.did, &rec.id, true, None).await,
        Err(DecisionError::NoPending)
    ));
}

#[tokio::test]
async fn revoking_through_git_ns_closes_the_item_as_declined() {
    let f = carol_admin_fixture().await;
    let (_, rec) = carol_breaks_glass(&f).await;
    ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        "0.3",
        json!({ "subject": f.carol.did, "right": "git.repo.own", "resource": WIDGETS }),
    )
    .await);
    let done = item(&f.vtc.state, &rec.id).await;
    assert_eq!(done.status, Status::Declined);
    assert_eq!(done.closed_by.as_deref(), Some(f.admin.did.as_str()));
}

#[tokio::test]
async fn a_refused_ratification_leaves_the_item_open() {
    let f = carol_admin_fixture().await;
    let (_, rec) = carol_breaks_glass(&f).await;
    // The administrator loses the authority between being given the slot and
    // deciding: the decision is refused as not theirs, and the item waits.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.admin.did)
        .await
        .unwrap();
    assert!(matches!(
        decide_as(&f.vtc.state, &f.admin.did, &rec.id, true, None).await,
        Err(DecisionError::NotAnApprover)
    ));
    assert_eq!(item(&f.vtc.state, &rec.id).await.status, Status::Open);
}

#[tokio::test]
async fn the_sweeper_raises_an_item_a_break_glass_lost_and_slots_new_administrators() {
    let f = carol_admin_fixture().await;
    let (_, rec) = carol_breaks_glass(&f).await;
    // As if the process died between the break-glass and its item.
    f.vtc
        .state
        .admin_actions_ks
        .remove(format!("action:{}", rec.id))
        .await
        .unwrap();
    assert!(
        items_of_kind(&f.vtc.state, KIND_BREAK_GLASS_REVIEW)
            .await
            .is_empty()
    );
    let erin = Party::new();
    seed_acl(&f.vtc.state, &erin.did, VtcRole::Admin).await;
    crate::admin_actions::sweep_once(&f.vtc.state)
        .await
        .unwrap();
    let again = items_of_kind(&f.vtc.state, KIND_BREAK_GLASS_REVIEW).await;
    assert_eq!(again.len(), 1, "raised again, once");
    assert!(again[0].approvers.iter().any(|s| s.did == erin.did));

    // An administrator who appears after the item was raised is given a slot.
    let fred = Party::new();
    seed_acl(&f.vtc.state, &fred.did, VtcRole::Admin).await;
    crate::admin_actions::sweep_once(&f.vtc.state)
        .await
        .unwrap();
    let id = again[0].id.clone();
    assert!(
        item(&f.vtc.state, &id)
            .await
            .approvers
            .iter()
            .any(|s| s.did == fred.did)
    );
    let out = decide_as(&f.vtc.state, &fred.did, &id, true, None)
        .await
        .unwrap();
    assert!(matches!(
        out,
        Decided::Granted {
            completed: true,
            ..
        }
    ));
}
