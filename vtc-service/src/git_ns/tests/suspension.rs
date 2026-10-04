//! A subject suspended pending a cooling-off reduction
//! (`vtc-action-list.md` §8.2, VTI-APV-019) is projected as holding nothing:
//! its Trust Registry records — the implied `git.commit.sign` among them —
//! are withdrawn and its forge roles leave every `desiredRoles`, while every
//! right it holds stays recorded; a cancelled cooling-off republishes them
//! from the stored rights, and a landed removal withdraws nothing twice.
//!
//! The suspension marker is what the action list writes
//! ([`crate::acl::storage::put_suspension`]) and the only input the
//! projection reads, so these tests set and lift it directly and drive the
//! projector's own pass. `tests/it/cooling_off_suspension.rs` drives a real
//! cooling-off end to end.

use std::collections::BTreeMap;

use super::super::bridge::JobKind;
use super::super::projection::{ProjectionView, Projector};
use super::*;
use crate::registry::TrustRegistryClient;

const ACTION: &str = "act-suspend-carol";

/// `widgets` in a bridge namespace, owned by Bob (forge id 100); Carol
/// maintains it, and Bob's and Carol's GitHub accounts are linked.
async fn suspension_fixture() -> (Fixture, String) {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, RES, "100").await;
    link_account(&f, &ns, &f.bob, "9120045", "bob-builds").await;
    link_account(&f, &ns, &f.carol, "5550001", "carol-c").await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.repo.maintain", RES).await);
    (f, ns)
}

fn projector(f: &Fixture, registry: &MockRegistryClient) -> Projector {
    let client: Arc<dyn TrustRegistryClient> = Arc::new(registry.clone());
    Projector::new(
        f.vtc.state.clone(),
        Some((client, TEST_VTC_DID.to_string())),
        Duration::from_secs(1),
    )
}

async fn suspend(f: &Fixture, who: &Party) {
    crate::acl::storage::put_suspension(
        &f.vtc.state.acl_ks,
        &who.did,
        &crate::acl::Suspension {
            action_id: ACTION.into(),
            lands_at: 4_102_444_800,
            requester: f.admin.did.clone(),
        },
    )
    .await
    .unwrap();
}

async fn lift(f: &Fixture, who: &Party) {
    crate::acl::storage::remove_suspension(&f.vtc.state.acl_ks, &who.did)
        .await
        .unwrap();
}

/// Every registry record held for `did`.
fn records_of(records: &BTreeMap<String, Value>, did: &str) -> BTreeMap<String, Value> {
    records
        .iter()
        .filter(|(k, _)| k.starts_with(&format!("{did}|")))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The `desiredRoles` of the last `projectRoles` job the bridge received for
/// `widgets`.
fn last_sent_roles(f: &Fixture) -> Vec<Value> {
    f.bridge
        .jobs
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(_, p)| p["kind"] == "projectRoles" && p["repo"] == RES)
        .map(|(_, p)| p["desiredRoles"].as_array().cloned().unwrap_or_default())
        .expect("a projectRoles job was sent for widgets")
}

fn sent_jobs(f: &Fixture) -> usize {
    f.bridge
        .jobs
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, p)| p["kind"] == "projectRoles" && p["repo"] == RES)
        .count()
}

fn names_account(roles: &[Value], id: &str) -> bool {
    roles
        .iter()
        .any(|r| r.pointer("/account/id").and_then(Value::as_str) == Some(id))
}

/// Carol's stored rights, from the records write paths read.
async fn stored_rows_of(f: &Fixture, did: &str) -> Vec<super::super::model::RightRow> {
    Snapshot::load(&f.vtc.state.git_ns)
        .await
        .unwrap()
        .rights
        .values()
        .flat_map(|s| s.rows.iter())
        .filter(|r| r.subject == did)
        .cloned()
        .collect()
}

async fn grants_of(f: &Fixture, did: &str) -> Vec<crate::acl::resource_grant::ResourceGrant> {
    crate::acl::get_acl_entry(&f.vtc.state.acl_ks, did)
        .await
        .unwrap()
        .expect("the entry is kept")
        .resource_grants
}

/// The details of every git-ns audit row with `action`.
async fn audited(f: &Fixture, action: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (_, v) in f
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
    {
        let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v) else {
            continue;
        };
        if let vti_common::audit::AuditEvent::GitNsOperation(d) = env.event
            && d.action == action
        {
            let detail = d
                .detail
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(Value::Null);
            out.push(detail);
        }
    }
    out
}

/// Suspension withdraws every published tuple of the subject and its forge
/// role, and changes nothing recorded: the rows, the entry's grants.
#[tokio::test]
async fn suspension_withdraws_projected_git_rights_without_deleting_them() {
    let (f, _ns) = suspension_fixture().await;
    let registry = MockRegistryClient::new();
    projector(&f, &registry).run_once().await;
    let carol_before = records_of(&registry.trust_records().await, &f.carol.did);
    assert!(carol_before.contains_key(&projection::tuple_key(
        &f.carol.did,
        "git.repo.maintain",
        RES
    )));
    let rows_before = stored_rows_of(&f, &f.carol.did).await;
    let grants_before = grants_of(&f, &f.carol.did).await;
    assert!(!rows_before.is_empty());

    suspend(&f, &f.carol).await;
    projector(&f, &registry).run_once().await;

    let records = registry.trust_records().await;
    assert!(
        records_of(&records, &f.carol.did).is_empty(),
        "nothing of Carol's is published: {records:?}"
    );
    // Everyone else's stays.
    assert!(records.contains_key(&projection::tuple_key(&f.bob.did, "git.repo.own", RES)));
    // Nothing recorded moved.
    assert_eq!(stored_rows_of(&f, &f.carol.did).await, rows_before);
    assert_eq!(grants_of(&f, &f.carol.did).await, grants_before);
    // The forge loses her role; Bob keeps his.
    let roles = last_sent_roles(&f);
    assert!(!names_account(&roles, "5550001"), "{roles:?}");
    assert!(names_account(&roles, "9120045"), "{roles:?}");
    // Audited once, naming the action.
    let rows = audited(&f, "gitNs.projection.withheld").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["actionId"], ACTION);
    assert_eq!(rows[0]["rights"], 1);
    // A further pass audits nothing new.
    projector(&f, &registry).run_once().await;
    assert_eq!(audited(&f, "gitNs.projection.withheld").await.len(), 1);
}

/// The verifier asks only about `git.commit.sign`: the subject's explicit
/// commit right and every one its rights imply are withdrawn, and nobody
/// else's.
#[tokio::test]
async fn suspended_subjects_commit_signing_right_is_not_published() {
    let (f, _ns) = suspension_fixture().await;
    // An explicit commit right on the namespace too.
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.commit.sign",
        "github.com/acme",
    )
    .await);
    let registry = MockRegistryClient::new();
    projector(&f, &registry).run_once().await;
    let records = registry.trust_records().await;
    let commit_on = |r: &str| projection::tuple_key(&f.carol.did, "git.commit.sign", r);
    assert!(records.contains_key(&commit_on(RES)), "implied by maintain");
    assert!(
        records.contains_key(&commit_on("github.com/acme")),
        "explicit"
    );

    suspend(&f, &f.carol).await;
    projector(&f, &registry).run_once().await;
    let records = registry.trust_records().await;
    assert!(!records.contains_key(&commit_on(RES)));
    assert!(!records.contains_key(&commit_on("github.com/acme")));
    // Bob's own implied commit right is untouched.
    assert!(records.contains_key(&projection::tuple_key(&f.bob.did, "git.commit.sign", RES)));
    // And the desired set, as the console reads it, agrees.
    let view = ProjectionView::load(&f.vtc.state).await.unwrap();
    assert!(view.withheld().contains_key(&f.carol.did));
    let want = projection::desired_all(&f.vtc.state, &view, super::super::ops::now())
        .await
        .unwrap();
    assert!(want.keys().all(|k| !k.starts_with(&f.carol.did)));
}

/// Cancelling the cooling-off (the marker lifted, the removal never landing)
/// republishes, from the stored rights, exactly what was withdrawn — and
/// the forge gets the same roles back.
#[tokio::test]
async fn cancelled_cooling_off_republishes_exactly_what_was_withdrawn() {
    let (f, _ns) = suspension_fixture().await;
    let registry = MockRegistryClient::new();
    projector(&f, &registry).run_once().await;
    let before = registry.trust_records().await;
    let roles_before = last_sent_roles(&f);

    suspend(&f, &f.carol).await;
    projector(&f, &registry).run_once().await;
    assert!(records_of(&registry.trust_records().await, &f.carol.did).is_empty());

    lift(&f, &f.carol).await;
    projector(&f, &registry).run_once().await;
    assert_eq!(registry.trust_records().await, before);
    assert_eq!(last_sent_roles(&f), roles_before);
    let rows = audited(&f, "gitNs.projection.restored").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["actionId"], ACTION);
    assert!(audited(&f, "gitNs.projection.released").await.is_empty());
}

/// The bridge receives a `projectRoles` job without the subject's account on
/// suspension, and one with it, at the right it held, on cancellation — each
/// through the job queue and its dispatch, not an in-line send.
#[tokio::test]
async fn bridge_receives_role_withdrawal_on_suspension_and_reprojection_on_cancel() {
    let (f, _ns) = suspension_fixture().await;
    super::super::bridge::project_roles(&f.vtc.state, false)
        .await
        .unwrap();
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    let carol_role = last_sent_roles(&f)
        .into_iter()
        .find(|r| r.pointer("/account/id").and_then(Value::as_str) == Some("5550001"))
        .expect("Carol's account is projected");
    assert_eq!(carol_role["right"], "git.repo.maintain");
    let sent = sent_jobs(&f);

    suspend(&f, &f.carol).await;
    super::super::bridge::project_roles(&f.vtc.state, false)
        .await
        .unwrap();
    // Queued first — a job the bridge has not acknowledged is retried.
    let queued = super::super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|j| j.kind == JobKind::ProjectRoles && j.payload["repo"] == RES)
        .max_by_key(|j| j.created_at)
        .unwrap();
    assert!(!names_account(
        queued.payload["desiredRoles"].as_array().unwrap(),
        "5550001"
    ));
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    assert_eq!(sent_jobs(&f), sent + 1, "the withdrawal job went out");
    let withdrawn = last_sent_roles(&f);
    assert!(!names_account(&withdrawn, "5550001"), "{withdrawn:?}");
    assert!(names_account(&withdrawn, "9120045"));

    lift(&f, &f.carol).await;
    super::super::bridge::project_roles(&f.vtc.state, false)
        .await
        .unwrap();
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    assert_eq!(sent_jobs(&f), sent + 2, "the re-projection job went out");
    let back = last_sent_roles(&f);
    assert!(back.contains(&carol_role), "{back:?}");
}

/// A removal that lands after a suspension takes the rights away once: the
/// tuples already withdrawn are not deleted again, no role job follows, and
/// the end of the suspension is recorded as `released`, not `restored`.
#[tokio::test]
async fn landing_after_suspension_removes_rights_once() {
    let (f, _ns) = suspension_fixture().await;
    let registry = MockRegistryClient::new();
    let mut backoff = Backoff::default();
    projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();

    suspend(&f, &f.carol).await;
    projector(&f, &registry).run_once().await;
    assert!(records_of(&registry.trust_records().await, &f.carol.did).is_empty());
    let jobs = sent_jobs(&f);

    // It lands as the action list lands it: the effect (the entry goes,
    // its grants with it) while the action is still open, then the marker.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.carol.did)
        .await
        .unwrap();
    // A pass between the effect and the lift republishes nothing.
    let mid = projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    assert_eq!((mid.put, mid.deleted, mid.failed), (0, 0, 0), "{mid:?}");
    lift(&f, &f.carol).await;
    let after = projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    assert_eq!(
        (after.put, after.deleted, after.failed),
        (0, 0, 0),
        "nothing withdrawn twice, nothing republished: {after:?}"
    );
    projector(&f, &registry).run_once().await;
    assert!(records_of(&registry.trust_records().await, &f.carol.did).is_empty());
    assert_eq!(sent_jobs(&f), jobs, "her role was already withdrawn");
    assert!(stored_rows_of(&f, &f.carol.did).await.is_empty());
    assert_eq!(audited(&f, "gitNs.projection.released").await.len(), 1);
    assert!(audited(&f, "gitNs.projection.restored").await.is_empty());
}

/// R2.1: the marker is the only state. A process that dies after writing
/// it, before any withdrawal — or after lifting it, before any republish —
/// leaves a projection the next process's first pass converges.
#[tokio::test]
async fn reconcile_converges_projection_after_crash_between_marker_and_withdraw() {
    let (f, _ns) = suspension_fixture().await;
    let registry = MockRegistryClient::new();
    projector(&f, &registry).run_once().await;
    let before = registry.trust_records().await;

    // Marker written; the process dies before its projector runs. A
    // withdrawal the registry refuses meanwhile is retried too.
    suspend(&f, &f.carol).await;
    registry
        .fail_next_trust_record(crate::registry::RegistryError::Transient(
            "registry down".into(),
        ))
        .await;
    let mut restarted = projector(&f, &registry);
    restarted.run_once().await;
    let mut again = projector(&f, &registry);
    again.run_once().await;
    assert!(records_of(&registry.trust_records().await, &f.carol.did).is_empty());
    assert!(!names_account(&last_sent_roles(&f), "5550001"));

    // Marker lifted; the process dies before republishing.
    lift(&f, &f.carol).await;
    projector(&f, &registry).run_once().await;
    assert_eq!(registry.trust_records().await, before);
    assert!(names_account(&last_sent_roles(&f), "5550001"));
}

/// No write path persists the projection view: write paths that run while
/// the subject is suspended — a grant on the same repository, the lifecycle
/// sweep, role projection's digest write — leave the subject's rights
/// recorded exactly as they were.
#[tokio::test]
async fn write_paths_never_persist_the_projection_view() {
    let (f, _ns) = suspension_fixture().await;
    let rows_before = stored_rows_of(&f, &f.carol.did).await;
    let grants_before = grants_of(&f, &f.carol.did).await;
    suspend(&f, &f.carol).await;
    let registry = MockRegistryClient::new();
    projector(&f, &registry).run_once().await;

    // `put_rights` rewrites the whole scope Carol holds a row on.
    ok(&grant(&f, &f.bob, &f.admin.did, "git.commit.sign", RES).await);
    super::super::lifecycle::sweep(&f.vtc.state).await.unwrap();
    super::super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    projector(&f, &registry).run_once().await;

    assert_eq!(stored_rows_of(&f, &f.carol.did).await, rows_before);
    assert_eq!(grants_of(&f, &f.carol.did).await, grants_before);
    // The view itself withholds her, and the records do not.
    let view = ProjectionView::load(&f.vtc.state).await.unwrap();
    let repo_id = Snapshot::load(&f.vtc.state.git_ns)
        .await
        .unwrap()
        .repo_at(RES)
        .unwrap()
        .id
        .clone();
    assert!(
        view.rows(&Scope::Repo(repo_id))
            .iter()
            .all(|r| r.subject != f.carol.did)
    );
}
