//! **Single-administrator mode on the git side** (VTI-APV-022 applied to fixed
//! rule 7 of `git-ns/right/grant/0.3`, `super::super::single_admin`).
//!
//! With `[acl] single_admin_mode` on, an elevated self-grant is waived — on the
//! requester's operation-bound step-up, with a `Critical` `SingleAdminMode {
//! selfGrantWaived }` row written before the write, and the record and the
//! answer marked — through every task rule 7 covers, whether or not anyone
//! else could make the grant (VTI-APV-022: every administrator is one person).
//! With the mode off it is refused `git-ns:selfGrantNotAllowed` as before.

use serde::Serialize;
use serde::de::DeserializeOwned;
use trust_tasks_rs::specs::git_ns::drift::resolve::v0_3 as resolve3;
use trust_tasks_rs::specs::git_ns::repo::{adopt::v0_1 as adopt, create::v0_3 as create};
use trust_tasks_rs::specs::git_ns::right::grant::v0_3 as grant3;
use vti_common::audit::{AuditEvent, AuditSeverity, SingleAdminModeData};

use super::*;
use crate::git_ns::model::Right;

const GADGETS: &str = "github.com/acme/gadgets";

async fn single_admin_mode(f: &Fixture, on: bool) {
    f.vtc.state.config.write().await.acl.single_admin_mode = on;
}

/// Record `who`'s passkey gesture for `payload` as `P` — the payload as the
/// VTC reads it back, which is what the step-up is bound to.
async fn gesture<P: DeserializeOwned + Serialize + trust_tasks_rs::Payload>(
    f: &Fixture,
    who: &Party,
    payload: &Value,
) {
    let read: P = serde_json::from_value(payload.clone()).unwrap();
    crate::acl::bound_step_up::record_mark_for_test(
        &f.vtc.state,
        &who.did,
        P::TYPE_URI,
        &serde_json::to_value(&read).unwrap(),
    )
    .await
    .unwrap();
}

/// Every `SingleAdminMode { selfGrantWaived }` row, each asserted `Critical`.
async fn waived_rows(f: &Fixture) -> Vec<SingleAdminModeData> {
    audit_events(f)
        .await
        .into_iter()
        .filter_map(|(_, e)| match e {
            AuditEvent::SingleAdminMode(d) if d.event == "selfGrantWaived" => {
                assert_eq!(
                    AuditEvent::SingleAdminMode(d.clone()).severity(),
                    AuditSeverity::Critical
                );
                Some(d)
            }
            _ => None,
        })
        .collect()
}

/// Every audit event, oldest first, with its timestamp.
async fn audit_events(f: &Fixture) -> Vec<(chrono::DateTime<chrono::Utc>, AuditEvent)> {
    let mut out: Vec<_> = f
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v).ok())
        .map(|env| (env.timestamp, env.event))
        .collect();
    out.sort_by_key(|(t, _)| *t);
    out
}

fn own_row(
    snap: &Snapshot,
    resource: &str,
    subject: &str,
) -> Option<super::super::model::RightRow> {
    let repo = snap.repo_at(resource)?;
    snap.rows(&Scope::Repo(repo.id.clone()))
        .iter()
        .find(|r| r.subject == subject && r.right == Right::RepoOwn)
        .cloned()
}

fn waived_ext(body: &Value) -> &Value {
    &body["ext"]["org.openvtc"]["selfGrantWaived"]
}

/// The single administrator adopts a repository naming themselves its owner —
/// `cnm git adopt github.com/<login>/<repo> --owner <their own DID>`.
#[tokio::test]
async fn vti_apv_022_a_sole_administrator_adopts_for_themselves_on_step_up_audited_first() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    bind_manual(&f).await;
    let p = json!({ "resource": GADGETS, "owners": [f.admin.did] });

    // No gesture: refused, nothing recorded, nothing audited.
    let out = send(&f.vtc.state, &f.admin, "repo/adopt", p.clone()).await;
    assert_eq!(code(&out), "permissionDenied", "{}", message(&out));
    assert!(message(&out).contains("step-up"), "{}", message(&out));
    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    assert!(snap.repo_at(GADGETS).is_none());
    assert!(waived_rows(&f).await.is_empty());

    // With the gesture: recorded, marked, and the answer says so.
    gesture::<adopt::Payload>(&f, &f.admin, &p).await;
    let body = ok(&send(&f.vtc.state, &f.admin, "repo/adopt", p.clone()).await);
    assert_eq!(body["repo"]["owners"], json!([f.admin.did]));
    let w = waived_ext(&body);
    assert_eq!(w["mode"], "singleAdministrator");
    assert_eq!(w["right"], "git.repo.own");
    assert_eq!(w["resource"], GADGETS);

    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    let row = own_row(&snap, GADGETS, &f.admin.did).unwrap();
    let mark = row.single_admin.as_ref().expect("the record is marked");
    assert!(mark.task.ends_with("/git-ns/repo/adopt/0.1"));
    assert!(row.break_glass.is_none(), "a waiver is no break-glass");

    // The Critical row names the rule, the task, the action, the right and
    // the resource — and was written before the grant it authorized.
    let rows = waived_rows(&f).await;
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        r.requirement.as_deref(),
        Some("git-ns/right/grant/0.3#rule-7")
    );
    assert_eq!(r.kind.as_deref(), Some("repo.adopt"));
    assert_eq!(r.right.as_deref(), Some("git.repo.own"));
    assert_eq!(r.resource.as_deref(), Some(GADGETS));
    assert!(
        r.task
            .as_deref()
            .unwrap()
            .ends_with("/git-ns/repo/adopt/0.1")
    );
    assert!(r.digest.is_some());
    let events = audit_events(&f).await;
    let waived_at = events
        .iter()
        .position(
            |(_, e)| matches!(e, AuditEvent::SingleAdminMode(d) if d.event == "selfGrantWaived"),
        )
        .unwrap();
    let granted_at = events
        .iter()
        .position(|(_, e)| {
            matches!(e, AuditEvent::GitNsOperation(d)
                if d.action == "gitNs.right.granted" && d.resource.as_deref() == Some(GADGETS))
        })
        .unwrap();
    assert!(waived_at < granted_at, "audited before the write");
    assert!(events.iter().any(|(_, e)| matches!(e,
        AuditEvent::GitNsOperation(d) if d.action == "gitNs.right.selfGrantWaived"
            && d.detail.as_deref() == Some("repo.adopt"))));

    // The administrator's view lists it under the same marker.
    let view = ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "view",
        "0.5",
        json!({ "scope": "administrator" }),
    )
    .await);
    let listed = view["ext"]["org.openvtc"]["selfGrantWaived"]
        .as_array()
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["subject"], json!(f.admin.did));
    assert_eq!(listed[0]["resource"], GADGETS);

    // And the ACL entry's resource grant carries it.
    let entry = crate::acl::get_acl_entry(&f.vtc.state.acl_ks, &f.admin.did)
        .await
        .unwrap()
        .unwrap();
    assert!(
        entry
            .resource_grants
            .iter()
            .any(|g| g.single_admin.is_some())
    );
}

/// VTI-APV-022: a second community administrator's entry does not bring
/// separation of duties back — the mode waives it whether or not other
/// administrators' entries exist (one person may hold one per device). The
/// self-adopt runs on the gesture, audited at `Critical`.
#[tokio::test]
async fn vti_apv_022_another_administrators_entry_does_not_restore_separation_of_duties() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    bind_manual(&f).await;
    let p = json!({ "resource": GADGETS, "owners": [f.admin.did] });
    gesture::<adopt::Payload>(&f, &f.admin, &p).await;
    let body = ok(&send(&f.vtc.state, &f.admin, "repo/adopt", p).await);
    assert_eq!(body["repo"]["owners"], json!([f.admin.did]));
    assert_eq!(waived_rows(&f).await.len(), 1);
}

/// VTI-APV-022: nor does a member whose git rights could make the grant —
/// Bob owns `widgets`, and the administrator's self-grant there is waived all
/// the same.
#[tokio::test]
async fn vti_apv_022_an_owner_who_could_grant_does_not_restore_separation_of_duties() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    active_repo(&f).await;
    let p = json!({ "subject": f.admin.did, "right": "git.repo.own", "resource": "github.com/acme/widgets" });
    gesture::<grant3::Payload>(&f, &f.admin, &p).await;
    let out = send(&f.vtc.state, &f.admin, "right/grant", p).await;
    ok(&out);
    assert_eq!(waived_rows(&f).await.len(), 1);
}

/// With the mode off nothing changes, even with a gesture recorded.
#[tokio::test]
async fn with_single_admin_mode_off_a_self_adopt_is_refused_as_before() {
    let f = fixture().await;
    bind_manual(&f).await;
    let p = json!({ "resource": GADGETS, "owners": [f.admin.did] });
    gesture::<adopt::Payload>(&f, &f.admin, &p).await;
    let out = send(&f.vtc.state, &f.admin, "repo/adopt", p).await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
    assert!(message(&out).contains("break-glass"));
    assert!(waived_rows(&f).await.is_empty());
}

/// VTI-APV-022 item 4: a waiver that cannot be audited is refused, and
/// nothing is recorded.
#[tokio::test]
async fn vti_apv_022_a_waiver_that_cannot_be_audited_is_refused() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    bind_manual(&f).await;
    let p = json!({ "resource": GADGETS, "owners": [f.admin.did] });
    gesture::<adopt::Payload>(&f, &f.admin, &p).await;
    // Take the audit key away: every audit write now fails.
    f.vtc
        .state
        .audit_key_ks
        .remove(b"audit_key:active".to_vec())
        .await
        .unwrap();
    let out = send(&f.vtc.state, &f.admin, "repo/adopt", p).await;
    assert!(
        !out.status.is_success(),
        "{}",
        String::from_utf8_lossy(&out.body)
    );
    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    assert!(snap.repo_at(GADGETS).is_none(), "nothing recorded");
    assert!(waived_rows(&f).await.is_empty());
    // It got as far as the waiver: the gesture was spent there, so the refusal
    // is the audit's and not an earlier check's.
    let read: adopt::Payload = serde_json::from_value(p_again(&f)).unwrap();
    assert!(
        !crate::acl::bound_step_up::has_mark(
            &f.vtc.state,
            &f.admin.did,
            <adopt::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            &serde_json::to_value(&read).unwrap(),
        )
        .await
        .unwrap()
    );
}

fn p_again(f: &Fixture) -> Value {
    json!({ "resource": GADGETS, "owners": [f.admin.did] })
}

/// Unlike an unratified break-glass record, a waived one counts toward the
/// last-owner invariant (fixed rule 3): it is how a one-administrator
/// community holds its rights.
#[tokio::test]
async fn a_waived_record_counts_for_the_last_owner_invariant() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    bind_manual(&f).await;
    let p = json!({ "resource": GADGETS, "owners": [f.admin.did] });
    gesture::<adopt::Payload>(&f, &f.admin, &p).await;
    ok(&send(&f.vtc.state, &f.admin, "repo/adopt", p).await);

    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    let row = own_row(&snap, GADGETS, &f.admin.did).unwrap();
    assert!(row.counts_for_invariants(super::super::ops::now()));
    let repo_id = snap.repo_at(GADGETS).unwrap().id.clone();
    assert!(super::super::rules::is_last_owner(
        &snap,
        &repo_id,
        &f.admin.did,
        super::super::ops::now()
    ));
    let out = send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.admin.did, "right": "git.repo.own", "resource": GADGETS }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:lastOwner");
}

/// `git-ns/right/grant`: the sole administrator grants themselves
/// `git.repo.create` on the namespace.
#[tokio::test]
async fn vti_apv_022_a_self_grant_is_waived_for_the_sole_administrator() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    bind_manual(&f).await;
    let p = json!({ "subject": f.admin.did, "right": "git.repo.create", "resource": "github.com/acme" });
    let out = send(&f.vtc.state, &f.admin, "right/grant", p.clone()).await;
    assert_eq!(code(&out), "permissionDenied");
    gesture::<grant3::Payload>(&f, &f.admin, &p).await;
    let body = ok(&send(&f.vtc.state, &f.admin, "right/grant", p).await);
    assert_eq!(body["right"]["right"], "git.repo.create");
    assert_eq!(waived_ext(&body)["right"], "git.repo.create");
    let rows = waived_rows(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind.as_deref(), Some("right.grant"));
    assert_eq!(rows[0].resource.as_deref(), Some("github.com/acme"));
}

/// `git-ns/repo/create`: an implied `repo.create` (from `git.ns.admin`)
/// naming its holder owner — by default — is waived the same way.
#[tokio::test]
async fn vti_apv_022_create_with_the_sole_administrator_as_owner_is_waived() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    let ns = bind_manual(&f).await;
    let p = json!({ "namespace": ns, "name": "gadgets", "visibility": "public" });
    let out = send(&f.vtc.state, &f.admin, "repo/create", p.clone()).await;
    assert_eq!(code(&out), "permissionDenied");
    gesture::<create::Payload>(&f, &f.admin, &p).await;
    let body = ok(&send(&f.vtc.state, &f.admin, "repo/create", p).await);
    assert_eq!(body["repo"]["owners"], json!([f.admin.did]));
    assert_eq!(waived_ext(&body)["resource"], GADGETS);
    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    assert!(
        own_row(&snap, GADGETS, &f.admin.did)
            .unwrap()
            .single_admin
            .is_some()
    );
    assert_eq!(
        waived_rows(&f).await[0].kind.as_deref(),
        Some("repo.create")
    );
}

/// `git-ns/namespace/reseat`: the community's only administrator reseats a
/// headless namespace to themselves.
#[tokio::test]
async fn vti_apv_022_reseat_to_oneself_is_waived_for_the_sole_administrator() {
    let f = fixture().await;
    single_admin_mode(&f, true).await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    let ns = bind_manual(&f).await;
    // The binder leaves: the namespace is headless, and Dana is the only
    // administrator.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.admin.did)
        .await
        .unwrap();
    let p = json!({ "namespace": ns, "subject": dana.did, "statement": "Alice left; Carol owns most repositories" });
    let out = reseat(&f, &dana, &ns, &dana.did).await;
    assert_eq!(code(&out), "permissionDenied", "{}", message(&out));
    gesture::<reseat3::Payload>(&f, &dana, &p).await;
    let body = ok(&reseat(&f, &dana, &ns, &dana.did).await);
    assert_eq!(body["right"]["subject"], json!(dana.did));
    assert_eq!(waived_ext(&body)["right"], "git.ns.admin");
    assert_eq!(
        waived_rows(&f).await[0].kind.as_deref(),
        Some("namespace.reseat")
    );
    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    let admin_row = snap
        .rows(&Scope::Namespace(ns.clone()))
        .iter()
        .find(|r| r.subject == dana.did && r.right == Right::NsAdmin)
        .cloned()
        .unwrap();
    assert!(admin_row.single_admin.is_some());
    assert!(super::super::rules::is_last_admin(
        &snap,
        &ns,
        &dana.did,
        super::super::ops::now()
    ));
}

/// `git-ns/drift/resolve` adopt: the sole administrator adopts their own forge
/// `admin` role as `git.repo.own`; the step-up is bound to the drift document
/// they signed.
#[tokio::test]
async fn vti_apv_022_a_drift_adoption_for_oneself_is_waived_for_the_sole_administrator() {
    let (f, ns) = drift_fixture(json!([])).await;
    single_admin_mode(&f, true).await;
    // Bob, widgets' owner, leaves: nobody but the administrator could make
    // the grant now.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.bob.did)
        .await
        .unwrap();
    link_account(&f, &ns, &f.admin, "5550077", "admin-a").await;
    let acct = json!({ "forge": "github.com", "id": "5550077", "login": "admin-a" });
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": acct.clone(), "observed": "admin" }]),
    )
    .await;
    let sel = json!({ "type": "roleAdded", "account": acct, "observed": "admin" });
    let out = resolve_naming(&f, &f.admin, sel.clone(), "adopt", Some(&f.admin.did)).await;
    assert_eq!(code(&out), "permissionDenied", "{}", message(&out));
    let p = json!({ "resource": RES, "drift": sel.clone(), "action": "adopt", "reason": "decided", "subject": f.admin.did });
    gesture::<resolve3::Payload>(&f, &f.admin, &p).await;
    let body = ok(&resolve_naming(&f, &f.admin, sel, "adopt", Some(&f.admin.did)).await);
    assert_eq!(body["right"]["right"], "git.repo.own");
    assert_eq!(body["right"]["subject"], json!(f.admin.did));
    assert_eq!(waived_ext(&body)["right"], "git.repo.own");
    let rows = waived_rows(&f).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind.as_deref(), Some("drift.adopt"));
    assert!(
        rows[0]
            .task
            .as_deref()
            .unwrap()
            .ends_with("/git-ns/drift/resolve/0.3")
    );
}
