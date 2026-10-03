//! Phase C3: git rights are capabilities on the ACL entry —
//! `docs/05-design-notes/vtc-admin-roles.md` §9, **VTI-VTC-020**,
//! **VTI-ACL-035 – 037**, **VTI-ACL-071**.

use super::*;
use crate::acl::resource_grant::{self as rg, RepoGrade};
use crate::acl::{Capability, ResourceQualifier, get_acl_entry};
use crate::git_ns::model::{Resource, Right, RightsSet};
use crate::git_ns::{lifecycle, migrate, ops, rules};

fn q(s: &str) -> ResourceQualifier {
    s.parse().unwrap()
}

async fn repo_id(f: &Fixture, res: &str) -> String {
    Snapshot::load(&f.vtc.state.git_ns)
        .await
        .unwrap()
        .repo_at(res)
        .unwrap()
        .id
        .clone()
}

async fn entry(f: &Fixture, did: &str) -> Option<VtcAclEntry> {
    get_acl_entry(&f.vtc.state.acl_ks, did).await.unwrap()
}

/// An external signer's commit right on `res`, granted by Bob, as a community
/// whose policy admits external signers would have it (the default refuses).
async fn seed_external(f: &Fixture, res: &str, did: &str) {
    let scope = Scope::Repo(repo_id(f, res).await);
    let mut set = store::get_rights(&f.vtc.state.git_ns, &scope)
        .await
        .unwrap();
    let mut row = ops::new_row(did, Right::CommitSign, &f.bob.did, false);
    row.granter_was_member = true;
    set.rows.push(row);
    store::put_rights(&f.vtc.state.git_ns, &scope, &set)
        .await
        .unwrap();
}

async fn git_review_actions(f: &Fixture) -> Vec<crate::admin_actions::ActionRecord> {
    crate::admin_actions::all(&f.vtc.state)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.payload.get("gitGrants").is_some())
        .collect()
}

/// VTI-VTC-020: the right a git-ns task grants is a capability on the
/// subject's own entry, qualified by repository id — and the entry's `can`
/// answers for it at that qualifier and nowhere else.
#[tokio::test]
async fn vti_vtc_020_a_grant_is_a_qualified_capability_on_the_holders_entry() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let id = repo_id(&f, &res).await;
    let at = q(&format!("git-repo:github.com/acme/{id}"));
    ok(&grant(&f, &f.bob, &f.carol.did, "git.repo.maintain", &res).await);

    let carol = entry(&f, &f.carol.did).await.unwrap();
    let g = carol
        .resource_grants
        .iter()
        .find(|g| g.resource == at)
        .expect("the grant is on Carol's entry");
    assert_eq!(g.capability, Capability::GitRepoManage);
    assert_eq!(g.grade, Some(RepoGrade::Maintain));
    assert_eq!(g.delegated_by, f.bob.did, "delegatedBy is the granter");
    // A maintainer signs commits there; it does not manage the repository,
    // and holds nothing on another.
    assert!(carol.can(Capability::GitCommitSign, Some(&at)));
    assert!(!carol.can(Capability::GitRepoManage, Some(&at)));
    assert!(!carol.can(
        Capability::GitCommitSign,
        Some(&q("git-repo:github.com/acme/repo_other"))
    ));

    // Bob owns it — a repository manager for that one repository, confined to
    // it; the namespace's admin holds `git.ns.admin` at the namespace.
    let bob = entry(&f, &f.bob.did).await.unwrap();
    assert!(bob.can(Capability::GitRepoManage, Some(&at)));
    assert!(!bob.can(
        Capability::GitRepoManage,
        Some(&q("git-ns:github.com/acme"))
    ));
    assert!(!bob.can(Capability::GitNsAdmin, Some(&q("git-ns:github.com/acme"))));
    let admin = entry(&f, &f.admin.did).await.unwrap();
    assert!(admin.resource_grants.iter().any(|g| {
        g.capability == Capability::GitNsAdmin && g.resource == q("git-ns:github.com/acme")
    }));

    // An ACL write by another administrator keeps the grants: they are not an
    // `acl/*` axis, and nothing but git-ns writes them.
    let mut rewritten = carol.clone();
    rewritten.label = Some("renamed".into());
    rewritten.resource_grants.clear();
    let planned = crate::routes::acl::plan_write(
        &f.vtc.state,
        &f.admin.did,
        rewritten,
        Some(carol.clone()),
        crate::routes::acl::PlanEvent::Updated,
        None,
    )
    .await
    .map_err(|_| ())
    .expect("a label change plans");
    crate::routes::acl::commit_grant(&f.vtc.state, &f.admin.did, planned)
        .await
        .unwrap();
    let after = entry(&f, &f.carol.did).await.unwrap();
    assert_eq!(after.label.as_deref(), Some("renamed"));
    assert_eq!(after.resource_grants, carol.resource_grants);
}

/// VTI-ACL-037: a grant confers nothing without a live entry — so a
/// non-member granted a non-elevated right gets an `application` entry, which
/// is never a membership, and loses it with its last grant.
#[tokio::test]
async fn vti_acl_037_a_non_member_holds_a_grant_on_an_application_entry() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    seed_external(&f, &res, &f.stranger.did).await;
    let app = entry(&f, &f.stranger.did)
        .await
        .expect("an entry for the grant to sit on");
    assert_eq!(app.role, VtcRole::Application);
    assert!(!app.is_administrator());
    assert!(
        crate::acl::auth_role_for(&app).is_err(),
        "an application entry never signs in"
    );
    assert!(
        !ops::standing(&f.vtc.state, &f.stranger.did)
            .await
            .unwrap()
            .member,
        "an application entry is not a membership"
    );
    // …so an elevated right is still refused to it (fixed rule 5).
    let elevated = grant(&f, &f.bob, &f.stranger.did, "git.repo.own", &res).await;
    assert_eq!(code(&elevated), "git-ns:membersOnly");

    ok(&send(
        &f.vtc.state,
        &f.bob,
        "right/revoke",
        json!({ "subject": f.stranger.did, "right": "git.commit.sign", "resource": res }),
    )
    .await);
    assert!(
        entry(&f, &f.stranger.did).await.is_none(),
        "the application entry goes with its last grant"
    );
}

/// Appendix F's open question, answered: the bridge has an entry — role
/// `application`, `git.commit.sign` qualified to the namespace it serves —
/// and is still authenticated as the namespace's recorded bridge.
#[tokio::test]
async fn the_bridge_holds_its_commit_right_on_an_application_entry() {
    let f = fixture().await;
    bind_bridge(&f).await;
    let bridge = entry(&f, &f.bridge_party.did)
        .await
        .expect("the bridge has an entry");
    assert_eq!(bridge.role, VtcRole::Application);
    assert!(bridge.can(
        Capability::GitCommitSign,
        Some(&q("git-ns:github.com/acme"))
    ));
    assert!(bridge.can(
        Capability::GitCommitSign,
        Some(&q("git-repo:github.com/acme/repo_any"))
    ));
    assert!(!bridge.can(
        Capability::GitCommitSign,
        Some(&q("git-ns:github.com/beta"))
    ));
    assert!(!bridge.can(
        Capability::GitRepoManage,
        Some(&q("git-ns:github.com/acme"))
    ));
    assert_eq!(
        bridge.resource_grants[0].delegated_by, TEST_VTC_DID,
        "the community grants it, as itself"
    );
}

/// §6.3 / VTI-ACL-071: a departed granter's git grants go to review in the
/// action list; re-affirming puts them under the approver's own authority,
/// and one not re-affirmed is withdrawn at the deadline.
#[tokio::test]
async fn vti_acl_071_a_departed_granters_git_grants_are_reviewed_then_withdrawn() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    seed_external(&f, &res, &f.stranger.did).await;
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.bob.did)
        .await
        .unwrap();
    assert!(lifecycle::sweep(&f.vtc.state).await.unwrap());

    let scope = Scope::Repo(repo_id(&f, &res).await);
    let rows = store::get_rights(&f.vtc.state.git_ns, &scope)
        .await
        .unwrap();
    let reviewed = rows
        .rows
        .iter()
        .filter(|r| r.review.as_ref().is_some_and(|v| v.granter == f.bob.did))
        .count();
    assert_eq!(
        reviewed, 2,
        "both of Bob's grants are under review, still in force"
    );

    // One item in the action list, listing the git grants; a second sweep
    // raises nothing new.
    let items = git_review_actions(&f).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].payload["granter"], f.bob.did.as_str());
    let listed: Vec<lifecycle::ReviewItem> =
        serde_json::from_value(items[0].payload["gitGrants"].clone()).unwrap();
    assert_eq!(listed.len(), 2);
    lifecycle::sweep(&f.vtc.state).await.unwrap();
    assert_eq!(git_review_actions(&f).await.len(), 1);

    // The namespace's admin re-affirms Carol's: it is delegated from them now,
    // and no longer under review.
    let carols: Vec<_> = listed
        .iter()
        .filter(|i| i.subject == f.carol.did)
        .cloned()
        .collect();
    let out = lifecycle::reaffirm(
        &f.vtc.state,
        &f.bob.did,
        &carols,
        std::slice::from_ref(&f.admin.did),
    )
    .await
    .unwrap();
    assert_eq!(out["reaffirmed"].as_array().unwrap().len(), 1);
    let carol = entry(&f, &f.carol.did).await.unwrap();
    let g = &carol.resource_grants[0];
    assert_eq!(g.delegated_by, f.admin.did);
    assert!(g.review.is_none());

    // The stranger's is left past its deadline: the sweep withdraws it, and
    // its application entry goes with it.
    let mut stranger = entry(&f, &f.stranger.did).await.unwrap();
    stranger.resource_grants[0]
        .review
        .as_mut()
        .unwrap()
        .deadline = "2020-01-01T00:00:00Z".parse().unwrap();
    store_acl_entry(&f.vtc.state.acl_ks, &stranger)
        .await
        .unwrap();
    assert!(lifecycle::sweep(&f.vtc.state).await.unwrap());
    assert!(
        entry(&f, &f.stranger.did).await.is_none(),
        "withdrawn at the deadline"
    );
    let rows = store::get_rights(&f.vtc.state.git_ns, &scope)
        .await
        .unwrap();
    assert!(rows.rows.iter().any(|r| r.subject == f.carol.did));
    assert!(rows.rows.iter().all(|r| r.subject != f.stranger.did));
}

/// Declining the review withdraws the grants at once.
#[tokio::test]
async fn a_declined_git_grants_review_withdraws_them_now() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.bob.did)
        .await
        .unwrap();
    lifecycle::sweep(&f.vtc.state).await.unwrap();
    let rec = git_review_actions(&f).await.remove(0);
    let items: Vec<lifecycle::ReviewItem> =
        serde_json::from_value(rec.payload["gitGrants"].clone()).unwrap();
    assert_eq!(
        lifecycle::withdraw_reviewed(&f.vtc.state, &f.bob.did, &items)
            .await
            .unwrap(),
        1
    );
    let carol = entry(&f, &f.carol.did).await.unwrap();
    assert!(carol.resource_grants.is_empty());
}

/// §9: a store from before C3 has its rights moved onto the entries — the
/// bridge onto an `application` entry, an elevated right with no member to
/// hold it kept inert and named — and a second run changes nothing.
#[tokio::test]
async fn the_rights_store_migrates_onto_the_entries_once() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let id = repo_id(&f, &res).await;
    let ns_id = Snapshot::load(&f.vtc.state.git_ns)
        .await
        .unwrap()
        .namespaces[0]
        .id
        .clone();
    let ks = &f.vtc.state.git_ns.ks;

    // What a pre-C3 node held: Carol maintains, the bridge signs on the
    // namespace, a DID with no entry owns, and a vanished repository's row.
    let row = |subject: &str, right: Right, member: bool| {
        let mut r = ops::new_row(subject, right, &f.bob.did, member);
        r.reason = Some("legacy".into());
        r
    };
    let bridge = Party::new();
    let legacy = [
        (
            format!("rights:repo:{id}"),
            vec![
                row(&f.carol.did, Right::RepoMaintain, true),
                row("did:key:z6MkGone", Right::RepoOwn, true),
            ],
        ),
        (
            format!("rights:ns:{ns_id}"),
            vec![row(&bridge.did, Right::CommitSign, false)],
        ),
        (
            "rights:repo:repo_vanished".to_string(),
            vec![row(&f.carol.did, Right::CommitSign, true)],
        ),
    ];
    for (key, rows) in &legacy {
        ks.insert(key.clone(), &RightsSet { rows: rows.clone() })
            .await
            .unwrap();
    }

    let first = migrate::migrate_rights(&f.vtc.state, "test").await.unwrap();
    assert_eq!(
        first.migrated, 2,
        "Carol's maintain and the bridge's commit right"
    );
    assert_eq!(first.applications, 1);
    assert_eq!(first.unmappable.len(), 2, "{:?}", first.unmappable);

    let carol = entry(&f, &f.carol.did).await.unwrap();
    let g = carol
        .resource_grants
        .iter()
        .find(|g| g.grade == Some(RepoGrade::Maintain))
        .unwrap();
    assert_eq!(g.resource, rg::repo_qualifier("github.com", "acme", &id));
    assert_eq!(g.delegated_by, f.bob.did);
    assert_eq!(
        g.reason.as_deref(),
        Some("legacy"),
        "the reason travels, unpublished"
    );
    let b = entry(&f, &bridge.did).await.unwrap();
    assert_eq!(b.role, VtcRole::Application);
    assert!(b.can(
        Capability::GitCommitSign,
        Some(&q("git-ns:github.com/acme"))
    ));
    assert!(
        entry(&f, "did:key:z6MkGone").await.is_none(),
        "an elevated right never lands on a non-member"
    );
    // The old store is gone; what could not be mapped is kept, inert, and an
    // acknowledge item names it to the administrators.
    assert!(
        ks.prefix_keys(b"rights:".to_vec())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ks.prefix_keys(b"rights-unmapped:".to_vec())
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        crate::admin_actions::all(&f.vtc.state)
            .await
            .unwrap()
            .iter()
            .any(|r| r.kind == crate::admin_actions::summary::KIND_OPERATOR_WRITE)
    );

    // The fixed rules read the migrated grants.
    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    assert!(
        rules::effective_on(
            &snap,
            &f.carol.did,
            &Resource::parse(&res).unwrap(),
            ops::now()
        )
        .contains(&Right::RepoMaintain)
    );

    let second = migrate::migrate_rights(&f.vtc.state, "test").await.unwrap();
    assert_eq!(second, Default::default(), "a second run does nothing");
    assert_eq!(
        entry(&f, &f.carol.did).await.unwrap().resource_grants,
        carol.resource_grants
    );
}

/// A key rotation moves the entry and its grants together, and the grants
/// the rotated subject delegated name it anew.
#[tokio::test]
async fn a_rotated_granter_stays_the_granter() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    let new = Party::new();
    let bob = entry(&f, &f.bob.did).await.unwrap();
    let moved = VtcAclEntry {
        did: new.did.clone(),
        ..bob
    };
    f.vtc
        .state
        .acl_ks
        .swap(
            format!("acl:{}", f.bob.did).into_bytes(),
            format!("acl:{}", new.did).into_bytes(),
            &moved,
        )
        .await
        .unwrap();
    crate::acl::delegation::repoint(&f.vtc.state, &f.bob.did, &new.did)
        .await
        .unwrap();
    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    assert!(
        rules::effective_on(&snap, &new.did, &Resource::parse(&res).unwrap(), ops::now())
            .contains(&Right::RepoOwn),
        "the rotated owner still owns"
    );
    assert_eq!(
        entry(&f, &f.carol.did).await.unwrap().resource_grants[0].delegated_by,
        new.did
    );
}

/// A non-member holding git rights on an `application` entry who then joins
/// becomes a member on the same entry, keeping those rights; a member's
/// entry is still never admitted over.
#[tokio::test]
async fn joining_turns_an_application_entry_into_a_membership() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    seed_external(&f, &res, &f.stranger.did).await;
    let before = entry(&f, &f.stranger.did).await.unwrap();
    // Admission issues a membership credential, which takes a status slot.
    for purpose in [
        affinidi_status_list::StatusPurpose::Revocation,
        affinidi_status_list::StatusPurpose::Suspension,
    ] {
        crate::status_list::ensure_initial(
            &f.vtc.state.status_lists_ks,
            purpose,
            format!("https://vtc.example.com/v1/status-lists/{purpose}"),
        )
        .await
        .unwrap();
    }
    let admit = |did: &str| crate::ceremony::EffectPlan::Admit {
        subject: did.to_string(),
        role: "member".into(),
        obligations: vec![],
        publish_consent: false,
    };
    crate::ceremony::apply(&f.vtc.state, admit(&f.stranger.did), &f.admin.did)
        .await
        .expect("an application entry is no membership to duplicate");
    let after = entry(&f, &f.stranger.did).await.unwrap();
    assert_eq!(after.role, VtcRole::Member);
    assert_eq!(after.resource_grants, before.resource_grants);
    assert!(
        ops::standing(&f.vtc.state, &f.stranger.did)
            .await
            .unwrap()
            .member
    );
    assert!(
        crate::ceremony::apply(&f.vtc.state, admit(&f.carol.did), &f.admin.did)
            .await
            .is_err()
    );
}
