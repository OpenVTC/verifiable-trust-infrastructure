//! End-to-end tests of the `git-ns/*` family through the dispatch spine:
//! signed documents in, the specification's codes and records out.
//!
//! Test names cite what they hold — the fixed rule, or the task's numbered
//! *Request* step.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::git_ns::bridge::job::v0_1 as job_wire;
use vti_rooms_dtg::test_support::Party;

use crate::acl::{VtcAclEntry, VtcRole, store_acl_entry};
use crate::registry::MockRegistryClient;
use crate::server::AppState;
use crate::test_support::{TEST_VTC_DID, TestVtc};
use crate::trust_tasks::{JoinAuthCtx, TrustTaskOutcome, dispatch_trust_task_core};

use super::GitNsConfig;
use super::bridge::{BridgeClient, BridgeSendError};
use super::model::{RepoState, Scope};
use super::projection::{self, Backoff};
use super::store::{self, Snapshot};

const URI: &str = "https://trusttasks.org/spec/git-ns";

fn uri(task: &str) -> String {
    format!("{URI}/{task}/0.1")
}

/// A bridge that accepts every job and remembers them.
#[derive(Default)]
struct FakeBridge {
    jobs: Mutex<Vec<(String, Value)>>,
    /// When set, the bridge reports each job's result *while* its send is
    /// still in flight — the race the dispatcher's write-back must survive.
    race: Mutex<Option<vti_common::store::KeyspaceHandle>>,
}

#[async_trait]
impl BridgeClient for FakeBridge {
    async fn send_job(
        &self,
        bridge_did: &str,
        payload: &Value,
        _timeout: Duration,
    ) -> Result<job_wire::Response, BridgeSendError> {
        self.jobs
            .lock()
            .unwrap()
            .push((bridge_did.to_string(), payload.clone()));
        let racing = self.race.lock().unwrap().clone();
        if let Some(ks) = racing
            && let Some(id) = payload["jobId"].as_str()
            && let Some(mut job) = super::bridge::get_job(&ks, id).await.unwrap()
        {
            job.state = super::bridge::JobState::Succeeded;
            job.result = Some(json!({ "jobId": id, "outcome": "succeeded" }));
            super::bridge::put_job(&ks, &job).await.unwrap();
        }
        let mut ack = json!({ "jobId": payload["jobId"], "accepted": true });
        if matches!(
            payload["kind"].as_str(),
            Some("beginBind" | "beginAccountLink")
        ) {
            ack["next"] = json!({
                "url": "https://github.com/apps/acme-vgi/installations/new?state=nonce",
                "expiresAt": "2099-01-01T00:00:00Z",
            });
        }
        Ok(serde_json::from_value(ack).unwrap())
    }
}

struct Fixture {
    vtc: TestVtc,
    bridge: Arc<FakeBridge>,
    admin: Party,
    bob: Party,
    carol: Party,
    stranger: Party,
    bridge_party: Party,
}

async fn seed_acl(state: &AppState, did: &str, role: VtcRole) {
    store_acl_entry(
        &state.acl_ks,
        &VtcAclEntry {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: vec![],
            created_at: 0,
            created_by: "test".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        },
    )
    .await
    .unwrap();
    crate::members::store_member(&state.members_ks, &crate::members::Member::fresh(did))
        .await
        .unwrap();
}

async fn fixture_with(config: GitNsConfig) -> Fixture {
    let bridge = Arc::new(FakeBridge::default());
    let bridge_party = Party::new();
    let mut config = config;
    config
        .bridges
        .insert("github.com".into(), bridge_party.did.clone());
    let vtc = TestVtc::builder()
        .with_audit(true)
        .with_signers(true)
        .with_git_ns_bridge(bridge.clone())
        .with_git_ns_config(config)
        .build()
        .await;
    crate::policy::default::install_defaults(&vtc.state.policies_ks, &vtc.state.active_policies_ks)
        .await
        .unwrap();
    let f = Fixture {
        vtc,
        bridge,
        admin: Party::new(),
        bob: Party::new(),
        carol: Party::new(),
        stranger: Party::new(),
        bridge_party,
    };
    seed_acl(&f.vtc.state, &f.admin.did, VtcRole::Admin).await;
    seed_acl(&f.vtc.state, &f.bob.did, VtcRole::Member).await;
    seed_acl(&f.vtc.state, &f.carol.did, VtcRole::Member).await;
    f
}

async fn fixture() -> Fixture {
    fixture_with(GitNsConfig::default()).await
}

async fn send(state: &AppState, who: &Party, task: &str, payload: Value) -> TrustTaskOutcome {
    let mut doc: TrustTask<Value> =
        vta_sdk::trust_task_sign::build_unsigned(&uri(task), payload, &who.did, TEST_VTC_DID)
            .unwrap();
    let key =
        vta_sdk::trust_task_sign::HolderKey::from_did_key(&who.did, &who.secret_multibase).unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    let body = serde_json::to_vec(&doc).unwrap();
    dispatch_trust_task_core(state, &JoinAuthCtx::rest(), &body).await
}

fn payload(out: &TrustTaskOutcome) -> Value {
    let doc: Value = serde_json::from_slice(&out.body).unwrap();
    doc["payload"].clone()
}

fn code(out: &TrustTaskOutcome) -> String {
    let p = payload(out);
    assert!(
        p.get("code").is_some(),
        "expected an error, got {}",
        String::from_utf8_lossy(&out.body)
    );
    p["code"].as_str().unwrap().to_string()
}

fn ok(out: &TrustTaskOutcome) -> Value {
    assert!(
        out.status.is_success() && payload(out).get("code").is_none(),
        "expected success, got {} {}",
        out.status,
        String::from_utf8_lossy(&out.body)
    );
    payload(out)
}

/// Bind `github.com/acme` in manual mode as the admin; returns its id.
async fn bind_manual(f: &Fixture) -> String {
    let out = send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "manual" }),
    )
    .await;
    ok(&out)["namespace"]["id"].as_str().unwrap().to_string()
}

async fn grant(
    f: &Fixture,
    actor: &Party,
    subject: &str,
    right: &str,
    resource: &str,
) -> TrustTaskOutcome {
    send(
        &f.vtc.state,
        actor,
        "right/grant",
        json!({ "subject": subject, "right": right, "resource": resource }),
    )
    .await
}

// ── namespace/bind, unbind ──────────────────────────────────────────────────

#[tokio::test]
async fn bind_manual_is_bound_at_once_and_the_binder_is_its_admin() {
    let f = fixture().await;
    let id = bind_manual(&f).await;
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let ns = snap.namespace(&id).unwrap();
    assert_eq!(ns.state, super::model::NamespaceState::Bound);
    assert_eq!(
        super::rules::admins(&snap, &id, super::ops::now()),
        vec![f.admin.did.clone()]
    );
}

#[tokio::test]
async fn bind_item_1_needs_the_community_administrator_capability() {
    let f = fixture().await;
    let out = send(
        &f.vtc.state,
        &f.bob,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "manual" }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

#[tokio::test]
async fn bind_item_2_refuses_an_owner_already_bound() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "manual" }),
    )
    .await;
    assert_eq!(code(&out), "git-ns/namespace/bind:alreadyBound");
}

#[tokio::test]
async fn bind_item_4_refuses_bridge_mode_with_no_bridge_for_the_forge() {
    let f = fixture().await;
    let out = send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "codeberg.org", "owner": "acme", "mode": "bridge" }),
    )
    .await;
    assert_eq!(code(&out), "git-ns/namespace/bind:noBridge");
}

#[tokio::test]
async fn bind_bridge_is_pending_until_the_bridge_reports_the_proof() {
    let f = fixture().await;
    let out = send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await;
    let body = ok(&out);
    assert_eq!(body["namespace"]["state"], "pending");
    assert!(
        body["next"]["url"]
            .as_str()
            .unwrap()
            .contains("state=nonce")
    );
    let ns_id = body["namespace"]["id"].as_str().unwrap().to_string();
    let job_id = f.bridge.jobs.lock().unwrap()[0].1["jobId"]
        .as_str()
        .unwrap()
        .to_string();

    // Nothing is granted in a pending namespace.
    let refused = grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await;
    assert_eq!(code(&refused), "git-ns:namespaceNotBound");

    // Only the serving bridge may complete it.
    let event = json!({
        "namespace": ns_id,
        "event": { "type": "bindCompleted", "jobId": job_id, "ownerId": "91827364", "kind": "organization" },
    });
    let forged = send(&f.vtc.state, &f.stranger, "bridge/event", event.clone()).await;
    assert_eq!(code(&forged), "permissionDenied");

    ok(&send(&f.vtc.state, &f.bridge_party, "bridge/event", event.clone()).await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let ns = snap.namespace(&ns_id).unwrap();
    assert_eq!(ns.state, super::model::NamespaceState::Bound);
    assert_eq!(ns.owner_id.as_deref(), Some("91827364"));
    assert_eq!(
        super::rules::admins(&snap, &ns_id, super::ops::now()),
        vec![f.admin.did.clone()],
        "the administrator who asked receives git.ns.admin"
    );

    // A replayed completion finds no pending binding.
    let again = send(&f.vtc.state, &f.bridge_party, "bridge/event", event).await;
    assert_eq!(code(&again), "permissionDenied");
}

#[tokio::test]
async fn an_event_for_an_unknown_namespace_is_refused() {
    let f = fixture().await;
    let out = send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": "ns_nope", "event": { "type": "installationRemoved" } }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:unknownNamespace");
}

#[tokio::test]
async fn unbind_revokes_everything_and_detaches_every_repository() {
    let f = fixture_with(GitNsConfig {
        elevated_requires_admin: false,
        ..GitNsConfig::default()
    })
    .await;
    let ns = bind_manual(&f).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await);
    let out = send(
        &f.vtc.state,
        &f.admin,
        "namespace/unbind",
        json!({ "namespace": ns }),
    )
    .await;
    let body = ok(&out);
    assert_eq!(body["rightsRevoked"], 3, "ns.admin, repo.create, own");
    assert_eq!(body["reposDetached"], 1);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(snap.namespace(&ns).is_none());
    assert!(snap.rights.is_empty());
    assert!(snap.repos.iter().all(|r| r.state == RepoState::Detached));
}

// ── right/grant: the fixed rules ────────────────────────────────────────────

#[tokio::test]
async fn grant_rule_1_a_repository_right_on_a_namespace_is_a_scope_violation() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = grant(&f, &f.admin, &f.bob.did, "git.repo.own", "github.com/acme").await;
    assert_eq!(code(&out), "git-ns:scopeViolation");
}

#[tokio::test]
async fn grant_rule_2_repo_create_is_not_re_delegable() {
    let f = fixture().await;
    bind_manual(&f).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);
    let out = grant(
        &f,
        &f.bob,
        &f.carol.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await;
    assert_eq!(code(&out), "git-ns:escalation");
}

#[tokio::test]
async fn grant_rule_2_nothing_held_is_permission_denied() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = grant(
        &f,
        &f.bob,
        &f.carol.did,
        "git.commit.sign",
        "github.com/acme",
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

#[tokio::test]
async fn grant_rule_5_namespace_rights_go_to_members_only() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = grant(
        &f,
        &f.admin,
        &f.stranger.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await;
    assert_eq!(code(&out), "git-ns:membersOnly");
}

#[tokio::test]
async fn grant_rule_6_the_default_policy_refuses_external_signers() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = grant(
        &f,
        &f.admin,
        &f.stranger.did,
        "git.commit.sign",
        "github.com/acme",
    )
    .await;
    assert_eq!(code(&out), "git-ns:policyDenied");
}

#[tokio::test]
async fn grant_item_2_a_resource_in_no_namespace_is_unknown() {
    let f = fixture().await;
    let out = grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.commit.sign",
        "codeberg.org/acme",
    )
    .await;
    assert_eq!(code(&out), "git-ns:unknownNamespace");
}

#[tokio::test]
async fn grant_item_3_an_unrecorded_repository_is_unknown() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.commit.sign",
        "github.com/acme/nope",
    )
    .await;
    assert_eq!(code(&out), "git-ns:unknownRepo");
}

#[tokio::test]
async fn grant_item_5_an_expiry_in_the_past_is_refused() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = send(
        &f.vtc.state,
        &f.admin,
        "right/grant",
        json!({
            "subject": f.bob.did, "right": "git.commit.sign", "resource": "github.com/acme",
            "expiresAt": "2020-01-01T00:00:00Z",
        }),
    )
    .await;
    assert_eq!(code(&out), "git-ns/right/grant:expiryInPast");
}

#[tokio::test]
async fn grant_item_6_a_repeated_grant_returns_the_record_unchanged() {
    let f = fixture().await;
    bind_manual(&f).await;
    let first = ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/grant",
        json!({ "subject": f.bob.did, "right": "git.commit.sign", "resource": "github.com/acme", "reason": "first" }),
    )
    .await);
    let second = ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/grant",
        json!({ "subject": f.bob.did, "right": "git.commit.sign", "resource": "github.com/acme", "reason": "second" }),
    )
    .await);
    assert_eq!(first["right"], second["right"]);
    assert_eq!(second["right"]["reason"], "first");
}

#[tokio::test]
async fn elevated_actions_fall_back_to_community_administrators() {
    // Design §6: `own` is elevated. With no member step-up, the default
    // configuration admits it only from a community administrator.
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await);
    // Bob owns gadgets and the rights model lets him name a co-owner …
    let out = grant(
        &f,
        &f.bob,
        &f.carol.did,
        "git.repo.own",
        "github.com/acme/gadgets",
    )
    .await;
    // … but the consent fallback does not.
    assert_eq!(code(&out), "permissionDenied");
    // A normal-class grant goes through.
    ok(&grant(
        &f,
        &f.bob,
        &f.carol.did,
        "git.commit.sign",
        "github.com/acme/gadgets",
    )
    .await);
}

// ── repo/create, adopt, transfer, archive ───────────────────────────────────

#[tokio::test]
async fn create_in_a_manual_namespace_reserves_and_returns_manual_steps() {
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);
    let out = send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await;
    let body = ok(&out);
    assert_eq!(body["repo"]["state"], "pendingCreate");
    assert_eq!(body["repo"]["owners"], json!([f.bob.did]));
    let steps = body["manualSteps"].as_array().unwrap();
    assert!(
        steps
            .last()
            .unwrap()
            .as_str()
            .unwrap()
            .contains("cnm git adopt")
    );

    let again = send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await;
    assert_eq!(code(&again), "git-ns/repo/create:nameTaken");

    // A reservation publishes nothing.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let want = projection::desired(&snap, super::ops::now());
    assert!(want.keys().all(|k| !k.contains("gadgets")));
}

#[tokio::test]
async fn create_needs_repo_create() {
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    let out = send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

#[tokio::test]
async fn adopt_activates_a_reservation_and_refuses_a_managed_repository() {
    let f = fixture_with(GitNsConfig {
        elevated_requires_admin: false,
        ..GitNsConfig::default()
    })
    .await;
    let ns = bind_manual(&f).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await);
    // The reservation's owner finishes the job.
    let body = ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/adopt",
        json!({ "resource": "github.com/acme/gadgets", "owners": [f.carol.did] }),
    )
    .await);
    assert_eq!(body["repo"]["state"], "active");
    let owners = body["repo"]["owners"].as_array().unwrap();
    assert_eq!(owners.len(), 2, "existing owners are kept and these added");

    let again = send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/gadgets", "owners": [f.carol.did] }),
    )
    .await;
    assert_eq!(code(&again), "git-ns/repo/adopt:alreadyManaged");
}

async fn active_repo(f: &Fixture) -> String {
    let ns = bind_manual(f).await;
    let _ = ns;
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/widgets", "owners": [f.bob.did] }),
    )
    .await);
    "github.com/acme/widgets".into()
}

#[tokio::test]
async fn transfer_moves_ownership_in_one_change() {
    let f = fixture_with(GitNsConfig {
        elevated_requires_admin: false,
        ..GitNsConfig::default()
    })
    .await;
    let res = active_repo(&f).await;
    let not_owner = send(
        &f.vtc.state,
        &f.carol,
        "repo/transfer",
        json!({ "resource": res, "to": f.bob.did }),
    )
    .await;
    assert_eq!(code(&not_owner), "git-ns/repo/transfer:notOwner");
    let selfie = send(
        &f.vtc.state,
        &f.bob,
        "repo/transfer",
        json!({ "resource": res, "to": f.bob.did }),
    )
    .await;
    assert_eq!(code(&selfie), "git-ns/repo/transfer:selfTransfer");
    let body = ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/transfer",
        json!({ "resource": res, "to": f.carol.did }),
    )
    .await);
    assert_eq!(body["repo"]["owners"], json!([f.carol.did]));
}

#[tokio::test]
async fn revoke_rules_3_and_4_keep_an_owner_and_an_admin() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let out = send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.bob.did, "right": "git.repo.own", "resource": res }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:lastOwner");
    let out = send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.admin.did, "right": "git.ns.admin", "resource": "github.com/acme" }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:lastAdmin", "resignations too");
    let out = send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.carol.did, "right": "git.commit.sign", "resource": res }),
    )
    .await;
    assert_eq!(code(&out), "git-ns/right/revoke:notGranted");
}

#[tokio::test]
async fn revoke_is_open_to_the_subject_and_closed_to_bystanders() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    let bystander = send(
        &f.vtc.state,
        &f.stranger,
        "right/revoke",
        json!({ "subject": f.carol.did, "right": "git.commit.sign", "resource": res }),
    )
    .await;
    assert_eq!(code(&bystander), "permissionDenied");
    let body = ok(&send(
        &f.vtc.state,
        &f.carol,
        "right/revoke",
        json!({ "subject": f.carol.did, "right": "git.commit.sign", "resource": res }),
    )
    .await);
    assert_eq!(body["revoked"]["subject"], json!(f.carol.did));
}

#[tokio::test]
async fn archive_revokes_every_commit_right_and_is_idempotent() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/archive",
        json!({ "resource": res }),
    )
    .await);
    assert_eq!(body["repo"]["state"], "archived");
    assert_eq!(body["rightsRevoked"], 1);
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/archive",
        json!({ "resource": res }),
    )
    .await);
    assert_eq!(body["rightsRevoked"], 0);

    // The owner record is kept; no commit right is published for it.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let want = projection::desired(&snap, super::ops::now());
    assert!(want.contains_key(&projection::tuple_key(&f.bob.did, "git.repo.own", &res)));
    assert!(!want.contains_key(&projection::tuple_key(&f.bob.did, "git.commit.sign", &res)));
}

// ── view ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn view_shows_reasons_only_to_those_who_govern_the_resource() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "right/grant",
        json!({ "subject": f.carol.did, "right": "git.commit.sign", "resource": res, "reason": "1.0 push" }),
    )
    .await);

    // Carol sees her own right, without its reason.
    let carol = ok(&send(&f.vtc.state, &f.carol, "view", json!({})).await);
    let rights = carol["rights"].as_array().unwrap();
    assert_eq!(rights.len(), 1);
    assert!(rights[0].get("reason").is_none());
    assert_eq!(carol["repos"][0]["owners"], json!([f.bob.did]));

    // Bob owns the repository: every right on it, reasons included.
    let bob = ok(&send(&f.vtc.state, &f.bob, "view", json!({ "resource": res })).await);
    let reasons: Vec<&Value> = bob["rights"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r.get("reason"))
        .collect();
    assert_eq!(reasons, vec![&json!("1.0 push")]);

    // A non-member is refused.
    let out = send(&f.vtc.state, &f.stranger, "view", json!({})).await;
    assert_eq!(code(&out), "permissionDenied");
}

// ── the projection ──────────────────────────────────────────────────────────

#[tokio::test]
async fn the_projection_publishes_implied_commit_rights_and_never_a_reason() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "right/grant",
        json!({ "subject": f.carol.did, "right": "git.repo.maintain", "resource": res, "reason": "secret" }),
    )
    .await);
    let registry = MockRegistryClient::new();
    let mut backoff = Backoff::default();
    let report = projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    assert_eq!(report.failed, 0);
    let records = registry.trust_records().await;
    let has = |e: &str, a: &str, r: &str| records.contains_key(&projection::tuple_key(e, a, r));
    // ns.admin → commit.sign on the namespace (trust-tasks-tf#623).
    assert!(has(&f.admin.did, "git.ns.admin", "github.com/acme"));
    assert!(has(&f.admin.did, "git.commit.sign", "github.com/acme"));
    // own and maintain → commit.sign on the repository.
    assert!(has(&f.bob.did, "git.repo.own", &res));
    assert!(has(&f.bob.did, "git.commit.sign", &res));
    assert!(has(&f.carol.did, "git.repo.maintain", &res));
    assert!(has(&f.carol.did, "git.commit.sign", &res));
    // Implied rights other than commit.sign are never records.
    assert!(!has(&f.admin.did, "git.repo.own", &res));
    for record in records.values() {
        assert_eq!(record["authority_id"], TEST_VTC_DID);
        assert_eq!(record["record_type"], "authorization");
        assert!(record["context"].get("reason").is_none());
        assert!(!record.to_string().contains("secret"));
    }

    // A second pass changes nothing; a revoke withdraws the tuples.
    let again = projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    assert_eq!((again.put, again.deleted), (0, 0));
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "right/revoke",
        json!({ "subject": f.carol.did, "right": "git.repo.maintain", "resource": res }),
    )
    .await);
    let after = projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    assert_eq!(after.deleted, 2);
    let records = registry.trust_records().await;
    assert!(!records.contains_key(&projection::tuple_key(
        &f.carol.did,
        "git.commit.sign",
        &res
    )));
}

#[tokio::test]
async fn a_rename_withdraws_the_old_name_before_publishing_the_new() {
    let f = fixture().await;
    // A bridge-mode namespace, bound through the bridge.
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let ns = body["namespace"]["id"].as_str().unwrap().to_string();
    let job = f.bridge.jobs.lock().unwrap()[0].1["jobId"].clone();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": { "type": "bindCompleted", "jobId": job, "ownerId": "1", "kind": "organization" } }),
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/widgets", "owners": [f.bob.did] }),
    )
    .await);
    // The inspection result gives the repository its forge id.
    let inspect = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .find(|j| j.kind == super::bridge::JobKind::Inspect)
        .unwrap();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/result",
        json!({
            "jobId": inspect.job_id, "outcome": "succeeded",
            "repo": { "resource": "github.com/acme/widgets", "forgeId": "812736451" },
            "steps": [
                { "step": "workflow", "outcome": "unchanged" },
                { "step": "keyring", "outcome": "unchanged" },
                { "step": "variables", "outcome": "unchanged" },
                { "step": "requiredCheck", "outcome": "unchanged" }
            ],
        }),
    )
    .await);

    let registry = MockRegistryClient::new();
    let mut backoff = Backoff::default();
    projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    let old = projection::tuple_key(&f.bob.did, "git.commit.sign", "github.com/acme/widgets");
    assert!(registry.trust_records().await.contains_key(&old));

    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": { "type": "repoRenamed", "forgeId": "812736451", "from": "github.com/acme/widgets", "to": "github.com/acme/widgets-core" } }),
    )
    .await);

    // The old name's withdrawal fails: nothing is published for the new name.
    registry
        .fail_next_trust_record(crate::registry::RegistryError::Transient("down".into()))
        .await;
    let held = projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    assert!(held.held_back > 0);
    let new = projection::tuple_key(
        &f.bob.did,
        "git.commit.sign",
        "github.com/acme/widgets-core",
    );
    assert!(!registry.trust_records().await.contains_key(&new));

    // Once withdrawn, the new name is published; the old stays gone.
    let mut backoff = Backoff::default();
    projection::reconcile(&f.vtc.state, &registry, TEST_VTC_DID, &mut backoff)
        .await
        .unwrap();
    let records = registry.trust_records().await;
    assert!(records.contains_key(&new));
    assert!(!records.contains_key(&old));
}

// ── bridge results ──────────────────────────────────────────────────────────

#[tokio::test]
async fn a_result_for_a_job_never_sent_is_unknown_and_only_the_bridge_reports() {
    let f = fixture().await;
    let out = send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/result",
        json!({ "jobId": "job_nope", "outcome": "succeeded" }),
    )
    .await;
    assert_eq!(code(&out), "git-ns/bridge/result:unknownJob");
}

#[tokio::test]
async fn create_in_a_bridge_organisation_activates_on_the_result() {
    let f = fixture().await;
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let ns = body["namespace"]["id"].as_str().unwrap().to_string();
    let job = f.bridge.jobs.lock().unwrap()[0].1["jobId"].clone();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": { "type": "bindCompleted", "jobId": job, "ownerId": "1", "kind": "organization" } }),
    )
    .await);
    let out = ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await);
    assert_eq!(out["repo"]["state"], "pendingCreate");
    assert!(out.get("manualSteps").is_none() || out["manualSteps"] == json!([]));

    // The queued job is sent by the projector's dispatch.
    super::bridge::dispatch_due(&f.vtc.state).await.unwrap();
    let create = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .find(|j| j.kind == super::bridge::JobKind::CreateRepo)
        .unwrap();
    assert_eq!(create.state, super::bridge::JobState::Accepted);

    // A stranger cannot report on it.
    let forged = send(
        &f.vtc.state,
        &f.stranger,
        "bridge/result",
        json!({ "jobId": create.job_id, "outcome": "succeeded" }),
    )
    .await;
    assert_eq!(code(&forged), "permissionDenied");

    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/result",
        json!({
            "jobId": create.job_id, "outcome": "succeeded",
            "repo": { "resource": "github.com/acme/gadgets", "forgeId": "812736990" },
            "steps": [
                { "step": "create", "outcome": "applied" },
                { "step": "workflow", "outcome": "applied" },
                { "step": "keyring", "outcome": "applied" },
                { "step": "variables", "outcome": "applied" },
                { "step": "requiredCheck", "outcome": "applied" }
            ],
        }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at("github.com/acme/gadgets").unwrap();
    assert_eq!(repo.state, RepoState::Active);
    assert_eq!(repo.forge_id.as_deref(), Some("812736990"));
    assert!(repo.bootstrap.required_check);
}

// ── lifecycle ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_departed_members_rights_go_and_their_sole_repository_is_orphaned() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    // Bob leaves: his ACL row goes, as removal does.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.bob.did)
        .await
        .unwrap();
    assert!(super::lifecycle::sweep(&f.vtc.state).await.unwrap());
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at(&res).unwrap();
    assert_eq!(repo.state, RepoState::Orphaned);
    let rows = snap.rows(&Scope::Repo(repo.id.clone()));
    assert!(rows.iter().all(|r| r.subject != f.bob.did));
    // The grant Bob issued stays, listed for review.
    assert!(rows.iter().any(|r| r.subject == f.carol.did));
    let departed = super::lifecycle::issued_by_departed(&f.vtc.state)
        .await
        .unwrap();
    assert_eq!(departed.get(&f.bob.did).map(Vec::len), Some(1));

    // A namespace admin names a new owner; the repository is active again.
    ok(&grant(&f, &f.admin, &f.carol.did, "git.repo.own", &res).await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert_eq!(snap.repo_at(&res).unwrap().state, RepoState::Active);
}

#[tokio::test]
async fn a_lapsed_right_is_withdrawn_and_recorded() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    // Write an already-lapsed row directly: the grant task refuses one.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let scope = Scope::Repo(snap.repo_at(&res).unwrap().id.clone());
    let mut set = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap();
    let mut row = set.rows[0].clone();
    row.subject = f.carol.did.clone();
    row.right = super::model::Right::CommitSign;
    row.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
    set.rows.push(row);
    store::put_rights(&f.vtc.state.git_ns.ks, &scope, &set)
        .await
        .unwrap();
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(
        !projection::desired(&snap, super::ops::now()).contains_key(&projection::tuple_key(
            &f.carol.did,
            "git.commit.sign",
            &res
        )),
        "a lapsed right is never published, sweep or no sweep"
    );
    assert!(super::lifecycle::sweep_expiry(&f.vtc.state).await.unwrap());
    let set = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap();
    assert!(set.rows.iter().all(|r| r.subject != f.carol.did));
}

// ── account links ───────────────────────────────────────────────────────────

#[tokio::test]
async fn account_link_needs_a_bridge_namespace_and_status_answers_only_its_owner() {
    let f = fixture().await;
    let out = send(
        &f.vtc.state,
        &f.bob,
        "account/link",
        json!({ "forge": "github.com" }),
    )
    .await;
    assert_eq!(code(&out), "git-ns/account/link:unsupportedForge");

    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let ns = body["namespace"]["id"].as_str().unwrap().to_string();
    let job = f.bridge.jobs.lock().unwrap()[0].1["jobId"].clone();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": { "type": "bindCompleted", "jobId": job, "ownerId": "1", "kind": "organization" } }),
    )
    .await);

    let link = ok(&send(
        &f.vtc.state,
        &f.bob,
        "account/link",
        json!({ "forge": "github.com" }),
    )
    .await);
    let link_id = link["linkId"].as_str().unwrap().to_string();
    let status = ok(&send(
        &f.vtc.state,
        &f.bob,
        "account/link-status",
        json!({ "linkId": link_id }),
    )
    .await);
    assert_eq!(status["state"], "pending");
    let other = send(
        &f.vtc.state,
        &f.carol,
        "account/link-status",
        json!({ "linkId": link_id }),
    )
    .await;
    assert_eq!(code(&other), "git-ns/account/link-status:unknownLink");

    // The bridge reports the link; the account is recorded on Bob.
    let link_job = f.bridge.jobs.lock().unwrap()[1].1["jobId"].clone();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": { "type": "accountLinked", "jobId": link_job, "account": { "forge": "github.com", "id": "9120045", "login": "bob-builds" } } }),
    )
    .await);
    let status = ok(&send(
        &f.vtc.state,
        &f.bob,
        "account/link-status",
        json!({ "linkId": link_id }),
    )
    .await);
    assert_eq!(status["state"], "linked");
    assert_eq!(status["account"]["id"], "9120045");
    let accounts = super::bridge::linked_accounts(&f.vtc.state).await.unwrap();
    assert_eq!(accounts[&f.bob.did]["github.com"].login, "bob-builds");
}

// ── the dispatcher ──────────────────────────────────────────────────────────

#[test]
fn every_git_ns_task_is_served() {
    let served = super::tasks::served_uris();
    for task in [
        "namespace/bind",
        "namespace/unbind",
        "repo/create",
        "repo/adopt",
        "repo/transfer",
        "repo/archive",
        "right/grant",
        "right/revoke",
        "view",
        "account/link",
        "account/link-status",
        "bridge/result",
        "bridge/event",
    ] {
        assert!(served.contains(&uri(task).as_str()), "{task} is not served");
    }
    // `bridge/job` is the VTC's to send, never to serve.
    assert!(!served.contains(&uri("bridge/job").as_str()));
}

#[tokio::test]
async fn a_proof_required_git_ns_task_is_refused_unsigned() {
    let f = fixture().await;
    let doc: TrustTask<Value> = vta_sdk::trust_task_sign::build_unsigned(
        &uri("right/grant"),
        json!({ "subject": f.bob.did, "right": "git.commit.sign", "resource": "github.com/acme" }),
        &f.admin.did,
        TEST_VTC_DID,
    )
    .unwrap();
    let out = dispatch_trust_task_core(
        &f.vtc.state,
        &JoinAuthCtx::rest(),
        &serde_json::to_vec(&doc).unwrap(),
    )
    .await;
    assert_eq!(code(&out), "proofRequired");
}

// ── the bridge's service grant ──────────────────────────────────────────────

#[tokio::test]
async fn a_bound_bridge_namespace_grants_its_bridge_commit_sign_and_nothing_else() {
    let f = fixture().await;
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let ns = body["namespace"]["id"].as_str().unwrap().to_string();
    let job = f.bridge.jobs.lock().unwrap()[0].1["jobId"].clone();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": { "type": "bindCompleted", "jobId": job, "ownerId": "1", "kind": "organization" } }),
    )
    .await);

    // Recorded as a service grant: the community itself is the granter, and
    // the bridge — not a member — holds `git.commit.sign` on the namespace.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let rows = snap.rows(&Scope::Namespace(ns.clone()));
    let grant_row = rows
        .iter()
        .find(|r| r.subject == f.bridge_party.did)
        .expect("the bridge holds a service grant");
    assert_eq!(grant_row.right, super::model::Right::CommitSign);
    assert_eq!(grant_row.granted_by, TEST_VTC_DID);
    assert!(!grant_row.subject_was_member);

    // Published like any other commit right.
    let registry = MockRegistryClient::new();
    projection::reconcile(
        &f.vtc.state,
        &registry,
        TEST_VTC_DID,
        &mut Backoff::default(),
    )
    .await
    .unwrap();
    let key = projection::tuple_key(&f.bridge_party.did, "git.commit.sign", "github.com/acme");
    let record = registry
        .trust_records()
        .await
        .get(&key)
        .cloned()
        .expect("published");
    // Who granted it stays inside the VTC, even when it is the VTC.
    assert!(record["context"].get("grantedBy").is_none());

    // The default policy's exception is exact: a grant to any other
    // non-member — even one naming the bridge's right — is still refused.
    let out = grant(
        &f,
        &f.admin,
        &f.stranger.did,
        "git.commit.sign",
        "github.com/acme",
    )
    .await;
    assert_eq!(code(&out), "git-ns:policyDenied");

    // A departure sweep does not touch it: the bridge never was a member.
    super::lifecycle::sweep(&f.vtc.state).await.unwrap();
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(
        snap.rows(&Scope::Namespace(ns.clone()))
            .iter()
            .any(|r| r.subject == f.bridge_party.did)
    );

    // Unbinding ends it with everything else.
    let out = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/unbind",
        json!({ "namespace": ns }),
    )
    .await);
    assert_eq!(
        out["rightsRevoked"], 2,
        "the admin's ns.admin and the bridge's grant"
    );
}

// ── console-key delegation (#1684, #1692) ───────────────────────────────────

#[tokio::test]
async fn a_console_key_acts_as_its_admin_and_a_revoked_one_as_nobody() {
    let f = fixture().await;
    let console = Party::new();
    crate::acl::console_key::enrol_delegation(
        &f.vtc.state.console_keys_ks,
        &f.vtc.state.acl_ks,
        &console.did,
        &f.admin.did,
        Some("browser".into()),
        None,
    )
    .await
    .unwrap();
    // The console key binds as the admin: the binder, and the first
    // `git.ns.admin`, is the admin DID, not the key.
    let body = ok(&send(
        &f.vtc.state,
        &console,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "manual" }),
    )
    .await);
    let ns = body["namespace"]["id"].as_str().unwrap().to_string();
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert_eq!(
        super::rules::admins(&snap, &ns, super::ops::now()),
        vec![f.admin.did.clone()]
    );
    // …and grants with the admin's git rights.
    ok(&grant(
        &f,
        &console,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);

    crate::acl::console_key::revoke_delegation(
        &f.vtc.state.console_keys_ks,
        &console.did,
        &f.admin.did,
    )
    .await
    .unwrap();
    let out = grant(
        &f,
        &console,
        &f.carol.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

// ── the bridge's ext report ─────────────────────────────────────────────────

#[tokio::test]
async fn the_bridges_ext_report_reaches_the_admin_rows() {
    let f = fixture().await;
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let ns = body["namespace"]["id"].as_str().unwrap().to_string();
    let job = f.bridge.jobs.lock().unwrap()[0].1["jobId"].clone();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({
            "namespace": ns,
            "event": { "type": "bindCompleted", "jobId": job, "ownerId": "1", "kind": "organization" },
            "ext": { "org.openvtc.git-ns": { "namespace": {
                "installationId": "55120033", "appSlug": "acme-vgi",
                "missingPermissions": ["organization_administration"],
                "orgRulesets": true
            } } },
        }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let status = snap.namespace(&ns).unwrap().forge_status.clone().unwrap();
    assert_eq!(status.installation_id.as_deref(), Some("55120033"));
    assert_eq!(
        status.missing_permissions,
        vec!["organization_administration"]
    );
    assert_eq!(status.org_rulesets, Some(true));

    // A repository's guard and step outcomes, from an inspect result.
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/widgets", "owners": [f.bob.did] }),
    )
    .await);
    let inspect = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .find(|j| j.kind == super::bridge::JobKind::Inspect)
        .unwrap();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/result",
        json!({
            "jobId": inspect.job_id, "outcome": "partial",
            "repo": { "resource": "github.com/acme/widgets", "forgeId": "7" },
            "steps": [{ "step": "requiredCheck", "outcome": "failed", "detail": "not required" }],
            "ext": { "org.openvtc.git-ns": { "repo": { "guard": "codeOwnerReview" } } },
        }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at("github.com/acme/widgets").unwrap();
    assert_eq!(repo.forge_report.guard.as_deref(), Some("codeOwnerReview"));
    assert_eq!(repo.forge_report.steps.len(), 1);
}

// ── the admin and activity reads ────────────────────────────────────────────

/// A REST read under a session. `contexts` empty is a community-wide admin;
/// a named context is an admin session scoped narrower than the community —
/// the only other kind a VTC authenticates (it admits the admin role alone).
async fn get(f: &Fixture, did: &str, contexts: Vec<String>, path: &str) -> (u16, Value) {
    use tower::ServiceExt;
    let token = f.vtc.token(did, "admin", contexts).await;
    let mut req = axum::http::Request::builder()
        .uri(format!("/v1{path}"))
        .header("authorization", format!("Bearer {token}"));
    if path.starts_with("/git-ns/view") {
        req = req.header("trust-task", uri("view"));
    }
    let req = req.body(axum::body::Body::empty()).unwrap();
    let resp = f.vtc.router.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_namespace_admin_reads_their_activity_and_nobody_elses() {
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    ok(&grant(&f, &f.admin, &f.bob.did, "git.ns.admin", "github.com/acme").await);

    // Bob administers the namespace; he is not a community administrator.
    let (status, body) = get(&f, &f.bob.did, vec!["ops".into()], "/git-ns/activity").await;
    assert_eq!(status, 200, "{body}");
    let items = body["items"].as_array().unwrap();
    assert!(items.iter().any(|i| i["action"] == "gitNs.right.granted"
        && i["subject"] == json!(f.bob.did)
        && i["namespace"] == json!(ns)));

    // Carol administers nothing.
    let (status, _) = get(&f, &f.carol.did, vec!["ops".into()], "/git-ns/activity").await;
    assert_eq!(status, 403);

    // The community administrator reads the linked accounts.
    let (status, body) = get(&f, &f.admin.did, vec![], "/git-ns/accounts").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["accounts"].as_array().unwrap().is_empty());
}

// ── review of #1694: regression tests, one or more per finding ──────────────

/// Bind `github.com/acme` through the bridge; returns its id.
async fn bind_bridge(f: &Fixture) -> String {
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let ns = body["namespace"]["id"].as_str().unwrap().to_string();
    let job = f.bridge.jobs.lock().unwrap()[0].1["jobId"].clone();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": { "type": "bindCompleted", "jobId": job, "ownerId": "1", "kind": "organization" } }),
    )
    .await);
    ns
}

/// Adopt `resource` for Bob in a bridge namespace, and give it `forge_id`
/// through the inspection result, as a bridge does.
async fn adopt_with_forge_id(f: &Fixture, resource: &str, forge_id: &str) {
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": resource, "owners": [f.bob.did] }),
    )
    .await);
    let inspect = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .find(|j| j.kind == super::bridge::JobKind::Inspect && j.payload["repo"] == resource)
        .unwrap();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/result",
        json!({
            "jobId": inspect.job_id, "outcome": "succeeded",
            "repo": { "resource": resource, "forgeId": forge_id },
            "steps": [{ "step": "requiredCheck", "outcome": "unchanged" }],
        }),
    )
    .await);
}

async fn event(f: &Fixture, ns: &str, event: Value) -> TrustTaskOutcome {
    send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({ "namespace": ns, "event": event }),
    )
    .await
}

async fn reconcile(f: &Fixture, registry: &MockRegistryClient) -> projection::PassReport {
    projection::reconcile(
        &f.vtc.state,
        registry,
        TEST_VTC_DID,
        &mut Backoff::default(),
    )
    .await
    .unwrap()
}

async fn desired_now(f: &Fixture) -> std::collections::BTreeMap<String, projection::Tuple> {
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    projection::desired_all(&f.vtc.state, &snap, super::ops::now())
        .await
        .unwrap()
}

// Finding 1 — bridge event scope.

/// The reviewer's reproduction: A is renamed away (webhook lost), B is created
/// at A's old name (webhook lost), then B is renamed. B's rename names A's old
/// resource as `from`; matched by name it would carry A's grants onto B.
#[tokio::test]
async fn finding_1_a_rename_of_a_repository_reusing_a_lost_name_does_not_move_its_grants() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
    ok(&grant(
        &f,
        &f.bob,
        &f.carol.did,
        "git.commit.sign",
        "github.com/acme/widgets",
    )
    .await);
    // Lost: A renamed widgets → widgets-old; lost: B created at widgets as 200.
    ok(&event(
        &f,
        &ns,
        json!({ "type": "repoRenamed", "forgeId": "200", "from": "github.com/acme/widgets", "to": "github.com/acme/gadgets" }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let a = snap.repo_at("github.com/acme/widgets").unwrap();
    assert_eq!(a.forge_id.as_deref(), Some("100"), "A was not taken for B");
    assert!(snap.repo_at("github.com/acme/gadgets").is_none());
    let want = desired_now(&f).await;
    assert!(
        want.values()
            .all(|t| t.resource != "github.com/acme/gadgets"),
        "no right of A's is published on B's new name"
    );
}

/// The same sequence when B's `repoCreatedUnmanaged` does arrive: the name's
/// new holder displaces A, whose rights are withdrawn, and B's later rename
/// carries nothing.
#[tokio::test]
async fn finding_1_a_repository_created_at_a_governed_name_detaches_the_old_one() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
    ok(&event(
        &f,
        &ns,
        json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": "github.com/acme/widgets" }),
    )
    .await);
    ok(&event(
        &f,
        &ns,
        json!({ "type": "repoRenamed", "forgeId": "200", "from": "github.com/acme/widgets", "to": "github.com/acme/gadgets" }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let a = snap
        .repos
        .iter()
        .find(|r| r.forge_id.as_deref() == Some("100"))
        .unwrap();
    assert_eq!(a.state, RepoState::Detached);
    assert!(snap.rows(&Scope::Repo(a.id.clone())).is_empty());
    let b = snap.repo_at("github.com/acme/gadgets").unwrap();
    assert_eq!(b.state, RepoState::Unmanaged);
    assert!(snap.rows(&Scope::Repo(b.id.clone())).is_empty());
    let want = desired_now(&f).await;
    assert!(want.values().all(|t| !t.resource.starts_with("github.com/acme/")
        || t.resource == "github.com/acme"));
}

/// Every resource an event names must be a repository of the event's own
/// namespace; a repository leaving it is detached, never moved.
#[tokio::test]
async fn finding_1_events_are_confined_to_their_namespace_and_a_transfer_out_detaches() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
    // A second namespace of this VTC, governed separately.
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "beta", "mode": "manual" }),
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/beta/tools", "owners": [f.carol.did] }),
    )
    .await);

    for bad in [
        json!({ "type": "repoDeleted", "forgeId": "9", "resource": "github.com/beta/tools" }),
        json!({ "type": "repoCreatedUnmanaged", "forgeId": "9", "resource": "codeberg.org/acme/x" }),
        json!({ "type": "repoRenamed", "forgeId": "100", "from": "github.com/acme/widgets", "to": "github.com/beta/widgets" }),
        json!({ "type": "repoTransferred", "forgeId": "9", "from": "github.com/beta/tools", "to": "github.com/acme/tools" }),
    ] {
        let out = event(&f, &ns, bad.clone()).await;
        assert_eq!(code(&out), "permissionDenied", "{bad}");
    }
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert_eq!(
        snap.repo_at("github.com/beta/tools").unwrap().state,
        RepoState::Active
    );
    assert_eq!(
        snap.repo_at("github.com/acme/widgets").unwrap().state,
        RepoState::Active
    );

    // Transferred into another bound namespace: detached, rights withdrawn,
    // nothing carried into `beta`.
    ok(&event(
        &f,
        &ns,
        json!({ "type": "repoTransferred", "forgeId": "100", "from": "github.com/acme/widgets", "to": "github.com/beta/widgets" }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let a = snap
        .repos
        .iter()
        .find(|r| r.forge_id.as_deref() == Some("100"))
        .unwrap();
    assert_eq!(a.state, RepoState::Detached);
    assert_eq!(a.resource, "github.com/acme/widgets");
    assert!(snap.rows(&Scope::Repo(a.id.clone())).is_empty());
    assert!(snap.repo_at("github.com/beta/widgets").is_none());
}

// Finding 2 — nothing of who granted or why is published.

#[tokio::test]
async fn finding_2_no_published_record_names_its_granter_or_a_reason() {
    let f = fixture().await;
    bind_bridge(&f).await;
    adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "right/grant",
        json!({ "subject": f.carol.did, "right": "git.repo.maintain", "resource": "github.com/acme/widgets", "reason": "secret" }),
    )
    .await);
    let registry = MockRegistryClient::new();
    reconcile(&f, &registry).await;
    let records = registry.trust_records().await;
    assert!(records.len() >= 6, "admin, bridge, bob, carol");
    for record in records.values() {
        let context = record["context"].as_object().unwrap();
        assert!(!context.contains_key("grantedBy"), "{record}");
        assert!(!context.contains_key("reason"), "{record}");
        assert!(!record.to_string().contains("secret"));
        for key in context.keys() {
            assert!(
                ["framework", "activeFrom", "activeTo", "impliedBy", "origin"]
                    .contains(&key.as_str()),
                "unexpected context member {key}"
            );
        }
    }
}

// Finding 3 — one writer per registry key.

async fn map_members_to(f: &Fixture, resource: &str) {
    f.vtc.state.config.write().await.hooks.git_trust = Some(crate::hooks::GitTrustHooksConfig {
        grant_on_role: std::collections::BTreeMap::from([(
            "member".to_string(),
            resource.to_string(),
        )]),
        revoke_with_membership: true,
    });
}

/// A v0.1 role-derived grant inside a bound namespace is a second source of
/// the projection's own; revoking an explicit grant of the same key does not
/// withdraw what the role still wants.
#[tokio::test]
async fn finding_3_a_role_derived_grant_is_a_source_and_survives_a_revoke_of_the_same_key() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    map_members_to(&f, &res).await;
    let registry = MockRegistryClient::new();
    reconcile(&f, &registry).await;
    let key = projection::tuple_key(&f.carol.did, "git.commit.sign", &res);
    let record = registry.trust_records().await.get(&key).cloned().unwrap();
    assert_eq!(record["context"]["origin"], "roleDerived");

    // An explicit grant of the same key, then its revoke.
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    reconcile(&f, &registry).await;
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "right/revoke",
        json!({ "subject": f.carol.did, "right": "git.commit.sign", "resource": res }),
    )
    .await);
    reconcile(&f, &registry).await;
    let record = registry
        .trust_records()
        .await
        .get(&key)
        .cloned()
        .expect("the role still wants it: not withdrawn");
    assert_eq!(record["context"]["origin"], "roleDerived");

    // The member leaves: now no source wants it.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.carol.did)
        .await
        .unwrap();
    reconcile(&f, &registry).await;
    assert!(!registry.trust_records().await.contains_key(&key));
}

/// The verify pass: a record the registry lost is put again, one it holds that
/// nothing wants is deleted — also after the mirror was lost (a restore).
#[tokio::test]
async fn finding_3_verify_repairs_the_registry_and_rebuilds_a_lost_mirror() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let registry = MockRegistryClient::new();
    reconcile(&f, &registry).await;
    let wanted = projection::tuple_key(&f.bob.did, "git.commit.sign", &res);
    let stray = |did: &str| {
        json!({
            "entity_id": did, "authority_id": TEST_VTC_DID,
            "action": "git.commit.sign", "resource": res,
            "record_type": "authorization", "authorized": true, "context": {},
        })
    };

    registry.forget_trust_record(&wanted).await;
    registry.plant_trust_record(stray(&f.stranger.did)).await;
    let report = projection::verify(
        &f.vtc.state,
        &registry,
        TEST_VTC_DID,
        &mut Backoff::default(),
    )
    .await
    .unwrap()
    .expect("the mock registry enumerates");
    assert_eq!((report.put, report.deleted), (1, 1));
    let records = registry.trust_records().await;
    assert!(records.contains_key(&wanted));
    assert!(!records.contains_key(&projection::tuple_key(
        &f.stranger.did,
        "git.commit.sign",
        &res
    )));

    // A restore: the mirror is gone, and the registry holds a stray. A plain
    // reconcile cannot see it; verify rebuilds the mirror first and does.
    for key in projection::published(&f.vtc.state).await.unwrap().keys() {
        f.vtc
            .state
            .git_ns
            .projection_ks
            .remove(format!("t:{key}"))
            .await
            .unwrap();
    }
    registry.plant_trust_record(stray(&f.carol.did)).await;
    let report = projection::verify(
        &f.vtc.state,
        &registry,
        TEST_VTC_DID,
        &mut Backoff::default(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((report.put, report.deleted), (0, 1));
    assert!(
        !registry
            .trust_records()
            .await
            .contains_key(&projection::tuple_key(
                &f.carol.did,
                "git.commit.sign",
                &res
            ))
    );
    assert_eq!(
        projection::published(&f.vtc.state).await.unwrap().len(),
        registry.trust_records().await.len()
    );
}

// Finding 4 — the console reads are for community administrators.

#[tokio::test]
async fn finding_4_the_console_reads_refuse_a_context_scoped_admin() {
    let f = fixture().await;
    bind_manual(&f).await;
    for path in [
        "/git-ns/view",
        "/git-ns/rights",
        "/git-ns/accounts",
        "/git-ns/rights/issued-by-departed",
        "/git-ns/projection",
    ] {
        let (status, body) = get(&f, &f.admin.did, vec!["ops".into()], path).await;
        assert_eq!(status, 403, "{path}: {body}");
    }
    for path in [
        "/git-ns/view",
        "/git-ns/rights",
        "/git-ns/accounts",
        "/git-ns/rights/issued-by-departed",
        "/git-ns/projection",
    ] {
        let (status, body) = get(&f, &f.admin.did, vec![], path).await;
        assert_eq!(status, 200, "{path}: {body}");
    }
}

// Finding 5 — finishing one's own reservation needs no administrator.

#[tokio::test]
async fn finding_5_under_the_default_config_an_owner_adopts_their_own_reservation() {
    let f = fixture().await;
    assert!(GitNsConfig::default().elevated_requires_admin);
    let ns = bind_manual(&f).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await);
    let body = ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/adopt",
        json!({ "resource": "github.com/acme/gadgets", "owners": [f.bob.did] }),
    )
    .await);
    assert_eq!(body["repo"]["state"], "active");

    // Everything else elevated still needs an administrator by default.
    let out = send(
        &f.vtc.state,
        &f.bob,
        "repo/transfer",
        json!({ "resource": "github.com/acme/gadgets", "to": f.carol.did }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

// Finding 6 — an account link is for the right forge, and in time.

async fn link(f: &Fixture, who: &Party) -> String {
    ok(&send(
        &f.vtc.state,
        who,
        "account/link",
        json!({ "forge": "github.com" }),
    )
    .await)["linkId"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn link_state(f: &Fixture, who: &Party, id: String) -> Value {
    ok(&send(
        &f.vtc.state,
        who,
        "account/link-status",
        json!({ "linkId": id }),
    )
    .await)["state"]
        .clone()
}

#[tokio::test]
async fn finding_6_account_linked_is_refused_on_another_forge_or_after_expiry() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    let last_job = |f: &Fixture| f.bridge.jobs.lock().unwrap().last().unwrap().1["jobId"].clone();
    // Another forge's identity.
    let id = link(&f, &f.bob).await;
    let out = event(
        &f,
        &ns,
        json!({ "type": "accountLinked", "jobId": last_job(&f), "account": { "forge": "codeberg.org", "id": "1", "login": "bob" } }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    assert_eq!(link_state(&f, &f.bob, id).await, "failed");

    // After the attempt lapsed.
    let id = link(&f, &f.carol).await;
    let mut attempt = store::get_link(&f.vtc.state.git_ns.ks, &id)
        .await
        .unwrap()
        .unwrap();
    attempt.expires_at = "2020-01-01T00:00:00Z".parse().unwrap();
    store::put_link(&f.vtc.state.git_ns.ks, &attempt)
        .await
        .unwrap();
    let out = event(
        &f,
        &ns,
        json!({ "type": "accountLinked", "jobId": last_job(&f), "account": { "forge": "github.com", "id": "2", "login": "carol" } }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    assert_eq!(link_state(&f, &f.carol, id).await, "expired");
    let accounts = super::bridge::linked_accounts(&f.vtc.state).await.unwrap();
    assert!(accounts.is_empty());

    // A good link goes through the members write path: the member's other
    // extensions survive it.
    crate::members::storage::edit_member(&f.vtc.state.members_ks, &f.bob.did, |m| {
        m.extensions = json!({ "note": "kept" });
        true
    })
    .await
    .unwrap();
    let id = link(&f, &f.bob).await;
    ok(&event(
        &f,
        &ns,
        json!({ "type": "accountLinked", "jobId": last_job(&f), "account": { "forge": "github.com", "id": "3", "login": "bob" } }),
    )
    .await);
    assert_eq!(link_state(&f, &f.bob, id).await, "linked");
    let bob = crate::members::get_member(&f.vtc.state.members_ks, &f.bob.did)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bob.extensions["note"], "kept");
    assert_eq!(bob.extensions["forges"]["github.com"]["login"], "bob");
}

// Finding 7 — an expiring right never keeps the last-admin or last-owner rule.

#[tokio::test]
async fn finding_7_an_expiring_co_admin_or_co_owner_does_not_count_toward_the_last() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let later = "2099-01-01T00:00:00Z";
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/grant",
        json!({ "subject": f.carol.did, "right": "git.ns.admin", "resource": "github.com/acme", "expiresAt": later }),
    )
    .await);
    let out = send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.admin.did, "right": "git.ns.admin", "resource": "github.com/acme" }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:lastAdmin");

    ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/grant",
        json!({ "subject": f.carol.did, "right": "git.repo.own", "resource": res, "expiresAt": later }),
    )
    .await);
    let out = send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.bob.did, "right": "git.repo.own", "resource": res }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:lastOwner");
}

// Finding 8 — the departure sweep keeps the departed member's DID out of the log.

#[tokio::test]
async fn finding_8_departure_audit_rows_carry_no_plaintext_departed_did() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
    let before: std::collections::BTreeSet<Vec<u8>> = f
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.bob.did)
        .await
        .unwrap();
    assert!(super::lifecycle::sweep(&f.vtc.state).await.unwrap());
    let new: Vec<Value> = f
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
        .into_iter()
        .filter(|(k, _)| !before.contains(k))
        .map(|(_, v)| serde_json::from_slice(&v).unwrap())
        .collect();
    assert!(new.len() >= 2, "the revocation and the orphaning");
    for row in &new {
        assert!(
            !row.to_string().contains(&f.bob.did),
            "the departed member's DID in plaintext: {row}"
        );
        assert_eq!(row["actor_did_plain"], TEST_VTC_DID, "{row}");
    }
}

// Finding 9.

/// 9a — a name whose previous records are still being withdrawn cannot be
/// created or adopted again until they are gone.
#[tokio::test]
async fn finding_9a_create_and_adopt_wait_for_an_old_names_withdrawal() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
    let registry = MockRegistryClient::new();
    reconcile(&f, &registry).await;
    // Renamed on the forge: the old name is free there, but its records are
    // still in the registry until the projector withdraws them.
    ok(&event(
        &f,
        &ns,
        json!({ "type": "repoRenamed", "forgeId": "100", "from": "github.com/acme/widgets", "to": "github.com/acme/widgets-core" }),
    )
    .await);
    let create = json!({ "namespace": ns, "name": "widgets", "visibility": "public" });
    let out = send(&f.vtc.state, &f.admin, "repo/create", create.clone()).await;
    assert_eq!(code(&out), "unavailable");
    let out = send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/widgets", "owners": [f.carol.did] }),
    )
    .await;
    assert_eq!(code(&out), "unavailable");

    reconcile(&f, &registry).await;
    ok(&send(&f.vtc.state, &f.admin, "repo/create", create).await);
}

/// 9b — a later report naming the installation clears `installationRemoved`.
#[tokio::test]
async fn finding_9b_a_later_installation_report_clears_installation_removed() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    ok(&event(&f, &ns, json!({ "type": "installationRemoved" })).await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(snap.namespace(&ns).unwrap().installation_removed);
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({
            "namespace": ns,
            "event": { "type": "repoDeleted", "forgeId": "999", "resource": "github.com/acme/nothing" },
            "ext": { "org.openvtc.git-ns": { "namespace": { "installationId": "55120034" } } },
        }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(!snap.namespace(&ns).unwrap().installation_removed);
}

/// 9c — a result that lands while its job's send is in flight is not
/// overwritten by the dispatcher's write-back.
#[tokio::test]
async fn finding_9c_a_result_racing_the_send_survives_the_write_back() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await);
    *f.bridge.race.lock().unwrap() = Some(f.vtc.state.git_ns.jobs_ks.clone());
    super::bridge::dispatch_due(&f.vtc.state).await.unwrap();
    let create = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .find(|j| j.kind == super::bridge::JobKind::CreateRepo)
        .unwrap();
    assert_eq!(create.state, super::bridge::JobState::Succeeded);
    assert!(create.result.is_some());
}

/// 9e — a repository an unbind left behind is shown to administrators only.
#[tokio::test]
async fn finding_9e_detached_repositories_of_an_unbound_namespace_are_hidden_from_members() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let ns = snap.repo_at(&res).unwrap().namespace_id.clone();
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/unbind",
        json!({ "namespace": ns }),
    )
    .await);
    let bob = ok(&send(&f.vtc.state, &f.bob, "view", json!({})).await);
    assert_eq!(bob["repos"], json!([]));
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let admin = super::view::build(&snap, super::view::Viewer::Administrator, None);
    assert_eq!(admin["repos"].as_array().unwrap().len(), 1);
}

/// 9g — under the default policy an external signer may give up their own
/// right (the policy admits resignation for anyone).
#[tokio::test]
async fn finding_9g_an_external_signer_resigns_under_the_default_policy() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    // An external signer's row, as a community with a permissive policy
    // would have granted it.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let scope = Scope::Repo(snap.repo_at(&res).unwrap().id.clone());
    let mut set = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap();
    let mut row = set.rows[0].clone();
    row.subject = f.stranger.did.clone();
    row.right = super::model::Right::CommitSign;
    row.subject_was_member = false;
    set.rows.push(row);
    store::put_rights(&f.vtc.state.git_ns.ks, &scope, &set)
        .await
        .unwrap();
    let body = ok(&send(
        &f.vtc.state,
        &f.stranger,
        "right/revoke",
        json!({ "subject": f.stranger.did, "right": "git.commit.sign", "resource": res }),
    )
    .await);
    assert_eq!(body["revoked"]["subject"], json!(f.stranger.did));
}
