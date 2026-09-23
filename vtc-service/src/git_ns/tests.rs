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
    assert_eq!(record["context"]["grantedBy"], TEST_VTC_DID);

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
