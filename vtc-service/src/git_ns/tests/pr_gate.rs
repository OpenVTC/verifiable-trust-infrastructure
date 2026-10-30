//! The pull-request gate end to end: a `git-ns/bridge/event/0.5`
//! `pullRequestOpened` in, a `git-ns/bridge/job/0.6` `closePullRequest` out
//! (request step 6 of the event, step 7 of the job).

use super::super::bridge::{JOB_TYPE, JobKind, JobState};
use super::*;

/// A policy allowing every member action, with `settings` as given.
fn gate_policy(settings: &str) -> String {
    format!(
        r#"package vtc.git_namespace

import rego.v1

settings := {settings}

default decision := {{"effect": "allow"}}
"#
    )
}

/// A bound bridge namespace with `widgets` active (Bob owns it, forge id
/// 100), Bob and Carol each with a linked account, and the pull-request
/// policy `settings`.
async fn gate_fixture(settings: &str) -> (Fixture, String) {
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, RES, "100").await;
    link_account(&f, &ns, &f.bob, "9120045", "bob-builds").await;
    link_account(&f, &ns, &f.carol, "5550001", "carol-c").await;
    activate_git_policy(&f, &gate_policy(settings)).await;
    (f, ns)
}

/// Make the fake list job 0.6 (`true`) or only 0.4 and 0.5 (`false`), and the
/// VTC forget what it answered before.
async fn take_v0_6(f: &Fixture, takes: bool) {
    *f.bridge.pre_v0_6.lock().unwrap() = !takes;
    forget_versions(f).await;
}

async fn forget_versions(f: &Fixture) {
    f.vtc
        .state
        .git_ns
        .jobs_ks
        .remove(format!("bridgever:{}", f.bridge_party.did))
        .await
        .unwrap();
}

fn acct(id: &str, login: &str) -> Value {
    json!({ "forge": "github.com", "id": id, "login": login })
}

const EVE: (&str, &str) = ("777", "eve-dev");
const BOB: (&str, &str) = ("9120045", "bob-builds");
const CAROL: (&str, &str) = ("5550001", "carol-c");

async fn pr_event(
    f: &Fixture,
    ns: &str,
    number: u64,
    action: &str,
    author: (&str, &str),
    actor: (&str, &str),
) -> TrustTaskOutcome {
    send_ver(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        "0.5",
        json!({
            "namespace": ns,
            "event": {
                "type": "pullRequestOpened",
                "forgeId": "100",
                "resource": RES,
                "number": number,
                "action": action,
                "author": acct(author.0, author.1),
                "actor": acct(actor.0, actor.1),
                "draft": false,
                "fromFork": true,
            },
        }),
    )
    .await
}

/// The `closePullRequest` jobs queued, in order.
async fn close_jobs(f: &Fixture) -> Vec<super::super::bridge::BridgeJob> {
    super::super::bridge::list_jobs(&f.vtc.state.git_ns.jobs_ks)
        .await
        .unwrap()
        .into_iter()
        .filter(|j| j.kind == JobKind::ClosePullRequest)
        .collect()
}

/// The details of every git-ns audit row with `action`.
async fn audited(f: &Fixture, action: &str) -> Vec<Option<String>> {
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
            out.push(d.detail);
        }
    }
    out
}

/// `bridge/event` and `bridge/result` are served at their current versions
/// only (`vgi-bridge` sends nothing older since v0.26.0); the administrator's
/// `bridge/job/list` at 0.4 only.
#[test]
fn bridge_events_and_results_are_served_at_their_current_version_only() {
    let served = super::super::tasks::served_uris();
    assert!(served.contains(&format!("{URI}/bridge/event/0.5").as_str()));
    for v in ["0.1", "0.2", "0.3", "0.4"] {
        assert!(
            !served.contains(&format!("{URI}/bridge/event/{v}").as_str()),
            "bridge/event {v} is still served"
        );
    }
    assert!(served.contains(&format!("{URI}/bridge/result/0.2").as_str()));
    assert!(!served.contains(&format!("{URI}/bridge/result/0.1").as_str()));
    assert!(served.contains(&format!("{URI}/bridge/job/list/0.4").as_str()));
    for v in ["0.1", "0.2", "0.3"] {
        assert!(
            !served.contains(&format!("{URI}/bridge/job/list/{v}").as_str()),
            "bridge/job/list {v} is still served"
        );
    }
}

#[tokio::test]
async fn an_outsiders_pull_request_is_closed_by_a_0_6_job_with_the_rendered_message() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "committers"}"#).await;
    take_v0_6(&f, true).await;
    ok(&pr_event(&f, &ns, 42, "opened", EVE, EVE).await);

    let jobs = close_jobs(&f).await;
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!(job.payload["kind"], "closePullRequest");
    assert_eq!(job.payload["repo"], RES);
    assert_eq!(job.payload["number"], 42);
    let msg = job.payload["message"].as_str().unwrap();
    assert!(msg.contains("eve-dev"), "{msg}");
    assert!(msg.contains("acme/widgets"), "{msg}");
    // Nothing from the VTC's records about anyone.
    assert!(!msg.contains("did:"), "{msg}");
    assert!(!msg.contains("committers"), "{msg}");
    let pr = job.pull_request.as_ref().unwrap();
    assert_eq!(pr.author_login, "eve-dev");
    assert_eq!(pr.level, "committers");
    // The generated job 0.6 type accepts it.
    serde_json::from_value::<vti_specs::git_ns::bridge::job::v0_6::Payload>(job.payload.clone())
        .unwrap();

    // A repeated event while the job is open queues nothing more.
    ok(&pr_event(&f, &ns, 42, "opened", EVE, EVE).await);
    assert_eq!(close_jobs(&f).await.len(), 1);

    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    let sent: Vec<(String, Value)> = f
        .bridge
        .types
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .zip(f.bridge.jobs.lock().unwrap().iter().map(|(_, p)| p.clone()))
        .collect();
    let (ty, _) = sent
        .iter()
        .find(|(_, p)| p["kind"] == "closePullRequest")
        .expect("the close was sent");
    assert_eq!(ty, JOB_TYPE);

    // `bridge/job/list/0.4` lists it with its pull request's number; 0.1 and
    // 0.2 are no longer served.
    for old in ["0.1", "0.2"] {
        let out = send_ver(
            &f.vtc.state,
            &f.admin,
            "bridge/job/list",
            old,
            json!({ "namespace": ns }),
        )
        .await;
        assert_eq!(code(&out), "unsupportedVersion", "bridge/job/list {old}");
    }
    let listed = ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "bridge/job/list",
        "0.4",
        json!({ "namespace": ns }),
    )
    .await);
    let jobs = listed["jobs"].as_array().unwrap();
    let close = jobs
        .iter()
        .find(|j| j["kind"] == "closePullRequest")
        .expect("0.4 lists the close");
    assert_eq!(close["number"], 42);
    assert_eq!(close["repo"], RES);
    assert!(
        jobs.iter()
            .filter(|j| j["kind"] != "closePullRequest")
            .all(|j| j.get("number").is_none()),
        "{listed}"
    );

    // The bridge reports it closed: one audit row, without a DID.
    ok(&send(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/result",
        json!({
            "jobId": job.job_id, "outcome": "succeeded",
            "steps": [
                { "step": "comment", "outcome": "applied" },
                { "step": "close", "outcome": "applied" },
            ],
        }),
    )
    .await);
    let rows = audited(&f, "gitNs.pullRequest.closed").await;
    assert_eq!(rows.len(), 1);
    let detail: Value = serde_json::from_str(rows[0].as_deref().unwrap()).unwrap();
    assert_eq!(
        detail,
        json!({ "number": 42, "author": "eve-dev", "level": "committers" })
    );
    let done = super::super::bridge::get_job(&f.vtc.state.git_ns.jobs_ks, &job.job_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.state, JobState::Succeeded);
}

#[tokio::test]
async fn owners_are_always_allowed_and_committers_pass_the_committers_level() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "committers"}"#).await;
    take_v0_6(&f, true).await;
    // Bob owns widgets.
    ok(&pr_event(&f, &ns, 1, "opened", BOB, BOB).await);
    // Carol is a member with no right there: closed.
    ok(&pr_event(&f, &ns, 2, "opened", CAROL, CAROL).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
    assert_eq!(close_jobs(&f).await[0].payload["number"], 2);
    // Given git.commit.sign, her next one stays open.
    ok(&grant(&f, &f.bob, &f.carol.did, "git.commit.sign", RES).await);
    ok(&pr_event(&f, &ns, 3, "opened", CAROL, CAROL).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
}

#[tokio::test]
async fn members_level_allows_a_linked_member_and_closes_the_unlinked() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "members"}"#).await;
    take_v0_6(&f, true).await;
    ok(&pr_event(&f, &ns, 1, "opened", CAROL, CAROL).await);
    assert!(close_jobs(&f).await.is_empty());
    ok(&pr_event(&f, &ns, 2, "opened", EVE, EVE).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
    // Dependabot is exempt by default, linked or not.
    ok(&pr_event(
        &f,
        &ns,
        3,
        "opened",
        ("49699333", "dependabot[bot]"),
        ("49699333", "dependabot[bot]"),
    )
    .await);
    assert_eq!(close_jobs(&f).await.len(), 1);
}

#[tokio::test]
async fn a_maintainers_reopen_is_an_override_and_anyone_elses_is_rechecked() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "maintainers"}"#).await;
    take_v0_6(&f, true).await;
    // Bob (an owner) reopens Eve's: left open.
    ok(&pr_event(&f, &ns, 7, "reopened", EVE, BOB).await);
    assert!(close_jobs(&f).await.is_empty());
    // Carol (no right) reopens it: Eve is checked again, and closed.
    ok(&pr_event(&f, &ns, 7, "reopened", EVE, CAROL).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
}

#[tokio::test]
async fn nothing_happens_under_anyone_or_on_a_repository_not_active_here() {
    // The shipped default: no gate.
    let f = fixture().await;
    let ns = bind_bridge(&f).await;
    adopt_with_forge_id(&f, RES, "100").await;
    take_v0_6(&f, true).await;
    ok(&pr_event(&f, &ns, 1, "opened", EVE, EVE).await);
    assert!(close_jobs(&f).await.is_empty());

    // A gate, but a repository the VTC does not record as active.
    activate_git_policy(&f, &gate_policy(r#"{"pr_open": "members"}"#)).await;
    let out = send_ver(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        "0.5",
        json!({
            "namespace": ns,
            "event": {
                "type": "pullRequestOpened", "forgeId": "999",
                "resource": "github.com/acme/elsewhere", "number": 5, "action": "opened",
                "author": acct(EVE.0, EVE.1), "actor": acct(EVE.0, EVE.1),
            },
        }),
    )
    .await;
    ok(&out);
    assert!(close_jobs(&f).await.is_empty());
}

#[tokio::test]
async fn a_per_repository_override_wins_over_the_community_level() {
    let (f, ns) = gate_fixture(
        r#"{"pr_open": "members", "pr_open_overrides": {"github.com/acme/widgets": "anyone"}}"#,
    )
    .await;
    take_v0_6(&f, true).await;
    ok(&pr_event(&f, &ns, 1, "opened", EVE, EVE).await);
    assert!(close_jobs(&f).await.is_empty());
}

#[tokio::test]
async fn a_bridge_without_job_0_6_is_sent_no_close_and_its_admins_are_told_once() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "members"}"#).await;
    // A bridge before `vgi-bridge` v0.26.0 (job 0.4 and 0.5 only), not asked
    // since it bound: the job is queued, and the dispatcher, asking, drops it.
    take_v0_6(&f, false).await;
    let sent_before = f.bridge.jobs.lock().unwrap().len();
    ok(&pr_event(&f, &ns, 1, "opened", EVE, EVE).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    let job = &close_jobs(&f).await[0];
    assert_eq!(job.state, JobState::Cancelled);
    assert!(
        job.last_error.as_deref().unwrap().contains("0.6"),
        "{:?}",
        job.last_error
    );
    assert!(
        f.bridge
            .jobs
            .lock()
            .unwrap()
            .iter()
            .all(|(_, p)| p["kind"] != "closePullRequest"),
        "a closePullRequest reached a bridge without job 0.6"
    );
    assert_eq!(
        audited(&f, "gitNs.pullRequest.gateUnenforced").await.len(),
        1
    );
    assert!(super::super::pr_gate::is_unenforced(&f.vtc.state, &ns).await);

    // Now the VTC knows: nothing is queued for the next one, and nobody is
    // told twice.
    ok(&pr_event(&f, &ns, 2, "opened", EVE, EVE).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
    assert_eq!(
        audited(&f, "gitNs.pullRequest.gateUnenforced").await.len(),
        1
    );

    // No other job goes to it either: the VTC sends job 0.6 only.
    super::super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    assert_eq!(f.bridge.jobs.lock().unwrap().len(), sent_before);

    // Upgraded, the gate works again — and a later loss is told again.
    take_v0_6(&f, true).await;
    ok(&pr_event(&f, &ns, 3, "opened", EVE, EVE).await);
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    assert!(
        f.bridge
            .jobs
            .lock()
            .unwrap()
            .iter()
            .any(|(_, p)| p["kind"] == "closePullRequest" && p["number"] == 3)
    );
    assert!(!super::super::pr_gate::is_unenforced(&f.vtc.state, &ns).await);
}

#[tokio::test]
async fn every_job_goes_as_0_6_to_a_bridge_that_lists_it() {
    let (f, _ns) = gate_fixture("{}").await;
    take_v0_6(&f, true).await;
    let before = f.bridge.types.lock().unwrap().len();
    super::super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    let types = f.bridge.types.lock().unwrap().clone();
    assert!(types.len() > before, "nothing was sent");
    assert!(types[before..].iter().all(|t| t == JOB_TYPE), "{types:?}");
}

/// An event at a version before 0.5 is refused: `vgi-bridge` has sent 0.5
/// since v0.26.0, and the VTC serves the current version only.
#[tokio::test]
async fn an_event_before_0_5_is_refused() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "members"}"#).await;
    let event = json!({
        "namespace": ns,
        "event": { "type": "protectionChanged", "forgeId": "100", "resource": RES, "requiredCheck": true },
    });
    for old in ["0.3", "0.4"] {
        let out = send_ver(
            &f.vtc.state,
            &f.bridge_party,
            "bridge/event",
            old,
            event.clone(),
        )
        .await;
        assert_eq!(code(&out), "unsupportedVersion", "bridge/event {old}");
    }
    ok(&send_ver(&f.vtc.state, &f.bridge_party, "bridge/event", "0.5", event).await);
}

// ── a suspended holder (vtc-action-list.md §8.2) ────────────────────────────

async fn suspend(f: &Fixture, who: &Party) {
    crate::acl::storage::put_suspension(
        &f.vtc.state.acl_ks,
        &who.did,
        &crate::acl::Suspension {
            action_id: "act-gate".into(),
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

/// While Bob's removal cools off, his ownership of `widgets` lets nothing
/// through: his own pull request is closed under `committers`, and his reopen
/// of somebody else's is no override. Nothing he holds is changed.
#[tokio::test]
async fn pr_gate_ignores_a_suspended_holders_rights() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "committers"}"#).await;
    take_v0_6(&f, true).await;
    ok(&pr_event(&f, &ns, 1, "opened", BOB, BOB).await);
    assert!(close_jobs(&f).await.is_empty(), "an owner, before");

    suspend(&f, &f.bob).await;
    ok(&pr_event(&f, &ns, 2, "opened", BOB, BOB).await);
    let closed = close_jobs(&f).await;
    assert_eq!(closed.len(), 1, "his ownership counts for nothing");
    assert_eq!(closed[0].payload["number"], 2);
    // His reopen of Eve's is no override: Eve is checked, and closed.
    ok(&pr_event(&f, &ns, 3, "reopened", EVE, BOB).await);
    assert_eq!(close_jobs(&f).await.len(), 2);
    // The rights are still recorded.
    let snap = Snapshot::load(&f.vtc.state.git_ns).await.unwrap();
    assert!(
        super::super::rules::effective_on(
            &snap,
            &f.bob.did,
            &super::super::model::Resource::parse(RES).unwrap(),
            super::super::ops::now()
        )
        .contains(&super::super::model::Right::RepoOwn)
    );
}

/// A suspended member's role counts for nothing under a `roles` level either.
#[tokio::test]
async fn pr_gate_ignores_a_suspended_holders_role() {
    let (f, ns) = gate_fixture(r#"{"pr_open": {"roles": ["member"]}}"#).await;
    take_v0_6(&f, true).await;
    ok(&pr_event(&f, &ns, 1, "opened", CAROL, CAROL).await);
    assert!(close_jobs(&f).await.is_empty());
    suspend(&f, &f.carol).await;
    ok(&pr_event(&f, &ns, 2, "opened", CAROL, CAROL).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
}

/// Cancelling the cooling-off counts it all again: his pull request stays
/// open and his reopen is an override once more.
#[tokio::test]
async fn pr_gate_counts_the_rights_again_after_cancel() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "committers"}"#).await;
    take_v0_6(&f, true).await;
    suspend(&f, &f.bob).await;
    ok(&pr_event(&f, &ns, 1, "opened", BOB, BOB).await);
    assert_eq!(close_jobs(&f).await.len(), 1);

    lift(&f, &f.bob).await;
    ok(&pr_event(&f, &ns, 2, "opened", BOB, BOB).await);
    ok(&pr_event(&f, &ns, 3, "reopened", EVE, BOB).await);
    assert_eq!(close_jobs(&f).await.len(), 1, "nothing more closed");
}
