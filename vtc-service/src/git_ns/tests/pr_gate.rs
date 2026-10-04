//! The pull-request gate end to end: a `git-ns/bridge/event/0.4`
//! `pullRequestOpened` in, a `git-ns/bridge/job/0.5` `closePullRequest` out
//! (request step 6 of the event, step 7 of the job).

use super::super::bridge::{JOB_TYPE, JOB_TYPE_V0_5, JobKind, JobState};
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

/// Make the fake list job 0.5 and the VTC forget what it answered before.
async fn take_v0_5(f: &Fixture) {
    *f.bridge.takes_v0_5.lock().unwrap() = true;
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
        "0.4",
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

#[test]
fn event_0_4_is_served_beside_the_earlier_versions() {
    let served = super::super::tasks::served_uris();
    for v in ["0.1", "0.2", "0.3", "0.4"] {
        assert!(
            served.contains(&format!("{URI}/bridge/event/{v}").as_str()),
            "bridge/event {v} is not served"
        );
    }
    for v in ["0.1", "0.2"] {
        assert!(
            served.contains(&format!("{URI}/bridge/job/list/{v}").as_str()),
            "bridge/job/list {v} is not served"
        );
    }
}

#[tokio::test]
async fn an_outsiders_pull_request_is_closed_by_a_0_5_job_with_the_rendered_message() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "committers"}"#).await;
    take_v0_5(&f).await;
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
    // The generated job 0.5 type accepts it.
    serde_json::from_value::<trust_tasks_rs::specs::git_ns::bridge::job::v0_5::Payload>(
        job.payload.clone(),
    )
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
    assert_eq!(ty, JOB_TYPE_V0_5);

    // `bridge/job/list` 0.1 cannot carry the kind and leaves it out — before
    // paging; 0.2 lists it with its pull request's number.
    let v1 = ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "bridge/job/list",
        "0.1",
        json!({ "namespace": ns }),
    )
    .await);
    let v1_jobs = v1["jobs"].as_array().unwrap();
    assert!(!v1_jobs.is_empty(), "{v1}");
    assert!(
        v1_jobs
            .iter()
            .all(|j| j["kind"] != "closePullRequest" && j.get("number").is_none()),
        "{v1}"
    );
    let v1_one = ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "bridge/job/list",
        "0.1",
        json!({ "namespace": ns, "limit": 1 }),
    )
    .await);
    assert_eq!(v1_one["jobs"].as_array().unwrap().len(), 1);
    assert_ne!(v1_one["jobs"][0]["kind"], "closePullRequest");
    let v2 = ok(&send_ver(
        &f.vtc.state,
        &f.admin,
        "bridge/job/list",
        "0.2",
        json!({ "namespace": ns }),
    )
    .await);
    let v2_jobs = v2["jobs"].as_array().unwrap();
    assert_eq!(v2_jobs.len(), v1_jobs.len() + 1, "{v2}");
    let close = v2_jobs
        .iter()
        .find(|j| j["kind"] == "closePullRequest")
        .expect("0.2 lists the close");
    assert_eq!(close["number"], 42);
    assert_eq!(close["repo"], RES);
    assert!(
        v2_jobs
            .iter()
            .filter(|j| j["kind"] != "closePullRequest")
            .all(|j| j.get("number").is_none()),
        "{v2}"
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
    take_v0_5(&f).await;
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
    take_v0_5(&f).await;
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
    take_v0_5(&f).await;
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
    take_v0_5(&f).await;
    ok(&pr_event(&f, &ns, 1, "opened", EVE, EVE).await);
    assert!(close_jobs(&f).await.is_empty());

    // A gate, but a repository the VTC does not record as active.
    activate_git_policy(&f, &gate_policy(r#"{"pr_open": "members"}"#)).await;
    let out = send_ver(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        "0.4",
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
    take_v0_5(&f).await;
    ok(&pr_event(&f, &ns, 1, "opened", EVE, EVE).await);
    assert!(close_jobs(&f).await.is_empty());
}

#[tokio::test]
async fn a_bridge_without_job_0_5_is_sent_no_close_and_its_admins_are_told_once() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "members"}"#).await;
    // The bridge has not been asked since it bound: the job is queued, and
    // the dispatcher, asking, drops it.
    forget_versions(&f).await;
    ok(&pr_event(&f, &ns, 1, "opened", EVE, EVE).await);
    assert_eq!(close_jobs(&f).await.len(), 1);
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    let job = &close_jobs(&f).await[0];
    assert_eq!(job.state, JobState::Cancelled);
    assert!(
        job.last_error.as_deref().unwrap().contains("0.5"),
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
        "a closePullRequest reached a bridge without job 0.5"
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

    // Every other job still goes out as 0.4.
    super::super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    assert!(f.bridge.types.lock().unwrap().iter().all(|t| t == JOB_TYPE));

    // Upgraded, the gate works again — and a later loss is told again.
    take_v0_5(&f).await;
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
async fn every_job_goes_as_0_5_to_a_bridge_that_lists_it() {
    let (f, _ns) = gate_fixture("{}").await;
    take_v0_5(&f).await;
    let before = f.bridge.types.lock().unwrap().len();
    super::super::bridge::project_roles(&f.vtc.state, true)
        .await
        .unwrap();
    super::super::bridge::dispatch_due(&f.vtc.state)
        .await
        .unwrap();
    let types = f.bridge.types.lock().unwrap().clone();
    assert!(types.len() > before, "nothing was sent");
    assert!(
        types[before..].iter().all(|t| t == JOB_TYPE_V0_5),
        "{types:?}"
    );
}

#[tokio::test]
async fn an_earlier_event_version_still_works_under_0_4() {
    let (f, ns) = gate_fixture(r#"{"pr_open": "members"}"#).await;
    // A 0.3 event type sent as 0.4.
    ok(&send_ver(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        "0.4",
        json!({
            "namespace": ns,
            "event": { "type": "protectionChanged", "forgeId": "100", "resource": RES, "requiredCheck": true },
        }),
    )
    .await);
    // And a 0.3 document still does.
    ok(&send_ver(
        &f.vtc.state,
        &f.bridge_party,
        "bridge/event",
        "0.3",
        json!({
            "namespace": ns,
            "event": { "type": "protectionChanged", "forgeId": "100", "resource": RES, "requiredCheck": true },
        }),
    )
    .await);
}
