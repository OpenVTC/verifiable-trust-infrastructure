#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;
use vti_common::audit::{
    AuditKeyStore, AuditWriter, MemberAddedData, MemberRemovedData, RoleChangedData,
};
use vti_common::config::StoreConfig;
use vti_common::store::Store;

const VTC: &str = "did:webvh:vtc.example";
const ALICE: &str = "did:webvh:alice.example";

struct TestKs {
    audit: KeyspaceHandle,
    queue: KeyspaceHandle,
    cursor: KeyspaceHandle,
    writer: AuditWriter,
    _dir: tempfile::TempDir,
}

async fn temp_keyspaces() -> TestKs {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
    })
    .expect("store");
    let audit = store.keyspace("audit").unwrap();
    let audit_key = store.keyspace("audit_key").unwrap();
    let queue = store.keyspace("hooks_queue").unwrap();
    let cursor = store.keyspace("hooks_cursor").unwrap();
    let key_store = AuditKeyStore::new(audit_key);
    key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
    let writer = AuditWriter::new(audit.clone(), key_store);
    TestKs {
        audit,
        queue,
        cursor,
        writer,
        _dir: dir,
    }
}

fn config() -> GitTrustHooksConfig {
    GitTrustHooksConfig {
        grant_on_role: BTreeMap::from([
            ("maintainer".to_string(), "openvtc".to_string()),
            ("committer".to_string(), "openvtc/openvtc".to_string()),
        ]),
        revoke_with_membership: true,
    }
}

/// Scripted mock: pops outcomes from a queue (default: Success) and records
/// every job it was asked to write.
#[derive(Default)]
struct MockWriter {
    outcomes: Mutex<VecDeque<Result<WriteOutcome, HookWriteError>>>,
    written: Mutex<Vec<HookJob>>,
}

impl MockWriter {
    fn script(&self, outcome: Result<WriteOutcome, HookWriteError>) {
        self.outcomes.lock().unwrap().push_back(outcome);
    }
    fn written(&self) -> Vec<HookJob> {
        self.written.lock().unwrap().clone()
    }
}

#[async_trait]
impl CapabilityWriter for MockWriter {
    async fn write(&self, job: &HookJob) -> Result<WriteOutcome, HookWriteError> {
        self.written.lock().unwrap().push(job.clone());
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(WriteOutcome::Success))
    }
}

fn relay(ks: &TestKs, writer: Arc<MockWriter>) -> HookRelay {
    HookRelay::new(
        ks.audit.clone(),
        ks.queue.clone(),
        ks.cursor.clone(),
        config(),
        writer,
    )
}

async fn add_member(ks: &TestKs, role: &str) {
    ks.writer
        .write(
            VTC,
            Some(ALICE),
            AuditEvent::MemberAdded(MemberAddedData {
                role: role.into(),
                via_join_request_id: None,
            }),
        )
        .await
        .unwrap();
}

// --- mapping ------------------------------------------------------------------

#[tokio::test]
async fn member_added_grants_only_mapped_roles() {
    let ks = temp_keyspaces().await;
    add_member(&ks, "maintainer").await;
    let writer = Arc::new(MockWriter::default());
    let relay = relay(&ks, writer.clone());

    relay.walk_audit_tail().await.unwrap();
    let jobs = list_jobs(&ks.queue).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].op, HookOp::Grant);
    assert_eq!(jobs[0].subject_did, ALICE);
    assert_eq!(jobs[0].resource, "openvtc");

    // Unmapped role produces nothing.
    let ks2 = temp_keyspaces().await;
    add_member(&ks2, "member").await;
    let relay2 = relay_for(&ks2);
    relay2.walk_audit_tail().await.unwrap();
    assert!(list_jobs(&ks2.queue).await.unwrap().is_empty());
}

fn relay_for(ks: &TestKs) -> HookRelay {
    relay(ks, Arc::new(MockWriter::default()))
}

#[tokio::test]
async fn role_change_enqueues_revoke_then_grant_in_order() {
    let ks = temp_keyspaces().await;
    ks.writer
        .write(
            VTC,
            Some(ALICE),
            AuditEvent::RoleChanged(RoleChangedData {
                previous_role: "committer".into(),
                new_role: "maintainer".into(),
            }),
        )
        .await
        .unwrap();
    let relay = relay_for(&ks);
    relay.walk_audit_tail().await.unwrap();

    let jobs = list_jobs(&ks.queue).await.unwrap();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].op, HookOp::Revoke);
    assert_eq!(jobs[0].resource, "openvtc/openvtc");
    assert_eq!(jobs[1].op, HookOp::Grant);
    assert_eq!(jobs[1].resource, "openvtc");
}

#[tokio::test]
async fn member_removed_revokes_every_mapped_resource() {
    let ks = temp_keyspaces().await;
    ks.writer
        .write(
            VTC,
            Some(ALICE),
            AuditEvent::MemberRemoved(MemberRemovedData {
                disposition: "tombstone".into(),
                reason: String::new(),
                prior_role: None,
            }),
        )
        .await
        .unwrap();
    let relay = relay_for(&ks);
    relay.walk_audit_tail().await.unwrap();

    let jobs = list_jobs(&ks.queue).await.unwrap();
    assert_eq!(jobs.len(), 2, "one revoke per distinct mapped resource");
    assert!(jobs.iter().all(|j| j.op == HookOp::Revoke));
}

// --- relay semantics ----------------------------------------------------------

#[tokio::test]
async fn tail_walk_is_cursor_deduplicated_and_dispatch_drains() {
    let ks = temp_keyspaces().await;
    add_member(&ks, "maintainer").await;
    let writer = Arc::new(MockWriter::default());
    let relay = relay(&ks, writer.clone());

    relay.walk_audit_tail().await.unwrap();
    relay.walk_audit_tail().await.unwrap(); // second walk: cursor blocks re-enqueue
    assert_eq!(list_jobs(&ks.queue).await.unwrap().len(), 1);

    relay.dispatch_due().await.unwrap();
    assert!(list_jobs(&ks.queue).await.unwrap().is_empty());
    assert_eq!(writer.written().len(), 1);
}

#[tokio::test]
async fn idempotent_success_completes_the_job() {
    let ks = temp_keyspaces().await;
    add_member(&ks, "maintainer").await;
    let writer = Arc::new(MockWriter::default());
    writer.script(Ok(WriteOutcome::IdempotentSuccess));
    let relay = relay(&ks, writer.clone());

    relay.walk_audit_tail().await.unwrap();
    relay.dispatch_due().await.unwrap();
    assert!(
        list_jobs(&ks.queue).await.unwrap().is_empty(),
        "already_granted/not_granted means the end state holds — job done"
    );
}

#[tokio::test]
async fn rejection_is_terminal_and_loud() {
    let ks = temp_keyspaces().await;
    add_member(&ks, "maintainer").await;
    let writer = Arc::new(MockWriter::default());
    writer.script(Ok(WriteOutcome::Rejected {
        code: "unsupportedType".into(),
        message: Some("git-trust is not enabled".into()),
    }));
    let relay = relay(&ks, writer.clone());

    relay.walk_audit_tail().await.unwrap();
    relay.dispatch_due().await.unwrap();

    let jobs = list_jobs(&ks.queue).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].state, HookJobState::Failed);
    assert!(jobs[0].last_error.as_deref().unwrap().contains("rejected"));
}

#[tokio::test]
async fn revokes_retry_past_the_grant_budget_grants_do_not() {
    let ks = temp_keyspaces().await;

    // A revoke that has already burned well past the grant budget…
    let mut revoke = HookJob::new(
        "seq-r".into(),
        HookOp::Revoke,
        ALICE.into(),
        "openvtc".into(),
        None,
        Utc::now(),
    );
    revoke.attempts = GRANT_MAX_ATTEMPTS + 5;
    store_job(&ks.queue, &revoke).await.unwrap();
    // …and a grant exactly one attempt from its budget.
    let mut grant = HookJob::new(
        "seq-g".into(),
        HookOp::Grant,
        ALICE.into(),
        "openvtc".into(),
        None,
        Utc::now(),
    );
    grant.attempts = GRANT_MAX_ATTEMPTS - 1;
    store_job(&ks.queue, &grant).await.unwrap();

    let writer = Arc::new(MockWriter::default());
    writer.script(Err(HookWriteError::Unreachable("registry down".into())));
    writer.script(Err(HookWriteError::Unreachable("registry down".into())));
    let relay = relay(&ks, writer.clone());
    relay.dispatch_due().await.unwrap();

    let jobs = list_jobs(&ks.queue).await.unwrap();
    let revoke_after = jobs.iter().find(|j| j.op == HookOp::Revoke).unwrap();
    let grant_after = jobs.iter().find(|j| j.op == HookOp::Grant).unwrap();
    assert_eq!(
        revoke_after.state,
        HookJobState::Pending,
        "revocation is delivery-critical: it retries indefinitely"
    );
    assert!(revoke_after.next_attempt_at > Utc::now());
    assert_eq!(
        grant_after.state,
        HookJobState::Failed,
        "grants exhaust their retry budget"
    );
}

#[tokio::test]
async fn boot_recovery_flips_in_flight_back_to_pending() {
    let ks = temp_keyspaces().await;
    let mut job = HookJob::new(
        "seq-x".into(),
        HookOp::Grant,
        ALICE.into(),
        "openvtc".into(),
        None,
        Utc::now(),
    );
    job.state = HookJobState::InFlight;
    store_job(&ks.queue, &job).await.unwrap();

    let relay = relay_for(&ks);
    relay.recover_in_flight().await.unwrap();
    let jobs = list_jobs(&ks.queue).await.unwrap();
    assert_eq!(jobs[0].state, HookJobState::Pending);
}
