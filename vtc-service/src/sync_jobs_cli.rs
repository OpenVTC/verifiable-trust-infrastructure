//! Offline triage for the membership-sync queue.
//!
//! `vtc sync-jobs {list,retry,discard}` — direct fjall access to the
//! `sync_queue` keyspace, no running daemon and no auth ceremony (the
//! operator's filesystem access *is* the authority, same trust model as
//! `vtc acl` and `vtc admin invite`). Run on a **stopped** daemon — fjall
//! takes an exclusive lock, so these fail while the server holds the store
//! open. Not for TEE deployments (the store lives behind the vsock proxy
//! there).
//!
//! ## Why this is an offline surface
//!
//! A `Failed` sync job is terminal: the syncer skips it on every tick, boot
//! recovery rescues only `InFlight`, and nothing re-derives it. Until this
//! module the only operator surfaces were a bare count on
//! `/v1/health/diagnostics` and a line in the log, and there was no way at
//! all to act on one — the row sat until the retention sweeper purged it
//! ~30 days later, with the member still absent from the registry.
//!
//! The read half now also exists online, in `/v1/health/diagnostics`'s `ext`
//! envelope, which is where an operator will normally look. The *write* half
//! is here rather than on a REST route because binding a new
//! `spec/vtc/registry/…` Trust Task URI ahead of its upstream specification
//! is exactly what `tests/trust_task_manifest.rs` refuses
//! (`UNPUBLISHED_CANONICAL_OK`: "Author the spec upstream, or bind an
//! authority we control; raising this number is the wrong fix"). Break-glass
//! recovery on a stopped daemon needs no wire contract, and the VTA's
//! `vta approvals` / `vta policy` / `vta services` surfaces are the same
//! shape for the same reason.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use uuid::Uuid;
use vti_common::store::KeyspaceHandle;

use crate::config::AppConfig;
use crate::registry::{
    SyncJob, SyncJobState, delete_sync_job, get_sync_job, list_sync_jobs, store_sync_job,
};
use crate::store::{Store, keyspaces};
use vta_sdk::display_name::shorten_did;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Open the `sync_queue` keyspace on a stopped daemon.
fn open(config_path: Option<PathBuf>) -> Result<KeyspaceHandle, Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    Ok(store.keyspace(keyspaces::SYNC_QUEUE)?)
}

fn state_label(state: SyncJobState) -> &'static str {
    match state {
        SyncJobState::Pending => "pending",
        SyncJobState::InFlight => "in-flight",
        SyncJobState::Complete => "complete",
        SyncJobState::Failed => "FAILED",
    }
}

/// Reset a terminally-failed job so the syncer will dispatch it again.
///
/// The one mutation `retry` performs, factored out so it is the same code the
/// tests exercise.
///
/// `attempts` is reset to zero deliberately. The count is a budget against a
/// registry that would not answer; once the operator has changed something,
/// the old attempts describe a situation that no longer exists, and carrying
/// them over would let a retry against a still-broken registry exhaust the
/// budget on its first tick.
///
/// `rtbf_batched` deliberately survives: it records *why* the job was
/// scheduled when it was, and the RTBF timer identifies its own jobs by it.
/// Clearing it would hide an erasure-batched removal from the timer that is
/// meant to be holding it.
pub fn requeue(job: &mut SyncJob, now: DateTime<Utc>) {
    job.state = SyncJobState::Pending;
    job.attempts = 0;
    job.next_attempt_at = now;
    job.last_error = None;
}

/// `vtc sync-jobs list [--all]` — print the queue.
///
/// Defaults to `Failed` rows only, because those are the ones that need a
/// human: everything else is either moving or will move on its own.
pub async fn run_list(config_path: Option<PathBuf>, all: bool) -> CliResult {
    let ks = open(config_path)?;
    let mut jobs = list_sync_jobs(&ks).await?;
    if !all {
        jobs.retain(|j| j.state == SyncJobState::Failed);
    }

    if jobs.is_empty() {
        if all {
            println!("The membership-sync queue is empty.");
        } else {
            println!("No failed sync jobs. (Use --all to see pending and in-flight rows.)");
        }
        return Ok(());
    }

    // Newest failure first — a long list usually shares one cause, and the
    // most recent row carries the freshest error text.
    jobs.sort_by_key(|j| std::cmp::Reverse(j.last_attempted_at.unwrap_or(j.created_at)));

    println!(
        "{:<38} {:<10} {:<16} {:<8} MEMBER",
        "JOB ID", "STATE", "KIND", "ATTEMPTS"
    );
    for j in &jobs {
        println!(
            "{:<38} {:<10} {:<16} {:<8} {}",
            j.id,
            state_label(j.state),
            j.kind.as_str(),
            j.attempts,
            shorten_did(&j.member_did)
        );
        println!("    member: {}", j.member_did);
        if let Some(err) = &j.last_error {
            println!("    error:  {err}");
        }
        if let Some(at) = j.last_attempted_at {
            println!("    last attempt: {at}");
        }
    }

    let failed = jobs
        .iter()
        .filter(|j| j.state == SyncJobState::Failed)
        .count();
    if failed > 0 {
        println!();
        println!(
            "{failed} failed job(s). The syncer will not retry these on its own.\n\
             Fix the cause first, then `vtc sync-jobs retry --job-id <id>`.\n\
             An error naming `unsupportedType` means the deployed trust registry does not\n\
             route that Trust Task at all — upgrade the registry, then retry."
        );
    }
    Ok(())
}

/// `vtc sync-jobs retry` — reset one job, or every failed job, to
/// `Pending` for immediate dispatch.
///
/// This is the only thing that re-drives a terminally-failed row. The sync
/// cursor has long since advanced past the audit envelope that created it, so
/// nothing else will ever enqueue that work again — short of provoking a
/// fresh member event for the same DID.
pub async fn run_retry(
    config_path: Option<PathBuf>,
    job_id: Option<String>,
    all: bool,
) -> CliResult {
    if job_id.is_none() && !all {
        return Err("pass --job-id <id>, or --all to retry every failed job".into());
    }
    let ks = open(config_path)?;

    let targets: Vec<SyncJob> = match &job_id {
        Some(id) => {
            let uuid = Uuid::parse_str(id).map_err(|e| format!("not a job id: {e}"))?;
            match get_sync_job(&ks, uuid).await? {
                Some(j) => vec![j],
                None => {
                    return Err(format!(
                        "no sync job {id}. It may already have been retried, discarded, or \
                         purged by the retention sweeper."
                    )
                    .into());
                }
            }
        }
        None => list_sync_jobs(&ks)
            .await?
            .into_iter()
            .filter(|j| j.state == SyncJobState::Failed)
            .collect(),
    };

    if targets.is_empty() {
        println!("No failed sync jobs to retry.");
        return Ok(());
    }

    let now = Utc::now();
    let mut requeued = 0usize;
    for mut job in targets {
        // Only `Failed` rows are eligible. A pending or in-flight row belongs
        // to the syncer; resetting one would re-dispatch work already moving.
        if job.state != SyncJobState::Failed {
            println!(
                "skipping {} — state is {}, not failed (the syncer already owns it)",
                job.id,
                state_label(job.state)
            );
            continue;
        }
        requeue(&mut job, now);
        store_sync_job(&ks, &job).await?;
        requeued += 1;
        println!(
            "requeued {} ({} {})",
            job.id,
            job.kind.as_str(),
            job.member_did
        );
    }

    if requeued > 0 {
        println!();
        println!(
            "{requeued} job(s) requeued. Start the daemon; the syncer dispatches them on its \
             next tick."
        );
    }
    Ok(())
}

/// `vtc sync-jobs discard` — delete a failed job without dispatching it.
///
/// For a job that should never be retried — a member removed again since, or
/// a record an operator has already fixed at the registry by hand. The member
/// stays as the registry currently has them; discarding changes nothing
/// upstream.
pub async fn run_discard(config_path: Option<PathBuf>, job_id: String) -> CliResult {
    let ks = open(config_path)?;
    let uuid = Uuid::parse_str(&job_id).map_err(|e| format!("not a job id: {e}"))?;

    let Some(job) = get_sync_job(&ks, uuid).await? else {
        return Err(format!("no sync job {job_id}").into());
    };
    if job.state != SyncJobState::Failed {
        return Err(format!(
            "sync job {job_id} is {}, not failed — discarding a live row would drop work the \
             syncer is still doing.",
            state_label(job.state)
        )
        .into());
    }

    delete_sync_job(&ks, uuid).await?;
    println!(
        "discarded {} ({} {}).",
        job.id,
        job.kind.as_str(),
        job.member_did
    );
    println!(
        "The registry's record for this member is unchanged — it still reflects whatever was \
         last published, which for a failed publishMember is nothing at all."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::registry::SyncJobKind;
    use vti_common::config::StoreConfig;

    async fn temp_queue() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let queue = store.keyspace(keyspaces::SYNC_QUEUE).expect("keyspace");
        (queue, dir)
    }

    fn failed(kind: SyncJobKind, did: &str) -> SyncJob {
        let mut job = SyncJob::fresh(kind, did);
        job.state = SyncJobState::Failed;
        job.attempts = 17;
        job.last_error = Some(
            "permanent registry failure: registry rejected registry/record/put: unsupportedType"
                .into(),
        );
        job.next_attempt_at = Utc::now() + chrono::Duration::days(1);
        job
    }

    /// A requeued job comes back dispatchable with a clean attempt budget —
    /// `is_dispatchable` is the predicate the syncer's tick actually reads,
    /// so asserting on it is asserting the job will really move.
    #[tokio::test]
    async fn requeue_makes_a_failed_job_dispatchable() {
        let (ks, _dir) = temp_queue().await;
        let mut job = failed(SyncJobKind::PublishMember, "did:key:zMember");
        store_sync_job(&ks, &job).await.unwrap();

        requeue(&mut job, Utc::now());
        store_sync_job(&ks, &job).await.unwrap();

        let back = get_sync_job(&ks, job.id).await.unwrap().unwrap();
        assert_eq!(back.state, SyncJobState::Pending);
        assert_eq!(back.attempts, 0);
        assert!(back.last_error.is_none());
        assert!(back.is_dispatchable(Utc::now()));
    }

    /// `rtbf_batched` survives a requeue. It is how the RTBF timer recognises
    /// its own jobs; clearing it would hide an erasure-batched removal from
    /// the timer that is meant to be holding it.
    #[tokio::test]
    async fn requeue_preserves_the_rtbf_batch_marker() {
        let mut job = failed(SyncJobKind::MarkDeparted, "did:key:zGone");
        job.rtbf_batched = true;

        requeue(&mut job, Utc::now());

        assert!(job.rtbf_batched, "RTBF marker must survive a retry");
    }

    /// `--all` targets only terminal rows, so a job the syncer is still
    /// working never gets reset out from under it.
    #[tokio::test]
    async fn retry_all_targets_only_failed_rows() {
        let (ks, _dir) = temp_queue().await;
        let pending = SyncJob::fresh(SyncJobKind::UpdateMember, "did:key:zBusy");
        store_sync_job(&ks, &pending).await.unwrap();
        let mut in_flight = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zMid");
        in_flight.state = SyncJobState::InFlight;
        store_sync_job(&ks, &in_flight).await.unwrap();
        let dead = failed(SyncJobKind::PublishMember, "did:key:zDead");
        store_sync_job(&ks, &dead).await.unwrap();

        let targets: Vec<_> = list_sync_jobs(&ks)
            .await
            .unwrap()
            .into_iter()
            .filter(|j| j.state == SyncJobState::Failed)
            .collect();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, dead.id);
    }

    /// Discard refuses anything the syncer still owns.
    #[tokio::test]
    async fn discard_refuses_a_live_row() {
        let (ks, dir) = temp_queue().await;
        let mut in_flight = SyncJob::fresh(SyncJobKind::PublishMember, "did:key:zMid");
        in_flight.state = SyncJobState::InFlight;
        store_sync_job(&ks, &in_flight).await.unwrap();
        drop(ks);

        // `run_discard` opens the store itself, so this asserts the guard
        // through the real entry point rather than a re-implementation.
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "vtc_did = \"did:key:zVtc\"\n[store]\ndata_dir = \"{}\"\n",
                dir.path().display()
            ),
        )
        .unwrap();
        let err = run_discard(Some(config), in_flight.id.to_string())
            .await
            .expect_err("a live row must not be discardable");
        assert!(
            err.to_string().contains("in-flight"),
            "the refusal should name the state: {err}"
        );
    }
}
