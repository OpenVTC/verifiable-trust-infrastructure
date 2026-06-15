//! Audit-log tail walker — Phase 3 M3.3.
//!
//! Walks the `audit:` keyspace from a persisted cursor and
//! converts membership-affecting envelopes into [`SyncJob`]
//! rows. The cursor is the RFC3339 timestamp of the
//! last-processed envelope; a daemon restart picks up
//! exactly where the prior run left off (no double-enqueue,
//! no missed event).
//!
//! ## Why poll, not subscribe
//!
//! Plan §D3 traded latency for a clean separation: emitters
//! (the route handlers + the syncer task) never know about
//! each other. A future architecture could plumb an in-process
//! channel to drop tail latency below the audit-row write
//! latency, but the polling design wins on restart resilience
//! — the audit log IS the event source of truth, so cursor-
//! driven replay handles every "daemon crashed mid-flight"
//! scenario the same way.
//!
//! ## Which audit variants enqueue jobs
//!
//! - `MemberAdded` → `SyncJobKind::PublishMember`
//! - `MemberRemoved` → `SyncJobKind::DeleteMember` when
//!   disposition is `Purge`; `SyncJobKind::MarkDeparted`
//!   when `Tombstone` / `Historical`. (Disposition resolves
//!   at the emitter; we trust the `MemberRemovedData.disposition`
//!   field.)
//! - `RoleChanged` → `SyncJobKind::UpdateMember`. The role
//!   itself doesn't propagate to the registry record shape
//!   today — the registry-record `status` flips between
//!   `Active`/`Departed` only — but the `UpdateMember` job
//!   keeps the local mirror's `last_synced_at` fresh so drift
//!   detection has something to anchor against.
//!
//! Every other audit variant is ignored. Operator-action
//! envelopes (`ConfigChanged`, `AdminPasskeyRegistered`, etc.)
//! never reach the registry.

use chrono::{DateTime, Utc};
use tracing::{debug, warn};
use vti_common::audit::{AuditEnvelope, AuditEvent, MemberRemovedData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::model::{SyncJob, SyncJobKind};
use super::policy::{clamp_disposition, is_rtbf_purge, read_min_disposition};
use super::storage::store_sync_job;

/// Captured policy-override decision the walker discovered for
/// a single `MemberRemoved` envelope. The syncer turns each one
/// into a `RegistryRecordPolicyOverride` audit envelope after
/// the walk completes — keeping audit emission out of the
/// walker means the walker doesn't need the `AuditWriter`
/// directly, which keeps its async surface narrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideEvent {
    /// Member-DID acting on themselves; this is also the
    /// `target_did` of the envelope by RTBF construction
    /// (`actor == target`).
    pub actor_did: String,
    /// Same as `actor_did` for RTBF — the target the override
    /// applies to. Carried explicitly so future override
    /// reasons (Phase 4 legal-hold) can populate distinct
    /// actor/target pairs.
    pub target_did: String,
    /// Reason code for the override. Phase 3 only emits
    /// `"rtbf"`.
    pub reason: String,
    /// The disposition the active `registry.rego.min_disposition`
    /// would have clamped to. Captured so operators can audit
    /// the gap between "what policy said" and "what RTBF
    /// produced".
    pub attempted_disposition: String,
    /// The disposition the override actually applied. Always
    /// `"purge"` for RTBF in Phase 3.
    pub effective_disposition: String,
}

/// Outcome of one walk pass. `new_cursor` is the RFC3339
/// timestamp of the latest envelope inspected (Some unless the
/// audit log is empty); `jobs_enqueued` counts how many fresh
/// `SyncJob` rows landed; `overrides` enumerates RTBF override
/// events the syncer should turn into
/// `RegistryRecordPolicyOverride` audit envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalkOutcome {
    pub new_cursor: Option<DateTime<Utc>>,
    pub jobs_enqueued: usize,
    pub overrides: Vec<OverrideEvent>,
}

/// Walk audit envelopes since `cursor`. Returns the new cursor
/// + the number of jobs enqueued.
///
/// `cursor = None` walks from the start of the audit log
/// (first-boot path). Subsequent calls pass the previous
/// `new_cursor` back in.
///
/// The function is idempotent under concurrent runs only when
/// the caller serializes calls (typically the syncer's tick
/// loop holds exclusive access). A racy double-call could
/// enqueue duplicate jobs; the syncer's tick loop never runs
/// concurrently with itself, so this isn't a hazard in
/// production.
pub async fn walk(
    audit_ks: &KeyspaceHandle,
    sync_queue_ks: &KeyspaceHandle,
    policies_ks: &KeyspaceHandle,
    active_policies_ks: &KeyspaceHandle,
    rtbf_batch_window_hours: u64,
    cursor: Option<DateTime<Utc>>,
) -> Result<WalkOutcome, AppError> {
    // Seek past everything at-or-before the cursor instead of
    // re-scanning the whole audit log every tick (P3.8). Audit keys are
    // `<rfc3339-ts>:<event_id>`, which sort chronologically, so a
    // `<cursor-ts>:` lower bound skips the already-processed prefix. The
    // in-loop `timestamp <= cursor` filter below still handles the exact
    // boundary (several events can share a timestamp). First boot
    // (`cursor = None`) walks from the start.
    let pairs = match cursor {
        Some(c) => {
            let lower = format!("{}:", c.to_rfc3339()).into_bytes();
            audit_ks.range_from_raw(lower).await?
        }
        None => audit_ks.prefix_iter_raw(Vec::new()).await?,
    };
    let mut jobs_enqueued = 0_usize;
    let mut latest_seen = cursor;
    let mut overrides: Vec<OverrideEvent> = Vec::new();
    // Resolve once per walk — a policy upload between walks
    // takes effect on the next tick, which is the same
    // freshness `dispatch_one` gets for `publish_on_join`.
    let floor = read_min_disposition(policies_ks, active_policies_ks).await;

    for (key, value) in pairs {
        let envelope: AuditEnvelope = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    error = %err,
                    key = %String::from_utf8_lossy(&key),
                    "skipping unparseable audit envelope during tail walk"
                );
                continue;
            }
        };
        // Skip envelopes at-or-before the cursor. The cursor
        // semantic is "everything up to and including this
        // timestamp has been processed", so equality also
        // skips.
        if let Some(c) = cursor
            && envelope.timestamp <= c
        {
            continue;
        }
        // Track the latest-seen timestamp regardless of
        // whether we enqueue — cursor advances over rows we
        // chose not to enqueue (other audit variants), so a
        // future restart doesn't re-walk them.
        if latest_seen.is_none_or(|prev| envelope.timestamp > prev) {
            latest_seen = Some(envelope.timestamp);
        }
        if let Some((mut job, override_event)) = audit_to_sync_job(&envelope, floor.as_deref()) {
            // Derive the job id from the audit `event_id` (P3.8) — one
            // envelope maps to at most one job, so a re-walk after a
            // mid-walk store failure (cursor didn't advance) **overwrites**
            // the already-stored row at the same key instead of enqueuing
            // a fresh-UUID duplicate. Idempotent: exactly one job per
            // source envelope.
            job.id = envelope.event_id;
            // M3.7: park RTBF DeleteMember jobs by the batch
            // window. A non-RTBF DeleteMember (admin force-
            // purge) dispatches immediately — only RTBF gets
            // the de-correlation delay. Identified by the
            // walker having produced an OverrideEvent (the
            // only override reason in Phase 3 is RTBF).
            if override_event.is_some() && rtbf_batch_window_hours > 0 {
                job.next_attempt_at =
                    chrono::Utc::now() + chrono::Duration::hours(rtbf_batch_window_hours as i64);
                job.rtbf_batched = true;
            }
            store_sync_job(sync_queue_ks, &job).await?;
            jobs_enqueued += 1;
            debug!(
                job_id = %job.id,
                kind = job.kind.as_str(),
                did = %job.member_did,
                "enqueued sync job from audit envelope"
            );
            if let Some(ov) = override_event {
                overrides.push(ov);
            }
        }
    }

    Ok(WalkOutcome {
        new_cursor: latest_seen,
        jobs_enqueued,
        overrides,
    })
}

/// Convert an audit envelope into a `SyncJob` + an optional
/// `OverrideEvent` (RTBF). Returns `None` for variants that
/// don't drive registry mutations.
///
/// For `MemberRemoved`:
/// - Reads the envelope's `disposition`.
/// - Detects RTBF (`actor == target` + `purge`); if the
///   active `registry.rego.min_disposition` floor would
///   have clamped the purge to something with more
///   preservation, emits an `OverrideEvent` and keeps
///   `effective = "purge"`.
/// - Otherwise, applies [`clamp_disposition`] against the
///   floor and produces a SyncJob carrying the *effective*
///   (post-clamp) disposition. The `MemberRemovedData` audit
///   envelope itself retains the as-requested disposition;
///   the SyncJob carries the resolved one.
fn audit_to_sync_job(
    envelope: &AuditEnvelope,
    floor: Option<&str>,
) -> Option<(SyncJob, Option<OverrideEvent>)> {
    match &envelope.event {
        AuditEvent::MemberAdded(_data) => {
            let target = envelope.target_did_plain.as_deref()?;
            Some((SyncJob::fresh(SyncJobKind::PublishMember, target), None))
        }
        AuditEvent::MemberRemoved(MemberRemovedData { disposition, .. }) => {
            let target = envelope.target_did_plain.as_deref()?;
            let actor = envelope.actor_did_plain.as_deref().unwrap_or("");
            let requested = disposition.as_str();

            // RTBF override path: member self-purge bypasses
            // the min_disposition clamp. We only emit the
            // override audit envelope when the floor *would*
            // have clamped — otherwise the override is
            // semantically a no-op and emitting noise would
            // pollute the audit log.
            let is_rtbf = is_rtbf_purge(actor, target, requested);
            let (effective_disposition, override_event) = if is_rtbf {
                let clamp = clamp_disposition(requested, floor);
                if clamp.clamped {
                    let ov = OverrideEvent {
                        actor_did: actor.to_string(),
                        target_did: target.to_string(),
                        reason: "rtbf".to_string(),
                        attempted_disposition: clamp.effective.clone(),
                        effective_disposition: "purge".to_string(),
                    };
                    ("purge".to_string(), Some(ov))
                } else {
                    // RTBF + purge but the floor didn't clamp
                    // — just publish purge, no override
                    // envelope needed.
                    ("purge".to_string(), None)
                }
            } else {
                let clamp = clamp_disposition(requested, floor);
                (clamp.effective, None)
            };

            let mut job = match effective_disposition.as_str() {
                "purge" => SyncJob::fresh(SyncJobKind::DeleteMember, target),
                "tombstone" | "historical" => SyncJob::fresh(SyncJobKind::MarkDeparted, target),
                other => {
                    warn!(
                        disposition = other,
                        target = target,
                        "MemberRemoved with unknown effective disposition — defaulting to MarkDeparted"
                    );
                    SyncJob::fresh(SyncJobKind::MarkDeparted, target)
                }
            };
            job.disposition = Some(effective_disposition);
            Some((job, override_event))
        }
        AuditEvent::RoleChanged(_data) => {
            let target = envelope.target_did_plain.as_deref()?;
            Some((SyncJob::fresh(SyncJobKind::UpdateMember, target), None))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::model::SyncJobState;
    use crate::registry::storage::list_sync_jobs;
    use vti_common::audit::{
        AuditKeyStore, AuditWriter, JoinRequestData, MemberAddedData, MemberRemovedData,
        RoleChangedData,
    };
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    struct TestKs {
        audit: KeyspaceHandle,
        queue: KeyspaceHandle,
        policies: KeyspaceHandle,
        active_policies: KeyspaceHandle,
        writer: AuditWriter,
        _dir: tempfile::TempDir,
    }

    async fn temp_keyspaces() -> TestKs {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let audit_ks = store.keyspace("audit").unwrap();
        let audit_key_ks = store.keyspace("audit_key").unwrap();
        let sync_queue_ks = store.keyspace("sync_queue").unwrap();
        let policies_ks = store.keyspace("policies").unwrap();
        let active_policies_ks = store.keyspace("active_policies").unwrap();
        let key_store = AuditKeyStore::new(audit_key_ks);
        key_store.ensure_initial(&[0xAB; 32]).await.unwrap();
        let writer = AuditWriter::new(audit_ks.clone(), key_store);
        TestKs {
            audit: audit_ks,
            queue: sync_queue_ks,
            policies: policies_ks,
            active_policies: active_policies_ks,
            writer,
            _dir: dir,
        }
    }

    async fn install_registry_policy_with_floor(
        policies: &KeyspaceHandle,
        active: &KeyspaceHandle,
        floor: &str,
    ) {
        use crate::policy::{Policy, PolicyPurpose, set_active_policy_id, store_policy};
        use sha2::{Digest, Sha256};
        let src = format!(
            "package vtc.registry\nimport rego.v1\ndefault min_disposition := \"{floor}\"\n"
        );
        let sha: [u8; 32] = Sha256::digest(src.as_bytes()).into();
        let id = uuid::Uuid::new_v4();
        let policy = Policy {
            id,
            purpose: PolicyPurpose::Registry,
            rego_source: src,
            sha256: sha,
            activated_at: Some(chrono::Utc::now()),
            author_did: "did:key:test".into(),
            created_at: chrono::Utc::now(),
            version: 1,
        };
        store_policy(policies, &policy).await.unwrap();
        set_active_policy_id(active, PolicyPurpose::Registry, id)
            .await
            .unwrap();
    }

    async fn write_member_removed_by_self(
        writer: &AuditWriter,
        member_did: &str,
        disposition: &str,
    ) {
        // RTBF construction: actor == target.
        writer
            .write(
                member_did,
                Some(member_did),
                AuditEvent::MemberRemoved(MemberRemovedData {
                    disposition: disposition.into(),
                    reason: String::new(),
                }),
            )
            .await
            .unwrap();
    }

    async fn write_member_added(writer: &AuditWriter, target: &str) {
        writer
            .write(
                "did:webvh:vtc.example",
                Some(target),
                AuditEvent::MemberAdded(MemberAddedData {
                    role: "member".into(),
                    via_join_request_id: None,
                }),
            )
            .await
            .unwrap();
    }

    async fn write_member_removed(writer: &AuditWriter, target: &str, disposition: &str) {
        writer
            .write(
                "did:webvh:vtc.example",
                Some(target),
                AuditEvent::MemberRemoved(MemberRemovedData {
                    disposition: disposition.into(),
                    reason: String::new(),
                }),
            )
            .await
            .unwrap();
    }

    async fn write_role_changed(writer: &AuditWriter, target: &str) {
        writer
            .write(
                "did:webvh:vtc.example",
                Some(target),
                AuditEvent::RoleChanged(RoleChangedData {
                    previous_role: "member".into(),
                    new_role: "moderator".into(),
                }),
            )
            .await
            .unwrap();
    }

    async fn write_unrelated_envelope(writer: &AuditWriter) {
        writer
            .write(
                "did:webvh:vtc.example",
                None,
                AuditEvent::JoinRequestSubmitted(JoinRequestData {
                    request_id: "ignored".into(),
                    transport: "rest".into(),
                }),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enqueues_publish_for_member_added() {
        let t = temp_keyspaces().await;
        write_member_added(&t.writer, "did:key:zA").await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(outcome.jobs_enqueued, 1);
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, SyncJobKind::PublishMember);
        assert_eq!(jobs[0].member_did, "did:key:zA");
        assert_eq!(jobs[0].state, SyncJobState::Pending);
    }

    #[tokio::test]
    async fn member_removed_dispositions_map_to_correct_kinds() {
        let t = temp_keyspaces().await;
        // No registry policy installed → no floor → no clamp.
        write_member_removed(&t.writer, "did:key:zPurge", "purge").await;
        write_member_removed(&t.writer, "did:key:zTomb", "tombstone").await;
        write_member_removed(&t.writer, "did:key:zHist", "historical").await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(outcome.jobs_enqueued, 3);
        assert!(
            outcome.overrides.is_empty(),
            "no policy → no clamp → no overrides"
        );
        let mut jobs = list_sync_jobs(&t.queue).await.unwrap();
        jobs.sort_by(|a, b| a.member_did.cmp(&b.member_did));
        let by_did: std::collections::HashMap<_, _> = jobs
            .into_iter()
            .map(|j| (j.member_did.clone(), j))
            .collect();
        assert_eq!(by_did["did:key:zPurge"].kind, SyncJobKind::DeleteMember);
        assert_eq!(
            by_did["did:key:zPurge"].disposition.as_deref(),
            Some("purge")
        );
        assert_eq!(by_did["did:key:zTomb"].kind, SyncJobKind::MarkDeparted);
        assert_eq!(by_did["did:key:zHist"].kind, SyncJobKind::MarkDeparted);
    }

    #[tokio::test]
    async fn role_changed_enqueues_update_member() {
        let t = temp_keyspaces().await;
        write_role_changed(&t.writer, "did:key:zRole").await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(outcome.jobs_enqueued, 1);
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(jobs[0].kind, SyncJobKind::UpdateMember);
    }

    #[tokio::test]
    async fn unrelated_envelopes_are_ignored() {
        let t = temp_keyspaces().await;
        write_unrelated_envelope(&t.writer).await;
        write_member_added(&t.writer, "did:key:zA").await;
        write_unrelated_envelope(&t.writer).await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(outcome.jobs_enqueued, 1);
        // Cursor still advances over the unrelated rows so a
        // subsequent walk doesn't re-process them.
        assert!(outcome.new_cursor.is_some());
    }

    #[tokio::test]
    async fn cursor_advances_so_restart_is_idempotent() {
        let t = temp_keyspaces().await;
        write_member_added(&t.writer, "did:key:zA").await;
        let first = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(first.jobs_enqueued, 1);

        // Second walk with the prior cursor enqueues nothing.
        let second = walk(
            &t.audit,
            &t.queue,
            &t.policies,
            &t.active_policies,
            0,
            first.new_cursor,
        )
        .await
        .unwrap();
        assert_eq!(second.jobs_enqueued, 0);

        // New event after the cursor lands as a fresh job.
        write_member_added(&t.writer, "did:key:zB").await;
        let third = walk(
            &t.audit,
            &t.queue,
            &t.policies,
            &t.active_policies,
            0,
            first.new_cursor,
        )
        .await
        .unwrap();
        assert_eq!(third.jobs_enqueued, 1);
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[tokio::test]
    async fn rewalk_without_cursor_advance_overwrites_not_duplicates() {
        // P3.8: when a mid-walk store failure leaves the cursor unmoved,
        // the next tick re-walks the same envelopes. Job ids are derived
        // from the audit `event_id`, so the re-walk overwrites the same
        // rows — exactly one job per source envelope, no fresh-UUID
        // duplicates.
        let t = temp_keyspaces().await;
        write_member_added(&t.writer, "did:key:zA").await;
        write_member_added(&t.writer, "did:key:zB").await;

        let first = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(first.jobs_enqueued, 2);
        let ids1: std::collections::BTreeSet<_> = list_sync_jobs(&t.queue)
            .await
            .unwrap()
            .iter()
            .map(|j| j.id)
            .collect();
        assert_eq!(ids1.len(), 2);

        // Re-walk from the start (cursor never advanced).
        walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        let jobs2 = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(jobs2.len(), 2, "re-walk must overwrite, not duplicate");
        let ids2: std::collections::BTreeSet<_> = jobs2.iter().map(|j| j.id).collect();
        assert_eq!(
            ids1, ids2,
            "job ids are stable across re-walks (event_id-derived)"
        );
    }

    #[tokio::test]
    async fn empty_audit_log_yields_no_cursor() {
        let t = temp_keyspaces().await;
        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(outcome.jobs_enqueued, 0);
        assert!(outcome.new_cursor.is_none());
    }

    // ─── M3.6: RTBF override + min_disposition clamp ───────

    #[tokio::test]
    async fn min_disposition_clamps_non_rtbf_purge_up_to_floor() {
        let t = temp_keyspaces().await;
        install_registry_policy_with_floor(&t.policies, &t.active_policies, "tombstone").await;
        // Admin removes member with purge — not RTBF (admin
        // didn't ask for their own removal). Floor "tombstone"
        // (preservation 2) > purge (1) → clamp UP to tombstone.
        write_member_removed(&t.writer, "did:key:zMember", "purge").await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert!(
            outcome.overrides.is_empty(),
            "non-RTBF clamp must not produce overrides"
        );
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(
            jobs[0].kind,
            SyncJobKind::MarkDeparted,
            "purge clamped UP to tombstone → MarkDeparted job"
        );
        assert_eq!(jobs[0].disposition.as_deref(), Some("tombstone"));
    }

    #[tokio::test]
    async fn rtbf_purge_overrides_min_disposition_floor() {
        let t = temp_keyspaces().await;
        install_registry_policy_with_floor(&t.policies, &t.active_policies, "tombstone").await;
        // Member purges themselves. RTBF construction
        // (actor == target + purge) → bypass floor.
        write_member_removed_by_self(&t.writer, "did:key:zSelf", "purge").await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert_eq!(outcome.overrides.len(), 1);
        let ov = &outcome.overrides[0];
        assert_eq!(ov.actor_did, "did:key:zSelf");
        assert_eq!(ov.target_did, "did:key:zSelf");
        assert_eq!(ov.reason, "rtbf");
        assert_eq!(ov.attempted_disposition, "tombstone");
        assert_eq!(ov.effective_disposition, "purge");

        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(
            jobs[0].kind,
            SyncJobKind::DeleteMember,
            "RTBF override → DeleteMember, not MarkDeparted"
        );
        assert_eq!(jobs[0].disposition.as_deref(), Some("purge"));
    }

    #[tokio::test]
    async fn rtbf_purge_without_clamp_emits_no_override_envelope() {
        let t = temp_keyspaces().await;
        // Floor is purge (the default-policy value) — no
        // clamp would happen, so the override is moot.
        install_registry_policy_with_floor(&t.policies, &t.active_policies, "purge").await;
        write_member_removed_by_self(&t.writer, "did:key:zSelf", "purge").await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert!(
            outcome.overrides.is_empty(),
            "no clamp → no override envelope (avoid audit noise)"
        );
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(jobs[0].kind, SyncJobKind::DeleteMember);
    }

    #[tokio::test]
    async fn rtbf_batching_window_defers_dispatch() {
        let t = temp_keyspaces().await;
        install_registry_policy_with_floor(&t.policies, &t.active_policies, "tombstone").await;
        write_member_removed_by_self(&t.writer, "did:key:zSelf", "purge").await;

        // 24h batch window: the RTBF DeleteMember job lands with
        // next_attempt_at in the future and rtbf_batched=true.
        let outcome = walk(
            &t.audit,
            &t.queue,
            &t.policies,
            &t.active_policies,
            24,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.overrides.len(), 1);
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].rtbf_batched, "RTBF job must be marked batched");
        // next_attempt_at should be ~24h out — assert it's
        // beyond 23h to avoid clock-skew flake.
        let delta = jobs[0].next_attempt_at - chrono::Utc::now();
        assert!(
            delta.num_hours() >= 23,
            "next_attempt_at must be at least ~24h in the future, got {delta:?}"
        );
        assert!(
            !jobs[0].is_dispatchable(chrono::Utc::now()),
            "RTBF job must not be dispatchable until the window expires"
        );
        assert!(
            jobs[0].is_dispatchable(chrono::Utc::now() + chrono::Duration::hours(25)),
            "RTBF job must dispatch once the window expires"
        );
    }

    #[tokio::test]
    async fn rtbf_batching_window_zero_dispatches_immediately() {
        let t = temp_keyspaces().await;
        install_registry_policy_with_floor(&t.policies, &t.active_policies, "tombstone").await;
        write_member_removed_by_self(&t.writer, "did:key:zSelf", "purge").await;

        let _ = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert!(!jobs[0].rtbf_batched);
        assert!(
            jobs[0].is_dispatchable(chrono::Utc::now()),
            "with batching disabled, RTBF dispatches on the next tick"
        );
    }

    #[tokio::test]
    async fn non_rtbf_delete_is_not_batched() {
        let t = temp_keyspaces().await;
        // No policy → no clamp → non-RTBF purge stays purge,
        // no override event → walker doesn't apply the batch
        // delay even when batch_window > 0.
        write_member_removed(&t.writer, "did:key:zMember", "purge").await;

        let outcome = walk(
            &t.audit,
            &t.queue,
            &t.policies,
            &t.active_policies,
            24,
            None,
        )
        .await
        .unwrap();
        assert!(outcome.overrides.is_empty());
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert!(
            !jobs[0].rtbf_batched,
            "admin-initiated purge must not be subject to the RTBF batch delay"
        );
        assert!(
            jobs[0].is_dispatchable(chrono::Utc::now()),
            "non-RTBF DeleteMember must dispatch immediately"
        );
    }

    #[tokio::test]
    async fn member_self_tombstone_request_is_not_rtbf() {
        let t = temp_keyspaces().await;
        install_registry_policy_with_floor(&t.policies, &t.active_policies, "historical").await;
        // Member self-removes with tombstone (not purge) →
        // NOT an RTBF case. Clamp UP to historical.
        write_member_removed_by_self(&t.writer, "did:key:zSelf", "tombstone").await;

        let outcome = walk(&t.audit, &t.queue, &t.policies, &t.active_policies, 0, None)
            .await
            .unwrap();
        assert!(outcome.overrides.is_empty());
        let jobs = list_sync_jobs(&t.queue).await.unwrap();
        assert_eq!(jobs[0].kind, SyncJobKind::MarkDeparted);
        assert_eq!(jobs[0].disposition.as_deref(), Some("historical"));
    }
}
