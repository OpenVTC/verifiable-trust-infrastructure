//! The online operator surface for the trust-registry reconciler.
//!
//! Four administrator verbs, one per Trust Task in the
//! `vtc/registry/{sync-jobs,records}` family
//! (trustoverip/dtgwg-trust-tasks-tf#460), each a signed document served by
//! the spine on every transport (`trust_tasks::admin_tasks`); none has a
//! REST route:
//!
//! - `sync-jobs/list`    — what is queued, and what failed
//! - `sync-jobs/retry`   — requeue an abandoned job
//! - `sync-jobs/discard` — drop one that should not be
//! - `records/list`      — enumerate every trust record under our authority
//!
//! ## Why these exist here rather than only on the CLI
//!
//! `vtc sync-jobs …` already does all of this offline, and did first, because
//! binding a Trust Task URI ahead of its upstream specification is what
//! `tests/trust_task_manifest.rs` refuses. Now that the specs are published the
//! constraint is lifted, and the offline surface stays: it is the break-glass
//! path for a daemon that will not start, which is exactly when an HTTP route
//! is useless.
//!
//! The two must not drift. `retry` and `discard` both go through
//! [`crate::sync_jobs_cli::requeue`] and the same eligibility rule the CLI
//! applies, so "only a `Failed` row may move" is written once.

use tracing::info;
use uuid::Uuid;

use vti_common::error::AppError;

use trust_tasks_rs::specs::vtc::registry::records::list as records_list;
use trust_tasks_rs::specs::vtc::registry::sync_jobs::{
    discard as discard_spec, list as list_spec, retry as retry_spec,
};

use crate::registry::{
    RegistryRecord, RegistryStatus, SyncJob, SyncJobKind, SyncJobState, delete_sync_job,
    get_sync_job, list_records, list_sync_jobs, store_sync_job,
};
use crate::server::AppState;
use crate::sync_jobs_cli::requeue;

/// Page size when the caller names none. The spec clamps to 1..=200.
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;

fn clamp(limit: Option<std::num::NonZeroU64>) -> usize {
    limit.map_or(DEFAULT_LIMIT, |n| (n.get() as usize).clamp(1, MAX_LIMIT))
}

// ---------------------------------------------------------------------------
// sync-jobs/list
// ---------------------------------------------------------------------------

fn state_wire(state: SyncJobState) -> Option<list_spec::v0_1::State> {
    match state {
        SyncJobState::Pending => Some(list_spec::v0_1::State::Pending),
        SyncJobState::InFlight => Some(list_spec::v0_1::State::InFlight),
        SyncJobState::Failed => Some(list_spec::v0_1::State::Failed),
        // `Complete` rows are deleted rather than listed, so the published
        // vocabulary has no word for one. A row seen in this state is
        // mid-deletion; omitting it is honest, and inventing a fourth enum
        // member would put a value on the wire no consumer can handle.
        SyncJobState::Complete => None,
    }
}

/// The registry's error text, fitted to the schema's 1024-character bound.
///
/// Truncated rather than refused. The bound exists because the string comes
/// from outside this community, and a registry that answers with something
/// enormous must not be able to make a row unrenderable — dropping the tail of
/// a diagnostic costs an operator a little context, while failing the whole
/// response costs them the queue. The marker says which happened, so nobody
/// reads a cut-off message as the registry's complete answer.
fn last_error_wire(err: &str) -> Result<list_spec::v0_1::JobLastError, AppError> {
    const MAX: usize = 1024;
    const MARKER: &str = "… (truncated)";
    let fitted = if err.chars().count() <= MAX {
        err.to_string()
    } else {
        let keep = MAX - MARKER.chars().count();
        err.chars().take(keep).collect::<String>() + MARKER
    };
    list_spec::v0_1::JobLastError::try_from(fitted)
        .map_err(|e| AppError::Internal(format!("last error does not fit its schema: {e}")))
}

fn kind_wire(kind: SyncJobKind) -> list_spec::v0_1::Kind {
    match kind {
        SyncJobKind::PublishMember => list_spec::v0_1::Kind::PublishMember,
        SyncJobKind::UpdateMember => list_spec::v0_1::Kind::UpdateMember,
        SyncJobKind::DeleteMember => list_spec::v0_1::Kind::DeleteMember,
        SyncJobKind::MarkDeparted => list_spec::v0_1::Kind::MarkDeparted,
    }
}

/// Render one queue row as the published `Job`.
///
/// `nextAttemptAt` is omitted on a failed job: the spec forbids giving one a
/// schedule it does not have, and the stored row keeps a stale value from its
/// last backoff.
fn job_wire(job: &SyncJob, retention_days: u32) -> Result<list_spec::v0_1::Job, AppError> {
    let state = state_wire(job.state)
        .ok_or_else(|| AppError::Internal("a Complete sync job reached the list surface".into()))?;
    let gave_up = job.last_attempted_at.unwrap_or(job.created_at);
    let mut builder = list_spec::v0_1::Job::builder()
        .job_id(job.id.to_string())
        .kind(kind_wire(job.kind))
        .member_did(job.member_did.clone())
        .state(state)
        .attempts(u64::from(job.attempts))
        .created_at(job.created_at)
        .last_attempted_at(job.last_attempted_at)
        .purge_due_at(Some(
            gave_up + chrono::Duration::days(i64::from(retention_days)),
        ));
    if job.state != SyncJobState::Failed {
        builder = builder.next_attempt_at(Some(job.next_attempt_at));
    }
    if let Some(err) = &job.last_error {
        builder = builder.last_error(Some(last_error_wire(err)?));
    }
    builder
        .try_into()
        .map_err(|e| AppError::Internal(format!("sync job does not fit its schema: {e}")))
}

/// `vtc/registry/sync-jobs/list/0.1`.
pub(crate) async fn sync_jobs_list(
    state: &AppState,
    q: list_spec::v0_1::Payload,
) -> Result<list_spec::v0_1::Response, AppError> {
    let want = match q.state {
        None => None,
        Some(list_spec::v0_1::State::Pending) => Some(SyncJobState::Pending),
        Some(list_spec::v0_1::State::InFlight) => Some(SyncJobState::InFlight),
        Some(list_spec::v0_1::State::Failed) => Some(SyncJobState::Failed),
        // `#[non_exhaustive]`: a later spec release may name a state this
        // build cannot map onto a stored row. Refusing names it rather than
        // silently returning the wrong page.
        Some(other) => {
            return Err(AppError::Validation(format!(
                "state `{other:?}` is in the specification but not served by this build"
            )));
        }
    };

    let retention_days = { state.config.read().await.join_requests.retention_days };
    let mut jobs = list_sync_jobs(&state.sync_queue_ks).await?;
    // Never list a Complete row: it is mid-deletion and has no wire spelling.
    jobs.retain(|j| j.state != SyncJobState::Complete);
    if let Some(want) = want {
        jobs.retain(|j| j.state == want);
    }
    // Stable order so the cursor enumerates without repeating or skipping —
    // `created_at` alone is not unique, so the id breaks ties.
    jobs.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));

    let start = match &q.cursor {
        None => 0,
        Some(c) => {
            let after =
                Uuid::parse_str(c).map_err(|_| AppError::Validation("malformed cursor".into()))?;
            jobs.iter().position(|j| j.id == after).map_or(0, |i| i + 1)
        }
    };
    let limit = clamp(q.limit);
    let page: Vec<_> = jobs.iter().skip(start).take(limit).collect();
    let next_cursor = (start + page.len() < jobs.len())
        .then(|| page.last().map(|j| j.id.to_string()))
        .flatten();

    let items = page
        .iter()
        .map(|j| job_wire(j, retention_days))
        .collect::<Result<Vec<_>, _>>()?;

    let response: list_spec::v0_1::Response = list_spec::v0_1::Response::builder()
        .items(items)
        .next_cursor(next_cursor)
        .try_into()
        .map_err(|e| AppError::Internal(format!("list response does not fit its schema: {e}")))?;
    Ok(response)
}

// ---------------------------------------------------------------------------
// sync-jobs/retry
// ---------------------------------------------------------------------------

/// `vtc/registry/sync-jobs/retry/0.1`, by `actor`.
pub(crate) async fn sync_jobs_retry(
    state: &AppState,
    actor: &str,
    body: retry_spec::v0_1::Payload,
) -> Result<retry_spec::v0_1::Response, AppError> {
    // The payload is an untagged enum admitting exactly one of the two
    // members, so the discriminator is decided by serde rather than by a
    // branch here that could get it wrong.
    let targets: Vec<SyncJob> = match &body {
        retry_spec::v0_1::Payload::Variant0 { job_id, .. } => {
            let id = Uuid::parse_str(job_id)
                .map_err(|_| AppError::Validation("jobId is not an identifier".into()))?;
            get_sync_job(&state.sync_queue_ks, id)
                .await?
                .into_iter()
                .collect()
        }
        retry_spec::v0_1::Payload::Variant1 { .. } => list_sync_jobs(&state.sync_queue_ks)
            .await?
            .into_iter()
            .filter(|j| j.state == SyncJobState::Failed)
            .collect(),
        // `#[non_exhaustive]`: a future spec release could add a third way to
        // name what to retry. Refusing is the only safe default — guessing
        // which of the existing two it resembles could turn a narrow request
        // into a bulk requeue.
        _ => {
            return Err(AppError::Validation(
                "this retry payload is in the specification but not served by this build".into(),
            ));
        }
    };

    // A named job that no longer exists is `notFound`, not an error: it may
    // have been retried, discarded, or swept between the operator reading the
    // list and pressing the button, and that race is ordinary.
    let named_missing = match &body {
        retry_spec::v0_1::Payload::Variant0 { job_id, .. } if targets.is_empty() => {
            Some(job_id.to_string())
        }
        _ => None,
    };

    let now = chrono::Utc::now();
    let mut requeued = Vec::new();
    let mut skipped = Vec::new();

    if let Some(id) = named_missing {
        skipped.push(
            retry_spec::v0_1::Skipped::builder()
                .job_id(id)
                .reason(retry_spec::v0_1::SkippedReason::NotFound)
                .try_into()
                .map_err(|e| AppError::Internal(format!("skip does not fit its schema: {e}")))?,
        );
    }

    for mut job in targets {
        if job.state != SyncJobState::Failed {
            skipped.push(
                retry_spec::v0_1::Skipped::builder()
                    .job_id(job.id.to_string())
                    .reason(retry_spec::v0_1::SkippedReason::NotFailed)
                    .try_into()
                    .map_err(|e| {
                        AppError::Internal(format!("skip does not fit its schema: {e}"))
                    })?,
            );
            continue;
        }
        // The same mutation `vtc sync-jobs retry` applies, so the two surfaces
        // cannot disagree about what a retry does.
        requeue(&mut job, now);
        store_sync_job(&state.sync_queue_ks, &job).await?;
        info!(
            job_id = %job.id,
            did = %job.member_did,
            kind = job.kind.as_str(),
            %actor,
            "sync job requeued by an operator",
        );
        requeued.push(
            retry_spec::v0_1::Requeued::builder()
                .job_id(job.id.to_string())
                .member_did(Some(
                    retry_spec::v0_1::RequeuedMemberDid::try_from(job.member_did.clone()).map_err(
                        |e| AppError::Internal(format!("member did does not fit its schema: {e}")),
                    )?,
                ))
                .try_into()
                .map_err(|e| AppError::Internal(format!("requeue does not fit its schema: {e}")))?,
        );
    }

    let response: retry_spec::v0_1::Response = retry_spec::v0_1::Response::builder()
        .requeued(requeued)
        .skipped(skipped)
        .try_into()
        .map_err(|e| AppError::Internal(format!("retry response does not fit its schema: {e}")))?;
    Ok(response)
}

// ---------------------------------------------------------------------------
// sync-jobs/discard
// ---------------------------------------------------------------------------

/// `vtc/registry/sync-jobs/discard/0.1`, by `actor`.
pub(crate) async fn sync_jobs_discard(
    state: &AppState,
    actor: &str,
    body: discard_spec::v0_1::Payload,
) -> Result<discard_spec::v0_1::Response, AppError> {
    let id = Uuid::parse_str(&body.job_id)
        .map_err(|_| AppError::Validation("jobId is not an identifier".into()))?;

    let Some(job) = get_sync_job(&state.sync_queue_ks, id).await? else {
        return Err(AppError::NotFound(format!("no sync job {}", *body.job_id)));
    };
    // Single-target and irreversible, so unlike retry this refuses rather than
    // reports: there is no partial outcome to describe.
    if job.state != SyncJobState::Failed {
        return Err(AppError::Conflict(format!(
            "sync job {} is not in the terminal failed state — discarding a live row would drop \
             work the reconciler is still doing",
            *body.job_id
        )));
    }

    delete_sync_job(&state.sync_queue_ks, id).await?;
    info!(
        job_id = %job.id,
        did = %job.member_did,
        kind = job.kind.as_str(),
        %actor,
        "sync job discarded by an operator — the registry's record for this member is unchanged",
    );

    let response: discard_spec::v0_1::Response = discard_spec::v0_1::Response::builder()
        .job_id(job.id.to_string())
        .member_did(job.member_did.clone())
        .try_into()
        .map_err(|e| {
            AppError::Internal(format!("discard response does not fit its schema: {e}"))
        })?;
    Ok(response)
}

// ---------------------------------------------------------------------------
// records/list
// ---------------------------------------------------------------------------

/// One trust record, before it is filtered and cut to a page.
///
/// Every record this community has under its authority, whatever its kind:
/// a member's recognition (`recognise` on `trust-graph`) and each git right
/// the git-namespace projection publishes (an authorization under the right's
/// own action string, on the namespace or repository it covers). Until these
/// were one list, the operator's Recognition page showed the memberships
/// alone, and the git rights the Repos page reports as published were nowhere
/// to be checked against the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordRow {
    entity_id: String,
    authority_id: String,
    action: String,
    resource: String,
    record_type: String,
    recognized: Option<bool>,
    authorized: Option<bool>,
}

impl RecordRow {
    /// A member's recognition, as the membership mirror holds it.
    fn membership(r: &RegistryRecord, authority: &str) -> Self {
        Self {
            entity_id: r.member_did.clone(),
            authority_id: authority.to_string(),
            action: crate::registry::RECOGNISE_ACTION.to_string(),
            resource: crate::registry::TRUST_GRAPH_RESOURCE.to_string(),
            record_type: "recognition".to_string(),
            recognized: Some(r.status == RegistryStatus::Active),
            authorized: None,
        }
    }

    /// A TRQP `TrustRecord` (snake_case, as `registry/record/query` answers
    /// and `registry/record/put` writes). `None` when a required member is
    /// missing or empty: such a record cannot be stated in the response
    /// schema, and inventing a value for it would misreport the registry.
    fn from_trqp(v: &serde_json::Value) -> Option<Self> {
        let text = |k: &str| {
            v.get(k)
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Some(Self {
            entity_id: text("entity_id")?,
            authority_id: text("authority_id")?,
            action: text("action")?,
            resource: text("resource")?,
            record_type: text("record_type")?,
            recognized: v.get("recognized").and_then(serde_json::Value::as_bool),
            authorized: v.get("authorized").and_then(serde_json::Value::as_bool),
        })
    }

    fn key(&self) -> (&str, &str, &str) {
        (&self.entity_id, &self.action, &self.resource)
    }

    fn wire(&self) -> Result<records_list::v0_1::Record, AppError> {
        records_list::v0_1::Record::builder()
            .entity_id(self.entity_id.clone())
            .authority_id(self.authority_id.clone())
            .action(self.action.clone())
            .resource(self.resource.clone())
            .record_type(self.record_type.clone())
            .recognized(self.recognized)
            .authorized(self.authorized)
            .try_into()
            .map_err(|e| AppError::Internal(format!("record does not fit its schema: {e}")))
    }
}

/// The cursor is the last row's `(entity, action, resource)`, JSON-encoded
/// and base64url'd: opaque to the caller, unambiguous whatever characters the
/// three parts hold, and resumable even when that row has since gone (the
/// page restarts after where it would have sorted).
fn encode_cursor(row: &RecordRow) -> String {
    use base64::Engine as _;
    let (e, a, r) = row.key();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&[e, a, r]).unwrap_or_default())
}

fn decode_cursor(cursor: &str) -> Result<(String, String, String), AppError> {
    use base64::Engine as _;
    let bad = || AppError::Validation("`cursor` is not one this list issued".into());
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| bad())?;
    let [e, a, r]: [String; 3] = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    Ok((e, a, r))
}

/// `vtc/registry/records/list/0.1`.
pub(crate) async fn records_list(
    state: &AppState,
    q: records_list::v0_1::Payload,
) -> Result<records_list::v0_1::Response, AppError> {
    // The specification's default: a caller who did not think about it gets
    // the authoritative view, not the community's own belief about it.
    let source = q.source.unwrap_or(records_list::v0_1::Source::Registry);

    let client = state
        .registry_client
        .as_deref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "no trust registry is configured for this community".into(),
        })?;
    let authority = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_default();

    let mut rows: Vec<RecordRow> = match source {
        // Never served from the mirrors. A stale local answer presented as
        // the registry's is the exact fault this surface exists to detect, so
        // an unreachable registry is an error rather than a substitution.
        records_list::v0_1::Source::Registry => client
            .list_all_trust_records()
            .await?
            .iter()
            .filter_map(RecordRow::from_trqp)
            .collect(),
        // What this community believes it published: the membership mirror
        // and the git-namespace projection's mirror, each rendered as the
        // record its writer puts.
        records_list::v0_1::Source::Local => {
            let mut rows: Vec<RecordRow> = list_records(&state.registry_records_ks)
                .await?
                .iter()
                .map(|r| RecordRow::membership(r, &authority))
                .collect();
            rows.extend(
                crate::git_ns::projection::published(state)
                    .await?
                    .values()
                    .filter_map(|p| RecordRow::from_trqp(&p.tuple.record(&authority))),
            );
            rows
        }
        // The enum is `#[non_exhaustive]`, so a future spec release can add a
        // view this build does not serve. Refusing names it instead of
        // silently answering from whichever arm happened to be first.
        other => {
            return Err(AppError::Validation(format!(
                "source `{other:?}` is in the specification but not served by this build"
            )));
        }
    };

    // The four key filters, applied to every row alike.
    rows.retain(|r| {
        q.entity_id
            .as_ref()
            .is_none_or(|e| r.entity_id == e.as_str())
            && q.authority_id
                .as_ref()
                .is_none_or(|a| r.authority_id == a.as_str())
            && q.action.as_ref().is_none_or(|a| r.action == a.as_str())
            && q.resource.as_ref().is_none_or(|x| r.resource == x.as_str())
    });

    rows.sort_by(|a, b| a.key().cmp(&b.key()));
    // A record the registry somehow states twice is listed once.
    rows.dedup_by(|a, b| a.key() == b.key());

    let start = match &q.cursor {
        None => 0,
        Some(c) => {
            let (e, a, r) = decode_cursor(c)?;
            let after = (e.as_str(), a.as_str(), r.as_str());
            rows.partition_point(|row| row.key() <= after)
        }
    };
    let limit = clamp(q.limit);
    let page: Vec<&RecordRow> = rows.iter().skip(start).take(limit).collect();
    let next_cursor = (start + page.len() < rows.len())
        .then(|| page.last().map(|r| encode_cursor(r)))
        .flatten();

    let items = page
        .iter()
        .map(|r| r.wire())
        .collect::<Result<Vec<_>, _>>()?;

    let response: records_list::v0_1::Response = records_list::v0_1::Response::builder()
        .source(source)
        .items(items)
        .next_cursor(next_cursor)
        .try_into()
        .map_err(|e| {
            AppError::Internal(format!("records response does not fit its schema: {e}"))
        })?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::git_ns::projection::{Published, Tuple, mirror_put};
    use crate::registry::{MockRegistryClient, TrustRegistryClient, store_record};
    use crate::test_support::{TEST_VTC_DID, TestVtc};

    const MEMBER: &str = "did:key:z6MkMember";
    const OWNER: &str = "did:key:z6MkOwner";
    const REPO: &str = "github.com/acme/widgets";

    fn payload(v: serde_json::Value) -> records_list::v0_1::Payload {
        serde_json::from_value(v).expect("payload fits its schema")
    }

    fn tuple(entity: &str, action: &str, resource: &str) -> Tuple {
        Tuple {
            entity: entity.into(),
            action: action.into(),
            resource: resource.into(),
            context: json!({ "framework": crate::git_ns::projection::FRAMEWORK }),
            repo_id: None,
        }
    }

    /// A VTC with one member in the membership mirror and an owner's two git
    /// records (the right and its implied commit right) in the projection's,
    /// the registry holding all three.
    async fn vtc() -> TestVtc {
        let registry = Arc::new(MockRegistryClient::new());
        let vtc = TestVtc::builder()
            .with_registry_client(registry.clone())
            .build()
            .await;
        store_record(
            &vtc.state.registry_records_ks,
            &RegistryRecord {
                member_did: MEMBER.into(),
                status: RegistryStatus::Active,
                active_from: Utc::now(),
                active_to: None,
                last_synced_at: Utc::now(),
            },
        )
        .await
        .unwrap();
        for t in [
            tuple(OWNER, "git.repo.own", REPO),
            tuple(OWNER, "git.commit.sign", REPO),
        ] {
            registry
                .put_trust_record(&t.record(TEST_VTC_DID))
                .await
                .unwrap();
            mirror_put(
                &vtc.state,
                &Published {
                    tuple: t,
                    published_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        }
        registry
            .put_trust_record(&json!({
                "entity_id": MEMBER,
                "authority_id": TEST_VTC_DID,
                "action": crate::registry::RECOGNISE_ACTION,
                "resource": crate::registry::TRUST_GRAPH_RESOURCE,
                "record_type": "recognition",
                "recognized": true,
            }))
            .await
            .unwrap();
        vtc
    }

    fn keys(r: &records_list::v0_1::Response) -> Vec<(String, String)> {
        r.items
            .iter()
            .map(|i| (i.entity_id.to_string(), i.action.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn local_lists_git_rights_as_authorization_records_beside_memberships() {
        let vtc = vtc().await;
        let r = records_list(&vtc.state, payload(json!({ "source": "local" })))
            .await
            .unwrap();
        assert_eq!(
            keys(&r),
            [
                (MEMBER.to_string(), "recognise".to_string()),
                (OWNER.to_string(), "git.commit.sign".to_string()),
                (OWNER.to_string(), "git.repo.own".to_string()),
            ]
        );
        let own = &r.items[2];
        assert_eq!(own.record_type.as_str(), "authorization");
        assert_eq!(own.authorized, Some(true));
        assert_eq!(own.recognized, None);
        assert_eq!(own.resource.as_str(), REPO);
        assert_eq!(own.authority_id.as_str(), TEST_VTC_DID);
        let member = &r.items[0];
        assert_eq!(member.record_type.as_str(), "recognition");
        assert_eq!(member.recognized, Some(true));
        assert_eq!(member.authorized, None);
    }

    #[tokio::test]
    async fn registry_lists_every_record_under_the_authority() {
        let vtc = vtc().await;
        let r = records_list(&vtc.state, payload(json!({ "source": "registry" })))
            .await
            .unwrap();
        assert_eq!(r.items.len(), 3, "{r:?}");
        assert!(
            r.items
                .iter()
                .any(|i| i.action.as_str() == "git.repo.own" && i.authorized == Some(true))
        );
    }

    #[tokio::test]
    async fn action_entity_and_resource_filters_match_git_records() {
        let vtc = vtc().await;
        for source in ["local", "registry"] {
            let r = records_list(
                &vtc.state,
                payload(json!({ "source": source, "action": "git.repo.own" })),
            )
            .await
            .unwrap();
            assert_eq!(keys(&r), [(OWNER.to_string(), "git.repo.own".to_string())]);

            let r = records_list(
                &vtc.state,
                payload(json!({ "source": source, "resource": REPO })),
            )
            .await
            .unwrap();
            assert_eq!(r.items.len(), 2, "{source}: {r:?}");

            let r = records_list(
                &vtc.state,
                payload(json!({ "source": source, "entityId": MEMBER })),
            )
            .await
            .unwrap();
            assert_eq!(keys(&r), [(MEMBER.to_string(), "recognise".to_string())]);
        }
    }

    #[tokio::test]
    async fn a_cursor_pages_across_mixed_records() {
        let vtc = vtc().await;
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..5 {
            let mut p = json!({ "source": "local", "limit": 1 });
            if let Some(c) = &cursor {
                p["cursor"] = json!(c);
            }
            let r = records_list(&vtc.state, payload(p)).await.unwrap();
            seen.extend(keys(&r));
            cursor = r.next_cursor.clone();
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(cursor.is_none());
        let mut sorted = seen.clone();
        sorted.sort();
        assert_eq!(seen, sorted);
    }

    #[tokio::test]
    async fn a_cursor_this_list_did_not_issue_is_refused() {
        let vtc = vtc().await;
        let err = records_list(
            &vtc.state,
            payload(json!({ "source": "local", "cursor": "not-ours" })),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }
}
