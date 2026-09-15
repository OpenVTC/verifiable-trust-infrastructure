//! The online operator surface for the trust-registry reconciler.
//!
//! Four admin-gated endpoints, one per Trust Task in the
//! `vtc/registry/{sync-jobs,records}` family
//! (trustoverip/dtgwg-trust-tasks-tf#460):
//!
//! - `GET  /v1/registry/sync-jobs`         — what is queued, and what failed
//! - `POST /v1/registry/sync-jobs/retry`   — requeue an abandoned job
//! - `POST /v1/registry/sync-jobs/discard` — drop one that should not be
//! - `GET  /v1/registry/records`           — enumerate the recognition graph
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

use axum::Json;
use axum::extract::{Query, State};
use tracing::info;
use uuid::Uuid;

use vta_sdk::openapi::{
    RegistryRecordsList01Response, RegistrySyncJobsDiscard01Payload,
    RegistrySyncJobsDiscard01Response, RegistrySyncJobsList01Response,
    RegistrySyncJobsRetry01Payload, RegistrySyncJobsRetry01Response,
};
use vti_common::auth::AdminAuth;
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

#[utoipa::path(
    get, path = "/registry/sync-jobs",
    operation_id = "registrySyncJobsList", tag = "registry",
    params(
        ("state" = Option<String>, Query, description = "pending | inFlight | failed. Omit for every state."),
        ("cursor" = Option<String>, Query, description = "Continuation token from a previous page's nextCursor."),
        ("limit" = Option<u32>, Query, description = "Page size, clamped to 1..=200 (default 50)."),
    ),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "The reconciliation queue", body = RegistrySyncJobsList01Response),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn sync_jobs_list(
    _auth: AdminAuth,
    State(state): State<AppState>,
    // The published payload itself, deserialized from the query string. A GET
    // has no body, but the members are flat and their names are the wire's, so
    // the generated type is the contract here exactly as it would be in a body
    // — and a hand-written mirror of it is what
    // `generated_wire_types_census` refuses.
    Query(q): Query<list_spec::v0_1::Payload>,
) -> Result<Json<RegistrySyncJobsList01Response>, AppError> {
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
    Ok(Json(response.into()))
}

// ---------------------------------------------------------------------------
// sync-jobs/retry
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/registry/sync-jobs/retry",
    operation_id = "registrySyncJobsRetry", tag = "registry",
    request_body = RegistrySyncJobsRetry01Payload,
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "What was requeued, and what was declined", body = RegistrySyncJobsRetry01Response),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn sync_jobs_retry(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<RegistrySyncJobsRetry01Payload>,
) -> Result<Json<RegistrySyncJobsRetry01Response>, AppError> {
    // The payload is an untagged enum admitting exactly one of the two
    // members, so the discriminator is decided by serde rather than by a
    // branch here that could get it wrong.
    let targets: Vec<SyncJob> = match &*body {
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
    let named_missing = match &*body {
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
            actor = %auth.0.did,
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
    Ok(Json(response.into()))
}

// ---------------------------------------------------------------------------
// sync-jobs/discard
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/registry/sync-jobs/discard",
    operation_id = "registrySyncJobsDiscard", tag = "registry",
    request_body = RegistrySyncJobsDiscard01Payload,
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "The job was deleted", body = RegistrySyncJobsDiscard01Response),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "No such job"),
        (status = 409, description = "The job is not in the terminal failed state"),
    ),
)]
pub async fn sync_jobs_discard(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<RegistrySyncJobsDiscard01Payload>,
) -> Result<Json<RegistrySyncJobsDiscard01Response>, AppError> {
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
        actor = %auth.0.did,
        "sync job discarded by an operator — the registry's record for this member is unchanged",
    );

    let response: discard_spec::v0_1::Response = discard_spec::v0_1::Response::builder()
        .job_id(job.id.to_string())
        .member_did(job.member_did.clone())
        .try_into()
        .map_err(|e| {
            AppError::Internal(format!("discard response does not fit its schema: {e}"))
        })?;
    Ok(Json(response.into()))
}

// ---------------------------------------------------------------------------
// records/list
// ---------------------------------------------------------------------------

fn record_wire(
    r: &RegistryRecord,
    authority: &str,
) -> Result<records_list::v0_1::Record, AppError> {
    records_list::v0_1::Record::builder()
        .entity_id(r.member_did.clone())
        .authority_id(authority.to_string())
        .action(crate::registry::RECOGNISE_ACTION.to_string())
        .resource(crate::registry::TRUST_GRAPH_RESOURCE.to_string())
        .record_type("recognition".to_string())
        .recognized(Some(r.status == RegistryStatus::Active))
        .try_into()
        .map_err(|e| AppError::Internal(format!("record does not fit its schema: {e}")))
}

#[utoipa::path(
    get, path = "/registry/records",
    operation_id = "registryRecordsList", tag = "registry",
    params(
        ("source" = Option<String>, Query, description = "registry (default) or local."),
        ("entityId" = Option<String>, Query, description = "Filter to records about this entity."),
        ("authorityId" = Option<String>, Query, description = "Filter to records asserted by this authority."),
        ("action" = Option<String>, Query, description = "Filter to records for this action."),
        ("resource" = Option<String>, Query, description = "Filter to records for this resource."),
        ("cursor" = Option<String>, Query, description = "Continuation token from a previous page's nextCursor."),
        ("limit" = Option<u32>, Query, description = "Page size, clamped to 1..=200 (default 50)."),
    ),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Trust records from the requested view", body = RegistryRecordsList01Response),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 502, description = "The registry could not be enumerated"),
        (status = 503, description = "No trust registry is configured"),
    ),
)]
pub async fn records_list(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(q): Query<records_list::v0_1::Payload>,
) -> Result<Json<RegistryRecordsList01Response>, AppError> {
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

    let mut rows = match source {
        // Never served from the mirror. A stale local answer presented as the
        // registry's is the exact fault this surface exists to detect, so an
        // unreachable registry is an error rather than a substitution.
        records_list::v0_1::Source::Registry => client.list_records().await?,
        records_list::v0_1::Source::Local => list_records(&state.registry_records_ks).await?,
        // The enum is `#[non_exhaustive]`, so a future spec release can add a
        // view this build does not serve. Refusing names it instead of
        // silently answering from whichever arm happened to be first.
        other => {
            return Err(AppError::Validation(format!(
                "source `{other:?}` is in the specification but not served by this build"
            )));
        }
    };

    if let Some(entity) = &q.entity_id {
        rows.retain(|r| r.member_did.as_str() == entity.as_str());
    }
    // The remaining three filters are constants for every record this
    // community publishes, so a non-matching value is an empty page rather
    // than an error — the same answer the registry would give.
    if q.authority_id
        .as_ref()
        .is_some_and(|a| a.as_str() != authority)
    {
        rows.clear();
    }
    if q.action
        .as_deref()
        .is_some_and(|a| a != crate::registry::RECOGNISE_ACTION)
    {
        rows.clear();
    }
    if q.resource
        .as_deref()
        .is_some_and(|r| r != crate::registry::TRUST_GRAPH_RESOURCE)
    {
        rows.clear();
    }

    rows.sort_by(|a, b| a.member_did.cmp(&b.member_did));
    let start = match &q.cursor {
        None => 0,
        Some(c) => rows
            .iter()
            .position(|r| &r.member_did == c)
            .map_or(0, |i| i + 1),
    };
    let limit = clamp(q.limit);
    let page: Vec<_> = rows.iter().skip(start).take(limit).collect();
    let next_cursor = (start + page.len() < rows.len())
        .then(|| page.last().map(|r| r.member_did.clone()))
        .flatten();

    let items = page
        .iter()
        .map(|r| record_wire(r, &authority))
        .collect::<Result<Vec<_>, _>>()?;

    let response: records_list::v0_1::Response = records_list::v0_1::Response::builder()
        .source(source)
        .items(items)
        .next_cursor(next_cursor)
        .try_into()
        .map_err(|e| {
            AppError::Internal(format!("records response does not fit its schema: {e}"))
        })?;
    Ok(Json(response.into()))
}
