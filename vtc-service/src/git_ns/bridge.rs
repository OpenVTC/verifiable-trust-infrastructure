//! The VTC's side of the bridge conversation: `git-ns/bridge/job` out,
//! `git-ns/bridge/result` and `git-ns/bridge/event` in.
//!
//! # Transport
//!
//! A bridge is a peer with its own DID, so it is reached the way every peer
//! is (CLAUDE.md, *Prefer TSP, then DIDComm, then REST*): its DID document is
//! resolved, the highest-preference protocol both sides advertise is chosen by
//! service **type**, and an empty intersection is a typed refusal rather than
//! a downgrade. The job is a signed Trust Task document — the specification
//! requires the proof, because it is what lets the bridge tell its own VTC's
//! jobs from anyone else's on every transport — and the bridge's
//! acknowledgement comes back on the shared inbound stream, correlated by
//! `threadId` through the same [`PendingReplies`](crate::hooks::PendingReplies)
//! the registry client and the hook relay use.
//!
//! # Durability
//!
//! Every job except the two `begin*` kinds is queued in
//! [`GIT_NS_JOBS`](crate::store::keyspaces::GIT_NS_JOBS) before it is sent,
//! and a send `Ok` is never read as delivery (R1.1): a job is `accepted` only
//! when the bridge says so, and finished only when its result arrives. Jobs
//! are convergent (the bridge checks the forge and changes only what
//! differs), so re-sending is always safe; a `projectRoles` job — the one that
//! removes a departed member's forge role — retries forever, the others
//! within a budget. The two `begin*` kinds are sent in-line, because their
//! answer (`next.url`) is what the member's request is waiting for.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::git_ns::bridge::{
    event::v0_1 as event_wire, job::v0_1 as job_wire, result::v0_1 as result_wire,
};
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::credentials::LocalSigner;
use crate::hooks::PendingReplies;
use crate::messaging::VtcMessaging;
use crate::server::AppState;

use super::model::{
    FORGE_REPORT_EXT, ForgeAccount, LinkState, Mode, Namespace, NamespaceForgeStatus,
    NamespaceState, OwnerKind, Repo, RepoForgeReport, RepoState, Resource, Right, RightRow, Scope,
    SyncState, SyncStatus, Visibility, new_id,
};
use super::ops::{self, Audit, OpError, OpResult, audit, now};
use super::rules;
use super::store::{self, Snapshot};
use super::wire;

/// `git-ns/bridge/job/0.1`.
pub const JOB_TYPE: &str = <job_wire::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// How long an in-line `begin*` job waits for the bridge's acknowledgement.
const INLINE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a queued job's send waits for the acknowledgement.
const QUEUED_TIMEOUT: Duration = Duration::from_secs(60);
/// A job the bridge accepted and never reported on is sent again after this —
/// the specification's recovery path: "for a `jobId` it has already finished,
/// answers `accepted: false` … and sends its result again".
const RESULT_WAIT_MINUTES: i64 = 30;
/// Attempts before a bounded job gives up.
const MAX_ATTEMPTS: u32 = 20;
const BACKOFF_BASE_SECONDS: i64 = 5;
const BACKOFF_CAP_SECONDS: i64 = 3600;

// ── the job record ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobKind {
    ProjectRoles,
    CreateRepo,
    Bootstrap,
    Archive,
    Inspect,
    BeginBind,
    BeginAccountLink,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::ProjectRoles => "projectRoles",
            JobKind::CreateRepo => "createRepo",
            JobKind::Bootstrap => "bootstrap",
            JobKind::Archive => "archive",
            JobKind::Inspect => "inspect",
            JobKind::BeginBind => "beginBind",
            JobKind::BeginAccountLink => "beginAccountLink",
        }
    }

    fn is_begin(self) -> bool {
        matches!(self, JobKind::BeginBind | JobKind::BeginAccountLink)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobState {
    /// Queued, not yet accepted by the bridge.
    Pending,
    /// The bridge recorded it; its result has not arrived.
    Accepted,
    Succeeded,
    Partial,
    /// The result reported failure, or the bridge refused the job, or a
    /// bounded job ran out of attempts.
    Failed,
    /// Superseded by a newer job for the same target, or its namespace was
    /// unbound.
    Cancelled,
}

impl JobState {
    pub fn is_open(self) -> bool {
        matches!(self, JobState::Pending | JobState::Accepted)
    }
}

/// One job, as the VTC keeps it until its result is recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeJob {
    pub job_id: String,
    pub namespace_id: String,
    /// The bridge it was sent to — recorded so a result is accepted only from
    /// that DID even after the namespace itself is gone.
    pub bridge_did: String,
    pub kind: JobKind,
    /// The exact `git-ns/bridge/job` payload. Re-sent byte-for-byte on a
    /// retry: a repeat with different content is `jobIdReused`.
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_id: Option<String>,
    pub state: JobState,
    pub attempts: u32,
    /// Revokes and role removals retry forever (R7.2); the rest give up.
    pub retry_forever: bool,
    pub created_at: DateTime<Utc>,
    pub next_attempt_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The bridge's `git-ns/bridge/result` payload, once recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

/// What a caller asks to be queued.
pub struct NewJob {
    pub namespace_id: String,
    pub kind: JobKind,
    /// The job payload without `jobId`, which [`enqueue`] assigns.
    pub payload: Value,
    pub repo_id: Option<String>,
    pub link_id: Option<String>,
}

fn job_key(id: &str) -> String {
    format!("job:{id}")
}

pub async fn get_job(ks: &KeyspaceHandle, id: &str) -> Result<Option<BridgeJob>, AppError> {
    ks.get(job_key(id)).await
}

pub async fn put_job(ks: &KeyspaceHandle, job: &BridgeJob) -> Result<(), AppError> {
    ks.insert(job_key(&job.job_id), job).await
}

pub async fn list_jobs(ks: &KeyspaceHandle) -> Result<Vec<BridgeJob>, AppError> {
    let rows = ks.prefix_iter_raw(b"job:".to_vec()).await?;
    let mut out: Vec<BridgeJob> = rows
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    out.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then(a.job_id.cmp(&b.job_id))
    });
    Ok(out)
}

fn target_of(job: &BridgeJob) -> Option<&str> {
    job.payload.get("repo").and_then(Value::as_str)
}

/// Queue a job for its namespace's bridge.
///
/// A `projectRoles` job carries the *complete* desired set, so a newer one
/// for the same target makes an older one that has not yet been sent
/// pointless: it is cancelled rather than sent first and then overwritten.
pub async fn enqueue(state: &AppState, new: NewJob) -> Result<Option<String>, AppError> {
    let Some(ns) = store::get_namespace(&state.git_ns.ks, &new.namespace_id).await? else {
        return Ok(None);
    };
    let (Mode::Bridge, Some(bridge_did)) = (ns.mode, ns.bridge_did.clone()) else {
        return Ok(None);
    };
    let job_id = new_id("job");
    let mut payload = new.payload;
    payload["jobId"] = json!(job_id);
    if new.kind == JobKind::ProjectRoles {
        let target = payload
            .get("repo")
            .and_then(Value::as_str)
            .map(str::to_string);
        for mut old in list_jobs(&state.git_ns.jobs_ks).await? {
            if old.kind == JobKind::ProjectRoles
                && old.namespace_id == new.namespace_id
                && old.state == JobState::Pending
                && target_of(&old).map(str::to_string) == target
            {
                old.state = JobState::Cancelled;
                old.last_error = Some(format!("superseded by {job_id}"));
                put_job(&state.git_ns.jobs_ks, &old).await?;
            }
        }
    }
    let t = now();
    let job = BridgeJob {
        job_id: job_id.clone(),
        namespace_id: new.namespace_id,
        bridge_did,
        kind: new.kind,
        payload,
        repo_id: new.repo_id,
        link_id: new.link_id,
        state: JobState::Pending,
        attempts: 0,
        retry_forever: new.kind == JobKind::ProjectRoles,
        created_at: t,
        next_attempt_at: t,
        accepted_at: None,
        last_error: None,
        result: None,
    };
    put_job(&state.git_ns.jobs_ks, &job).await?;
    debug!(job_id, kind = job.kind.as_str(), "git-ns bridge job queued");
    Ok(Some(job_id))
}

/// Record a `begin*` job that was sent in-line and accepted, so its result
/// and completion event can be matched to it.
pub async fn record_inline_job(
    state: &AppState,
    bridge_did: &str,
    namespace_id: &str,
    kind: JobKind,
    payload: Value,
    repo_id: Option<String>,
    link_id: Option<String>,
) -> Result<(), AppError> {
    let job_id = payload
        .get("jobId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let t = now();
    put_job(
        &state.git_ns.jobs_ks,
        &BridgeJob {
            job_id,
            namespace_id: namespace_id.to_string(),
            bridge_did: bridge_did.to_string(),
            kind,
            payload,
            repo_id,
            link_id,
            state: JobState::Accepted,
            attempts: 1,
            retry_forever: false,
            created_at: t,
            next_attempt_at: t,
            accepted_at: Some(t),
            last_error: None,
            result: None,
        },
    )
    .await
}

/// Cancel every open job of a namespace that is being unbound.
pub async fn cancel_namespace_jobs(state: &AppState, namespace_id: &str) -> Result<(), AppError> {
    for mut job in list_jobs(&state.git_ns.jobs_ks).await? {
        if job.namespace_id == namespace_id && job.state.is_open() {
            job.state = JobState::Cancelled;
            job.last_error = Some("namespace unbound".into());
            put_job(&state.git_ns.jobs_ks, &job).await?;
        }
    }
    Ok(())
}

// ── sending ─────────────────────────────────────────────────────────────────

/// A job send that did not end in an acknowledgement.
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeSendError {
    /// Worth another attempt: no transport yet, no reply in the window, a
    /// send that failed below the Trust Task layer.
    Transient(String),
    /// The bridge answered with a `trust-task-error`. Not retried — the same
    /// document would be refused again.
    Rejected { code: String, message: String },
}

impl std::fmt::Display for BridgeSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeSendError::Transient(m) => write!(f, "transient: {m}"),
            BridgeSendError::Rejected { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

/// Sends one `git-ns/bridge/job` payload to a bridge and returns its
/// acknowledgement. Production is [`MessagingBridgeClient`]; tests
/// substitute a fake bridge.
#[async_trait]
pub trait BridgeClient: Send + Sync {
    async fn send_job(
        &self,
        bridge_did: &str,
        payload: &Value,
        timeout: Duration,
    ) -> Result<job_wire::Response, BridgeSendError>;
}

/// Send a `begin*` job and wait for its acknowledgement, for a request that
/// is waiting on the answer.
pub async fn send_inline(
    state: &AppState,
    bridge_did: &str,
    payload: &Value,
) -> OpResult<job_wire::Response> {
    match state
        .git_ns
        .bridge
        .send_job(bridge_did, payload, INLINE_TIMEOUT)
        .await
    {
        Ok(ack) if ack.accepted => Ok(ack),
        Ok(_) => Err(OpError::Unavailable(
            "the bridge reports it already finished this job, which a fresh one cannot be; \
             try again"
                .into(),
        )),
        Err(BridgeSendError::Transient(m)) => Err(OpError::Unavailable(format!(
            "the bridge {bridge_did} did not answer: {m}"
        ))),
        Err(BridgeSendError::Rejected { code, message }) => Err(OpError::Unavailable(format!(
            "the bridge {bridge_did} refused the job ({code}): {message}"
        ))),
    }
}

/// The production [`BridgeClient`]: resolves the bridge's DID, picks the
/// transport both parties advertise, signs the job with the community's key,
/// and awaits the acknowledgement by `threadId`.
pub struct MessagingBridgeClient {
    didcomm: Arc<OnceCell<Arc<VtcMessaging>>>,
    signer: Option<Arc<LocalSigner>>,
    replies: PendingReplies,
    resolver: Option<affinidi_did_resolver_cache_sdk::DIDCacheClient>,
}

impl MessagingBridgeClient {
    pub fn new(
        didcomm: Arc<OnceCell<Arc<VtcMessaging>>>,
        signer: Option<Arc<LocalSigner>>,
        replies: PendingReplies,
        resolver: Option<affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    ) -> Self {
        Self {
            didcomm,
            signer,
            replies,
            resolver,
        }
    }

    async fn select(&self, bridge_did: &str) -> Result<Protocol, BridgeSendError> {
        let resolver = self.resolver.as_ref().ok_or_else(|| {
            BridgeSendError::Transient(
                "no DID resolver configured — cannot read the bridge's advertised transports"
                    .into(),
            )
        })?;
        let resolved = resolver.resolve(bridge_did).await.map_err(|e| {
            BridgeSendError::Transient(format!("could not resolve bridge DID {bridge_did}: {e}"))
        })?;
        let doc = serde_json::to_value(&resolved.doc)
            .map_err(|e| BridgeSendError::Transient(format!("unreadable DID document: {e}")))?;
        let theirs = ServiceCapabilities::from_did_document(&doc);
        let up = self.didcomm.get().is_some();
        let ours = ServiceCapabilities {
            tsp: (up && cfg!(feature = "tsp")).then(|| bridge_did.to_string()),
            didcomm: up.then(|| bridge_did.to_string()),
            // A bridge is reached over messaging only; a REST-only bridge has
            // no transport in common with this client, which is reported as
            // such rather than guessed around.
            rest: None,
        };
        if ours.advertised().is_empty() {
            return Err(BridgeSendError::Transient(
                "VTC messaging is not running yet".into(),
            ));
        }
        select_protocol(&ours, &theirs, bridge_did)
            .map(|m| m.protocol)
            .map_err(|e| BridgeSendError::Rejected {
                code: "noMatchingProtocol".into(),
                message: e.to_string(),
            })
    }
}

#[async_trait]
impl BridgeClient for MessagingBridgeClient {
    async fn send_job(
        &self,
        bridge_did: &str,
        payload: &Value,
        timeout: Duration,
    ) -> Result<job_wire::Response, BridgeSendError> {
        let messaging = self
            .didcomm
            .get()
            .ok_or_else(|| BridgeSendError::Transient("VTC messaging is not running yet".into()))?;
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| BridgeSendError::Transient("this VTC has no signing key yet".into()))?;
        let protocol = self.select(bridge_did).await?;

        let doc = vti_common::capability_client::build_document(
            &messaging.vtc_did,
            bridge_did,
            JOB_TYPE,
            payload.clone(),
        );
        let mut value = serde_json::to_value(&doc)
            .map_err(|e| BridgeSendError::Transient(format!("serialise job: {e}")))?;
        signer
            .sign_doc(&mut value)
            .await
            .map_err(|e| BridgeSendError::Transient(format!("sign job: {e}")))?;
        let doc: TrustTask<Value> = serde_json::from_value(value)
            .map_err(|e| BridgeSendError::Transient(format!("reparse signed job: {e}")))?;

        let receiver = self.replies.register(&doc.id);
        let sent = match protocol {
            #[cfg(feature = "tsp")]
            Protocol::Tsp => {
                let body = crate::outbound::seal_trust_task_tsp(&doc)
                    .map_err(|e| BridgeSendError::Transient(e.to_string()))?;
                let route = vec![messaging.mediator_did.clone(), bridge_did.to_string()];
                messaging
                    .atm
                    .tsp()
                    .send_reestablishing(&messaging.profile, bridge_did, &route, &body)
                    .await
                    .map(|_| ())
                    .map_err(|e| BridgeSendError::Transient(format!("TSP send failed: {e}")))
            }
            Protocol::Didcomm => {
                crate::outbound::send_trust_task_didcomm(messaging, bridge_did, &doc)
                    .await
                    .map_err(|e| BridgeSendError::Transient(e.to_string()))
            }
            _ => Err(BridgeSendError::Rejected {
                code: "noMatchingProtocol".into(),
                message: format!("{bridge_did} can be reached by no transport this VTC speaks"),
            }),
        };
        if let Err(e) = sent {
            self.replies.abandon(&doc.id);
            return Err(e);
        }
        let reply = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => {
                self.replies.abandon(&doc.id);
                return Err(BridgeSendError::Transient("reply channel closed".into()));
            }
            Err(_) => {
                self.replies.abandon(&doc.id);
                return Err(BridgeSendError::Transient(format!(
                    "no reply from the bridge within {}s",
                    timeout.as_secs()
                )));
            }
        };
        classify_reply(&reply)
    }
}

/// A correlated reply as an acknowledgement or a refusal.
pub fn classify_reply(reply: &TrustTask<Value>) -> Result<job_wire::Response, BridgeSendError> {
    if reply.type_uri.slug() == "trust-task-error" {
        let code = reply
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let message = reply
            .payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        return match code.as_str() {
            "internalError" | "unavailable" => {
                Err(BridgeSendError::Transient(format!("{code}: {message}")))
            }
            _ => Err(BridgeSendError::Rejected { code, message }),
        };
    }
    serde_json::from_value(reply.payload.clone()).map_err(|e| {
        BridgeSendError::Transient(format!("the bridge's acknowledgement is unreadable: {e}"))
    })
}

fn backoff(attempts: u32) -> chrono::Duration {
    let secs = BACKOFF_BASE_SECONDS
        .saturating_mul(2i64.saturating_pow(attempts.min(16)))
        .min(BACKOFF_CAP_SECONDS);
    chrono::Duration::seconds(secs)
}

/// Send every due job, in queue order.
pub async fn dispatch_due(state: &AppState) -> Result<(), AppError> {
    let t = now();
    for mut job in list_jobs(&state.git_ns.jobs_ks).await? {
        let read_state = job.state;
        // An accepted job whose result never came is asked for again.
        if job.state == JobState::Accepted
            && !job.kind.is_begin()
            && job
                .accepted_at
                .is_some_and(|a| a + chrono::Duration::minutes(RESULT_WAIT_MINUTES) < t)
        {
            job.state = JobState::Pending;
            job.next_attempt_at = t;
        }
        if job.state != JobState::Pending || job.next_attempt_at > t {
            continue;
        }
        let outcome = state
            .git_ns
            .bridge
            .send_job(&job.bridge_did, &job.payload, QUEUED_TIMEOUT)
            .await;
        job.attempts += 1;
        match outcome {
            Ok(_ack) => {
                // `accepted: false` means the bridge already finished it and
                // is sending the result again — either way, the result is
                // what is awaited now.
                job.state = JobState::Accepted;
                job.accepted_at = Some(now());
                job.last_error = None;
            }
            Err(BridgeSendError::Rejected { code, message }) => {
                warn!(
                    job_id = %job.job_id,
                    kind = job.kind.as_str(),
                    %code,
                    "the bridge refused a git-ns job"
                );
                job.state = JobState::Failed;
                job.last_error = Some(format!("{code}: {message}"));
            }
            Err(BridgeSendError::Transient(m)) => {
                job.last_error = Some(m);
                if !job.retry_forever && job.attempts >= MAX_ATTEMPTS {
                    job.state = JobState::Failed;
                } else {
                    job.next_attempt_at = t + backoff(job.attempts);
                }
            }
        }
        // Write back under the store lock, and only over the row this pass
        // read: while the send was in flight the bridge may already have
        // reported the result, or an unbind cancelled the job, and a stale
        // "accepted" written over either would lose it.
        let written = {
            let _guard = store::write_lock().await;
            match get_job(&state.git_ns.jobs_ks, &job.job_id).await? {
                Some(current) if current.result.is_none() && current.state == read_state => {
                    put_job(&state.git_ns.jobs_ks, &job).await?;
                    true
                }
                _ => false,
            }
        };
        if written && job.state == JobState::Failed {
            note_job_failure(state, &job).await?;
        }
    }
    Ok(())
}

/// Surface a job that will not complete on the repository it was for.
async fn note_job_failure(state: &AppState, job: &BridgeJob) -> Result<(), AppError> {
    let Some(repo_id) = &job.repo_id else {
        return Ok(());
    };
    let _guard = store::write_lock().await;
    if let Some(mut repo) = store::get_repo(&state.git_ns.ks, repo_id).await? {
        repo.last_error = job.last_error.clone();
        if job.kind == JobKind::CreateRepo {
            repo.failed_step = Some("create".into());
        }
        store::put_repo(&state.git_ns.ks, &repo).await?;
    }
    Ok(())
}

// ── forge accounts ──────────────────────────────────────────────────────────

/// Every member's linked forge accounts: DID → forge host → account.
///
/// Stored on the member row, `extensions.forges[<host>] = {id, login}`
/// (design §4.4), so the binding is erased with the member.
pub async fn linked_accounts(
    state: &AppState,
) -> Result<HashMap<String, BTreeMap<String, ForgeAccount>>, AppError> {
    let mut out = HashMap::new();
    for m in crate::members::list_members(&state.members_ks).await? {
        if m.removed_at.is_some() {
            continue;
        }
        let Some(forges) = m.extensions.get("forges").and_then(Value::as_object) else {
            continue;
        };
        let mut map = BTreeMap::new();
        for (host, acct) in forges {
            let (Some(id), Some(login)) = (
                acct.get("id").and_then(Value::as_str),
                acct.get("login").and_then(Value::as_str),
            ) else {
                continue;
            };
            map.insert(
                host.clone(),
                ForgeAccount {
                    forge: host.clone(),
                    id: id.to_string(),
                    login: login.to_string(),
                },
            );
        }
        if !map.is_empty() {
            out.insert(m.did.clone(), map);
        }
    }
    Ok(out)
}

// ── role projection ─────────────────────────────────────────────────────────

/// Each subject's highest right on a repository, from the namespace's rows
/// and the repository's own. `own` > `maintain` > `commit.sign`; an
/// `ns.admin` is an owner here, by implication.
pub fn highest_repo_rights(
    ns_res: &Resource,
    ns_rows: &[RightRow],
    repo_res: &Resource,
    repo_rows: &[RightRow],
    t: DateTime<Utc>,
) -> BTreeMap<String, Right> {
    let mut out: BTreeMap<String, Right> = BTreeMap::new();
    let consider = |rows: &[RightRow], on: &Resource, out: &mut BTreeMap<String, Right>| {
        for row in rows.iter().filter(|r| r.is_live(t)) {
            if let Some(best) = rules::conferred(row.right, on, repo_res)
                .into_iter()
                .filter(|r| matches!(r, Right::RepoOwn | Right::RepoMaintain | Right::CommitSign))
                .max_by_key(|r| r.rank())
            {
                let e = out.entry(row.subject.clone()).or_insert(best);
                if best.rank() > e.rank() {
                    *e = best;
                }
            }
        }
    };
    consider(ns_rows, ns_res, &mut out);
    consider(repo_rows, repo_res, &mut out);
    out
}

fn desired_role_json(subject: &str, right: Right, account: &ForgeAccount) -> Value {
    json!({
        "subject": subject,
        "right": right.as_str(),
        "account": { "forge": account.forge, "id": account.id, "login": account.login },
    })
}

/// The desired forge roles for a repository being created, before it is in
/// the snapshot: its owners plus everyone the namespace's rows reach.
pub async fn desired_roles_for_repo(
    state: &AppState,
    snap: &Snapshot,
    ns: &Namespace,
    repo: &Repo,
    owners: &[String],
) -> Result<Vec<Value>, AppError> {
    let accounts = linked_accounts(state).await?;
    let t = now();
    let Some(repo_res) = repo.resource() else {
        return Ok(Vec::new());
    };
    let owner_rows: Vec<RightRow> = owners
        .iter()
        .map(|o| RightRow {
            subject: o.clone(),
            right: Right::RepoOwn,
            granted_by: o.clone(),
            granted_at: t,
            expires_at: None,
            reason: None,
            subject_was_member: true,
            granter_was_member: true,
        })
        .collect();
    let rights = highest_repo_rights(
        &ns.resource(),
        snap.rows(&Scope::Namespace(ns.id.clone())),
        &repo_res,
        &owner_rows,
        t,
    );
    Ok(render_roles(&rights, &ns.forge, &accounts))
}

fn render_roles(
    rights: &BTreeMap<String, Right>,
    forge: &str,
    accounts: &HashMap<String, BTreeMap<String, ForgeAccount>>,
) -> Vec<Value> {
    rights
        .iter()
        .filter_map(|(subject, right)| {
            accounts
                .get(subject)
                .and_then(|m| m.get(forge))
                .map(|a| desired_role_json(subject, *right, a))
        })
        .collect()
}

fn digest(roles: &[Value]) -> String {
    let bytes = serde_json::to_vec(roles).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

/// Queue a `projectRoles` job for every target whose desired role set has
/// changed since the last one was queued.
///
/// The desired set is recomputed from the records every time — never
/// patched — so a departed member, a revoked right, an unlinked account or a
/// renamed repository all reach the forge the same way: the next set simply
/// does not contain them.
pub async fn project_roles(state: &AppState, force: bool) -> Result<(), AppError> {
    let accounts = linked_accounts(state).await?;
    let t = now();
    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    for ns in snap.namespaces.iter().filter(|n| {
        n.mode == Mode::Bridge && n.state == NamespaceState::Bound && !n.installation_removed
    }) {
        let ns_scope = Scope::Namespace(ns.id.clone());
        let ns_res = ns.resource();

        // The namespace itself: its admins, as owners of the organisation.
        let admins: BTreeMap<String, Right> = snap
            .rows(&ns_scope)
            .iter()
            .filter(|r| r.right == Right::NsAdmin && r.is_live(t))
            .map(|r| (r.subject.clone(), Right::NsAdmin))
            .collect();
        let roles = render_roles(&admins, &ns.forge, &accounts);
        let d = digest(&roles);
        if force || ns.roles_digest.as_deref() != Some(d.as_str()) {
            let mut updated = ns.clone();
            updated.roles_digest = Some(d);
            store::put_namespace(&state.git_ns.ks, &updated).await?;
            enqueue(
                state,
                NewJob {
                    namespace_id: ns.id.clone(),
                    kind: JobKind::ProjectRoles,
                    payload: json!({
                        "namespace": ns.id,
                        "kind": "projectRoles",
                        "desiredRoles": roles,
                    }),
                    repo_id: None,
                    link_id: None,
                },
            )
            .await?;
        }

        for repo in snap.repos.iter().filter(|r| {
            r.namespace_id == ns.id && matches!(r.state, RepoState::Active | RepoState::Orphaned)
        }) {
            let Some(repo_res) = repo.resource() else {
                continue;
            };
            let rights = highest_repo_rights(
                &ns_res,
                snap.rows(&ns_scope),
                &repo_res,
                snap.rows(&Scope::Repo(repo.id.clone())),
                t,
            );
            let roles = render_roles(&rights, &ns.forge, &accounts);
            let d = digest(&roles);
            if force || repo.roles_digest.as_deref() != Some(d.as_str()) {
                let mut updated = repo.clone();
                updated.roles_digest = Some(d);
                store::put_repo(&state.git_ns.ks, &updated).await?;
                enqueue(
                    state,
                    NewJob {
                        namespace_id: ns.id.clone(),
                        kind: JobKind::ProjectRoles,
                        payload: json!({
                            "namespace": ns.id,
                            "kind": "projectRoles",
                            "repo": repo.resource,
                            "desiredRoles": roles,
                        }),
                        repo_id: Some(repo.id.clone()),
                        link_id: None,
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}

// ── git-ns/bridge/result/0.1 ────────────────────────────────────────────────

fn step_ok(outcome: &str) -> bool {
    matches!(outcome, "applied" | "unchanged")
}

/// Apply reported steps to a repository's bootstrap status. Steps the report
/// does not mention keep their last known value.
fn apply_steps(repo: &mut Repo, steps: &[Value]) -> Option<String> {
    let mut first_failed = None;
    for s in steps {
        let (Some(name), Some(outcome)) = (
            s.get("step").and_then(Value::as_str),
            s.get("outcome").and_then(Value::as_str),
        ) else {
            continue;
        };
        let ok = step_ok(outcome);
        match name {
            "workflow" => repo.bootstrap.workflow = ok,
            "keyring" => repo.bootstrap.keyring = ok,
            "variables" => repo.bootstrap.variables = ok,
            "requiredCheck" => repo.bootstrap.required_check = ok,
            _ => {}
        }
        if outcome == "failed" && first_failed.is_none() {
            first_failed = Some(name.to_string());
        }
    }
    first_failed
}

pub async fn handle_result(
    state: &AppState,
    issuer: &str,
    p: result_wire::Payload,
) -> OpResult<result_wire::Response> {
    let job_id = p.job_id.to_string();
    let unknown = || OpError::Declared {
        code: result_wire::error_codes::UNKNOWN_JOB.code,
        message: format!("this VTC sent no job `{job_id}` to this bridge"),
    };
    let _guard = store::write_lock().await;
    let mut job = get_job(&state.git_ns.jobs_ks, &job_id)
        .await?
        .ok_or_else(unknown)?;
    // Only the bridge the job went to may report on it.
    if job.bridge_did != issuer {
        return Err(OpError::PermissionDenied(
            "only the bridge that serves this job's namespace may report its result".into(),
        ));
    }
    let ack: result_wire::Response = wire::into(json!({ "jobId": job_id }))?;
    // Item 2 — recorded once.
    if job.result.is_some() {
        return Ok(ack);
    }
    let raw = serde_json::to_value(&p).map_err(AppError::from)?;
    let outcome = raw
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("failed")
        .to_string();
    let steps: Vec<Value> = raw
        .get("steps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let error_code = raw
        .pointer("/error/code")
        .and_then(Value::as_str)
        .map(str::to_string);
    let error_message = raw
        .pointer("/error/message")
        .and_then(Value::as_str)
        .map(str::to_string);
    let forge_id = raw
        .pointer("/repo/forgeId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let describe = || {
        error_code.as_deref().map(|c| match &error_message {
            Some(m) => format!("{c}: {m}"),
            None => c.to_string(),
        })
    };

    job.result = Some(raw.clone());
    job.state = match outcome.as_str() {
        "succeeded" => JobState::Succeeded,
        "partial" => JobState::Partial,
        _ => JobState::Failed,
    };
    job.last_error = describe();

    match job.kind {
        JobKind::CreateRepo | JobKind::Bootstrap | JobKind::Inspect => {
            if let Some(repo_id) = job.repo_id.clone()
                && let Some(mut repo) = store::get_repo(&state.git_ns.ks, &repo_id).await?
            {
                // Item 4 — `repo.resource` is never taken as a rename; the id
                // is recorded where it was unknown.
                if repo.forge_id.is_none() {
                    repo.forge_id = forge_id.clone();
                }
                let failed_step = apply_steps(&mut repo, &steps);
                let t = now();
                match (job.kind, outcome.as_str()) {
                    (JobKind::CreateRepo, "succeeded") => {
                        if repo.state == RepoState::PendingCreate {
                            repo.state = RepoState::Active;
                        }
                        repo.failed_step = None;
                        repo.last_error = None;
                        repo.sync = SyncStatus {
                            state: SyncState::InSync,
                            checked_at: Some(t),
                            drift: repo.sync.drift.clone(),
                        };
                        audit(
                            state,
                            issuer,
                            None,
                            Audit {
                                action: "gitNs.repo.activated",
                                namespace: Some(&repo.namespace_id),
                                resource: Some(repo.resource.clone()),
                                right: None,
                                policy_version: None,
                                detail: forge_id.clone(),
                            },
                        )
                        .await;
                    }
                    (JobKind::CreateRepo, _) => {
                        repo.failed_step = failed_step.or(Some("create".into()));
                        repo.last_error = describe();
                    }
                    (JobKind::Inspect, _) if error_code.as_deref() == Some("notFound") => {
                        // "If the inspection finds no such repository, the
                        // VTC sets it detached."
                        detach(state, issuer, &mut repo, "notFound").await?;
                    }
                    (JobKind::Inspect, "succeeded") => {
                        repo.sync.checked_at = Some(t);
                        if repo.sync.state == SyncState::Pending {
                            repo.sync.state = SyncState::InSync;
                        }
                        let missing = repo.bootstrap.missing_steps();
                        if !missing.is_empty() && repo.state == RepoState::Active {
                            enqueue(
                                state,
                                NewJob {
                                    namespace_id: repo.namespace_id.clone(),
                                    kind: JobKind::Bootstrap,
                                    payload: json!({
                                        "namespace": repo.namespace_id,
                                        "kind": "bootstrap",
                                        "repo": repo.resource,
                                        "steps": missing,
                                    }),
                                    repo_id: Some(repo.id.clone()),
                                    link_id: None,
                                },
                            )
                            .await?;
                        }
                    }
                    _ => {
                        repo.failed_step = failed_step;
                        repo.last_error = describe();
                        repo.sync.checked_at = Some(t);
                    }
                }
                store::put_repo(&state.git_ns.ks, &repo).await?;
            }
        }
        JobKind::BeginBind => {
            // A failed binding ends the pending namespace; success already
            // arrived as `bindCompleted`.
            if job.state == JobState::Failed
                && let Some(ns) = store::get_namespace(&state.git_ns.ks, &job.namespace_id).await?
                && ns.state == NamespaceState::Pending
                && ns.bind_job_id.as_deref() == Some(job.job_id.as_str())
            {
                store::delete_namespace(&state.git_ns.ks, &ns.id).await?;
                audit(
                    state,
                    issuer,
                    None,
                    Audit {
                        action: "gitNs.namespace.bindFailed",
                        namespace: Some(&ns.id),
                        resource: Some(ns.resource().to_string()),
                        right: None,
                        policy_version: None,
                        detail: error_code.clone(),
                    },
                )
                .await;
            }
        }
        JobKind::BeginAccountLink => {
            if job.state == JobState::Failed
                && let Some(link_id) = &job.link_id
                && let Some(mut attempt) = store::get_link(&state.git_ns.ks, link_id).await?
                && attempt.state == LinkState::Pending
            {
                attempt.state = if error_code.as_deref() == Some("expired") {
                    LinkState::Expired
                } else {
                    LinkState::Failed
                };
                attempt.finished_at = Some(now());
                store::put_link(&state.git_ns.ks, &attempt).await?;
            }
        }
        JobKind::ProjectRoles | JobKind::Archive => {
            if job.state != JobState::Succeeded {
                warn!(
                    job_id = %job.job_id,
                    kind = job.kind.as_str(),
                    error = ?job.last_error,
                    "a git-ns bridge job did not succeed"
                );
            }
        }
    }
    // The bridge's report beyond the specification: the per-step outcomes
    // (for the console's create-progress view), and anything in `ext`.
    let (ns_status, mut repo_report) = ext_report(&raw);
    if matches!(
        job.kind,
        JobKind::CreateRepo | JobKind::Bootstrap | JobKind::Inspect
    ) && !steps.is_empty()
    {
        repo_report.get_or_insert_with(Default::default).steps = steps.clone();
    }
    if let (Some(report), Some(repo_id)) = (repo_report, job.repo_id.as_ref())
        && let Some(mut repo) = store::get_repo(&state.git_ns.ks, repo_id).await?
    {
        merge_repo_report(&mut repo, report);
        store::put_repo(&state.git_ns.ks, &repo).await?;
    }
    if let Some(status) = ns_status
        && let Some(mut ns) = store::get_namespace(&state.git_ns.ks, &job.namespace_id).await?
    {
        merge_ns_status(&mut ns, status);
        store::put_namespace(&state.git_ns.ks, &ns).await?;
    }
    put_job(&state.git_ns.jobs_ks, &job).await?;
    Ok(ack)
}

/// The bridge's `ext` report ([`FORGE_REPORT_EXT`]) on a result or event.
/// Unreadable parts are ignored: the report is for display, and a malformed
/// one must not fail the result it rides on.
fn ext_report(raw: &Value) -> (Option<NamespaceForgeStatus>, Option<RepoForgeReport>) {
    let Some(ext) = raw.get("ext").and_then(|e| e.get(FORGE_REPORT_EXT)) else {
        return (None, None);
    };
    let ns = ext
        .get("namespace")
        .and_then(|v| serde_json::from_value::<NamespaceForgeStatus>(v.clone()).ok());
    let repo = ext
        .get("repo")
        .and_then(|v| serde_json::from_value::<RepoForgeReport>(v.clone()).ok());
    (ns, repo)
}

/// Overwrite what the bridge reported; keep what it did not mention.
fn merge_ns_status(ns: &mut Namespace, s: NamespaceForgeStatus) {
    // A report naming an installation says the bridge has access again, so a
    // past `installationRemoved` no longer describes the namespace.
    if s.installation_id.is_some() {
        ns.installation_removed = false;
    }
    let cur = ns.forge_status.get_or_insert_with(Default::default);
    macro_rules! take {
        ($($f:ident),*) => { $( if s.$f.is_some() { cur.$f = s.$f.clone(); } )* };
    }
    take!(
        installation_id,
        app_name,
        app_slug,
        app_registration,
        permission_upgrade_pending,
        org_rulesets,
        required_workflow,
        bridge_posted_check
    );
    if !s.missing_permissions.is_empty() || s.permission_upgrade_pending.is_some() {
        cur.missing_permissions = s.missing_permissions;
    }
    cur.reported_at = Some(now());
}

fn merge_repo_report(repo: &mut Repo, r: RepoForgeReport) {
    if r.guard.is_some() {
        repo.forge_report.guard = r.guard;
    }
    if r.last_check.is_some() {
        repo.forge_report.last_check = r.last_check;
    }
    if !r.steps.is_empty() {
        repo.forge_report.steps = r.steps;
    }
}

/// Set a repository detached and withdraw its rights — a repository deleted
/// on the forge, moved out of every bound namespace, or not found when
/// adopted.
async fn detach(state: &AppState, actor: &str, repo: &mut Repo, why: &str) -> Result<(), AppError> {
    let scope = Scope::Repo(repo.id.clone());
    let set = store::get_rights(&state.git_ns.ks, &scope).await?;
    for row in &set.rows {
        audit(
            state,
            actor,
            Some(&row.subject),
            Audit {
                action: "gitNs.right.revoked",
                namespace: Some(&repo.namespace_id),
                resource: Some(repo.resource.clone()),
                right: Some(row.right),
                policy_version: None,
                detail: Some(why.to_string()),
            },
        )
        .await;
    }
    store::put_rights(&state.git_ns.ks, &scope, &Default::default()).await?;
    repo.state = RepoState::Detached;
    repo.roles_digest = None;
    audit(
        state,
        actor,
        None,
        Audit {
            action: "gitNs.repo.detached",
            namespace: Some(&repo.namespace_id),
            resource: Some(repo.resource.clone()),
            right: None,
            policy_version: None,
            detail: Some(why.to_string()),
        },
    )
    .await;
    Ok(())
}

// ── git-ns/bridge/event/0.1 ─────────────────────────────────────────────────

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

pub async fn handle_event(
    state: &AppState,
    issuer: &str,
    p: event_wire::Payload,
) -> OpResult<event_wire::Response> {
    let ns_id = p.namespace.to_string();
    let raw = serde_json::to_value(&p).map_err(AppError::from)?;
    let event = raw.get("event").cloned().unwrap_or(Value::Null);
    let kind = s(&event, "type").unwrap_or_default();
    let drift: Vec<Value> = raw
        .get("drift")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let _guard = store::write_lock().await;
    let snap = Snapshot::load(&state.git_ns.ks).await?;
    let ns = snap
        .namespace(&ns_id)
        .cloned()
        .ok_or_else(|| OpError::Declared {
            code: event_wire::error_codes::UNKNOWN_NAMESPACE.code,
            message: format!("no namespace `{ns_id}` is bound to this VTC"),
        })?;
    // Only the bridge that serves the namespace may report on it.
    if ns.bridge_did.as_deref() != Some(issuer) {
        return Err(OpError::PermissionDenied(
            "only the bridge that serves this namespace may report events for it".into(),
        ));
    }
    let ack: event_wire::Response = wire::into(json!({}))?;
    let t = now();
    let mut concerned: Vec<String> = Vec::new();

    // Every lookup is scoped to the event's own namespace: a bridge speaks for
    // the namespace it serves and for nothing else, so neither a repository
    // in another namespace nor one whose resource lies outside this one can
    // be moved, detached or annotated by it.
    let ns_res = ns.resource();
    let inside = |raw: &str| -> OpResult<Resource> {
        let r = Resource::parse(raw).map_err(OpError::Malformed)?;
        if r.is_namespace() || !ns_res.contains(&r) {
            return Err(OpError::PermissionDenied(format!(
                "{raw} is not a repository of {ns_res}, which is all this bridge reports for"
            )));
        }
        Ok(r)
    };
    // By forge id first — the identity that survives a rename. By name only
    // where the recorded repository's forge id is unknown or is the same one:
    // a repository recorded at a name, but with *another* forge id, is a
    // different repository, and taking it for this one is how a renamed-away
    // repository's rights would land on whatever was later created in its
    // place (design §9, *Rename attacks*).
    let find = |forge_id: Option<&str>, resource: Option<&str>| -> Option<Repo> {
        forge_id
            .and_then(|f| snap.repo_by_forge_id(&ns.id, f))
            .or_else(|| {
                resource.and_then(|r| {
                    snap.repos.iter().find(|repo| {
                        repo.namespace_id == ns.id
                            && repo.resource == r
                            && (repo.forge_id.is_none()
                                || forge_id.is_none()
                                || repo.forge_id.as_deref() == forge_id)
                    })
                })
            })
            .cloned()
    };

    match kind.as_str() {
        "repoRenamed" | "repoTransferred" => {
            let forge_id = s(&event, "forgeId");
            let from = s(&event, "from").unwrap_or_default();
            let to = s(&event, "to").unwrap_or_default();
            inside(&from)?;
            let to_res = Resource::parse(&to).map_err(OpError::Malformed)?;
            // A rename stays under the owner; a rename that lands elsewhere is
            // not a rename, and is refused rather than guessed at.
            if kind == "repoRenamed" {
                inside(&to)?;
            }
            if let Some(mut repo) = find(forge_id.as_deref(), Some(&from)) {
                // A repository keeps its rights only while it stays inside
                // this namespace. Out of it — to another owner, another
                // forge, or another namespace of this VTC, which another
                // bridge may serve and whose admins granted none of these
                // rights — it is detached, and its rights withdrawn.
                if ns_res.contains(&to_res) && !to_res.is_namespace() {
                    // A stale record at the new name in this namespace — an
                    // unmanaged or detached row for what is now this
                    // repository — is folded away rather than left to shadow it.
                    if let Some(stale) = snap
                        .repos
                        .iter()
                        .find(|r| r.namespace_id == ns.id && r.resource == to && r.id != repo.id)
                    {
                        if matches!(stale.state, RepoState::Unmanaged | RepoState::Detached) {
                            store::delete_repo(&state.git_ns.ks, &stale.id).await?;
                            store::put_rights(
                                &state.git_ns.ks,
                                &Scope::Repo(stale.id.clone()),
                                &Default::default(),
                            )
                            .await?;
                        } else {
                            warn!(
                                %to,
                                "a repository was renamed onto a name another governed \
                                 repository holds; left for an admin to resolve"
                            );
                            return Ok(ack);
                        }
                    }
                    repo.resource = to.clone();
                    if repo.forge_id.is_none() {
                        repo.forge_id = forge_id.clone();
                    }
                    repo.roles_digest = None;
                    audit(
                        state,
                        issuer,
                        None,
                        Audit {
                            action: if kind == "repoRenamed" {
                                "gitNs.repo.renamed"
                            } else {
                                "gitNs.repo.transferred"
                            },
                            namespace: Some(&ns.id),
                            resource: Some(to.clone()),
                            right: None,
                            policy_version: None,
                            detail: Some(from.clone()),
                        },
                    )
                    .await;
                } else {
                    detach(state, issuer, &mut repo, "transferredOut").await?;
                }
                store::put_repo(&state.git_ns.ks, &repo).await?;
                concerned.push(repo.resource.clone());
            }
        }
        "repoCreatedUnmanaged" => {
            let forge_id = s(&event, "forgeId");
            let resource = s(&event, "resource").unwrap_or_default();
            inside(&resource)?;
            // A governed repository recorded at this name under a *different*
            // forge id has left the name (renamed or deleted, and the event
            // saying so was lost). The name now belongs to someone else, so the
            // old repository's rights must not stay published there: it is
            // detached, and the new repository starts unmanaged with nothing.
            if let Some(fid) = forge_id.as_deref() {
                let displaced: Vec<Repo> = snap
                    .repos
                    .iter()
                    .filter(|r| {
                        r.namespace_id == ns.id
                            && r.resource == resource
                            && r.forge_id.as_deref().is_some_and(|f| f != fid)
                            && r.state != RepoState::Detached
                    })
                    .cloned()
                    .collect();
                for mut old in displaced {
                    detach(state, issuer, &mut old, "nameReused").await?;
                    store::put_repo(&state.git_ns.ks, &old).await?;
                }
            }
            match find(forge_id.as_deref(), Some(&resource)) {
                Some(mut repo) => {
                    if repo.forge_id.is_none() {
                        repo.forge_id = forge_id;
                    }
                    if repo.state == RepoState::Detached {
                        repo.state = RepoState::Unmanaged;
                        repo.namespace_id = ns.id.clone();
                    }
                    store::put_repo(&state.git_ns.ks, &repo).await?;
                }
                None => {
                    let repo = Repo {
                        id: new_id("repo"),
                        namespace_id: ns.id.clone(),
                        resource: resource.clone(),
                        forge_id,
                        visibility: Visibility::Public,
                        description: None,
                        state: RepoState::Unmanaged,
                        created_by: None,
                        created_at: t,
                        bootstrap: Default::default(),
                        sync: SyncStatus::new(SyncState::Unchecked),
                        failed_step: None,
                        last_error: None,
                        roles_digest: None,
                        forge_report: Default::default(),
                    };
                    store::put_repo(&state.git_ns.ks, &repo).await?;
                }
            }
            concerned.push(resource);
        }
        "repoDeleted" => {
            let forge_id = s(&event, "forgeId");
            let resource = s(&event, "resource");
            if let Some(r) = &resource {
                inside(r)?;
            }
            if let Some(mut repo) = find(forge_id.as_deref(), resource.as_deref()) {
                detach(state, issuer, &mut repo, "deleted").await?;
                store::put_repo(&state.git_ns.ks, &repo).await?;
                concerned.push(repo.resource.clone());
            }
        }
        "roleChanged" => {
            let resource = s(&event, "resource");
            if let Some(r) = &resource {
                inside(r)?;
            }
            if let Some(mut repo) = find(s(&event, "forgeId").as_deref(), resource.as_deref()) {
                if super::policy::active_settings(state)
                    .await
                    .enforce_role_drift
                {
                    // Forget what was sent, so the projector sends it again.
                    repo.roles_digest = None;
                    store::put_repo(&state.git_ns.ks, &repo).await?;
                }
                concerned.push(repo.resource.clone());
            }
        }
        "protectionChanged" => {
            let resource = s(&event, "resource");
            if let Some(r) = &resource {
                inside(r)?;
            }
            let required = event
                .get("requiredCheck")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(mut repo) = find(s(&event, "forgeId").as_deref(), resource.as_deref()) {
                repo.bootstrap.required_check = required;
                store::put_repo(&state.git_ns.ks, &repo).await?;
                if !required && repo.state == RepoState::Active {
                    // The one drift that silently removes the guarantee: put
                    // it back by default, and say so.
                    enqueue(
                        state,
                        NewJob {
                            namespace_id: ns.id.clone(),
                            kind: JobKind::Bootstrap,
                            payload: json!({
                                "namespace": ns.id,
                                "kind": "bootstrap",
                                "repo": repo.resource,
                                "steps": ["requiredCheck"],
                            }),
                            repo_id: Some(repo.id.clone()),
                            link_id: None,
                        },
                    )
                    .await?;
                    audit(
                        state,
                        issuer,
                        None,
                        Audit {
                            action: "gitNs.repo.protectionWeakened",
                            namespace: Some(&ns.id),
                            resource: Some(repo.resource.clone()),
                            right: None,
                            policy_version: None,
                            detail: Some("requiredCheck".into()),
                        },
                    )
                    .await;
                }
                concerned.push(repo.resource.clone());
            }
        }
        "installationRemoved" => {
            let mut updated = ns.clone();
            updated.installation_removed = true;
            store::put_namespace(&state.git_ns.ks, &updated).await?;
            for mut repo in snap
                .repos
                .iter()
                .filter(|r| r.namespace_id == ns.id)
                .cloned()
            {
                repo.sync.state = SyncState::Unchecked;
                store::put_repo(&state.git_ns.ks, &repo).await?;
            }
            audit(
                state,
                issuer,
                None,
                Audit {
                    action: "gitNs.namespace.installationRemoved",
                    namespace: Some(&ns.id),
                    resource: Some(ns.resource().to_string()),
                    right: None,
                    policy_version: None,
                    detail: None,
                },
            )
            .await;
        }
        "accountLinked" => {
            let job_id = s(&event, "jobId").unwrap_or_default();
            let account = event.get("account").cloned().unwrap_or(Value::Null);
            complete_account_link(state, issuer, &ns, &job_id, &account).await?;
        }
        "bindCompleted" => {
            let job_id = s(&event, "jobId").unwrap_or_default();
            complete_binding(state, issuer, &ns, &job_id, &event).await?;
        }
        other => {
            // A newer bridge speaking a newer vocabulary: recorded in the log,
            // changes nothing.
            info!(
                event = other,
                "ignoring a bridge event type this VTC does not know"
            );
        }
    }

    // The drift for each repository the event concerns replaces what was held.
    for item in &drift {
        if let Some(r) = item.get("resource").and_then(Value::as_str)
            && inside(r).is_ok()
            && !concerned.iter().any(|c| c == r)
        {
            concerned.push(r.to_string());
        }
    }
    if !concerned.is_empty() {
        let snap = Snapshot::load(&state.git_ns.ks).await?;
        for resource in concerned {
            let Some(mut repo) = snap
                .repos
                .iter()
                .find(|r| {
                    r.namespace_id == ns.id
                        && r.resource == resource
                        && r.state != RepoState::Detached
                })
                .cloned()
            else {
                continue;
            };
            let items: Vec<Value> = drift
                .iter()
                .filter(|d| d.get("resource").and_then(Value::as_str) == Some(resource.as_str()))
                .cloned()
                .collect();
            repo.sync.state = if items.is_empty() {
                SyncState::InSync
            } else {
                SyncState::Drift
            };
            if !items.is_empty() {
                // For the namespace admins' activity feed: the drift, counted.
                // The items themselves (forge accounts of people outside the
                // VTC) stay on the repository, not in the audit log.
                audit(
                    state,
                    issuer,
                    None,
                    Audit {
                        action: "gitNs.drift.reported",
                        namespace: Some(&repo.namespace_id),
                        resource: Some(repo.resource.clone()),
                        right: None,
                        policy_version: None,
                        detail: Some(items.len().to_string()),
                    },
                )
                .await;
            }
            repo.sync.drift = items;
            repo.sync.checked_at = Some(t);
            if let Some(report) = ext_report(&raw).1 {
                merge_repo_report(&mut repo, report);
            }
            store::put_repo(&state.git_ns.ks, &repo).await?;
        }
    }
    if let Some(status) = ext_report(&raw).0
        && let Some(mut ns) = store::get_namespace(&state.git_ns.ks, &ns.id).await?
    {
        merge_ns_status(&mut ns, status);
        store::put_namespace(&state.git_ns.ks, &ns).await?;
    }
    Ok(ack)
}

/// `bindCompleted`: accepted only for the `beginBind` job this VTC sent this
/// bridge and has not yet seen completed.
async fn complete_binding(
    state: &AppState,
    issuer: &str,
    ns: &Namespace,
    job_id: &str,
    event: &Value,
) -> OpResult<()> {
    if ns.state != NamespaceState::Pending || ns.bind_job_id.as_deref() != Some(job_id) {
        return Err(OpError::PermissionDenied(
            "no binding of this namespace is waiting on that job".into(),
        ));
    }
    let job = get_job(&state.git_ns.jobs_ks, job_id).await?;
    if !job.is_some_and(|j| j.kind == JobKind::BeginBind && j.bridge_did == issuer) {
        return Err(OpError::PermissionDenied(
            "that job is not a binding this VTC sent this bridge".into(),
        ));
    }
    let mut bound = ns.clone();
    bound.owner_id = s(event, "ownerId");
    bound.kind = match s(event, "kind").as_deref() {
        Some("organization") => Some(OwnerKind::Organization),
        Some("user") => Some(OwnerKind::User),
        _ => None,
    };
    bound.state = NamespaceState::Bound;
    bound.bound_at = Some(now());
    bound.bind_job_id = None;
    bound.installation_removed = false;
    store::put_namespace(&state.git_ns.ks, &bound).await?;
    audit(
        state,
        &ns.bound_by,
        None,
        Audit {
            action: "gitNs.namespace.bound",
            namespace: Some(&ns.id),
            resource: Some(ns.resource().to_string()),
            right: None,
            policy_version: None,
            detail: Some("bridge".into()),
        },
    )
    .await;
    // The administrator who asked receives the first `git.ns.admin` — if they
    // are still a member; the floor holds for this grant as for any other.
    let binder = ops::standing(state, &ns.bound_by).await?;
    if binder.member {
        let scope = Scope::Namespace(ns.id.clone());
        let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
        if !set
            .rows
            .iter()
            .any(|r| r.subject == ns.bound_by && r.right == Right::NsAdmin)
        {
            set.rows.push(RightRow {
                subject: ns.bound_by.clone(),
                right: Right::NsAdmin,
                granted_by: ns.bound_by.clone(),
                granted_at: now(),
                expires_at: None,
                reason: None,
                subject_was_member: true,
                granter_was_member: true,
            });
            store::put_rights(&state.git_ns.ks, &scope, &set).await?;
            audit(
                state,
                &ns.bound_by,
                Some(&ns.bound_by),
                Audit {
                    action: "gitNs.right.granted",
                    namespace: Some(&ns.id),
                    resource: Some(ns.resource().to_string()),
                    right: Some(Right::NsAdmin),
                    policy_version: None,
                    detail: Some("binding".into()),
                },
            )
            .await;
        }
    } else {
        warn!(
            namespace = %ns.id,
            "the administrator who began this binding is no longer a member; the namespace is \
             bound with no admin"
        );
    }
    service_grant(state, &bound).await?;
    Ok(())
}

/// The bridge's own `git.commit.sign` on the namespace — a **service grant**.
///
/// The bridge re-signs Dependabot pull requests with its own DID (design §9,
/// *Dependabot re-sign bot*), so the commits it authors must pass the check
/// like anyone else's. It is not a member and holds no right anyone granted:
/// the community grants it, as itself (`grantedBy` = the VTC's DID), when a
/// bridge-mode namespace becomes bound, and the grant ends with the binding
/// (unbind revokes every record in the namespace). A namespace's bridge is
/// recorded at bind and never changes, so there is no other moment for it to
/// move.
///
/// It is still a grant to a non-member, so it goes through the community's
/// policy as `bridge.serviceGrant`; the shipped default admits exactly this —
/// `git.commit.sign`, on the namespace, to that namespace's own bridge — and
/// nothing else for a non-member. A policy that refuses it leaves the
/// namespace bound without it, which is logged.
pub async fn service_grant(state: &AppState, ns: &Namespace) -> OpResult<()> {
    let Some(bridge_did) = ns.bridge_did.clone() else {
        return Ok(());
    };
    let Some(vtc_did) = state.config.read().await.vtc_did.clone() else {
        return Ok(());
    };
    let scope = Scope::Namespace(ns.id.clone());
    let mut set = store::get_rights(&state.git_ns.ks, &scope).await?;
    if set
        .rows
        .iter()
        .any(|r| r.subject == bridge_did && r.right == Right::CommitSign)
    {
        return Ok(());
    }
    let resource = ns.resource();
    let vtc = ops::standing(state, &vtc_did).await?;
    let bridge = ops::standing(state, &bridge_did).await?;
    let passed =
        rules::service_grant_admitted(&bridge_did, &bridge_did, Right::CommitSign, &resource)
            .map_err(OpError::from)?;
    let version = match ops::check_policy(
        state,
        ops::PolicyInput {
            action: "bridge.serviceGrant",
            actor: &ops::Standing {
                did: vtc_did.clone(),
                member: true,
                ..vtc
            },
            actor_rights: vec![],
            resource: &resource,
            right: Some(Right::CommitSign),
            subject: Some((&bridge, vec![])),
            visibility: None,
            expires_at: None,
            namespace: Some(ns),
            passed,
        },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(
                namespace = %ns.id,
                error = %e,
                "the git-namespace policy refused the bridge's service grant; the bridge's own \
                 commits will not pass the check"
            );
            return Ok(());
        }
    };
    set.rows.push(RightRow {
        subject: bridge_did.clone(),
        right: Right::CommitSign,
        granted_by: vtc_did.clone(),
        granted_at: now(),
        expires_at: None,
        reason: None,
        subject_was_member: false,
        granter_was_member: false,
    });
    store::put_rights(&state.git_ns.ks, &scope, &set).await?;
    audit(
        state,
        &vtc_did,
        Some(&bridge_did),
        Audit {
            action: "gitNs.right.granted",
            namespace: Some(&ns.id),
            resource: Some(resource.to_string()),
            right: Some(Right::CommitSign),
            policy_version: version,
            detail: Some("serviceGrant".into()),
        },
    )
    .await;
    Ok(())
}

/// `accountLinked`: completes the link begun with `git-ns/account/link`.
async fn complete_account_link(
    state: &AppState,
    issuer: &str,
    ns: &Namespace,
    job_id: &str,
    account: &Value,
) -> OpResult<()> {
    let job = get_job(&state.git_ns.jobs_ks, job_id)
        .await?
        .filter(|j| {
            j.kind == JobKind::BeginAccountLink && j.bridge_did == issuer && j.namespace_id == ns.id
        })
        .ok_or_else(|| {
            OpError::PermissionDenied(
                "that job is not an account link this VTC sent this bridge".into(),
            )
        })?;
    let Some(link_id) = job.link_id else {
        return Ok(());
    };
    let Some(mut attempt) = store::get_link(&state.git_ns.ks, &link_id).await? else {
        return Ok(());
    };
    if attempt.state != LinkState::Pending {
        // Already completed: a repeated event is harmless.
        return Ok(());
    }
    let (Some(id), Some(login)) = (s(account, "id"), s(account, "login")) else {
        return Err(OpError::Malformed(
            "accountLinked carries no account".into(),
        ));
    };
    let t = now();
    // The account must be on the forge the member asked to link, which is the
    // namespace's forge — a bridge serving `github.com` cannot hand a member a
    // `codeberg.org` identity — and must arrive while the attempt is open.
    let Some(forge) = s(account, "forge") else {
        return Err(OpError::Malformed(
            "accountLinked carries an account with no forge".into(),
        ));
    };
    if forge != attempt.forge || forge != ns.forge {
        attempt.state = LinkState::Failed;
        attempt.finished_at = Some(t);
        store::put_link(&state.git_ns.ks, &attempt).await?;
        return Err(OpError::PermissionDenied(format!(
            "the linked account is on {forge}, but the member asked to link {} through a \
             namespace on {}",
            attempt.forge, ns.forge
        )));
    }
    if attempt.expires_at <= t {
        attempt.state = LinkState::Expired;
        attempt.finished_at = Some(t);
        store::put_link(&state.git_ns.ks, &attempt).await?;
        return Err(OpError::PermissionDenied(
            "the link attempt had already lapsed when the account arrived".into(),
        ));
    }

    // Item 4 — a forge account links to one member at most.
    let taken_by_other = linked_accounts(state)
        .await?
        .into_iter()
        .any(|(did, forges)| {
            did != attempt.member && forges.get(&forge).is_some_and(|a| a.id == id)
        });
    let linked = if taken_by_other {
        None
    } else {
        let entry = json!({ "id": id, "login": login, "linkedAt": wire::timestamp(t) });
        crate::members::storage::edit_member(&state.members_ks, &attempt.member, |m| {
            if m.removed_at.is_some() {
                return false;
            }
            if !m.extensions.is_object() {
                m.extensions = json!({});
            }
            if let Some(o) = m.extensions.as_object_mut() {
                let forges = o.entry("forges").or_insert_with(|| json!({}));
                if !forges.is_object() {
                    *forges = json!({});
                }
                forges[&forge] = entry.clone();
            }
            true
        })
        .await?
        .filter(|m| m.removed_at.is_none())
    };
    match linked {
        Some(_) => {
            attempt.state = LinkState::Linked;
            attempt.account = Some(ForgeAccount {
                forge: forge.clone(),
                id,
                login,
            });
            audit(
                state,
                &attempt.member,
                Some(&attempt.member),
                Audit {
                    action: "gitNs.account.linked",
                    namespace: Some(&ns.id),
                    resource: None,
                    right: None,
                    policy_version: None,
                    detail: Some(forge),
                },
            )
            .await;
        }
        _ => {
            attempt.state = LinkState::Failed;
        }
    }
    attempt.finished_at = Some(t);
    store::put_link(&state.git_ns.ks, &attempt).await?;
    Ok(())
}
