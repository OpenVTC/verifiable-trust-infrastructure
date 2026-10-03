//! The administrator **action list** — consent-gated operations that wait for
//! N-of-M approval and complete themselves on the N-th
//! (`docs/05-design-notes/vtc-action-list.md` §4–§7a).
//!
//! ## What an action is
//!
//! An operation that needs other administrators' agreement —
//! [`crate::acl::admin_consent::Act`]: an unrestricted grant (VTI-APV-014), a
//! reduction of another unrestricted administrator (VTI-APV-019), a lowered
//! consent threshold (VTI-APV-020), a change to an authority-deciding policy
//! (VTI-VTC-022) — is **parked** here rather than refused. Its record keeps the
//! requester's signed document verbatim, the operation's type and payload, the
//! requester and the evidence of their passkey gesture (VTI-APV-015), the
//! approver set and threshold, one salted challenge per approver, a pin on the
//! state the approvers are shown, and a lifetime (VTI-APV-008).
//!
//! The requester is answered with `trust-task-next-step/0.1` (continuation
//! `proceed`, expecting `vtc/admin/actions/show` with the action's id): the
//! operation is not refused and is never sent again.
//!
//! ## How it ends (VTI-APV-017)
//!
//! - **Approve.** Each approval is recorded against the approver's own
//!   challenge; a subject counts once (VTI-APV-007). The approval that reaches
//!   the threshold moves the action out of `open` **under [`ACTION_LOCK`]** —
//!   so two N-th approvals arriving together cannot both execute it — and then
//!   dispatches the stored document through the same handler it was submitted
//!   to. Every check that handler makes runs again against the community as it
//!   is now: the requester's authority, separation of duties, the role-change
//!   policy, attrition, and at the consent gate the approvals themselves (still
//!   eligible, still enough, state pin unmoved — [`recheck`]). The write
//!   happens at most once; the action closes `completed`, or `failed` with the
//!   refusal and nothing written.
//! - **Deny.** One deny closes it `declined` for everyone ("`deny` aborts the
//!   pending request", `task-consent/decision`).
//! - **Cancel.** The requester withdraws it (`vtc/admin/actions/cancel`).
//! - **Expire.** Past `expiresAt` it is never executable; it closes `expired`.
//! - **Invalidate** (§4.4). The requester losing the authority the operation
//!   needs, the pinned state moving, or the approver set no longer able to reach
//!   the threshold closes it `cancelled` (`closedReason: invalidated`). Decided
//!   lazily — on every read and decision, and by the sweeper — so nothing reads
//!   an action that should already have closed.
//!
//! The requester's document is held to freshness and replay once, when it is
//! submitted (VTI-OPS-024…027). Execution dispatches this service's own stored
//! copy past the spine, so the document is never accepted twice.
//!
//! ## Lock order
//!
//! [`ACTION_LOCK`] is **not** held across the execution: the handlers take the
//! promotion and admin-set locks themselves, and a submission parks while
//! holding them, so holding this one across the dispatch would invert the
//! order. The status transition `open → executing` under the lock is what
//! makes the execution single; the handler's own locks serialise the write.

pub mod summary;

/// The declared error codes of `vtc/admin/actions/*`, read off the generated
/// specifications — what the tests that witness each one compare against.
pub mod codes {
    use trust_tasks_rs::specs::vtc::admin::actions as a;

    pub const LIST_NOT_ADMINISTRATOR: &str = a::list::v0_1::error_codes::NOT_ADMINISTRATOR.code;
    pub const LIST_INVALID_CURSOR: &str = a::list::v0_1::error_codes::INVALID_CURSOR.code;
    pub const LIST_INVALID_FILTER: &str = a::list::v0_1::error_codes::INVALID_FILTER.code;
    pub const SHOW_NOT_FOUND: &str = a::show::v0_1::error_codes::NOT_FOUND.code;
    pub const SHOW_NOT_ADMINISTRATOR: &str = a::show::v0_1::error_codes::NOT_ADMINISTRATOR.code;
    pub const CANCEL_NOT_FOUND: &str = a::cancel::v0_1::error_codes::NOT_FOUND.code;
    pub const CANCEL_NOT_REQUESTER: &str = a::cancel::v0_1::error_codes::NOT_REQUESTER.code;
    pub const CANCEL_NOT_OPEN: &str = a::cancel::v0_1::error_codes::NOT_OPEN.code;
    pub const ACKNOWLEDGE_NOT_FOUND: &str = a::acknowledge::v0_1::error_codes::NOT_FOUND.code;
    pub const ACKNOWLEDGE_NOT_ACKNOWLEDGEABLE: &str =
        a::acknowledge::v0_1::error_codes::NOT_ACKNOWLEDGEABLE.code;
}

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tracing::{debug, info, warn};
use vti_common::audit::{AuditEvent, TaskConsentData};
use vti_common::error::AppError;
use vti_common::task_consent::{self, effects::Effect, effects::StatePin};

use crate::acl::admin_consent::{self, Act, Operation};
use crate::acl::bound_step_up::StepUpEvidence;
use crate::auth::session::now_epoch;
use crate::config_store::ConfigStore;
use crate::join::JoinTransport;
use crate::server::AppState;

/// The code an [`AppError::ApprovalRequired`] carries when the operation was
/// parked. Never on the wire: the dispatcher answers it with a
/// `trust-task-next-step/0.1` ([`next_step_payload`]), not an error.
pub const ACTION_PARKED: &str = "vtc:action_parked";

/// How long a closed action stays in History (§4.1).
pub const HISTORY_SECS: u64 = 30 * 24 * 3600;

/// The burst alert (§7a.1): more than this many actions raised by one
/// requester inside [`BURST_WINDOW_SECS`].
pub const BURST_MAX: usize = 3;
pub const BURST_WINDOW_SECS: u64 = 600;

/// An approver's own decisions: at most this many a minute (§7a.1,
/// anti-scripting).
pub const DECISIONS_PER_MINUTE: usize = 10;

/// An action left `executing` this long was interrupted — the process died
/// mid-execution — and is failed closed by the sweeper.
const INTERRUPTED_AFTER_SECS: u64 = 600;

const ACTION_PREFIX: &str = "action:";
const WIRE_PREFIX: &str = "wire:";

/// Serialises every change to an action's record in this process — raise,
/// decide, cancel, invalidate, sweep. fjall is not multi-process safe, so a
/// process-wide lock is the right granularity. See the module docs for why it is
/// not held across an execution.
static ACTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ─── the record ──────────────────────────────────────────────────────────

/// An action's state. `executing` is internal: it reads as `open` on the
/// wire, and exists so that the move out of `open` can happen under the lock
/// before the operation runs outside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Open,
    Executing,
    Completed,
    Declined,
    Expired,
    Cancelled,
    Failed,
}

impl Status {
    fn wire(self) -> &'static str {
        match self {
            Self::Open | Self::Executing => "open",
            Self::Completed => "completed",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Executing)
    }
}

/// Why an action closed, in the specification's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClosedReason {
    ThresholdMet,
    Declined,
    Expired,
    CancelledByRequester,
    Invalidated,
    FailedRecheck,
}

impl ClosedReason {
    fn wire(self) -> &'static str {
        match self {
            Self::ThresholdMet => "thresholdMet",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::CancelledByRequester => "cancelledByRequester",
            Self::Invalidated => "invalidated",
            Self::FailedRecheck => "failedRecheck",
        }
    }
}

/// One eligible approver's slot: the challenge that approver alone is shown,
/// and the wire digest salted with it (VTI-APV-004).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproverSlot {
    pub did: String,
    pub challenge: String,
    pub wire_digest: String,
}

/// One approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub did: String,
    pub at: u64,
    /// The additional factor the approver presented, if any —
    /// `webauthn:<credential id hex>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// The requester's gesture, recorded at submission (VTI-APV-015, §4.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequesterStepUp {
    pub kind: String,
    pub credential_id: String,
    pub bound_to: String,
    pub at: u64,
}

/// A parked operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRecord {
    pub id: String,
    pub kind: String,
    pub act: Act,
    pub type_uri: String,
    /// The payload the digest is taken over and the one that executes.
    pub payload: Value,
    /// `vti_common::task_consent::payload_digest` — executor-internal.
    pub digest: String,
    /// The requester's signed document, exactly as received.
    pub submitted_doc: Value,
    /// The DID whose proof the document carried — the requester, or a console
    /// key acting for them. Execution resolves it again.
    pub submitted_signer: String,
    pub transport: String,
    /// The acting administrator (a console key resolved to its admin).
    pub requester: String,
    pub subject: String,
    pub requester_step_up: RequesterStepUp,
    pub approver_set: String,
    pub approvers: Vec<ApproverSlot>,
    pub threshold: u64,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    pub state_pin: StatePin,
    /// What the approvers' devices are shown in a pushed request.
    pub summary_text: String,
    pub status: Status,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executing_since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_reason: Option<ClosedReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
    /// The executed operation's response payload, shown to the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The result carries a bearer secret (an invite's claim code): shown to
    /// the requester once, by `show`, then dropped.
    #[serde(default)]
    pub result_secret: bool,
}

impl ActionRecord {
    fn slot(&self, did: &str) -> Option<&ApproverSlot> {
        self.approvers.iter().find(|s| s.did == did)
    }

    fn approved_by(&self, did: &str) -> bool {
        self.approvals.iter().any(|a| a.did == did)
    }

    fn close(&mut self, status: Status, reason: ClosedReason, message: Option<String>, now: u64) {
        self.status = status;
        self.closed_reason = Some(reason);
        self.closed_message = message;
        self.closed_at = Some(now);
        self.executing_since = None;
    }
}

fn action_key(id: &str) -> String {
    format!("{ACTION_PREFIX}{id}")
}

fn wire_key(wire: &str) -> String {
    format!("{WIRE_PREFIX}{wire}")
}

async fn load(state: &AppState, id: &str) -> Result<Option<ActionRecord>, AppError> {
    state.admin_actions_ks.get(action_key(id)).await
}

async fn save(state: &AppState, rec: &ActionRecord) -> Result<(), AppError> {
    state
        .admin_actions_ks
        .insert(action_key(&rec.id), rec)
        .await
}

async fn all(state: &AppState) -> Result<Vec<ActionRecord>, AppError> {
    let mut out = Vec::new();
    for (_, value) in state
        .admin_actions_ks
        .prefix_iter_raw(ACTION_PREFIX.as_bytes().to_vec())
        .await?
    {
        match serde_json::from_slice::<ActionRecord>(&value) {
            Ok(r) => out.push(r),
            Err(e) => debug!(error = %e, "action list: unreadable record"),
        }
    }
    Ok(out)
}

async fn by_wire(state: &AppState, wire: &str) -> Result<Option<ActionRecord>, AppError> {
    let Some(id) = state.admin_actions_ks.get_raw(wire_key(wire)).await? else {
        return Ok(None);
    };
    let id = String::from_utf8(id)
        .map_err(|e| AppError::Internal(format!("action wire index not utf-8: {e}")))?;
    load(state, &id).await
}

async fn delete(state: &AppState, rec: &ActionRecord) -> Result<(), AppError> {
    for slot in &rec.approvers {
        state
            .admin_actions_ks
            .remove(wire_key(&slot.wire_digest))
            .await?;
    }
    state.admin_actions_ks.remove(action_key(&rec.id)).await
}

// ─── submission and execution context ────────────────────────────────────

/// The document being dispatched, as the spine received it — what a parked
/// action stores and later executes.
#[derive(Clone)]
pub(crate) struct Submission {
    pub received: Arc<Value>,
    pub signer: Option<String>,
    pub transport: JoinTransport,
}

/// The approved action whose stored document is executing.
#[derive(Clone, Debug)]
pub(crate) struct Executing {
    pub action_id: String,
    pub requester: String,
    pub type_uri: String,
    pub digest: String,
    gate_spent: Arc<AtomicBool>,
}

tokio::task_local! {
    static SUBMISSION: Submission;
    static EXECUTING: Executing;
}

/// Run `fut` — the spine's dispatch of one document — with that document
/// available to [`park`].
pub(crate) async fn with_submission<F: std::future::Future>(
    submission: Submission,
    fut: F,
) -> F::Output {
    SUBMISSION.scope(submission, fut).await
}

/// Run `fut` — an approved action's stored document — as that action's
/// execution, which the consent gate recognises ([`executing`]).
pub(crate) fn executing_scope<F: std::future::Future>(
    exec: Executing,
    fut: F,
) -> tokio::task::futures::TaskLocalFuture<Executing, F> {
    EXECUTING.scope(exec, fut)
}

/// The approved action executing on this task, if any.
pub(crate) fn executing() -> Option<Executing> {
    EXECUTING.try_with(Clone::clone).ok()
}

/// Record that the executing action's consent gate was reached and spent.
pub(crate) fn note_gate_spent(action_id: &str) {
    let _ = EXECUTING.try_with(|e| {
        if e.action_id == action_id {
            e.gate_spent.store(true, Ordering::SeqCst);
        }
    });
}

fn transport_name(t: JoinTransport) -> &'static str {
    match t {
        JoinTransport::Rest => "rest",
        JoinTransport::DIDComm => "didcomm",
        JoinTransport::Tsp => "tsp",
    }
}

fn transport_from(name: &str) -> JoinTransport {
    match name {
        "didcomm" => JoinTransport::DIDComm,
        "tsp" => JoinTransport::Tsp,
        _ => JoinTransport::Rest,
    }
}

// ─── settings ────────────────────────────────────────────────────────────

async fn setting(state: &AppState, key: &str) -> Result<u64, AppError> {
    let cfg = state.config.read().await.clone();
    crate::config_store::live_action_setting(key, &cfg, &ConfigStore::new(state.config_ks.clone()))
        .await
}

// ─── raising an action ───────────────────────────────────────────────────

/// The open action already raised for this operation by this requester.
pub(crate) async fn open_for(
    state: &AppState,
    requester: &str,
    op: Operation<'_>,
) -> Result<Option<ActionRecord>, AppError> {
    let digest = task_consent::payload_digest(op.type_uri, op.payload)?;
    refresh_all(state).await?;
    Ok(all(state)
        .await?
        .into_iter()
        .find(|r| r.status.is_open() && r.requester == requester && r.digest == digest))
}

/// The approval-fatigue limits (§7a.1), checked before the requester is asked
/// for a gesture and again when the action is written.
pub(crate) async fn check_limits(
    state: &AppState,
    act: Act,
    requester: &str,
    subject: &str,
) -> Result<(), AppError> {
    let now = now_epoch();
    let actions = all(state).await?;
    let per_requester = setting(state, crate::config_store::ACTION_MAX_OPEN_PER_REQUESTER).await?;
    let community = setting(state, crate::config_store::ACTION_MAX_OPEN).await?;
    let cooldown = setting(state, crate::config_store::ACTION_DECLINE_COOLDOWN).await?;

    let open_mine = actions
        .iter()
        .filter(|r| r.status.is_open() && r.requester == requester)
        .count() as u64;
    if open_mine >= per_requester {
        return Err(AppError::Conflict(format!(
            "you already have {open_mine} actions waiting for approval, the most \
             {} allows. Wait for one to be decided, or cancel one \
             (vtc/admin/actions/cancel), and send this again",
            crate::config_store::ACTION_MAX_OPEN_PER_REQUESTER
        )));
    }
    let open_all = actions.iter().filter(|r| r.status.is_open()).count() as u64;
    if open_all >= community {
        return Err(AppError::Conflict(format!(
            "this community already has {open_all} actions waiting for approval, the most \
             {} allows. Decide or cancel some first",
            crate::config_store::ACTION_MAX_OPEN
        )));
    }
    let kind = act.kind("");
    let declined_recently = actions.iter().any(|r| {
        r.status == Status::Declined
            && r.requester == requester
            && r.subject == subject
            && r.act.kind("") == kind
            && r.closed_at
                .is_some_and(|c| c.saturating_add(cooldown) > now)
    });
    if declined_recently {
        return Err(AppError::Conflict(format!(
            "an action of this kind against {subject} was declined less than {} minutes ago; \
             {} refuses the same request again until then",
            cooldown / 60,
            crate::config_store::ACTION_DECLINE_COOLDOWN
        )));
    }
    Ok(())
}

/// What [`park`] needs.
pub(crate) struct Parking<'a> {
    pub act: Act,
    pub requester: &'a str,
    pub subject: &'a str,
    pub op: Operation<'a>,
    pub summary: &'a str,
    pub evidence: StepUpEvidence,
    pub approvers: Vec<String>,
    pub threshold: u64,
    pub pin: StatePin,
}

/// Park the operation being dispatched as an action. The requester's gesture
/// has been spent; the action records it (VTI-APV-015).
pub(crate) async fn park(state: &AppState, p: Parking<'_>) -> Result<ActionRecord, AppError> {
    let Ok(submission) = SUBMISSION.try_with(Clone::clone) else {
        return Err(AppError::Forbidden(format!(
            "{} needs other administrators' approval ({}), which only a signed document can \
             wait for",
            p.summary,
            p.act.requirement()
        )));
    };
    let signer = submission.signer.clone().ok_or_else(|| {
        AppError::Internal("an action can only be raised from a signed document".into())
    })?;
    let now = now_epoch();
    let lifetime = setting(state, crate::config_store::ACTION_LIFETIME).await?;
    let digest = task_consent::payload_digest(p.op.type_uri, p.op.payload)?;

    let mut approvers = Vec::with_capacity(p.approvers.len());
    for did in &p.approvers {
        // 256 bits: the challenge is both the per-approver binding and the salt
        // that keeps the wire digest from confirming a guess at a short,
        // predictable payload.
        let challenge = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        approvers.push(ApproverSlot {
            did: did.clone(),
            wire_digest: task_consent::wire_digest(p.op.type_uri, p.op.payload, &challenge)?,
            challenge,
        });
    }

    let rec = ActionRecord {
        id: format!("act-{}", uuid::Uuid::new_v4().simple()),
        kind: p.act.kind(p.op.type_uri).to_string(),
        act: p.act,
        type_uri: p.op.type_uri.to_string(),
        payload: p.op.payload.clone(),
        digest,
        submitted_doc: (*submission.received).clone(),
        submitted_signer: signer,
        transport: transport_name(submission.transport).to_string(),
        requester: p.requester.to_string(),
        subject: p.subject.to_string(),
        requester_step_up: RequesterStepUp {
            kind: "webauthn".into(),
            credential_id: p.evidence.credential_id,
            bound_to: p.evidence.bound_to,
            at: now,
        },
        approver_set: p.act.approver_set().to_string(),
        approvers,
        threshold: p.threshold,
        approvals: Vec::new(),
        state_pin: p.pin,
        summary_text: p.summary.to_string(),
        status: Status::Open,
        created_at: now,
        expires_at: now.saturating_add(lifetime),
        executing_since: None,
        closed_at: None,
        closed_reason: None,
        closed_message: None,
        closed_by: None,
        result: None,
        result_secret: false,
    };

    let recent = {
        let _guard = ACTION_LOCK.lock().await;
        // The limits again, under the lock: two submissions racing past the
        // first check cannot both take the last slot.
        check_limits(state, p.act, p.requester, p.subject).await?;
        for slot in &rec.approvers {
            state
                .admin_actions_ks
                .insert_raw(wire_key(&slot.wire_digest), rec.id.as_bytes().to_vec())
                .await?;
        }
        save(state, &rec).await?;
        all(state)
            .await?
            .iter()
            .filter(|r| {
                r.requester == rec.requester && r.created_at.saturating_add(BURST_WINDOW_SECS) > now
            })
            .count()
    };

    audit(state, &rec, p.requester, "parked", Vec::new()).await;
    if recent > BURST_MAX {
        warn!(
            requester = %rec.requester,
            raised = recent,
            "action burst: one requester raised more than {BURST_MAX} actions in \
             {BURST_WINDOW_SECS} s (vtc-action-list.md §7a.1)"
        );
        if let Some(writer) = state.audit_writer.as_ref()
            && let Err(e) = writer
                .write(
                    &rec.requester,
                    None,
                    AuditEvent::AdminActionBurst(vti_common::audit::AdminActionBurstData {
                        action_id: rec.id.clone(),
                        kind: rec.kind.clone(),
                        raised: recent as u32,
                        window_secs: BURST_WINDOW_SECS,
                    }),
                )
                .await
        {
            warn!(error = %e, "could not audit an action burst");
        }
    }
    info!(
        action = %rec.id,
        kind = %rec.kind,
        requester = %rec.requester,
        approvers = rec.approvers.len(),
        threshold = rec.threshold,
        "operation parked for approval"
    );
    push_requests(state, &rec).await;
    Ok(rec)
}

/// The parked answer, as the error every gate's caller already propagates.
/// The dispatcher renders it as a `trust-task-next-step/0.1`.
pub(crate) async fn parked_error(state: &AppState, rec: &ActionRecord) -> AppError {
    let eligible = match tally(state, rec).await {
        Ok(t) => t.eligible,
        Err(_) => rec.approvers.len() as u64,
    };
    AppError::ApprovalRequired {
        code: ACTION_PARKED,
        details: json!({
            "actionId": rec.id,
            "kind": rec.kind,
            "threshold": rec.threshold,
            "approvers": eligible,
            "approvals": rec.approvals.len(),
            "expiresAt": rfc3339(rec.expires_at),
            "message": parked_message(rec, eligible),
        }),
    }
}

fn parked_message(rec: &ActionRecord, eligible: u64) -> String {
    let left = rec.expires_at.saturating_sub(now_epoch());
    format!(
        "Sent for approval — {} of {} unrestricted administrator(s) must approve within {}.",
        rec.threshold,
        eligible,
        human_duration(left)
    )
}

/// The `trust-task-next-step/0.1` payload for a parked operation (§9.1 item
/// 4): continuation `proceed` — approval is not a prerequisite the requester
/// re-submits after, it *is* the continuation — expecting
/// `vtc/admin/actions/show` with the action's id.
pub(crate) fn next_step_payload(doc_id: &str, doc_type: &str, details: &Value) -> Value {
    json!({
        "continuation": "proceed",
        "expects": [{
            "typeUri": crate::trust_tasks::action_tasks::SHOW_TYPE,
            "hint": { "actionId": details["actionId"] },
            "reason": "the operation waits in the action list until enough administrators approve it",
        }],
        "inResponseTo": { "id": doc_id, "typeUri": doc_type },
        "message": details["message"],
        "ext": { "org.openvtc": {
            "actionId": details["actionId"],
            "kind": details["kind"],
            "threshold": details["threshold"],
            "approvers": details["approvers"],
            "approvals": details["approvals"],
            "expiresAt": details["expiresAt"],
        }},
    })
}

// ─── the re-check at execution (VTI-APV-017) ─────────────────────────────

/// How an action's approvals stand against the community now.
pub(crate) struct Tally {
    /// Approvals by approvers who are still eligible.
    pub valid: u64,
    /// The approvals needed now: the threshold the action was raised with, or
    /// the live one if it has risen since.
    pub needed: u64,
    /// Approver slots whose holder is still eligible.
    pub eligible: u64,
}

pub(crate) async fn tally(state: &AppState, rec: &ActionRecord) -> Result<Tally, AppError> {
    let now_eligible =
        admin_consent::approvers_for(state, rec.act, &rec.requester, &rec.subject, now_epoch())
            .await?;
    let eligible_dids: Vec<String> = rec
        .approvers
        .iter()
        .filter(|s| now_eligible.contains(&s.did))
        .map(|s| s.did.clone())
        .collect();
    let valid = rec
        .approvals
        .iter()
        .filter(|a| eligible_dids.contains(&a.did))
        .count() as u64;
    let needed = rec.threshold.max(admin_consent::threshold(state).await?);
    Ok(Tally {
        valid,
        needed,
        eligible: eligible_dids.len() as u64,
    })
}

/// The consent gate, reached again while an approved action executes: the
/// operation must be the one approved, and its approvals must still hold
/// against the community as it is now. `Ok(action id)` when they do.
pub(crate) async fn recheck(
    state: &AppState,
    exec: &Executing,
    act: Act,
    requester: &str,
    subject: &str,
    op: Operation<'_>,
) -> Result<String, AppError> {
    let digest = task_consent::payload_digest(op.type_uri, op.payload)?;
    if exec.requester != requester || exec.type_uri != op.type_uri || exec.digest != digest {
        return Err(AppError::Forbidden(
            "an approved action executes only the operation its approvers were shown".into(),
        ));
    }
    let rec = load(state, &exec.action_id)
        .await?
        .ok_or_else(|| AppError::Internal("the executing action is gone".into()))?;
    if rec.status != Status::Executing {
        return Err(AppError::Conflict(
            "this action is no longer the one executing".into(),
        ));
    }
    if rec.act != act || rec.subject != subject {
        return Err(AppError::Conflict(format!(
            "the operation now needs a different approval ({}) than its approvers gave ({})",
            act.requirement(),
            rec.act.requirement()
        )));
    }
    if admin_consent::pin_for(state, act, subject).await? != rec.state_pin {
        return Err(AppError::Conflict(format!(
            "{subject} has changed since the approvers were shown this; nothing was written"
        )));
    }
    let t = tally(state, &rec).await?;
    if t.valid < t.needed {
        return Err(AppError::Conflict(format!(
            "{} of the approvals still count, and {} are needed now: an approver has lost \
             their standing or the threshold has risen",
            t.valid, t.needed
        )));
    }
    Ok(rec.id)
}

// ─── lapse and invalidation (§4.4) ───────────────────────────────────────

/// Apply expiry and invalidation to one record. `true` if it changed.
async fn settle(state: &AppState, rec: &mut ActionRecord, now: u64) -> Result<bool, AppError> {
    match rec.status {
        Status::Open => {}
        Status::Executing => {
            if rec
                .executing_since
                .is_some_and(|t| t.saturating_add(INTERRUPTED_AFTER_SECS) <= now)
            {
                rec.close(
                    Status::Failed,
                    ClosedReason::FailedRecheck,
                    Some(
                        "execution was interrupted before it finished; check the audit log for \
                         whether the operation took effect"
                            .into(),
                    ),
                    now,
                );
                return Ok(true);
            }
            return Ok(false);
        }
        _ => return Ok(false),
    }
    if now >= rec.expires_at {
        rec.close(Status::Expired, ClosedReason::Expired, None, now);
        return Ok(true);
    }
    let requester_ok = crate::acl::get_acl_entry(&state.acl_ks, &rec.requester)
        .await?
        .is_some_and(|e| admin_consent::is_live_unrestricted(&e, now));
    if !requester_ok {
        rec.close(
            Status::Cancelled,
            ClosedReason::Invalidated,
            Some("the requester no longer holds the authority this operation needs".into()),
            now,
        );
        return Ok(true);
    }
    if admin_consent::pin_for(state, rec.act, &rec.subject).await? != rec.state_pin {
        rec.close(
            Status::Cancelled,
            ClosedReason::Invalidated,
            Some(format!(
                "{} changed after the approvers were asked, so they would no longer be \
                 approving what they saw",
                rec.subject
            )),
            now,
        );
        return Ok(true);
    }
    let t = tally(state, rec).await?;
    if t.eligible < t.needed {
        rec.close(
            Status::Cancelled,
            ClosedReason::Invalidated,
            Some(format!(
                "only {} eligible approver(s) remain and {} approvals are needed (VTI-APV-009)",
                t.eligible, t.needed
            )),
            now,
        );
        return Ok(true);
    }
    Ok(false)
}

/// Settle every action, and prune closed ones past their 30 days of history.
pub(crate) async fn refresh_all(state: &AppState) -> Result<(), AppError> {
    let _guard = ACTION_LOCK.lock().await;
    refresh_locked(state).await
}

async fn refresh_locked(state: &AppState) -> Result<(), AppError> {
    let now = now_epoch();
    for mut rec in all(state).await? {
        if rec
            .closed_at
            .is_some_and(|c| c.saturating_add(HISTORY_SECS) <= now)
        {
            delete(state, &rec).await?;
            continue;
        }
        if settle(state, &mut rec, now).await? {
            save(state, &rec).await?;
            let stage = match rec.status {
                Status::Expired => "expired",
                Status::Failed => "failed",
                _ => "invalidated",
            };
            audit(state, &rec, &rec.requester.clone(), stage, Vec::new()).await;
            info!(action = %rec.id, status = rec.status.wire(), "action closed");
        }
    }
    Ok(())
}

/// The expiry and invalidation sweeper, so an action closes on time even when
/// nobody reads the list. A storage and housekeeping bound only: every read
/// settles what it reads first.
pub fn spawn_sweeper(
    state: AppState,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = refresh_all(&state).await {
                warn!(error = %e, "action-list sweep failed");
            }
            tokio::select! {
                _ = shutdown_rx.changed() => return,
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
        }
    })
}

// ─── deciding ─────────────────────────────────────────────────────────────

/// A `task-consent/decision`, 0.1 or 0.2, read off the validated payload.
pub(crate) struct DecisionInput {
    pub challenge: String,
    pub payload_digest: String,
    pub approve: bool,
    pub reason: Option<String>,
    pub action_id: Option<String>,
    /// The 0.2 `evidence` member, as received.
    pub evidence: Option<Value>,
}

/// What a recorded decision came to.
#[derive(Debug)]
pub(crate) enum Decided {
    /// The threshold was met and the operation ran — or the re-check refused
    /// it, in which case `completed` is `false` and the action is `failed`.
    Granted {
        action_id: String,
        payload_digest: String,
        approvals: u64,
        completed: bool,
        message: Option<String>,
    },
    /// Recorded; more approvals are needed.
    Pending {
        action_id: String,
        payload_digest: String,
        approvals: u64,
        needed: u64,
    },
    /// Declined: the action is closed for everyone.
    Denied {
        action_id: String,
        payload_digest: String,
    },
}

/// Why a decision was refused — `task-consent/decision`'s declared codes.
#[derive(Debug)]
pub(crate) enum DecisionError {
    NoPending,
    ChallengeMismatch,
    NotAnApprover,
    RequesterExcluded,
    ActionMismatch,
    EvidenceInvalid(&'static str),
    /// `approverSigned` evidence: the approver store it is checked against is a
    /// later change (A2). Refused, never ignored.
    EvidenceUnsupported,
    /// More than [`DECISIONS_PER_MINUTE`] decisions by this approver.
    RateLimited,
    Internal(AppError),
}

impl From<AppError> for DecisionError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// Per-approver decision times, for the anti-scripting limit.
static DECISION_TIMES: std::sync::LazyLock<std::sync::Mutex<HashMap<String, VecDeque<u64>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn rate_limited(approver: &str, now: u64) -> bool {
    let mut map = DECISION_TIMES.lock().unwrap_or_else(|p| p.into_inner());
    let times = map.entry(approver.to_string()).or_default();
    while times.front().is_some_and(|t| t.saturating_add(60) <= now) {
        times.pop_front();
    }
    if times.len() >= DECISIONS_PER_MINUTE {
        return true;
    }
    times.push_back(now);
    false
}

/// Process a decision by `approver` — the document's proven signer, which is
/// the approver's **own** DID: the spine refuses an approval signed by a
/// delegated console key before it reaches here.
///
/// The operation the decision concerns is this service's record of the action,
/// found by the salted digest, never anything the decision says (VTI-APV-004).
pub(crate) async fn decide(
    state: &AppState,
    approver: &str,
    input: DecisionInput,
) -> Result<Decided, DecisionError> {
    let now = now_epoch();
    let mut rec = {
        let _guard = ACTION_LOCK.lock().await;
        let Some(mut rec) = by_wire(state, &input.payload_digest).await? else {
            return Err(DecisionError::NoPending);
        };
        // `actionId` is a locator only: the digest and challenge decide which
        // action this is, and a decision naming another is refused.
        if input.action_id.as_ref().is_some_and(|id| *id != rec.id) {
            return Err(DecisionError::ActionMismatch);
        }
        if settle(state, &mut rec, now).await? {
            save(state, &rec).await?;
        }
        if rec.status != Status::Open {
            return Err(DecisionError::NoPending);
        }
        let slot = rec
            .approvers
            .iter()
            .find(|s| s.wire_digest == input.payload_digest)
            .cloned()
            .ok_or(DecisionError::NoPending)?;
        if slot.challenge != input.challenge {
            return Err(DecisionError::ChallengeMismatch);
        }
        if approver == rec.requester {
            return Err(DecisionError::RequesterExcluded);
        }
        // The challenge is per approver: one approver cannot answer another's.
        if slot.did != approver {
            return Err(DecisionError::NotAnApprover);
        }
        let eligible =
            admin_consent::approvers_for(state, rec.act, &rec.requester, &rec.subject, now).await?;
        if !eligible.iter().any(|d| d == approver) {
            return Err(DecisionError::NotAnApprover);
        }
        if rate_limited(approver, now) {
            return Err(DecisionError::RateLimited);
        }
        let evidence = match input.evidence.as_ref() {
            None => None,
            Some(ev) => Some(verify_evidence(state, approver, &slot.challenge, ev).await?),
        };

        if !input.approve {
            rec.close(
                Status::Declined,
                ClosedReason::Declined,
                input.reason.clone(),
                now,
            );
            rec.closed_by = Some(approver.to_string());
            save(state, &rec).await?;
            drop(_guard);
            audit(
                state,
                &rec,
                approver,
                "declined",
                vec![approver.to_string()],
            )
            .await;
            info!(action = %rec.id, approver, "action declined");
            return Ok(Decided::Denied {
                action_id: rec.id,
                payload_digest: input.payload_digest,
            });
        }

        if !rec.approved_by(approver) {
            rec.approvals.push(Approval {
                did: approver.to_string(),
                at: now,
                evidence,
            });
        }
        let t = tally(state, &rec).await?;
        if t.valid < t.needed {
            save(state, &rec).await?;
            drop(_guard);
            audit(
                state,
                &rec,
                approver,
                "approved",
                vec![approver.to_string()],
            )
            .await;
            return Ok(Decided::Pending {
                action_id: rec.id,
                payload_digest: input.payload_digest,
                approvals: t.valid,
                needed: t.needed,
            });
        }
        // Out of `open` under the lock: a second N-th approval arriving now
        // finds `executing` and is answered `noPending`. The execution itself
        // runs outside the lock (module docs, *Lock order*).
        rec.status = Status::Executing;
        rec.executing_since = Some(now);
        save(state, &rec).await?;
        rec
    };
    audit(
        state,
        &rec,
        approver,
        "approved",
        vec![approver.to_string()],
    )
    .await;

    let (completed, result, message) = execute(state, &rec).await;
    let approvers: Vec<String> = rec.approvals.iter().map(|a| a.did.clone()).collect();
    {
        let _guard = ACTION_LOCK.lock().await;
        if let Some(latest) = load(state, &rec.id).await? {
            rec = latest;
        }
        let at = now_epoch();
        if completed {
            rec.close(Status::Completed, ClosedReason::ThresholdMet, None, at);
            rec.result_secret = is_secret_response(&rec.type_uri);
            rec.result = result;
        } else {
            rec.close(
                Status::Failed,
                ClosedReason::FailedRecheck,
                message.clone(),
                at,
            );
        }
        rec.closed_by = Some(approver.to_string());
        save(state, &rec).await?;
    }
    audit(
        state,
        &rec,
        approver,
        if completed { "completed" } else { "failed" },
        approvers.clone(),
    )
    .await;
    info!(action = %rec.id, completed, "action executed on its final approval");
    Ok(Decided::Granted {
        action_id: rec.id,
        payload_digest: input.payload_digest,
        approvals: approvers.len() as u64,
        completed,
        message,
    })
}

fn is_secret_response(type_uri: &str) -> bool {
    crate::trust_tasks::admin_tasks::SECRET_RESPONSES.contains(&type_uri)
        || crate::trust_tasks::step_up_passkey_tasks::SECRET_RESPONSES.contains(&type_uri)
        || crate::trust_tasks::community_tasks::SECRET_RESPONSES.contains(&type_uri)
}

/// Dispatch the action's stored document through the handler it was submitted
/// to. `(completed, response payload, refusal message)`.
async fn execute(state: &AppState, rec: &ActionRecord) -> (bool, Option<Value>, Option<String>) {
    let doc: trust_tasks_rs::TrustTask<Value> =
        match serde_json::from_value(rec.submitted_doc.clone()) {
            Ok(d) => d,
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("the stored document no longer parses: {e}")),
                );
            }
        };
    let transport = transport_from(&rec.transport);
    let ctx = crate::trust_tasks::JoinAuthCtx {
        transport,
        sender_did: (transport != JoinTransport::Rest).then(|| rec.submitted_signer.clone()),
        verified_signer: Some(rec.submitted_signer.clone()),
    };
    let exec = Executing {
        action_id: rec.id.clone(),
        requester: rec.requester.clone(),
        type_uri: rec.type_uri.clone(),
        digest: rec.digest.clone(),
        gate_spent: Arc::new(AtomicBool::new(false)),
    };
    let gate_spent = exec.gate_spent.clone();
    // On a task of its own: the decision handler that got here is itself one
    // arm of the dispatcher this re-enters, and polling the dispatcher inside
    // itself would stack one large future frame on another. Boxed behind a
    // plain fn for the same reason (an `async fn` cycle cannot prove its own
    // future `Send`).
    let owned = state.clone();
    let outcome = match tokio::spawn(async move {
        crate::trust_tasks::dispatch_parked_boxed(&owned, ctx, doc, exec).await
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!(action = %rec.id, error = %e, "approved action's execution did not finish");
            return (
                false,
                None,
                Some("the operation's execution did not finish; nothing was confirmed".into()),
            );
        }
    };
    let body: Value = serde_json::from_slice(&outcome.body).unwrap_or(Value::Null);
    let is_response = body["type"]
        .as_str()
        .is_some_and(|t| t.ends_with("#response"));
    if outcome.status.is_success() && is_response {
        if !gate_spent.load(Ordering::SeqCst) {
            // The operation no longer needed the approval it waited for (the
            // community moved so that it confers nothing gated). It ran as any
            // administrator could have run it alone, and the record says so.
            info!(
                action = %rec.id,
                "the approved operation executed without needing its approval"
            );
        }
        (true, Some(body["payload"].clone()), None)
    } else {
        let message = body["payload"]["message"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("the operation was refused ({})", outcome.status));
        warn!(action = %rec.id, %message, "approved action failed its re-check at execution");
        (false, None, Some(message))
    }
}

/// Verify a decision's optional extra factor, on top of its proof (decision
/// 0.2). `webauthn:<credential>` on success.
async fn verify_evidence(
    state: &AppState,
    approver: &str,
    challenge: &str,
    evidence: &Value,
) -> Result<String, DecisionError> {
    match evidence["kind"].as_str() {
        Some("webauthn") => {
            let cred = crate::acl::bound_step_up::verify_assertion_over_challenge(
                state,
                approver,
                challenge.as_bytes(),
                &evidence["assertion"],
            )
            .await
            .map_err(DecisionError::EvidenceInvalid)?;
            Ok(format!("webauthn:{cred}"))
        }
        Some("approverSigned") => Err(DecisionError::EvidenceUnsupported),
        _ => Err(DecisionError::EvidenceInvalid("unknownKind")),
    }
}

// ─── cancelling ───────────────────────────────────────────────────────────

/// Why a cancel was refused — `vtc/admin/actions/cancel`'s declared codes.
#[derive(Debug)]
pub(crate) enum CancelError {
    NotFound,
    NotRequester,
    NotOpen,
    Internal(AppError),
}

impl From<AppError> for CancelError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// The requester withdraws their own open action.
pub(crate) async fn cancel(
    state: &AppState,
    caller: &str,
    caller_unrestricted: bool,
    action_id: &str,
    reason: Option<String>,
) -> Result<ActionRecord, CancelError> {
    let now = now_epoch();
    let rec = {
        let _guard = ACTION_LOCK.lock().await;
        let Some(mut rec) = load(state, action_id).await? else {
            return Err(CancelError::NotFound);
        };
        if !visible_to(&rec, caller, caller_unrestricted) {
            return Err(CancelError::NotFound);
        }
        if settle(state, &mut rec, now).await? {
            save(state, &rec).await?;
        }
        if rec.requester != caller {
            return Err(CancelError::NotRequester);
        }
        if rec.status != Status::Open {
            return Err(CancelError::NotOpen);
        }
        rec.close(
            Status::Cancelled,
            ClosedReason::CancelledByRequester,
            reason,
            now,
        );
        rec.closed_by = Some(caller.to_string());
        save(state, &rec).await?;
        rec
    };
    audit(state, &rec, caller, "cancelled", Vec::new()).await;
    Ok(rec)
}

// ─── reading ─────────────────────────────────────────────────────────────

/// Whether `caller` may see `rec`: its requester, one of its approvers, or an
/// unrestricted administrator (the audit-read capability) as an observer.
pub(crate) fn visible_to(rec: &ActionRecord, caller: &str, caller_unrestricted: bool) -> bool {
    rec.requester == caller || rec.slot(caller).is_some() || caller_unrestricted
}

/// The four views of `vtc/admin/actions/list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum View {
    WaitingForMe,
    RequestedByMe,
    History,
    All,
}

/// One page.
pub(crate) struct Page {
    pub actions: Vec<Value>,
    pub waiting_for_me: u64,
    pub requested_by_me: u64,
    pub next_offset: Option<usize>,
}

/// The caller's view of the action list: one page of `view`, and the badge
/// counts across everything.
pub(crate) async fn list(
    state: &AppState,
    caller: &str,
    caller_unrestricted: bool,
    view: View,
    since: Option<u64>,
    offset: usize,
    limit: usize,
) -> Result<Page, AppError> {
    refresh_all(state).await?;
    let now = now_epoch();
    let records = all(state).await?;
    let mut ctx = ViewCtx::new(state, &records, now).await?;

    let mut waiting_for_me = 0;
    let mut requested_by_me = 0;
    let mut selected: Vec<&ActionRecord> = Vec::new();
    for rec in &records {
        if !visible_to(rec, caller, caller_unrestricted) {
            continue;
        }
        let waiting = rec.status == Status::Open
            && rec.slot(caller).is_some()
            && !rec.approved_by(caller)
            && ctx.eligible(rec).iter().any(|d| d == caller);
        if waiting {
            waiting_for_me += 1;
        }
        let mine = rec.status.is_open() && rec.requester == caller;
        if mine {
            requested_by_me += 1;
        }
        let take = match view {
            View::WaitingForMe => waiting,
            View::RequestedByMe => mine,
            View::History => {
                !rec.status.is_open() && since.is_none_or(|s| rec.closed_at.is_some_and(|c| c >= s))
            }
            View::All => true,
        };
        if take {
            selected.push(rec);
        }
    }
    selected.sort_by_key(|a| order_key(a));
    let total = selected.len();
    let page: Vec<&ActionRecord> = selected.into_iter().skip(offset).take(limit).collect();
    let next_offset = (offset + page.len() < total).then_some(offset + page.len());
    let mut actions = Vec::with_capacity(page.len());
    for rec in page {
        actions.push(ctx.render(rec, caller, false));
    }
    Ok(Page {
        actions,
        waiting_for_me,
        requested_by_me,
        next_offset,
    })
}

/// Open views by `expiresAt` soonest first, `history` by `closedAt` newest
/// first, and in `all` open before closed in those orders.
fn order_key(rec: &ActionRecord) -> (u8, i64, u64) {
    if rec.status.is_open() {
        (0, rec.expires_at as i64, rec.created_at)
    } else {
        (1, -(rec.closed_at.unwrap_or(0) as i64), rec.created_at)
    }
}

/// One action, as `caller` may see it. `None` when it does not exist or the
/// caller may not see it — the two answer alike (`notFound`), so an id is not
/// an oracle.
pub(crate) async fn show(
    state: &AppState,
    caller: &str,
    caller_unrestricted: bool,
    action_id: &str,
) -> Result<Option<Value>, AppError> {
    refresh_all(state).await?;
    let Some(rec) = load(state, action_id).await? else {
        return Ok(None);
    };
    if !visible_to(&rec, caller, caller_unrestricted) {
        return Ok(None);
    }
    let records = all(state).await?;
    let mut ctx = ViewCtx::new(state, &records, now_epoch()).await?;
    let mut view = ctx.render(&rec, caller, true);
    // An approver who may decide now also gets the VTC-signed
    // `task-consent/request/0.1` for their slot — the same document the push
    // carries — so a client that verifies a request (`cnm consent`) has one
    // without waiting on a push that may not arrive.
    if view.get("challenge").is_some()
        && let Ok(mut signed) = sign_requests(state, &rec, Some(caller)).await
        && let Some((_, doc)) = signed.pop()
    {
        view["ext"]["org.openvtc"]["consentRequest"] = doc;
    }
    // A secret result (an invite's claim code) is shown to the requester once.
    if rec.requester == caller && rec.result_secret && rec.result.is_some() {
        let _guard = ACTION_LOCK.lock().await;
        if let Some(mut latest) = load(state, action_id).await? {
            latest.result = None;
            save(state, &latest).await?;
        }
    }
    Ok(Some(view))
}

/// One action, as `caller` may see it, by id — for a refusal of a verb on an
/// action that exists but is not the caller's to act on.
pub(crate) async fn view_one(
    state: &AppState,
    caller: &str,
    rec: &ActionRecord,
) -> Result<Value, AppError> {
    let records = all(state).await?;
    let mut ctx = ViewCtx::new(state, &records, now_epoch()).await?;
    Ok(ctx.render(rec, caller, false))
}

/// What rendering many actions shares: who is eligible, who has how many open.
struct ViewCtx<'a> {
    records: &'a [ActionRecord],
    now: u64,
    threshold: u64,
    unrestricted: Vec<String>,
}

impl<'a> ViewCtx<'a> {
    async fn new(
        state: &'a AppState,
        records: &'a [ActionRecord],
        now: u64,
    ) -> Result<Self, AppError> {
        Ok(Self {
            records,
            now,
            threshold: admin_consent::threshold(state).await?,
            unrestricted: admin_consent::unrestricted_admins(state, now).await?,
        })
    }

    /// The slot holders still eligible to decide `rec`.
    fn eligible(&self, rec: &ActionRecord) -> Vec<String> {
        rec.approvers
            .iter()
            .filter(|s| {
                self.unrestricted.contains(&s.did)
                    && s.did != rec.requester
                    && !(rec.act.excludes_subject() && s.did == rec.subject)
            })
            .map(|s| s.did.clone())
            .collect()
    }

    fn render(&mut self, rec: &ActionRecord, caller: &str, detailed: bool) -> Value {
        let eligible = self.eligible(rec);
        let approvals: Vec<Value> = rec
            .approvals
            .iter()
            .filter(|a| !rec.status.is_open() || eligible.contains(&a.did))
            .map(|a| json!({ "subject": a.did, "at": rfc3339(a.at) }))
            .collect();
        let caller_role = if rec.requester == caller {
            "requester"
        } else if rec.slot(caller).is_some() {
            "approver"
        } else {
            "observer"
        };
        let requester_open = self
            .records
            .iter()
            .filter(|r| r.status.is_open() && r.requester == rec.requester)
            .count();
        let recent = self
            .records
            .iter()
            .filter(|r| {
                r.requester == rec.requester
                    && r.created_at.saturating_add(BURST_WINDOW_SECS) > self.now
            })
            .count();

        let mut ext = Map::new();
        ext.insert("approverCount".into(), json!(eligible.len()));
        ext.insert("requesterRecentActions".into(), json!(recent));
        ext.insert("burst".into(), json!(recent > BURST_MAX));
        if let Some(m) = &rec.closed_message {
            ext.insert("closedMessage".into(), json!(m));
        }
        if let Some(by) = &rec.closed_by {
            ext.insert("closedBy".into(), json!(by));
        }
        if rec.requester == caller
            && let Some(result) = &rec.result
            && (detailed || !rec.result_secret)
        {
            ext.insert("result".into(), result.clone());
        }

        let mut action = json!({
            "actionId": rec.id,
            "category": "approval",
            "kind": rec.kind,
            "typeUri": rec.type_uri,
            "requester": rec.requester,
            "status": rec.status.wire(),
            "createdAt": rfc3339(rec.created_at),
            "expiresAt": rfc3339(rec.expires_at),
            "approvals": approvals,
            "summary": summary::render(&rec.kind, &rec.type_uri, &rec.payload),
            "payload": rec.payload,
            "payloadDigest": summary::payload_digest(&rec.payload).unwrap_or_default(),
            "callerRole": caller_role,
            "requesterOpenActions": requester_open,
            "threshold": rec.threshold.max(1),
            "ext": { "org.openvtc": Value::Object(ext) },
        });
        if rec.status.is_open() {
            let needed = rec.threshold.max(self.threshold);
            let valid = approvals.len() as u64;
            action["approversRemaining"] = json!(needed.saturating_sub(valid));
            if rec.status == Status::Open
                && let Some(slot) = rec.slot(caller)
                && !rec.approved_by(caller)
                && eligible.iter().any(|d| d == caller)
            {
                action["challenge"] = json!(slot.challenge);
            }
        } else {
            action["closedAt"] = json!(rfc3339(rec.closed_at.unwrap_or(rec.created_at)));
            if let Some(r) = rec.closed_reason {
                action["closedReason"] = json!(r.wire());
            }
        }
        action
    }
}

// ─── pushing the request to approvers' devices ───────────────────────────

/// One VTC-signed `task-consent/request/0.1` per approver, carrying that
/// approver's own challenge, pushed best-effort. The action list is the source
/// of truth; a lost push loses nothing (§7.1). A copy an approver holds is
/// what `cnm consent approve <file>` answers.
async fn push_requests(state: &AppState, rec: &ActionRecord) {
    match sign_requests(state, rec, None).await {
        Ok(docs) => {
            let ttl = Duration::from_secs(rec.expires_at.saturating_sub(now_epoch()).max(60));
            for (approver, doc) in docs {
                // Queued is all an `Ok` means (R1.1).
                if let Err(e) =
                    crate::member_push::push_trust_task(state, &approver, doc, ttl).await
                {
                    debug!(approver, error = %e, "consent request not pushed; the action list has it");
                }
            }
        }
        Err(e) => debug!(error = %e, "consent requests not signed; the action list has them"),
    }
}

/// The signed request for each approver slot — or only `only`'s.
pub(crate) async fn sign_requests(
    state: &AppState,
    rec: &ActionRecord,
    only: Option<&str>,
) -> Result<Vec<(String, Value)>, AppError> {
    use crate::acl::admin_consent::REQUEST_TYPE;
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;
    let signer = state
        .credential_signer
        .clone()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;
    let (kind, detail, consequence) = match rec.act {
        Act::GrantUnrestricted => (
            "authorityGrant",
            json!({ "subject": rec.subject, "actScope": "all", "role": "admin" }),
            "The subject can grant and remove any authority in this community, including yours.",
        ),
        Act::ReduceUnrestricted => (
            "authorityRevoke",
            json!({ "subject": rec.subject, "actScope": "all", "role": "admin" }),
            "The subject loses unrestricted authority in this community. They are not asked: \
             a party to a removal never decides it.",
        ),
        Act::LowerThreshold => (
            "configChange",
            json!({ "key": rec.subject }),
            "Fewer administrators will be needed to make an unrestricted administrator — \
             including the next one this requester asks for.",
        ),
        Act::ChangeAuthorityPolicy(purpose) => (
            "policyChange",
            json!({ "purpose": purpose.as_str() }),
            "The rules that decide who holds authority in this community change.",
        ),
    };
    let effect = Effect::new(kind, rec.summary_text.clone())
        .detail(detail.as_object().cloned().unwrap_or_default());
    let mut out = Vec::with_capacity(rec.approvers.len());
    for slot in rec
        .approvers
        .iter()
        .filter(|s| only.is_none_or(|d| d == s.did))
    {
        let payload = json!({
            "challenge": slot.challenge,
            "taskType": rec.type_uri,
            "payloadDigest": slot.wire_digest,
            "sideEffects": "mutating",
            "exposure": { "actsAsSubject": false, "discloses": "none" },
            "effects": [effect],
            "consequences": [consequence],
            "requester": rec.requester,
            "approverSet": rec.approver_set,
            "minApprovals": rec.threshold,
            "excludeRequester": true,
            "expiresAt": rfc3339(rec.expires_at),
            "subject": rec.subject,
            "statePin": rec.state_pin,
        });
        {
            use trust_tasks_rs::validate::ValidatedPayload as _;
            trust_tasks_rs::specs::task_consent::request::v0_1::Payload::validate_value(&payload)
                .map_err(|e| {
                AppError::Internal(format!("task-consent request does not conform: {e}"))
            })?;
        }
        let mut doc = vti_common::capability_client::build_document(
            &vtc_did,
            &slot.did,
            REQUEST_TYPE,
            payload,
        );
        doc.thread_id = Some(rec.id.clone());
        let mut doc = serde_json::to_value(&doc)
            .map_err(|e| AppError::Internal(format!("serialise task-consent request: {e}")))?;
        // The operational key, under `authentication`: a request the VTC sends
        // as itself, not a credential it issues (VTI-KEY-106).
        signer.sign_operational_doc(&mut doc).await?;
        out.push((slot.did.clone(), doc));
    }
    Ok(out)
}

// ─── audit ───────────────────────────────────────────────────────────────

/// Every transition is audited (§4.1), whatever the history keeps.
async fn audit(
    state: &AppState,
    rec: &ActionRecord,
    actor: &str,
    stage: &str,
    approvers: Vec<String>,
) {
    let Some(writer) = state.audit_writer.as_ref() else {
        return;
    };
    let result = writer
        .write(
            actor,
            (!rec.subject.is_empty()).then_some(rec.subject.as_str()),
            AuditEvent::TaskConsentRecorded(TaskConsentData {
                stage: stage.to_string(),
                task: rec.type_uri.clone(),
                requester: rec.requester.clone(),
                subject: rec.subject.clone(),
                payload_digest: rec.digest.clone(),
                min_approvals: u32::try_from(rec.threshold).unwrap_or(u32::MAX),
                approvers,
            }),
        )
        .await;
    if let Err(e) = result {
        warn!(action = %rec.id, stage, error = %e, "could not audit an action transition");
    }
}

// ─── small helpers ───────────────────────────────────────────────────────

pub(crate) fn rfc3339(epoch: u64) -> String {
    chrono::DateTime::from_timestamp(epoch as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn human_duration(secs: u64) -> String {
    let hours = secs / 3600;
    if hours >= 48 {
        format!("{} days", hours / 24)
    } else if hours >= 1 {
        format!("{hours} hours")
    } else {
        format!("{} minutes", (secs / 60).max(1))
    }
}

/// A list cursor: opaque to the caller, bound to the view and `since` it was
/// issued for.
pub(crate) fn encode_cursor(view: &str, since: Option<&str>, offset: usize) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("v1|{view}|{}|{offset}", since.unwrap_or_default()))
}

/// The offset a cursor carries, if it was issued for this `view` and `since`.
pub(crate) fn decode_cursor(cursor: &str, view: &str, since: Option<&str>) -> Option<usize> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let mut parts = text.split('|');
    (parts.next()? == "v1").then_some(())?;
    (parts.next()? == view).then_some(())?;
    (parts.next()? == since.unwrap_or_default()).then_some(())?;
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_is_bound_to_its_view_and_filter() {
        let c = encode_cursor("history", Some("2026-10-01T00:00:00Z"), 25);
        assert_eq!(
            decode_cursor(&c, "history", Some("2026-10-01T00:00:00Z")),
            Some(25)
        );
        assert_eq!(decode_cursor(&c, "all", Some("2026-10-01T00:00:00Z")), None);
        assert_eq!(decode_cursor(&c, "history", None), None);
        assert_eq!(decode_cursor("not a cursor", "history", None), None);
    }

    /// §7a.1: the eleventh decision in a minute is refused; a minute later the
    /// window has moved on.
    #[test]
    fn an_approver_is_held_to_ten_decisions_a_minute() {
        let who = format!("did:key:zRate{}", uuid::Uuid::new_v4().simple());
        for i in 0..DECISIONS_PER_MINUTE {
            assert!(!rate_limited(&who, 1_000 + i as u64), "decision {i}");
        }
        assert!(rate_limited(&who, 1_020));
        assert!(!rate_limited(&who, 1_070));
    }

    #[test]
    fn executing_reads_as_open_on_the_wire() {
        assert_eq!(Status::Executing.wire(), "open");
        assert!(Status::Executing.is_open());
        assert!(!Status::Completed.is_open());
    }
}
