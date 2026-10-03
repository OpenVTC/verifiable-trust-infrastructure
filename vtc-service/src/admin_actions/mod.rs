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
//! ## Acknowledge items (VTI-VTC-023)
//!
//! An operator's offline write — `vtc acl add/remove`, `vtc admin invite`,
//! `vtc admin enrol-approver`, `vtc create-did-key --admin`, `vtc admin
//! emergency-bootstrap` — happened outside the operation surface and cannot be
//! refused. It is raised at the next boot as an `acknowledge`-category action
//! ([`raise_operator_item`]): no approve, no decline, no expiry; every
//! administrator who held a role when the write was made (minus any who has
//! since lost every admin role) acknowledges it, and acknowledging is audited.
//! An emergency bootstrap wiped the administrators it would have told, so its
//! item is for whoever administers the community now. Every such item names the
//! record type `vtc/operator/offline-write/0.1` as its `typeUri`, with the
//! record as its payload ([`OPERATOR_OFFLINE_WRITE_URI`]).
//!
//! ## The two-administrator cooling-off (VTI-APV-019, §8.2)
//!
//! A reduction of an unrestricted administrator that nobody but the requester
//! and the subject could consent to is parked with no approvers and a
//! cooling-off ([`ActionRecord::cooling_off_until`]). It lands by itself when
//! the window ends ([`sweep_once`]) unless the requester cancels it; the subject
//! sees it coming — sent `vtc/members/authority-reduction-pending-notice/0.1`
//! when it is parked, and shown it as `callerRole: subject` at `_shared/0.2`
//! ([`WireVersion`]), where it is category `coolingOff` with `landsAt`. If the subject meanwhile asks to reduce the requester, the
//! earlier request lands first ([`refuse_if_reduced_first`]) and the subject's
//! own actions are then invalidated: first to act wins.
//!
//! ## Crash-safe execution (CLAUDE.md R2.1)
//!
//! An action is persisted `executing`, with an execution id, before its
//! operation runs. The operation records its effect at its write
//! ([`record_effect`]: a marker beside the action and an `AdminActionEffect`
//! audit row naming the action and execution). An action found `executing` by
//! no live execution of this process — a crash, at boot or later — is
//! reconciled from that evidence ([`reconcile`]): `completed` if the effect
//! landed, `failed` if it did not, never a blind guess.
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
    pub const ACKNOWLEDGE_ALREADY_ACKNOWLEDGED: &str =
        a::acknowledge::v0_1::error_codes::ALREADY_ACKNOWLEDGED.code;
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

const ACTION_PREFIX: &str = "action:";
const WIRE_PREFIX: &str = "wire:";
/// `effect:<action id>` → the execution id whose operation wrote its effect.
const EFFECT_PREFIX: &str = "effect:";

/// The `kind` of an operator's offline write, raised for acknowledgement.
pub const KIND_OPERATOR_WRITE: &str = summary::KIND_OPERATOR_WRITE;

/// Executions running in this process, by execution id. An action whose
/// `executing` record names none of these was interrupted — the process that
/// started it is gone — and is reconciled ([`reconcile`]). Registered before the
/// record is saved `executing`, so the sweeper can never mistake a live
/// execution for an interrupted one.
static IN_FLIGHT: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

fn in_flight_insert(id: &str) {
    IN_FLIGHT
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id.to_string());
}

fn in_flight_remove(id: &str) {
    IN_FLIGHT
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(id);
}

fn in_flight(id: &str) -> bool {
    IN_FLIGHT
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(id)
}

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
    Acknowledged,
    /// A cooling-off reached its landing time uncancelled and its operation
    /// executed (`_shared/0.2`). A 0.1 caller reads it as `thresholdMet`, which
    /// is all 0.1 can say.
    LandedAfterCoolingOff,
}

impl ClosedReason {
    fn wire(self, version: WireVersion) -> &'static str {
        match self {
            Self::LandedAfterCoolingOff if version == WireVersion::V0_2 => "landedAfterCoolingOff",
            Self::ThresholdMet | Self::LandedAfterCoolingOff => "thresholdMet",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::CancelledByRequester => "cancelledByRequester",
            Self::Invalidated => "invalidated",
            Self::FailedRecheck => "failedRecheck",
            Self::Acknowledged => "acknowledged",
        }
    }
}

/// Which kind of decision an action waits for — the published `category`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Category {
    /// Approvers approve or decline, N-of-M; the operation executes on the
    /// N-th approval — or, for a cooling-off, when the window ends.
    #[default]
    Approval,
    /// Something that already happened outside the operation surface — an
    /// operator's offline write — that every remaining administrator
    /// acknowledges (VTI-VTC-023).
    Acknowledge,
}

impl Category {
    fn wire(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Acknowledge => "acknowledge",
        }
    }
}

/// Which `vtc/admin/actions/_shared` an action is rendered for. Both are
/// served (`trust_tasks::action_tasks`): 0.1 keeps answering as it did, and a
/// cooling-off reads there as an `approval` with no threshold and no expiry and
/// `ext["org.openvtc"].coolingOff`. 0.2 says it in the schema's own terms —
/// category `coolingOff`, `landsAt`, `cancellableBy: requester`, closed
/// `landedAfterCoolingOff`, and `callerRole: subject` for the administrator it
/// reduces (trust-tasks-tf #719).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireVersion {
    V0_1,
    V0_2,
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
    /// The capabilities at stake: what the approvers must hold and be able to
    /// approve, at a covering qualifier (`vtc-admin-roles.md` §7,
    /// VTI-APV-018). Empty reads as the act's default stake.
    #[serde(default)]
    pub stake: Vec<crate::acl::CapRef>,
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
    #[serde(default)]
    pub category: Category,
    /// For an unopposed reduction (VTI-APV-019, §8.2): when the cooling-off
    /// ends and the operation lands by itself. `None` for everything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooling_off_until: Option<u64>,
    /// The execution persisted with `executing`, before the operation ran
    /// (R2.1) — what [`record_effect`] names and [`reconcile`] looks for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
    /// For an acknowledge item: the administrators holding a role when the
    /// write was made. `None` (an emergency bootstrap, which wiped them) means
    /// whoever administers the community now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgers: Option<Vec<String>>,
    /// The step-up approver invite minted for a new administrator when this
    /// action made one (`vtc-approver-step-up.md` §6c, §11.4) — a bearer secret
    /// (the claim code) shown to the requester once, then dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_invite: Option<Value>,
    /// An operation single-administrator mode let through on the requester's
    /// own gesture, nobody else being eligible to consent (VTI-APV-022). Never
    /// open: entered in the history, completed, once its write landed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub consent_waived: bool,
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
    state.admin_actions_ks.remove(effect_key(&rec.id)).await?;
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
    /// A consent single-administrator mode waived for this document, spent
    /// and waiting for its write to land ([`spend_waiver`], [`record_effect`]).
    pub waiver: Arc<std::sync::Mutex<Option<Waiver>>>,
}

/// An operation whose consent single-administrator mode waived
/// (**VTI-APV-022**): nobody but the requester was eligible to give it, so the
/// requester's operation-bound gesture (VTI-APV-015) stands in for it.
#[derive(Debug, Clone)]
pub struct Waiver {
    act: Act,
    stake: Vec<crate::acl::CapRef>,
    requester: String,
    subject: String,
    type_uri: String,
    payload: Value,
    digest: String,
    summary: String,
    evidence: StepUpEvidence,
}

impl Waiver {
    pub(crate) fn new(
        act: Act,
        stake: Vec<crate::acl::CapRef>,
        requester: &str,
        subject: &str,
        op: Operation<'_>,
        summary: &str,
        evidence: StepUpEvidence,
    ) -> Result<Self, AppError> {
        Ok(Self {
            act,
            stake,
            requester: requester.to_string(),
            subject: subject.to_string(),
            type_uri: op.type_uri.to_string(),
            payload: op.payload.clone(),
            digest: task_consent::payload_digest(op.type_uri, op.payload)?,
            summary: summary.to_string(),
            evidence,
        })
    }
}

/// Spend a waived consent (**VTI-APV-022** item 4): a `Critical` audit row
/// naming the operation, its requirement and its digest, written before the
/// write it authorizes — so no waived operation can land unrecorded — and the
/// waiver held for [`record_effect`] to enter in the action list's history once
/// the write has landed.
///
/// A failure to audit refuses the operation: an unrecorded waiver is exactly
/// what the requirement forbids.
pub(crate) async fn spend_waiver(state: &AppState, waiver: Waiver) -> Result<(), AppError> {
    let kind = waiver.act.kind(&waiver.type_uri).to_string();
    warn!(
        requester = %waiver.requester,
        subject = %waiver.subject,
        task = %waiver.type_uri,
        requirement = waiver.act.requirement(),
        "consent waived — single-administrator mode (VTI-APV-022): nobody but the requester \
         could consent, and the requester's operation-bound step-up stands in for it"
    );
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &waiver.requester,
                (!waiver.subject.is_empty()).then_some(waiver.subject.as_str()),
                AuditEvent::SingleAdminMode(vti_common::audit::SingleAdminModeData {
                    event: "consentWaived".into(),
                    requirement: Some(waiver.act.requirement().into()),
                    task: Some(waiver.type_uri.clone()),
                    digest: Some(waiver.digest.clone()),
                    kind: Some(kind),
                }),
            )
            .await?;
    }
    let _ = SUBMISSION.try_with(|s| {
        if let Ok(mut slot) = s.waiver.lock() {
            *slot = Some(waiver);
        }
    });
    Ok(())
}

/// Enter a waived operation whose write has landed in the action list's
/// history: completed at once, with no approvers and no threshold, marked
/// `consentWaived` (VTI-APV-022). Best-effort, as [`record_effect`] is: the
/// write has happened and its `Critical` audit row is already written.
async fn record_waived(state: &AppState) {
    let Ok(Some((submission, waiver))) = SUBMISSION.try_with(|s| {
        s.waiver
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .map(|w| (s.clone(), w))
    }) else {
        return;
    };
    let now = now_epoch();
    let pin = match admin_consent::pin_for(state, waiver.act, &waiver.subject).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "could not pin a waived operation's state for its history entry");
            return;
        }
    };
    let mut rec = ActionRecord {
        id: format!("act-{}", uuid::Uuid::new_v4().simple()),
        kind: waiver.act.kind(&waiver.type_uri).to_string(),
        act: waiver.act,
        stake: waiver.stake,
        type_uri: waiver.type_uri,
        payload: waiver.payload,
        digest: waiver.digest,
        submitted_doc: (*submission.received).clone(),
        submitted_signer: submission.signer.clone().unwrap_or_default(),
        transport: transport_name(submission.transport).to_string(),
        requester: waiver.requester.clone(),
        subject: waiver.subject,
        requester_step_up: RequesterStepUp {
            kind: waiver.evidence.kind,
            credential_id: waiver.evidence.credential_id,
            bound_to: waiver.evidence.bound_to,
            at: now,
        },
        approver_set: waiver.act.approver_set().to_string(),
        approvers: Vec::new(),
        threshold: 0,
        approvals: Vec::new(),
        state_pin: pin,
        summary_text: waiver.summary,
        status: Status::Open,
        created_at: now,
        expires_at: now,
        executing_since: None,
        closed_at: None,
        closed_reason: None,
        closed_message: None,
        closed_by: None,
        result: None,
        result_secret: false,
        category: Category::Approval,
        cooling_off_until: None,
        execution_id: None,
        acknowledgers: None,
        approver_invite: None,
        consent_waived: true,
    };
    rec.close(
        Status::Completed,
        ClosedReason::ThresholdMet,
        Some(
            "Consent waived — single-administrator mode (VTI-APV-022): nobody else could \
             consent, so the requester's passkey gesture bound to this operation authorized it"
                .into(),
        ),
        now,
    );
    rec.closed_by = Some(waiver.requester);
    let _guard = ACTION_LOCK.lock().await;
    if let Err(e) = save(state, &rec).await {
        warn!(error = %e, "could not enter a waived operation in the action history");
    }
}

/// The approved action whose stored document is executing.
#[derive(Clone, Debug)]
pub(crate) struct Executing {
    pub action_id: String,
    pub requester: String,
    pub type_uri: String,
    pub digest: String,
    /// The execution persisted with the action (R2.1).
    pub execution_id: String,
    /// An unopposed reduction landing after its cooling-off, rather than an
    /// approval completing (VTI-APV-019, §8.2).
    pub cooling_off: bool,
    gate_spent: Arc<AtomicBool>,
    effect_recorded: Arc<AtomicBool>,
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

/// Record, at the write, that the executing action's operation has written its
/// effect (R2.1). A no-op outside an execution, and once per execution.
///
/// Called by each operation an action can execute, immediately after the store
/// write that *is* its effect: the marker beside the action and an
/// `AdminActionEffect` audit row naming the action and this execution. A crash
/// after the write and before the action closes is then reconciled as
/// `completed`; a crash before it, as `failed` ([`reconcile`]). Best-effort by
/// design: the write has already happened, and failing the operation because
/// its evidence could not be written would leave the effect in place and the
/// operation reported as refused.
pub(crate) async fn record_effect(state: &AppState) {
    let Ok(exec) = EXECUTING.try_with(Clone::clone) else {
        // Not an approved action — but perhaps an operation whose consent
        // single-administrator mode waived, now landed (VTI-APV-022).
        record_waived(state).await;
        return;
    };
    if exec.effect_recorded.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Err(e) = state
        .admin_actions_ks
        .insert_raw(
            effect_key(&exec.action_id),
            exec.execution_id.as_bytes().to_vec(),
        )
        .await
    {
        warn!(action = %exec.action_id, error = %e, "could not mark an action's effect");
    }
    if let Some(writer) = state.audit_writer.as_ref()
        && let Err(e) = writer
            .write(
                &exec.requester,
                None,
                AuditEvent::AdminActionEffect(vti_common::audit::AdminActionEffectData {
                    action_id: exec.action_id.clone(),
                    execution_id: exec.execution_id.clone(),
                    task: exec.type_uri.clone(),
                }),
            )
            .await
    {
        warn!(action = %exec.action_id, error = %e, "could not audit an action's effect");
    }
}

fn effect_key(action_id: &str) -> String {
    format!("{EFFECT_PREFIX}{action_id}")
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

pub(crate) async fn setting(state: &AppState, key: &str) -> Result<u64, AppError> {
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
    /// What the approvers must hold (`vtc-admin-roles.md` §7).
    pub stake: Vec<crate::acl::CapRef>,
    pub requester: &'a str,
    pub subject: &'a str,
    pub op: Operation<'a>,
    pub summary: &'a str,
    pub evidence: StepUpEvidence,
    pub approvers: Vec<String>,
    pub threshold: u64,
    pub pin: StatePin,
    /// `Some(window)` parks an unopposed reduction for its cooling-off
    /// (VTI-APV-019, §8.2): no approvers, threshold 0, and it lands by itself
    /// `window` seconds from now unless the requester cancels it.
    pub cooling_off: Option<u64>,
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
    let cooling_off_until = p.cooling_off.map(|w| now.saturating_add(w));

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
        stake: p.stake.clone(),
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
        // A cooling-off never lapses — it lands. Its `expires_at` is only the
        // moment it does, for ordering; the wire never shows it as an expiry.
        expires_at: cooling_off_until.unwrap_or_else(|| now.saturating_add(lifetime)),
        executing_since: None,
        closed_at: None,
        closed_reason: None,
        closed_message: None,
        closed_by: None,
        result: None,
        result_secret: false,
        category: Category::Approval,
        cooling_off_until,
        execution_id: None,
        acknowledgers: None,
        approver_invite: None,
        consent_waived: false,
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
    notify_cooling_off_subject(state, &rec).await;
    Ok(rec)
}

/// For a reduction parked on a cooling-off: tell the subject now, before it
/// lands (`vtc/members/authority-reduction-pending-notice/0.1`, VTI-APV-019).
/// Durable and best-effort — the action is already parked and lands on time
/// whether or not this is delivered. The landing sends the
/// authority-reduced notice; a cancellation reduces nothing and sends nothing.
async fn notify_cooling_off_subject(state: &AppState, rec: &ActionRecord) {
    let Some(until) = rec.cooling_off_until else {
        return;
    };
    let prior = match crate::acl::get_acl_entry(&state.acl_ks, &rec.subject).await {
        Ok(Some(entry)) => entry,
        Ok(None) => return,
        Err(e) => {
            warn!(action = %rec.id, error = %e, "no pending notice: the subject's entry could not be read");
            return;
        }
    };
    crate::ceremony::authority_reduction_pending_notice::send(
        state,
        &rec.id,
        &prior,
        &rec.type_uri,
        &rec.payload,
        &rec.requester,
        epoch_utc(rec.created_at),
        epoch_utc(until),
    )
    .await;
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
            "coolingOffUntil": rec.cooling_off_until.map(rfc3339),
            "message": parked_message(rec, eligible),
        }),
    }
}

fn parked_message(rec: &ActionRecord, eligible: u64) -> String {
    if let Some(until) = rec.cooling_off_until {
        return format!(
            "Nobody but you and {} can consent to this, so it waits out a cooling-off and \
             lands by itself in {} ({}) unless you cancel it. They can see it coming but \
             cannot block it (VTI-APV-019).",
            rec.subject,
            human_duration(until.saturating_sub(now_epoch())),
            rfc3339(until)
        );
    }
    let left = rec.expires_at.saturating_sub(now_epoch());
    format!(
        "Sent for approval — {} of {} administrator(s) holding what is at stake must approve within {}.",
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
    let cooling_off = details["coolingOffUntil"].is_string();
    let reason = if cooling_off {
        "the operation waits out a cooling-off in the action list and then lands by itself"
    } else {
        "the operation waits in the action list until enough administrators approve it"
    };
    let mut payload = json!({
        "continuation": "proceed",
        "expects": [{
            "typeUri": crate::trust_tasks::action_tasks::SHOW_V0_2_TYPE,
            "hint": { "actionId": details["actionId"] },
            "reason": reason,
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
    });
    if cooling_off {
        payload["ext"]["org.openvtc"]["coolingOffUntil"] = details["coolingOffUntil"].clone();
    }
    payload
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
    let now_eligible = admin_consent::approvers_for(
        state,
        rec.act,
        &rec.stake,
        &rec.requester,
        &rec.subject,
        now_epoch(),
    )
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
    // A grants review is re-affirmed by one covering administrator, as an
    // `acl/update` re-affirmation is; every other act needs the threshold as
    // it stands now, if it has risen.
    let needed = if rec.act == Act::GrantsReview {
        rec.threshold
    } else {
        rec.threshold.max(admin_consent::threshold(state).await?)
    };
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

/// The reduction gate, reached again while an unopposed reduction lands after
/// its cooling-off (VTI-APV-019, §8.2): the operation must be the one parked,
/// the subject's entry unmoved, and still nobody but the requester and the
/// subject able to consent — a third administrator who has appeared since
/// decides it instead. `Ok(action id)` when it may land.
pub(crate) async fn recheck_cooling_off(
    state: &AppState,
    exec: &Executing,
    requester: &str,
    subject: &str,
    op: Operation<'_>,
) -> Result<String, AppError> {
    let digest = task_consent::payload_digest(op.type_uri, op.payload)?;
    if exec.requester != requester || exec.type_uri != op.type_uri || exec.digest != digest {
        return Err(AppError::Forbidden(
            "a cooling-off lands only the operation that was parked".into(),
        ));
    }
    let rec = load(state, &exec.action_id)
        .await?
        .ok_or_else(|| AppError::Internal("the executing action is gone".into()))?;
    if rec.status != Status::Executing || rec.cooling_off_until.is_none() {
        return Err(AppError::Conflict(
            "this action is no longer the one executing".into(),
        ));
    }
    if rec.subject != subject {
        return Err(AppError::Conflict(
            "the operation now concerns a different subject than was parked".into(),
        ));
    }
    if admin_consent::pin_for(state, rec.act, subject).await? != rec.state_pin {
        return Err(AppError::Conflict(format!(
            "{subject} has changed since this was parked; nothing was written"
        )));
    }
    let now = now_epoch();
    if !admin_consent::approvers_for(state, rec.act, &rec.stake, requester, subject, now)
        .await?
        .is_empty()
    {
        return Err(AppError::Conflict(
            "another holder of what is at stake can now consent to this, so it no longer lands \
             on a cooling-off; send it again for them to decide"
                .into(),
        ));
    }
    Ok(rec.id)
}

// ─── lapse and invalidation (§4.4) ───────────────────────────────────────

/// Apply expiry, invalidation and acknowledgement completion to one record.
/// `true` if it changed. An `executing` record is [`reconcile`]'s, never this.
async fn settle(state: &AppState, rec: &mut ActionRecord, now: u64) -> Result<bool, AppError> {
    if rec.status != Status::Open {
        return Ok(false);
    }
    if rec.category == Category::Acknowledge {
        // VTI-VTC-023: complete once every remaining administrator expected to
        // acknowledge it has. Never expires; never invalidated.
        let admins = live_admins(state, now).await?;
        let expected = expected_acknowledgers(rec, &admins);
        if !rec.approvals.is_empty() && expected.iter().all(|d| rec.approved_by(d)) {
            rec.close(Status::Completed, ClosedReason::Acknowledged, None, now);
            return Ok(true);
        }
        return Ok(false);
    }
    if rec.cooling_off_until.is_none() && now >= rec.expires_at {
        rec.close(Status::Expired, ClosedReason::Expired, None, now);
        return Ok(true);
    }
    // A grants review is the community's own: it has no requester entry.
    let requester_ok = rec.act == Act::GrantsReview
        || crate::acl::get_acl_entry(&state.acl_ks, &rec.requester)
            .await?
            .is_some_and(|e| {
                admin_consent::requester_still_authorized(&e, rec.act, &rec.stake, now)
            });
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
    if rec.cooling_off_until.is_some() {
        // VTI-APV-019: it lands unopposed only while nobody else could consent.
        let others = admin_consent::approvers_for(
            state,
            rec.act,
            &rec.stake,
            &rec.requester,
            &rec.subject,
            now,
        )
        .await?;
        if !others.is_empty() {
            rec.close(
                Status::Cancelled,
                ClosedReason::Invalidated,
                Some(
                    "another holder of what is at stake can now consent to this, so it no \
                     longer lands on a cooling-off; send it again for them to decide"
                        .into(),
                ),
                now,
            );
            return Ok(true);
        }
        return Ok(false);
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

/// Every live administrator, scoped or not — who an acknowledge item can be
/// for (VTI-VTC-023).
async fn live_admins(state: &AppState, now: u64) -> Result<Vec<String>, AppError> {
    Ok(crate::acl::list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| e.admin.is_administrator() && !e.is_expired(now))
        .map(|e| e.did)
        .collect())
}

/// Who must acknowledge `rec` now: the administrators who held a role when the
/// write was made, minus any who has since lost every admin role — or, when
/// none of them remains (or none was recorded: an emergency bootstrap wiped
/// them), every administrator now.
fn expected_acknowledgers(rec: &ActionRecord, admins: &[String]) -> Vec<String> {
    let kept: Vec<String> = rec
        .acknowledgers
        .iter()
        .flatten()
        .filter(|d| admins.contains(d))
        .cloned()
        .collect();
    if kept.is_empty() {
        admins.to_vec()
    } else {
        kept
    }
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
        if rec.status == Status::Executing {
            // Interrupted: no execution in this process owns it (R2.1).
            if rec.execution_id.as_deref().is_none_or(|id| !in_flight(id)) {
                reconcile(state, &mut rec, now).await?;
                save(state, &rec).await?;
                let stage = if rec.status == Status::Completed {
                    "completed"
                } else {
                    "failed"
                };
                audit(state, &rec, &rec.requester.clone(), stage, Vec::new()).await;
                warn!(
                    action = %rec.id,
                    status = rec.status.wire(),
                    "an interrupted execution was reconciled from its recorded effect"
                );
            }
            continue;
        }
        if settle(state, &mut rec, now).await? {
            save(state, &rec).await?;
            let stage = match (rec.status, rec.closed_reason) {
                (Status::Expired, _) => "expired",
                (Status::Failed, _) => "failed",
                (_, Some(ClosedReason::Acknowledged)) => "completed",
                _ => "invalidated",
            };
            audit(state, &rec, &rec.requester.clone(), stage, Vec::new()).await;
            info!(action = %rec.id, status = rec.status.wire(), "action closed");
        }
    }
    Ok(())
}

/// Settle an action left `executing` by an execution that is no longer
/// running — the process died between persisting `executing` and closing it
/// (CLAUDE.md R2.1). Decided from evidence, never by age:
///
/// - the operation recorded its effect for this execution ([`record_effect`]:
///   the marker, or failing that its `AdminActionEffect` audit row) — it
///   landed: `completed`;
/// - no record, and the state the operation writes has moved from the pin it
///   was approved against — the effect landed in the instant between its
///   write and its record: `completed`;
/// - neither — it never wrote: `failed`, and nothing took effect.
pub(crate) async fn reconcile(
    state: &AppState,
    rec: &mut ActionRecord,
    now: u64,
) -> Result<(), AppError> {
    let exec_id = rec.execution_id.clone().unwrap_or_default();
    let marked = state
        .admin_actions_ks
        .get_raw(effect_key(&rec.id))
        .await?
        .is_some_and(|v| exec_id.is_empty() || v == exec_id.as_bytes());
    let recorded = marked
        || revision_written(state, rec, &exec_id).await?
        || effect_audited(state, &rec.id, &exec_id).await?;
    let pin_moved = !recorded
        && rec.category == Category::Approval
        && admin_consent::pin_for(state, rec.act, &rec.subject).await? != rec.state_pin;
    if recorded || pin_moved {
        rec.close(
            Status::Completed,
            if rec.cooling_off_until.is_some() {
                ClosedReason::LandedAfterCoolingOff
            } else {
                ClosedReason::ThresholdMet
            },
            Some(
                "the operation took effect; the record of its completion was interrupted and has \
                 been reconciled from the effect it wrote"
                    .into(),
            ),
            now,
        );
    } else {
        rec.close(
            Status::Failed,
            ClosedReason::FailedRecheck,
            Some(
                "execution was interrupted before the operation wrote anything; nothing took \
                 effect"
                    .into(),
            ),
            now,
        );
    }
    Ok(())
}

/// The id a `policy/upsert` revision is stored under when an action's execution
/// writes it — a function of the action and the execution, so the revision
/// row **is** the evidence of its own write ([`revision_written`]).
///
/// The upsert moves no state pin (it adds a revision; only `policy/activate`
/// moves the active pointer the pin reads), and its effect marker is a second
/// write in another keyspace. A crash between the two used to leave a revision
/// stored and the action reconciled `failed`. Keyed this way, the revision and
/// its evidence land in one write: if it exists, the effect landed.
pub fn policy_revision_id(action_id: &str, execution_id: &str) -> uuid::Uuid {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vtc-action-policy-revision\0");
    h.update(action_id.as_bytes());
    h.update(b"\0");
    h.update(execution_id.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

/// The id the executing action's `policy/upsert` revision must be stored
/// under ([`policy_revision_id`]), or `None` outside an execution — where a fresh
/// random id is right.
pub(crate) fn executing_revision_id() -> Option<uuid::Uuid> {
    EXECUTING
        .try_with(|e| policy_revision_id(&e.action_id, &e.execution_id))
        .ok()
}

/// Whether the executing `policy/upsert` this action ran stored its revision
/// ([`policy_revision_id`]). `false` for every other operation.
async fn revision_written(
    state: &AppState,
    rec: &ActionRecord,
    exec_id: &str,
) -> Result<bool, AppError> {
    if rec.type_uri != crate::trust_tasks::policy_tasks::POLICY_UPSERT_TYPE || exec_id.is_empty() {
        return Ok(false);
    }
    Ok(
        crate::policy::get_policy(&state.policies_ks, policy_revision_id(&rec.id, exec_id))
            .await?
            .is_some(),
    )
}

/// Whether an `AdminActionEffect` row names this action and execution.
async fn effect_audited(
    state: &AppState,
    action_id: &str,
    exec_id: &str,
) -> Result<bool, AppError> {
    for (_, value) in state.audit_ks.prefix_iter_raw(Vec::new()).await? {
        let Ok(env) = serde_json::from_slice::<vti_common::audit::AuditEnvelope>(&value) else {
            continue;
        };
        if let AuditEvent::AdminActionEffect(d) = &env.event
            && d.action_id == action_id
            && (exec_id.is_empty() || d.execution_id == exec_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One pass of housekeeping: settle every action (expiry, invalidation,
/// acknowledgement, reconciliation of interrupted executions), then land every
/// cooling-off whose window has ended (VTI-APV-019, §8.2). What the sweeper
/// runs each minute — and what a test drives directly.
pub async fn sweep_once(state: &AppState) -> Result<(), AppError> {
    refresh_all(state).await?;
    let now = now_epoch();
    let due: Vec<String> = all(state)
        .await?
        .into_iter()
        .filter(|r| r.status == Status::Open && r.cooling_off_until.is_some_and(|u| u <= now))
        .map(|r| r.id)
        .collect();
    for id in due {
        if let Err(e) = land_cooling_off(state, &id).await {
            warn!(action = %id, error = %e, "a cooling-off could not land");
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
            if let Err(e) = sweep_once(&state).await {
                warn!(error = %e, "action-list sweep failed");
            }
            // A departed granter's grants, withdrawn when their review lapses
            // (`vtc-admin-roles.md` §6.3, VTI-ACL-071).
            if let Err(e) = crate::acl::delegation::sweep(&state).await {
                warn!(error = %e, "delegation-review sweep failed");
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
    let rec = {
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
        let eligible = admin_consent::approvers_for(
            state,
            rec.act,
            &rec.stake,
            &rec.requester,
            &rec.subject,
            now,
        )
        .await?;
        if !eligible.iter().any(|d| d == approver) {
            return Err(DecisionError::NotAnApprover);
        }
        if rate_limited(approver, now) {
            return Err(DecisionError::RateLimited);
        }
        let evidence = match input.evidence.as_ref() {
            None => None,
            Some(ev) => Some(
                verify_evidence(
                    state,
                    approver,
                    &slot.challenge,
                    &slot.wire_digest,
                    (rec.created_at, rec.expires_at),
                    ev,
                )
                .await?,
            ),
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
            // A declined review withdraws the grants now rather than at the
            // deadline (`vtc-admin-roles.md` §6.3).
            if rec.act == Act::GrantsReview
                && let Err(e) = crate::acl::delegation::withdraw_reviewed(
                    state,
                    rec.payload["granter"].as_str().unwrap_or_default(),
                    &rec.payload["subjects"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|s| s.as_str().map(str::to_string))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                )
                .await
            {
                warn!(action = %rec.id, error = %e, "a declined review's grants could not be withdrawn now; the sweeper will at the deadline");
            }
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
        // runs outside the lock (module docs, *Lock order*). Persisted with
        // its execution id before the operation runs (R2.1), and registered as
        // running first, so the sweeper never mistakes it for an interrupted
        // one.
        begin_execution(&mut rec, now);
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

    let approvers: Vec<String> = rec.approvals.iter().map(|a| a.did.clone()).collect();
    let id = rec.id.clone();
    let (completed, message) = run_and_close(state, rec, Some(approver), approvers.clone()).await?;
    info!(action = %id, completed, "action executed on its final approval");
    Ok(Decided::Granted {
        action_id: id,
        payload_digest: input.payload_digest,
        approvals: approvers.len() as u64,
        completed,
        message,
    })
}

/// Move `rec` to `executing` under a fresh execution id, registered as running
/// in this process. The caller holds [`ACTION_LOCK`] and saves the record.
fn begin_execution(rec: &mut ActionRecord, now: u64) {
    let execution_id = format!("exe-{}", uuid::Uuid::new_v4().simple());
    in_flight_insert(&execution_id);
    rec.status = Status::Executing;
    rec.executing_since = Some(now);
    rec.execution_id = Some(execution_id);
}

/// Run an action already persisted `executing` and close it: `completed`, or
/// `failed` with the refusal and nothing written. `(completed, refusal)`.
///
/// On completion of an act that made a new unrestricted administrator, an
/// approver enrolment invite is minted for them (`vtc-approver-step-up.md`
/// §6c, §11.4) and shown once to the requester, who delivers its claim code.
async fn run_and_close(
    state: &AppState,
    rec: ActionRecord,
    closed_by: Option<&str>,
    approvers: Vec<String>,
) -> Result<(bool, Option<String>), AppError> {
    let execution_id = rec.execution_id.clone().unwrap_or_default();
    let (mut completed, result, mut message) = execute(state, &rec).await;
    // Refused after its write — an error later in the operation, or a panic —
    // is not "nothing took effect": the effect it recorded says otherwise, and
    // the action says what is true (R2.1).
    if !completed
        && state
            .admin_actions_ks
            .get_raw(effect_key(&rec.id))
            .await?
            .is_some_and(|v| v == execution_id.as_bytes())
    {
        completed = true;
        message = Some(format!(
            "the operation took effect, then reported an error: {}",
            message.unwrap_or_else(|| "no detail".into())
        ));
    }
    let mut rec = rec;
    {
        let _guard = ACTION_LOCK.lock().await;
        if let Some(latest) = load(state, &rec.id).await? {
            rec = latest;
        }
        let at = now_epoch();
        if completed {
            rec.close(
                Status::Completed,
                ClosedReason::ThresholdMet,
                message.clone(),
                at,
            );
            if rec.cooling_off_until.is_some() {
                rec.closed_reason = Some(ClosedReason::LandedAfterCoolingOff);
                rec.closed_message = Some(
                    "the cooling-off ended with nobody but the requester and the subject able \
                     to consent, so it landed unopposed (VTI-APV-019)"
                        .into(),
                );
            }
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
        rec.closed_by = closed_by.map(str::to_string);
        save(state, &rec).await?;
    }
    in_flight_remove(&execution_id);
    audit(
        state,
        &rec,
        closed_by.unwrap_or(&rec.requester),
        if completed { "completed" } else { "failed" },
        approvers,
    )
    .await;
    if completed
        && rec.act == Act::GrantUnrestricted
        && rec.type_uri != crate::trust_tasks::admin_tasks::INVITES_CREATE_TYPE
    {
        invite_new_administrator(state, &rec).await;
    }
    Ok((completed, message))
}

/// Mint a step-up approver enrolment invite for the administrator `rec` just
/// made, and keep it on the action for the requester to collect once
/// (`vtc-approver-step-up.md` §6c, §11.4). The creation already passed the
/// requester's step-up and another administrator's consent, so the invite
/// costs nothing extra and closes the gap before the new administrator meets
/// it. Best-effort: the administrator exists either way, and can be invited
/// from Settings if this fails.
async fn invite_new_administrator(state: &AppState, rec: &ActionRecord) {
    match crate::step_up_approver::invite_new_administrator(state, &rec.requester, &rec.subject)
        .await
    {
        Ok(Some(invite)) => {
            let _guard = ACTION_LOCK.lock().await;
            if let Ok(Some(mut latest)) = load(state, &rec.id).await {
                latest.approver_invite = Some(invite);
                if let Err(e) = save(state, &latest).await {
                    warn!(action = %rec.id, error = %e, "could not keep the approver invite");
                }
            }
        }
        Ok(None) => {}
        Err(e) => warn!(
            action = %rec.id,
            subject = %rec.subject,
            error = %e,
            "no approver invite was minted for the new administrator; issue one from Settings"
        ),
    }
}

/// Land a cooling-off whose window has ended (VTI-APV-019, §8.2): settle it
/// (it may have been invalidated meanwhile), move it to `executing` under the
/// lock, and run it. Nothing if it is no longer open or not yet due.
pub(crate) async fn land_cooling_off(state: &AppState, id: &str) -> Result<(), AppError> {
    let now = now_epoch();
    let rec = {
        let _guard = ACTION_LOCK.lock().await;
        let Some(mut rec) = load(state, id).await? else {
            return Ok(());
        };
        if settle(state, &mut rec, now).await? {
            save(state, &rec).await?;
            audit(
                state,
                &rec,
                &rec.requester.clone(),
                "invalidated",
                Vec::new(),
            )
            .await;
            return Ok(());
        }
        if rec.status != Status::Open || rec.cooling_off_until.is_none_or(|u| u > now) {
            return Ok(());
        }
        begin_execution(&mut rec, now);
        save(state, &rec).await?;
        rec
    };
    let (completed, _) = run_and_close(state, rec, None, Vec::new()).await?;
    info!(action = %id, completed, "a cooling-off ended and its reduction ran");
    // The subject, if removed, loses their own open actions now (§4.4) rather
    // than at the next read.
    refresh_all(state).await
}

fn is_secret_response(type_uri: &str) -> bool {
    crate::trust_tasks::admin_tasks::SECRET_RESPONSES.contains(&type_uri)
        || crate::trust_tasks::step_up_passkey_tasks::SECRET_RESPONSES.contains(&type_uri)
        || crate::trust_tasks::community_tasks::SECRET_RESPONSES.contains(&type_uri)
}

/// Dispatch the action's stored document through the handler it was submitted
/// to. `(completed, response payload, refusal message)`.
async fn execute(state: &AppState, rec: &ActionRecord) -> (bool, Option<Value>, Option<String>) {
    // Raised by the community, not from a document: nothing to dispatch.
    if rec.act == Act::GrantsReview {
        return execute_grants_review(state, rec).await;
    }
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
        execution_id: rec.execution_id.clone().unwrap_or_default(),
        cooling_off: rec.cooling_off_until.is_some(),
        gate_spent: Arc::new(AtomicBool::new(false)),
        effect_recorded: Arc::new(AtomicBool::new(false)),
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
    wire_digest: &str,
    window: (u64, u64),
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
        Some("approverSigned") => {
            // The approver's own step-up approver vouching for this decision
            // (decision/0.2 `approverSigned`; `vtc-approver-step-up.md` §6):
            // an attest/0.1 statement with purpose `decision`, whose subject is
            // the decision's signer, audience this VTC, challenge the
            // decision's own and boundTo its payloadDigest — each checked
            // against this service's record of the slot, never the document.
            let statement = evidence
                .get("statement")
                .filter(|s| s.is_object())
                .ok_or(DecisionError::EvidenceInvalid("statementMissing"))?;
            let offered: Vec<String> = crate::acl::approver::live_approvers(state, approver)
                .await?
                .into_iter()
                .map(|r| r.approver_did)
                .collect();
            let verified = crate::acl::approver::verify_statement(
                state,
                statement,
                &crate::acl::approver::ExpectedStatement {
                    purpose: trust_tasks_rs::specs::auth::step_up::approver::attest::v0_1::PayloadPurpose::Decision,
                    subject: approver,
                    challenge,
                    bound_to: wire_digest,
                    not_before: epoch_utc(window.0),
                    not_after: epoch_utc(window.1),
                    approver: crate::acl::approver::ExpectedApprover::BoundAmong(&offered),
                },
            )
            .await
            .map_err(|e| match e {
                crate::acl::approver::StatementError::Invalid(_) => {
                    DecisionError::EvidenceInvalid("statementInvalid")
                }
                crate::acl::approver::StatementError::NotBound => {
                    DecisionError::EvidenceInvalid("approverNotBound")
                }
                crate::acl::approver::StatementError::Internal(e) => DecisionError::Internal(e),
            })?;
            if let Err(e) = crate::acl::approver::record_use(
                &state.step_up_approvers_ks,
                verified.approver_did(),
            )
            .await
            {
                debug!(error = %e, "could not stamp the approver's last use");
            }
            Ok(format!("approverSigned:{}", verified.approver_did()))
        }
        _ => Err(DecisionError::EvidenceInvalid("unknownKind")),
    }
}

fn epoch_utc(epoch: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(epoch as i64, 0).unwrap_or_default()
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

/// Whether `caller` — an administrator — may see `rec`: its requester, one of
/// its approvers, the subject of a cooling-off (who must see it coming,
/// VTI-APV-019), any administrator for an operator's offline write (VTI-VTC-023
/// — it concerns the whole community), or an unrestricted administrator (the
/// audit-read capability) as an observer.
pub(crate) fn visible_to(rec: &ActionRecord, caller: &str, caller_unrestricted: bool) -> bool {
    rec.requester == caller
        || rec.slot(caller).is_some()
        || (rec.cooling_off_until.is_some() && rec.subject == caller)
        || rec.category == Category::Acknowledge
        || caller_unrestricted
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
    /// What the console's banners need beyond the counts (`ext.org.openvtc`):
    /// the operator writes still waiting for the caller's acknowledgement
    /// (VTI-VTC-023), the cooling-offs that will reduce the caller
    /// (VTI-APV-019), and whether single-administrator mode is in effect
    /// (VTI-APV-022).
    pub ext: Value,
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
    version: WireVersion,
) -> Result<Page, AppError> {
    refresh_all(state).await?;
    let now = now_epoch();
    let records = all(state).await?;
    let mut ctx = ViewCtx::new(state, &records, now, version).await?;

    let mut waiting_for_me = 0;
    let mut requested_by_me = 0;
    let mut unacknowledged = Vec::new();
    let mut against_me = Vec::new();
    let mut selected: Vec<&ActionRecord> = Vec::new();
    for rec in &records {
        if !visible_to(rec, caller, caller_unrestricted) {
            continue;
        }
        let waiting = ctx.waiting_for(rec, caller);
        if waiting {
            waiting_for_me += 1;
            if rec.category == Category::Acknowledge {
                unacknowledged.push(json!(rec.id));
            }
        }
        if rec.status.is_open()
            && rec.subject == caller
            && let Some(until) = rec.cooling_off_until
        {
            against_me.push(json!({
                "actionId": rec.id,
                "requester": rec.requester,
                "landsAt": rfc3339(until),
            }));
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
        ext: json!({
            "operatorWritesUnacknowledged": unacknowledged,
            "coolingOffAgainstMe": against_me,
            // VTI-APV-022 item 3: reported to every administrator, in every
            // session, for as long as it is in effect — this is the signed
            // read every console page makes.
            "singleAdminMode": admin_consent::single_admin_mode(state).await,
        }),
    })
}

/// Open views by `expiresAt` soonest first (non-expiring last, then by
/// `createdAt`), `history` by `closedAt` newest first, and in `all` open
/// before closed in those orders.
fn order_key(rec: &ActionRecord) -> (u8, i64, u64) {
    if rec.status.is_open() {
        let expiry = if rec.category == Category::Acknowledge {
            i64::MAX
        } else {
            rec.expires_at as i64
        };
        (0, expiry, rec.created_at)
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
    version: WireVersion,
) -> Result<Option<Value>, AppError> {
    refresh_all(state).await?;
    let Some(rec) = load(state, action_id).await? else {
        return Ok(None);
    };
    if !visible_to(&rec, caller, caller_unrestricted) {
        return Ok(None);
    }
    let records = all(state).await?;
    let mut ctx = ViewCtx::new(state, &records, now_epoch(), version).await?;
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
    // A secret result (an invite's claim code, a new administrator's approver
    // invite) is shown to the requester once.
    if rec.requester == caller
        && ((rec.result_secret && rec.result.is_some()) || rec.approver_invite.is_some())
    {
        let _guard = ACTION_LOCK.lock().await;
        if let Some(mut latest) = load(state, action_id).await? {
            if latest.result_secret {
                latest.result = None;
            }
            latest.approver_invite = None;
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
    version: WireVersion,
) -> Result<Value, AppError> {
    let records = all(state).await?;
    let mut ctx = ViewCtx::new(state, &records, now_epoch(), version).await?;
    Ok(ctx.render(rec, caller, false))
}

/// What rendering many actions shares: who is eligible, who has how many open.
struct ViewCtx<'a> {
    records: &'a [ActionRecord],
    now: u64,
    threshold: u64,
    /// Every ACL entry, read once: eligibility is per action, by its stake.
    entries: Vec<crate::acl::VtcAclEntry>,
    /// Every live administrator, of any role — who acknowledges (VTI-VTC-023).
    admins: Vec<String>,
    /// The `_shared` version the caller asked in.
    version: WireVersion,
}

impl<'a> ViewCtx<'a> {
    async fn new(
        state: &'a AppState,
        records: &'a [ActionRecord],
        now: u64,
        version: WireVersion,
    ) -> Result<Self, AppError> {
        Ok(Self {
            records,
            now,
            version,
            threshold: admin_consent::threshold(state).await?,
            entries: crate::acl::list_acl_entries(&state.acl_ks).await?,
            admins: live_admins(state, now).await?,
        })
    }

    /// The slot holders still eligible to decide `rec`.
    fn eligible(&self, rec: &ActionRecord) -> Vec<String> {
        rec.approvers
            .iter()
            .filter(|s| {
                self.entries.iter().any(|e| {
                    e.did == s.did
                        && admin_consent::may_approve(
                            e,
                            &rec.act.stake_or_default(&rec.stake),
                            self.now,
                        )
                }) && s.did != rec.requester
                    && !(rec.act.excludes_subject() && s.did == rec.subject)
            })
            .map(|s| s.did.clone())
            .collect()
    }

    /// Whether `rec` is waiting on `caller`: an approval they may still decide,
    /// or an operator's write they have yet to acknowledge.
    fn waiting_for(&self, rec: &ActionRecord, caller: &str) -> bool {
        if rec.status != Status::Open {
            return false;
        }
        match rec.category {
            Category::Acknowledge => {
                !rec.approved_by(caller)
                    && expected_acknowledgers(rec, &self.admins)
                        .iter()
                        .any(|d| d == caller)
            }
            Category::Approval => {
                rec.slot(caller).is_some()
                    && !rec.approved_by(caller)
                    && self.eligible(rec).iter().any(|d| d == caller)
            }
        }
    }

    fn render(&mut self, rec: &ActionRecord, caller: &str, detailed: bool) -> Value {
        if rec.category == Category::Acknowledge {
            return self.render_acknowledge(rec, caller);
        }
        let eligible = self.eligible(rec);
        let approvals: Vec<Value> = rec
            .approvals
            .iter()
            .filter(|a| !rec.status.is_open() || eligible.contains(&a.did))
            .map(|a| json!({ "subject": a.did, "at": rfc3339(a.at) }))
            .collect();
        let v0_2 = self.version == WireVersion::V0_2;
        let cooling_off = rec.cooling_off_until;
        let caller_role = if rec.requester == caller {
            "requester"
        } else if rec.slot(caller).is_some() {
            "approver"
        } else if v0_2 && cooling_off.is_some() && rec.subject == caller {
            // VTI-APV-019: shown it so they learn of it before it lands; they
            // can neither decide nor cancel it.
            "subject"
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
        if rec.requester == caller
            && detailed
            && let Some(invite) = &rec.approver_invite
        {
            ext.insert("approverInvite".into(), invite.clone());
        }
        if rec.consent_waived {
            // VTI-APV-022: nobody but the requester could consent, and
            // single-administrator mode let the requester's own
            // operation-bound gesture stand in for it. No threshold was met by
            // anyone else — so, as for a cooling-off, none is shown.
            ext.insert(
                "consentWaived".into(),
                json!({
                    "mode": "singleAdministrator",
                    "requirement": rec.act.requirement(),
                }),
            );
        }
        if let Some(until) = cooling_off.filter(|_| !v0_2) {
            // 0.1 only. VTI-APV-019 / §8.2: nobody else can consent, so there
            // is no threshold and no expiry — it lands by itself at `landsAt`
            // unless the requester cancels it. The subject sees it coming.
            // 0.1's schema has no way to say so; 0.2 does, in `category`,
            // `landsAt` and `cancellableBy`, and carries none of this.
            ext.insert(
                "coolingOff".into(),
                json!({
                    "landsAt": rfc3339(until),
                    "subject": rec.subject,
                    "agreement": "unopposed",
                    "againstYou": rec.subject == caller,
                }),
            );
        }

        let category = if v0_2 && cooling_off.is_some() {
            "coolingOff"
        } else {
            rec.category.wire()
        };
        let mut action = json!({
            "actionId": rec.id,
            "category": category,
            "kind": rec.kind,
            "typeUri": rec.type_uri,
            "requester": rec.requester,
            "status": rec.status.wire(),
            "createdAt": rfc3339(rec.created_at),
            "approvals": approvals,
            "summary": summary::render(&rec.kind, &rec.type_uri, &rec.payload),
            "payload": rec.payload,
            "payloadDigest": summary::payload_digest(&rec.payload).unwrap_or_default(),
            "callerRole": caller_role,
            "requesterOpenActions": requester_open,
            "ext": { "org.openvtc": Value::Object(ext) },
        });
        if v0_2 && let Some(until) = cooling_off {
            // `landsAt` exactly for `coolingOff`; neither threshold nor expiry.
            action["landsAt"] = json!(rfc3339(until));
            if rec.status.is_open() {
                action["cancellableBy"] = json!("requester");
            }
        }
        if cooling_off.is_none() {
            // A cooling-off has neither: no approval is needed, and it does
            // not lapse — the published `threshold` cannot say zero, so it is
            // absent rather than a number that is not true.
            action["expiresAt"] = json!(rfc3339(rec.expires_at));
            // A waived consent (VTI-APV-022) needed nobody else's approval:
            // no threshold, for the same reason.
            if !rec.consent_waived {
                action["threshold"] = json!(rec.threshold.max(1));
            }
        }
        if rec.status.is_open() {
            let needed = if cooling_off.is_some() {
                0
            } else {
                rec.threshold.max(self.threshold)
            };
            let valid = approvals.len() as u64;
            // 0.2: absent for `coolingOff`, which waits on time, not decisions.
            if !(v0_2 && cooling_off.is_some()) {
                action["approversRemaining"] = json!(needed.saturating_sub(valid));
            }
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
                action["closedReason"] = json!(r.wire(self.version));
            }
        }
        action
    }

    /// An operator's offline write (VTI-VTC-023): no threshold, no expiry, no
    /// challenge — only who has acknowledged it and how many still must.
    fn render_acknowledge(&self, rec: &ActionRecord, caller: &str) -> Value {
        let expected = expected_acknowledgers(rec, &self.admins);
        let approvals: Vec<Value> = rec
            .approvals
            .iter()
            .map(|a| json!({ "subject": a.did, "at": rfc3339(a.at) }))
            .collect();
        let caller_role = if expected.iter().any(|d| d == caller) {
            "acknowledger"
        } else {
            "observer"
        };
        let mut ext = Map::new();
        ext.insert("severity".into(), json!("critical"));
        ext.insert("acknowledgedByMe".into(), json!(rec.approved_by(caller)));
        if let Some(m) = &rec.closed_message {
            ext.insert("closedMessage".into(), json!(m));
        }
        let mut action = json!({
            "actionId": rec.id,
            "category": rec.category.wire(),
            "kind": rec.kind,
            "typeUri": rec.type_uri,
            "requester": rec.requester,
            "status": rec.status.wire(),
            "createdAt": rfc3339(rec.created_at),
            "approvals": approvals,
            "summary": summary::render(&rec.kind, &rec.type_uri, &rec.payload),
            "payload": rec.payload,
            "payloadDigest": summary::payload_digest(&rec.payload).unwrap_or_default(),
            "callerRole": caller_role,
            "ext": { "org.openvtc": Value::Object(ext) },
        });
        if rec.status.is_open() {
            let remaining = expected.iter().filter(|d| !rec.approved_by(d)).count();
            action["approversRemaining"] = json!(remaining);
        } else {
            action["closedAt"] = json!(rfc3339(rec.closed_at.unwrap_or(rec.created_at)));
            if let Some(r) = rec.closed_reason {
                action["closedReason"] = json!(r.wire(self.version));
            }
        }
        action
    }
}

// ─── acknowledging an operator's write (VTI-VTC-023) ─────────────────────

/// Why an acknowledgement was refused — `vtc/admin/actions/acknowledge`'s
/// declared codes.
#[derive(Debug)]
pub(crate) enum AcknowledgeError {
    NotFound,
    NotAcknowledgeable,
    AlreadyAcknowledged,
    Internal(AppError),
}

impl From<AppError> for AcknowledgeError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// Record `caller`'s acknowledgement of an operator's offline write. The item
/// completes (`closedReason: acknowledged`) once every administrator expected
/// to acknowledge it has. Audited.
pub(crate) async fn acknowledge(
    state: &AppState,
    caller: &str,
    caller_unrestricted: bool,
    action_id: &str,
) -> Result<ActionRecord, AcknowledgeError> {
    let now = now_epoch();
    let rec = {
        let _guard = ACTION_LOCK.lock().await;
        let Some(mut rec) = load(state, action_id).await? else {
            return Err(AcknowledgeError::NotFound);
        };
        if !visible_to(&rec, caller, caller_unrestricted) {
            return Err(AcknowledgeError::NotFound);
        }
        if rec.category != Category::Acknowledge {
            return Err(AcknowledgeError::NotAcknowledgeable);
        }
        // The earlier acknowledgement stands; the state the caller wanted is
        // already true.
        if rec.approved_by(caller) {
            return Err(AcknowledgeError::AlreadyAcknowledged);
        }
        if settle(state, &mut rec, now).await? {
            save(state, &rec).await?;
        }
        if rec.status != Status::Open {
            return Err(AcknowledgeError::NotAcknowledgeable);
        }
        let admins = live_admins(state, now).await?;
        if !expected_acknowledgers(&rec, &admins)
            .iter()
            .any(|d| d == caller)
        {
            return Err(AcknowledgeError::NotAcknowledgeable);
        }
        rec.approvals.push(Approval {
            did: caller.to_string(),
            at: now,
            evidence: None,
        });
        settle(state, &mut rec, now).await?;
        save(state, &rec).await?;
        rec
    };
    audit(
        state,
        &rec,
        caller,
        "acknowledged",
        vec![caller.to_string()],
    )
    .await;
    if rec.status == Status::Completed {
        audit(state, &rec, caller, "completed", Vec::new()).await;
    }
    info!(action = %rec.id, acknowledger = caller, "operator write acknowledged");
    Ok(rec)
}

/// An offline write the daemon found queued at boot, to be raised as an
/// acknowledge item (VTI-VTC-023).
#[derive(Debug, Clone)]
pub struct OperatorWrite {
    /// Stable for the queued marker, so raising it twice — a crash between
    /// raising and clearing the marker — finds the item already there.
    pub marker: String,
    /// The command line that wrote it, e.g. `vtc acl add`.
    pub command: String,
    /// `grant`, `remove`, `approverInvite`, `emergencyBootstrap` or
    /// `aclMigration`.
    pub action: String,
    /// The DIDs whose access the write changed, in the order the command
    /// reports them. Never empty on the record (`offline-write/0.1` `dids`):
    /// an emergency bootstrap recorded before its marker carried any is named
    /// by the community's own DID.
    pub dids: Vec<String>,
    pub operator_host: String,
    pub invoked_at: chrono::DateTime<chrono::Utc>,
    /// The administrators holding a role when the write was made. `None` for
    /// an emergency bootstrap, which wiped them.
    pub acknowledgers: Option<Vec<String>>,
}

/// The action id an operator's write is raised under — a function of its
/// marker, so the same write is never raised twice.
fn operator_item_id(marker: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "act-op-{}",
        &hex::encode(Sha256::digest(marker.as_bytes()))[..32]
    )
}

/// Whether the write queued under `marker` has already been raised.
pub async fn operator_item_raised(state: &AppState, marker: &str) -> Result<bool, AppError> {
    Ok(load(state, &operator_item_id(marker)).await?.is_some())
}

/// `vtc/operator/offline-write/0.1` — the **record type** an acknowledge item's
/// `typeUri` names for an operator's offline write (VTI-VTC-023). Those
/// commands run on the host, against the store, and are no Trust Task of their
/// own; the record gives the action a Type URI to name and its payload a
/// published shape. Never sent and never dispatched: a document of this type
/// arriving at the spine answers `unsupportedType`, like every embedded-only
/// type (`trust_task_manifest::EMBEDDED_ONLY`).
pub const OPERATOR_OFFLINE_WRITE_URI: &str =
    <trust_tasks_rs::specs::vtc::operator::offline_write::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The record's `command`, from the command line the marker carries — or,
/// failing a known one, from the kind of write.
fn offline_write_command(write: &OperatorWrite) -> &'static str {
    match write.command.as_str() {
        "vtc acl add" => "aclAdd",
        "vtc acl remove" => "aclRemove",
        "vtc admin invite" => "adminInvite",
        "vtc create-did-key --admin" => "createDidKeyAdmin",
        "vtc admin enrol-approver" => "enrolApprover",
        "vtc admin emergency-bootstrap" => "emergencyBootstrap",
        _ => match write.action.as_str() {
            "grant" => "aclAdd",
            "remove" => "aclRemove",
            "approverInvite" => "enrolApprover",
            _ => "emergencyBootstrap",
        },
    }
}

/// The `offline-write/0.1` record for `write`, held to its published schema.
pub(crate) fn offline_write_record(
    write: &OperatorWrite,
    fallback_did: &str,
) -> Result<Value, AppError> {
    use trust_tasks_rs::validate::ValidatedPayload as _;
    let mut dids: Vec<String> = Vec::with_capacity(write.dids.len());
    for d in &write.dids {
        if !d.is_empty() && !dids.contains(d) {
            dids.push(d.clone());
        }
    }
    dids.truncate(64);
    if dids.is_empty() {
        dids.push(fallback_did.to_string());
    }
    let host = if write.operator_host.trim().is_empty() {
        "unknown".to_string()
    } else {
        write.operator_host.chars().take(253).collect()
    };
    let record = json!({
        "command": offline_write_command(write),
        "dids": dids,
        "host": host,
        "at": write.invoked_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    trust_tasks_rs::specs::vtc::operator::offline_write::v0_1::Payload::validate_value(&record)
        .map_err(|e| {
            AppError::Internal(format!(
                "offline-write record rejected by its own schema: {e}"
            ))
        })?;
    Ok(record)
}

/// The `typeUri` the boot-time ACL migration's acknowledge item is recorded
/// under (`vtc-admin-roles.md` §9) — no Trust Task either.
pub const OPERATOR_ACL_MIGRATION_URI: &str = "urn:openvtc:vtc:operator:acl-migration";

/// Raise `write` as an acknowledge item, unless it already was. `Ok(true)` when
/// raised now. Never subject to the requester limits: an operator's write is
/// surfaced whatever else is open (VTI-VTC-023).
///
/// The item's `typeUri` is the record type `vtc/operator/offline-write/0.1`
/// and its payload that record (`{command, dids, host, at}`), for every
/// offline command — the emergency bootstrap included. The boot ACL migration
/// is not an offline command and keeps [`OPERATOR_ACL_MIGRATION_URI`].
pub async fn raise_operator_item(
    state: &AppState,
    write: &OperatorWrite,
) -> Result<bool, AppError> {
    let id = operator_item_id(&write.marker);
    // The boot migration to role-based administration is no operator command:
    // `offline-write/0.1`'s `command` is a closed set of offline commands with
    // no value for it, and no record type is specified for a migration. It
    // keeps its own URN and payload until one is (`vtc-admin-roles.md` §9).
    let migration = write.action == "aclMigration";
    let type_uri = if migration {
        OPERATOR_ACL_MIGRATION_URI
    } else {
        OPERATOR_OFFLINE_WRITE_URI
    };
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "did:key:vtc-break-glass".into());
    let payload = if migration {
        json!({
            "command": write.command,
            "operatorHost": write.operator_host,
            "invokedAt": write.invoked_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
    } else {
        offline_write_record(write, &vtc_did)?
    };
    let now = now_epoch();
    let digest = task_consent::payload_digest(type_uri, &payload)?;
    // The first DID the write changed — the one named in the audit row.
    let subject = write.dids.first().cloned().unwrap_or_default();
    let rec = ActionRecord {
        id: id.clone(),
        kind: KIND_OPERATOR_WRITE.to_string(),
        act: Act::OperatorWrite,
        stake: Vec::new(),
        type_uri: type_uri.to_string(),
        payload,
        digest,
        submitted_doc: Value::Null,
        submitted_signer: String::new(),
        transport: "host".into(),
        // The operator acts as the community: the host holds its keys.
        requester: vtc_did,
        subject,
        requester_step_up: RequesterStepUp {
            kind: "host".into(),
            credential_id: String::new(),
            bound_to: String::new(),
            at: now,
        },
        approver_set: "administrators".into(),
        approvers: Vec::new(),
        threshold: 0,
        approvals: Vec::new(),
        state_pin: StatePin {
            resource: String::new(),
            version: String::new(),
        },
        summary_text: write.command.clone(),
        status: Status::Open,
        created_at: now,
        expires_at: now,
        executing_since: None,
        closed_at: None,
        closed_reason: None,
        closed_message: None,
        closed_by: None,
        result: None,
        result_secret: false,
        category: Category::Acknowledge,
        cooling_off_until: None,
        execution_id: None,
        acknowledgers: write.acknowledgers.clone(),
        approver_invite: None,
        consent_waived: false,
    };
    {
        let _guard = ACTION_LOCK.lock().await;
        if load(state, &id).await?.is_some() {
            return Ok(false);
        }
        save(state, &rec).await?;
    }
    audit(state, &rec, &rec.requester.clone(), "raised", Vec::new()).await;
    warn!(
        action = %id,
        command = %write.command,
        host = %write.operator_host,
        "an operator's offline write is waiting for every administrator's acknowledgement \
         (VTI-VTC-023)"
    );
    Ok(true)
}

// ─── a departed granter's grants (`vtc-admin-roles.md` §6.3) ──────────────

/// Raise the review of the grants `granter` made that it no longer covers —
/// one approval-category action listing every one (**VTI-ACL-071**).
///
/// Its approvers are the holders who may approve `vtc.roles.assign`, except
/// the granter and the entries under review (none re-affirms itself:
/// VTI-OPS-050). One approval re-affirms every listed grant the approver
/// covers, under the approver's own authority ([`crate::acl::delegation`]);
/// a decline withdraws them now; a lapse leaves them to the delegation
/// sweeper, which withdraws them at the same deadline. Raised by the
/// community, not by a requester's document: the requester is the community's
/// own DID, and nobody can cancel it.
///
/// Nothing is raised when nobody could approve it — the sweeper still
/// withdraws at the deadline, and the entries still show the review.
pub(crate) async fn raise_grants_review(
    state: &AppState,
    granter: &str,
    subjects: &[String],
    deadline: u64,
) -> Result<Option<String>, AppError> {
    if subjects.is_empty() {
        return Ok(None);
    }
    let act = Act::GrantsReview;
    let now = now_epoch();
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "did:key:vtc-community".into());
    let stake = act.default_stake();
    let approvers: Vec<String> =
        admin_consent::approvers_for(state, act, &stake, &vtc_did, granter, now)
            .await?
            .into_iter()
            .filter(|d| !subjects.contains(d))
            .collect();
    if approvers.is_empty() {
        warn!(
            granter,
            subjects = subjects.len(),
            "a departed granter's grants are under review, and nobody else may approve \
             vtc.roles.assign to re-affirm them: they are withdrawn at the deadline"
        );
        return Ok(None);
    }
    let payload = json!({
        "granter": granter,
        "subjects": subjects,
        "deadline": rfc3339(deadline),
    });
    let type_uri = summary::GRANTS_REVIEW_URI;
    let digest = task_consent::payload_digest(type_uri, &payload)?;
    let mut slots = Vec::with_capacity(approvers.len());
    for did in &approvers {
        let challenge = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        slots.push(ApproverSlot {
            did: did.clone(),
            wire_digest: task_consent::wire_digest(type_uri, &payload, &challenge)?,
            challenge,
        });
    }
    let rec = ActionRecord {
        id: format!("act-{}", uuid::Uuid::new_v4().simple()),
        kind: act.kind(type_uri).to_string(),
        act,
        stake,
        type_uri: type_uri.to_string(),
        payload,
        digest,
        submitted_doc: Value::Null,
        submitted_signer: String::new(),
        transport: "host".into(),
        requester: vtc_did,
        subject: granter.to_string(),
        requester_step_up: RequesterStepUp {
            kind: "community".into(),
            credential_id: String::new(),
            bound_to: String::new(),
            at: now,
        },
        approver_set: act.approver_set().to_string(),
        approvers: slots,
        // One administrator who covers a grant re-affirms it, as writing it
        // again with acl/update does (`vtc-admin-roles.md` §6.3).
        threshold: 1,
        approvals: Vec::new(),
        state_pin: admin_consent::pin_for(state, act, granter).await?,
        summary_text: format!("Re-affirm or withdraw the grants {granter} made"),
        status: Status::Open,
        created_at: now,
        expires_at: deadline.max(now + 1),
        executing_since: None,
        closed_at: None,
        closed_reason: None,
        closed_message: None,
        closed_by: None,
        result: None,
        result_secret: false,
        category: Category::Approval,
        cooling_off_until: None,
        execution_id: None,
        acknowledgers: None,
        approver_invite: None,
        consent_waived: false,
    };
    {
        let _guard = ACTION_LOCK.lock().await;
        for slot in &rec.approvers {
            state
                .admin_actions_ks
                .insert_raw(wire_key(&slot.wire_digest), rec.id.as_bytes().to_vec())
                .await?;
        }
        save(state, &rec).await?;
    }
    audit(state, &rec, &rec.requester.clone(), "raised", Vec::new()).await;
    info!(
        action = %rec.id,
        granter,
        subjects = subjects.len(),
        approvers = rec.approvers.len(),
        "a departed granter's grants are raised for review (VTI-ACL-071)"
    );
    push_requests(state, &rec).await;
    Ok(Some(rec.id))
}

/// Execute an approved grants review: re-affirm each listed grant that is
/// still under this granter's review and that one of the approvers covers.
async fn execute_grants_review(
    state: &AppState,
    rec: &ActionRecord,
) -> (bool, Option<Value>, Option<String>) {
    let granter = rec.payload["granter"].as_str().unwrap_or_default();
    let subjects: Vec<String> = rec.payload["subjects"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // The approval that executes it, first: that administrator decided.
    let mut approvers: Vec<String> = rec.approvals.iter().map(|a| a.did.clone()).collect();
    approvers.reverse();
    match crate::acl::delegation::reaffirm(state, granter, &subjects, &approvers).await {
        Ok(outcome) => {
            if let Err(e) = state
                .admin_actions_ks
                .insert_raw(
                    effect_key(&rec.id),
                    rec.execution_id.clone().unwrap_or_default().into_bytes(),
                )
                .await
            {
                warn!(action = %rec.id, error = %e, "could not mark a review's effect");
            }
            (true, Some(outcome), None)
        }
        Err(e) => (false, None, Some(e.to_string())),
    }
}

// ─── role helpers ────────────────────────────────────────────────────────

/// The approvers whose approvals the action executing on this task carries —
/// the "defining administrators" `vtc/roles/define/0.1` item 4 bounds a role
/// by, beside the requester. Empty outside an execution.
pub(crate) async fn executing_approvers(state: &AppState) -> Vec<String> {
    let Some(exec) = executing() else {
        return Vec::new();
    };
    match load(state, &exec.action_id).await {
        Ok(Some(rec)) => rec.approvals.into_iter().map(|a| a.did).collect(),
        _ => Vec::new(),
    }
}

/// How many open actions would grant custom role `name` when they execute —
/// what `vtc/roles/delete/0.1` item 2 counts beside the entries holding it.
pub(crate) async fn pending_role_grants(state: &AppState, name: &str) -> Result<u32, AppError> {
    Ok(all(state)
        .await?
        .iter()
        .filter(|r| r.status.is_open())
        .filter(|r| {
            r.payload.pointer("/entry/role").and_then(Value::as_str) == Some(name)
                || r.payload.get("toRole").and_then(Value::as_str) == Some(name)
        })
        .count() as u32)
}

// ─── the two-administrator race (§8.2) ────────────────────────────────────

/// First to act wins (VTI-APV-019, `vtc-action-list.md` §8.2): when
/// `requester` asks to reduce `target` while a cooling-off raised by `target`
/// to reduce `requester` is still open, the earlier request lands first — now —
/// and this one is refused. The requester's own open actions are then
/// invalidated by losing their authority (§4.4).
pub(crate) async fn refuse_if_reduced_first(
    state: &AppState,
    requester: &str,
    target: &str,
) -> Result<(), AppError> {
    let earlier = {
        let _guard = ACTION_LOCK.lock().await;
        let now = now_epoch();
        let mut found = None;
        for mut rec in all(state).await? {
            if rec.status == Status::Open
                && rec.cooling_off_until.is_some()
                && rec.subject == requester
                && rec.requester == target
            {
                rec.cooling_off_until = Some(now);
                save(state, &rec).await?;
                found = Some(rec);
                break;
            }
        }
        found
    };
    let Some(rec) = earlier else {
        return Ok(());
    };
    warn!(
        action = %rec.id,
        requester,
        target,
        "a reduction answered by a counter-request: the earlier one lands first (§8.2)"
    );
    audit(state, &rec, requester, "accelerated", Vec::new()).await;
    // Off this task: the request being refused may hold the locks the earlier
    // one's operation takes.
    let owned = state.clone();
    let id = rec.id.clone();
    tokio::spawn(async move {
        if let Err(e) = land_cooling_off(&owned, &id).await {
            warn!(action = %id, error = %e, "the earlier reduction could not land");
        }
    });
    Err(AppError::Conflict(format!(
        "{target} asked to reduce your authority first ({}), so that request lands now and \
         yours was not raised: in a community of two unrestricted administrators the first to \
         act wins (VTI-APV-019)",
        rec.id
    )))
}

// ─── pushing the request to approvers' devices ───────────────────────────

/// One VTC-signed `task-consent/request/0.1` per approver, carrying that
/// approver's own challenge, pushed best-effort — and only when the community
/// turned it on (`acl.consent_request_push`, default off, §11.6). The action list is the source
/// of truth; a lost push loses nothing (§7.1). A copy an approver holds is
/// what `cnm consent approve <file>` answers.
async fn push_requests(state: &AppState, rec: &ActionRecord) {
    if rec.approvers.is_empty() {
        return;
    }
    // Off by default (§11.6): only when the community asked for it.
    let cfg = state.config.read().await.clone();
    match crate::config_store::live_consent_request_push(
        &cfg,
        &ConfigStore::new(state.config_ks.clone()),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            debug!(error = %e, "could not read whether to push; the action list has it");
            return;
        }
    }
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
        // An operator's write is acknowledged, never consented to: nothing to
        // sign a request for.
        Act::OperatorWrite => return Ok(Vec::new()),
        Act::ChangeRoles => (
            "roleDefinitionChange",
            json!({ "role": rec.subject }),
            "The ceiling every holder of this role is bounded by changes, for all of them at once.",
        ),
        Act::RestoreBackup => (
            "backupRestore",
            json!({ "bundleId": rec.subject }),
            "Every record in the backup replaces this community's, its access control included.",
        ),
        Act::GrantsReview => (
            "authorityGrant",
            json!({ "granter": rec.subject }),
            "Approving re-affirms these grants under your own authority; declining withdraws them.",
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
