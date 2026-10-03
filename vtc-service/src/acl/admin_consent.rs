//! Second-party consent for unrestricted admin authority — **VTI-APV-014**.
//!
//! > Creating an entry with unrestricted act scope, or widening an entry to
//! > unrestricted act scope, MUST require consent from a party other than the
//! > requester.
//!
//! Unrestricted authority is the grant every other grant is made from, including
//! the removal of the controls that govern it, so one stolen credential must not
//! be enough to make one. The requester's own passkey gesture proves the
//! requester is present; it says nothing about whether anyone else agrees. This
//! module is the anyone-else.
//!
//! Design: `docs/05-design-notes/vtc-action-list.md` §4 (the action list) over
//! `docs/05-design-notes/vtc-operation-bound-step-up.md` §4.
//!
//! ## One model, not a parallel one (VTI-VTC-020)
//!
//! It is the VTA's DTTE ceremony — `task-consent/{request,decision}` — with the
//! approver set fixed by the requirement rather than by a configured rule:
//!
//! - **Trigger** ([`confers_unrestricted`]): an `acl/grant` or `acl/change-role`
//!   whose resulting entry is an admin with `ActScope::All`, where the entry
//!   before it was not a live unrestricted admin.
//! - **Approvers**: every other live unrestricted admin — `excludeRequester` is
//!   always on (VTI-APV-007), and approving an unrestricted entry takes
//!   unrestricted approve authority, which only they hold (VTI-APV-006).
//! - **Threshold**: [`crate::config_store::UNRESTRICTED_ADMIN_CONSENT_THRESHOLD`],
//!   default and minimum 1. A value the community cannot meet is refused when it
//!   is written ([`check_threshold_meetable`], VTI-APV-009).
//!
//! ## The loop: park, then complete on the N-th approval
//!
//! 1. The operation arrives and every other check passes. The requester's
//!    passkey gesture, bound to the operation, is asked for and spent
//!    (VTI-APV-015). The operation is then **parked** as an action
//!    ([`crate::admin_actions`]) — the requester's signed document verbatim,
//!    the approver set, the threshold, one challenge per approver and a pin on
//!    the state the approvers are shown — and the requester is answered with a
//!    `trust-task-next-step/0.1` naming `vtc/admin/actions/show` (continuation
//!    `proceed`). Nothing is asked of the requester again.
//! 2. Approvers answer `task-consent/decision`, each signed by the approver's
//!    own DID. One deny closes the action for everyone.
//! 3. The approval that reaches the threshold **executes** the parked document
//!    through the same handler it was submitted to, with every check re-run
//!    against the community as it is then (VTI-APV-017). Reaching this gate
//!    again during that execution, [`gesture_then_consent_for`] re-checks the
//!    approvals — still eligible, still enough, state pin unmoved — instead of
//!    parking, and a failed re-check fails the action closed.
//!
//! The approval binds the payload digest (VTI-APV-004) and is spent by one
//! execution. It elevates nothing (VTI-APV-005): the operation runs as the
//! requester, with the requester's authority read again at execution.
//!
//! There is no re-send: a client that answers `consent_required` by sending
//! the operation again is not supported (design §8a).
//!
//! ## The other acts it gates
//!
//! The same machinery also gates the acts that could otherwise undo APV-014
//! one step at a time (`vtc-action-list.md` §7b, §8.1). Each is an [`Act`];
//! what differs between them is only who may consent and what they are shown:
//!
//! - [`Act::ReduceUnrestricted`] — **VTI-APV-019**: removing, demoting or
//!   narrowing *another* subject's unrestricted authority. The approvers exclude
//!   the subject as well as the requester, so neither party to the dispute can
//!   decide it. Where nobody is left, [`gate_reduction`] lets the requester's
//!   step-up suffice and the caller records it at `Critical`
//!   ([`record_unopposed_reduction`]).
//! - [`Act::LowerThreshold`] — **VTI-APV-020**: lowering
//!   `acl.unrestricted_admin_consent_threshold` needs consent at the threshold as
//!   it stands, which is what [`threshold`] reads.
//! - [`Act::ChangeAuthorityPolicy`] — **VTI-VTC-022**: replacing or activating
//!   the policy that decides authority (role change, removal, join,
//!   cross-community roles, git namespaces).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;
use trust_tasks_rs::specs::task_consent::decision::v0_1 as decision;
use trust_tasks_rs::specs::task_consent::decision::v0_2 as decision_v0_2;
use trust_tasks_rs::specs::task_consent::request::v0_1 as request;
use vti_common::audit::AuditEvent;
use vti_common::error::AppError;
use vti_common::task_consent::{self, effects::StatePin};

use super::{VtcAclEntry, VtcRole, as_vti_role, get_acl_entry, list_acl_entries};
use crate::auth::session::now_epoch;
use crate::config_store::{ConfigStore, UNRESTRICTED_ADMIN_CONSENT_THRESHOLD};
use crate::server::AppState;

/// The approver set a request names. Not configurable: VTI-APV-014 fixes who
/// may consent, so there is no rule to look it up in.
pub const APPROVER_SET: &str = "unrestricted-admins";

/// `task-consent/request/0.1` — what this service signs and pushes to each
/// approver, best-effort, when an action is raised.
pub(crate) const REQUEST_TYPE: &str = <request::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `task-consent/decision/0.1` — what an approver answers with.
pub(crate) const DECISION_TYPE: &str = <decision::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `task-consent/decision/0.2` — 0.1 plus an optional `evidence` factor and
/// an optional `actionId` locator.
pub(crate) const DECISION_V0_2_TYPE: &str =
    <decision_v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The approver set a request to end another subject's unrestricted authority
/// names (VTI-APV-019): the unrestricted admins other than the requester **and
/// the subject**.
pub const APPROVER_SET_EXCEPT_SUBJECT: &str = "unrestricted-admins-except-subject";

/// Domain tag for the [`StatePin`] version over a subject's ACL entry.
const STATE_DOMAIN: &[u8] = b"vtc/acl-entry-state/v1\0";

/// Domain tag for the [`StatePin`] version over a piece of community state that
/// is not an ACL entry — the consent threshold, the active policy of a purpose.
const SETTING_STATE_DOMAIN: &[u8] = b"vtc/consent-setting-state/v1\0";

/// Which act a consent is asked for. The machinery is one; what differs is who
/// may consent, what they are shown, and what state the consent is pinned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Act {
    /// **VTI-APV-014** — creating or widening to unrestricted admin authority.
    /// The subject is the DID that would hold it.
    GrantUnrestricted,
    /// **VTI-APV-019** — removing, demoting or narrowing another subject's
    /// unrestricted authority. The subject is the DID that holds it, and never
    /// counts as an approver.
    ReduceUnrestricted,
    /// **VTI-APV-020** — lowering the consent threshold. The subject is the
    /// threshold's config key; the consent is pinned to its current value.
    LowerThreshold,
    /// **VTI-VTC-022** — replacing or activating a policy that decides
    /// authority. The subject names the purpose; the consent is pinned to the
    /// revision active for it now.
    ChangeAuthorityPolicy(crate::policy::PolicyPurpose),
}

impl Act {
    /// The requirement this act's consent implements, for refusals.
    pub(crate) fn requirement(self) -> &'static str {
        match self {
            Self::GrantUnrestricted => "VTI-APV-014",
            Self::ReduceUnrestricted => "VTI-APV-019",
            Self::LowerThreshold => "VTI-APV-020",
            Self::ChangeAuthorityPolicy(_) => "VTI-VTC-022",
        }
    }

    pub(crate) fn approver_set(self) -> &'static str {
        match self {
            Self::ReduceUnrestricted => APPROVER_SET_EXCEPT_SUBJECT,
            _ => APPROVER_SET,
        }
    }

    /// Whether the subject is excluded from the approvers, beside the
    /// requester. Only for a reduction, where the subject is a party to it.
    pub(crate) fn excludes_subject(self) -> bool {
        matches!(self, Self::ReduceUnrestricted)
    }

    /// The action-list `kind` this act is raised as, for the task carrying it
    /// (`vtc-action-list.md` §7a.2).
    pub(crate) fn kind(self, type_uri: &str) -> &'static str {
        use crate::admin_actions::summary as s;
        match self {
            Self::GrantUnrestricted
                if type_uri == crate::trust_tasks::admin_tasks::INVITES_CREATE_TYPE =>
            {
                s::KIND_INVITE_CREATE
            }
            Self::GrantUnrestricted => s::KIND_GRANT_AUTHORITY,
            Self::ReduceUnrestricted => s::KIND_REDUCE_AUTHORITY,
            Self::LowerThreshold => s::KIND_THRESHOLD_LOWER,
            Self::ChangeAuthorityPolicy(_) => s::KIND_POLICY_AUTHORITY,
        }
    }
}

/// The operation being consented to: its task type and the payload the digest
/// is taken over.
///
/// Each door passes the payload it would execute — the signed document's own
/// payload — so the digest names the subject as well as the change.
#[derive(Debug, Clone, Copy)]
pub struct Operation<'a> {
    pub type_uri: &'a str,
    pub payload: &'a Value,
}

/// Whether writing an entry of `role` over `scopes` makes its subject an
/// unrestricted admin who was not one — the case VTI-APV-014 gates.
///
/// Decided through `ActScope` rather than by testing `scopes.is_empty()`: an
/// empty list means *unrestricted* for an admin and *nowhere* for every other
/// role, and a check that forgets the role gets one of them backwards.
///
/// An expired unrestricted entry is not unrestricted any more, so granting it
/// again is a new conferral.
#[must_use]
pub fn confers_unrestricted(
    prev: Option<&VtcAclEntry>,
    role: &VtcRole,
    scopes: &[String],
    now: u64,
) -> bool {
    let next = vti_common::acl::act_scope_for(&as_vti_role(role), scopes);
    next.is_unrestricted() && !prev.is_some_and(|p| p.is_super_admin() && !p.is_expired(now))
}

/// The DIDs of every live unrestricted admin.
pub async fn unrestricted_admins(state: &AppState, now: u64) -> Result<Vec<String>, AppError> {
    Ok(list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| e.is_super_admin() && !e.is_expired(now))
        .map(|e| e.did)
        .collect())
}

/// The threshold in force **now**.
///
/// Read through the config layers rather than from the in-memory `AppConfig`: a
/// runtime `config/patch` writes the database layer, and the in-memory copy only
/// follows on `config/reload`. A raised threshold must bind the next request,
/// not the one after the next reload.
pub async fn threshold(state: &AppState) -> Result<u64, AppError> {
    let fallback = state
        .config
        .read()
        .await
        .acl
        .unrestricted_admin_consent_threshold;
    crate::config_store::live_consent_threshold(
        fallback,
        &ConfigStore::new(state.config_ks.clone()),
    )
    .await
}

/// Refuse a threshold the community cannot meet (VTI-APV-009) — checked where
/// the value is written, not discovered when a grant is blocked by it.
///
/// A requester is always an unrestricted admin (only one can confer unrestricted
/// authority), and never counts, so at most `admins - 1` can approve. The
/// minimum, 1, is always accepted: refusing it would not make the community able
/// to meet it, and there is no lower value to choose instead.
pub async fn check_threshold_meetable(state: &AppState, threshold: u64) -> Result<(), AppError> {
    if threshold <= 1 {
        return Ok(());
    }
    let admins = unrestricted_admins(state, now_epoch()).await?.len() as u64;
    if threshold > admins.saturating_sub(1) {
        return Err(AppError::Validation(format!(
            "{UNRESTRICTED_ADMIN_CONSENT_THRESHOLD} = {threshold} could never be met: a grant of \
             unrestricted admin would need {threshold} unrestricted admins besides the one asking, \
             and this community has {admins} in total. Grant more unrestricted admins first, or \
             set it to at most {}",
            admins.saturating_sub(1).max(1)
        )));
    }
    Ok(())
}

/// Whether `entry` is a live unrestricted admin — one of the approvers.
#[must_use]
pub fn is_live_unrestricted(entry: &VtcAclEntry, now: u64) -> bool {
    entry.is_super_admin() && !entry.is_expired(now)
}

/// Refuse a change that takes `subject` — a live unrestricted admin — out of the
/// approvers, when what is left could never consent to anything: no other
/// unrestricted admin at all, or fewer than the threshold needs.
///
/// The attrition half of VTI-APV-009: a rule must not become unsatisfiable by
/// removal any more than by being written that way. Callers are every door that
/// can end an unrestricted admin — a revocation, a removal from the community, a
/// demotion, a grant rewrite that narrows the entry — and each must hold the
/// admin-set lock ([`crate::ceremony::lock_admin_set`]) from this check through
/// its write, or two such changes could each pass it and together strand the
/// community.
///
/// A threshold of 1 needs only one other unrestricted admin, the same bound the
/// write-time check accepts, so a two-admin community can still remove a
/// compromised one. Above 1 the threshold has to come down first.
pub async fn check_attrition(state: &AppState, subject: &str) -> Result<(), AppError> {
    let remaining = unrestricted_admins(state, now_epoch())
        .await?
        .into_iter()
        .filter(|d| d != subject)
        .count() as u64;
    if remaining == 0 {
        return Err(AppError::Conflict(format!(
            "refusing to end the last unrestricted admin ({subject}): nobody would be left who \
             could consent to another (VTI-APV-014). Make another unrestricted admin first"
        )));
    }
    let threshold = threshold(state).await?;
    if threshold > 1 && threshold > remaining.saturating_sub(1) {
        return Err(AppError::Conflict(format!(
            "refusing to end unrestricted admin {subject}: {remaining} would remain, so \
             {UNRESTRICTED_ADMIN_CONSENT_THRESHOLD} = {threshold} could never be met again \
             (VTI-APV-009). Lower it first — config/patch \
             {{\"{UNRESTRICTED_ADMIN_CONSENT_THRESHOLD}\": {}}} — then retry",
            remaining.saturating_sub(1).max(1)
        )));
    }
    Ok(())
}

/// Other administrators' consent, found sufficient for the operation now being
/// executed. Only an approved action's execution produces one
/// ([`crate::admin_actions`], VTI-APV-017): a submission parks instead.
#[derive(Debug)]
#[must_use = "a ReadyGrant authorizes nothing until it is spent with the write"]
pub struct ReadyGrant {
    action_id: String,
}

impl ReadyGrant {
    /// Spend the consent. Call it with the write, after every other check.
    ///
    /// The action itself is closed — and each approver's challenge consumed, as
    /// `task-consent/decision` requires — by the executor once the write has
    /// landed, under the same status transition that made this execution the
    /// only one ([`crate::admin_actions`]). This records that the gate was
    /// reached on the way.
    pub async fn spend(self, _state: &AppState) -> Result<(), AppError> {
        crate::admin_actions::note_gate_spent(&self.action_id);
        Ok(())
    }
}

/// What the signed door has once it has asked for both things an unrestricted
/// grant needs.
#[derive(Debug)]
pub enum SignedGate {
    /// An approved action is executing this operation and its consent still
    /// holds. Spend it with the write.
    Ready(ReadyGrant),
    /// No gesture yet. A ceremony is parked; refuse with it inline. Nothing
    /// was asked of any other admin.
    StepUpRequired(Box<crate::acl::bound_step_up::ApproveRequest>),
}

/// The signed door's gate for an unrestricted grant: the requester's
/// operation-bound gesture, then the action other admins approve.
///
/// Parked comes back as [`AppError::ApprovalRequired`] carrying
/// [`crate::admin_actions::ACTION_PARKED`], which the dispatcher answers with a
/// `trust-task-next-step/0.1`.
pub async fn gesture_then_consent(
    state: &AppState,
    requester: &str,
    subject: &str,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<SignedGate, AppError> {
    gesture_then_consent_for(
        state,
        Act::GrantUnrestricted,
        requester,
        subject,
        op,
        gesture_reason,
        consent_summary,
    )
    .await
}

/// [`gesture_then_consent`] for any [`Act`].
///
/// On **submission**: the community must be able to consent at all, the
/// requester must be within the action-list limits, and the requester's
/// gesture — bound to this operation — is asked for and spent (VTI-APV-015).
/// Then the operation is parked. A second submission of the same operation
/// while its action is open answers with that action rather than raising
/// another.
///
/// On **execution** of an approved action (VTI-APV-017): the approvals are
/// re-checked against the community as it is now, and [`SignedGate::Ready`]
/// comes back only if they still suffice.
pub async fn gesture_then_consent_for(
    state: &AppState,
    act: Act,
    requester: &str,
    subject: &str,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<SignedGate, AppError> {
    use super::bound_step_up::{self, EvidencedGate};

    if let Some(exec) = crate::admin_actions::executing() {
        let action_id =
            crate::admin_actions::recheck(state, &exec, act, requester, subject, op).await?;
        return Ok(SignedGate::Ready(ReadyGrant { action_id }));
    }

    // The same operation already waiting: point at it, and ask nothing again.
    if let Some(open) = crate::admin_actions::open_for(state, requester, op).await? {
        return Err(crate::admin_actions::parked_error(state, &open).await);
    }

    let now = now_epoch();
    // A consent nobody can give makes the gesture pointless, so say so before
    // asking the requester for one.
    let approvers = approvers_for(state, act, requester, subject, now).await?;
    let threshold = threshold(state).await?;
    refuse_if_unmeetable(act, approvers.len() as u64, threshold, consent_summary)?;
    // §7a.1: the action-list limits, before the gesture too.
    crate::admin_actions::check_limits(state, act, requester, subject).await?;

    let evidence = match bound_step_up::redeem_or_request_with_evidence(
        state,
        requester,
        op.type_uri,
        op.payload,
        gesture_reason,
    )
    .await?
    {
        EvidencedGate::Required(request) => return Ok(SignedGate::StepUpRequired(request)),
        EvidencedGate::Satisfied(evidence) => evidence,
    };

    let pin = pin_for(state, act, subject).await?;
    let action = crate::admin_actions::park(
        state,
        crate::admin_actions::Parking {
            act,
            requester,
            subject,
            op,
            summary: consent_summary,
            evidence,
            approvers,
            threshold,
            pin,
        },
    )
    .await?;
    Err(crate::admin_actions::parked_error(state, &action).await)
}

/// What the requester's side of a reduction has settled to, once the gesture is
/// spent — **VTI-APV-019**.
#[derive(Debug)]
#[must_use = "a consented reduction must spend its grant, and an unopposed one must be recorded"]
pub enum Reduction {
    /// The subject was not a live unrestricted admin (or is the requester): the
    /// gesture is the whole gate.
    StepUpOnly,
    /// Another unrestricted admin, neither the requester nor the subject,
    /// consented. Spend it with the write.
    Consented(ReadyGrant),
    /// The subject is a live unrestricted admin and nobody else is left who
    /// could consent. The gesture suffices; once the write lands the caller
    /// records it at `Critical` and notifies the subject
    /// ([`record_unopposed_reduction`]).
    Unopposed,
}

impl Reduction {
    /// Spend the consent, if this reduction carries one. Call it with the
    /// write, after every other check.
    ///
    /// `Ok(true)` when the reduction is [`Self::Unopposed`] — the caller's cue
    /// to [`record_unopposed_reduction`] once the write lands.
    pub async fn spend(self, state: &AppState) -> Result<bool, AppError> {
        match self {
            Self::StepUpOnly => Ok(false),
            Self::Consented(ready) => ready.spend(state).await.map(|()| false),
            Self::Unopposed => Ok(true),
        }
    }
}

/// [`gate_reduction`]'s answer.
#[derive(Debug)]
pub enum ReductionGate {
    /// The gesture is spent and the reduction may proceed as described.
    Cleared(Reduction),
    /// No gesture yet. A ceremony is parked; refuse with it inline.
    StepUpRequired(Box<crate::acl::bound_step_up::ApproveRequest>),
}

/// The gate on removing, demoting or narrowing an **administrator**'s entry —
/// `acl/revoke`, a downward `acl/change-role`, a narrowing `acl/update` or
/// `acl/grant` rewrite, `vtc/members/admin-remove` (`vtc-action-list.md` §7b).
///
/// Every such act takes the requester's operation-bound gesture. When the
/// subject is **another** live unrestricted admin, it is also parked for the
/// consent of an unrestricted admin who is neither the requester nor the
/// subject (**VTI-APV-019**), through the same machinery as APV-014
/// ([`Act::ReduceUnrestricted`]). Where no such admin exists — two unrestricted
/// admins in all — the gesture alone suffices and [`Reduction::Unopposed`] says
/// so: the VTC cannot tell a removal of a compromised co-admin from a
/// compromised admin's removal of the other, and must not make the first
/// impossible.
///
/// The attrition guard ([`check_attrition`]) is asked first as well, so a
/// reduction that would strand the community is refused before anybody is asked
/// for a gesture. It is not a substitute for the caller's own check under the
/// admin-set lock, which still runs.
///
/// Call it after every check that decides whether the act may happen, and
/// before anything is written.
pub async fn gate_reduction(
    state: &AppState,
    requester: &str,
    subject: &VtcAclEntry,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<ReductionGate, AppError> {
    use super::bound_step_up::{self, Gate};

    let now = now_epoch();
    let unrestricted = is_live_unrestricted(subject, now) && subject.did != requester;
    if unrestricted {
        check_attrition(state, &subject.did).await?;
        let third = approvers_for(state, Act::ReduceUnrestricted, requester, &subject.did, now)
            .await?
            .len();
        // An approved action executing this reduction goes through its consent
        // whatever the count is now: approvals that no longer suffice fail it
        // closed, rather than letting the unopposed path run it on the gesture
        // the requester made when there *were* approvers (VTI-APV-017).
        if third > 0 || crate::admin_actions::executing().is_some() {
            return Ok(
                match gesture_then_consent_for(
                    state,
                    Act::ReduceUnrestricted,
                    requester,
                    &subject.did,
                    op,
                    gesture_reason,
                    consent_summary,
                )
                .await?
                {
                    SignedGate::Ready(ready) => ReductionGate::Cleared(Reduction::Consented(ready)),
                    SignedGate::StepUpRequired(r) => ReductionGate::StepUpRequired(r),
                },
            );
        }
    }
    Ok(
        match bound_step_up::redeem_or_request(
            state,
            requester,
            op.type_uri,
            op.payload,
            gesture_reason,
        )
        .await?
        {
            Gate::Satisfied if unrestricted => {
                warn!(
                    requester,
                    subject = %subject.did,
                    task = op.type_uri,
                    "ending an unrestricted admin's authority with nobody else left to consent \
                     (VTI-APV-019): the requester's step-up is the only gate"
                );
                ReductionGate::Cleared(Reduction::Unopposed)
            }
            Gate::Satisfied => ReductionGate::Cleared(Reduction::StepUpOnly),
            Gate::Required(r) => ReductionGate::StepUpRequired(r),
        },
    )
}

/// [`gate_reduction`] for a door about to end or reduce `prior`, settled to one
/// answer: `Ok(false)` to go ahead, `Ok(true)` to go ahead and then
/// [`record_unopposed_reduction`], or the refusal — [`TaskError::StepUp`] with
/// the ceremony inline when no gesture is recorded yet, or the parked action.
///
/// Only an **administrator**'s live entry is gated (`vtc-action-list.md` §7b
/// item 1); ending an expired or non-admin entry is unchanged, and answers
/// `Ok(false)` without asking anything. Call it last before the write.
///
/// [`TaskError::StepUp`]: crate::error::TaskError::StepUp
pub async fn settle_reduction(
    state: &AppState,
    requester: &str,
    prior: &VtcAclEntry,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<bool, crate::error::TaskError> {
    if prior.role != VtcRole::Admin || prior.is_expired(now_epoch()) {
        return Ok(false);
    }
    match gate_reduction(state, requester, prior, op, gesture_reason, consent_summary).await? {
        ReductionGate::Cleared(reduction) => Ok(reduction.spend(state).await?),
        ReductionGate::StepUpRequired(request) => Err(crate::error::TaskError::step_up(request)),
    }
}

/// Record a [`Reduction::Unopposed`] once its write has landed: a `Critical`
/// audit row (**VTI-APV-019**). Telling the subject is the caller's, because
/// which notice fits depends on the act — a removal sends the removal notice.
///
/// Called after the write, never before: a refusal later in the write (the
/// attrition guard under its lock) must not leave a row saying it happened.
pub async fn record_unopposed_reduction(
    state: &AppState,
    requester: &str,
    prior: &VtcAclEntry,
    task: &str,
) -> Result<(), AppError> {
    let Some(writer) = state.audit_writer.as_ref() else {
        return Ok(());
    };
    writer
        .write(
            requester,
            Some(&prior.did),
            AuditEvent::AuthorityReducedUnopposed(
                vti_common::audit::AuthorityReducedUnopposedData {
                    task: task.to_string(),
                    prior_role: prior.role.to_string(),
                    prior_scopes: prior.allowed_contexts.clone(),
                },
            ),
        )
        .await?;
    Ok(())
}

/// The consent for an operation reached by a door with no signed document to
/// park — the session-gated role change.
///
/// Only an approved action's execution can satisfy it. Anything else is refused:
/// an operation that needs other administrators' approval waits in the action
/// list, and only a signed document can be parked there (`vtc-action-list.md`
/// §4.1 — the VTC executes its own stored copy of what the requester signed).
pub async fn require(
    state: &AppState,
    requester: &str,
    subject: &str,
    op: Operation<'_>,
    summary: &str,
) -> Result<ReadyGrant, AppError> {
    if let Some(exec) = crate::admin_actions::executing() {
        let action_id = crate::admin_actions::recheck(
            state,
            &exec,
            Act::GrantUnrestricted,
            requester,
            subject,
            op,
        )
        .await?;
        return Ok(ReadyGrant { action_id });
    }
    // A consent nobody could give is the more useful thing to say first.
    let approvers = approvers_for(
        state,
        Act::GrantUnrestricted,
        requester,
        subject,
        now_epoch(),
    )
    .await?
    .len() as u64;
    refuse_if_unmeetable(
        Act::GrantUnrestricted,
        approvers,
        threshold(state).await?,
        summary,
    )?;
    Err(AppError::Forbidden(format!(
        "{summary} needs the approval of another unrestricted administrator (VTI-APV-014), \
         which only a signed {} document can wait for",
        op.type_uri
    )))
}

/// Refuse, naming the fix, when there are fewer possible approvers than the
/// threshold needs. The operator's way out is the offline break-glass, which is
/// not reachable by a stolen session or key.
pub(crate) fn refuse_if_unmeetable(
    act: Act,
    approvers: u64,
    threshold: u64,
    summary: &str,
) -> Result<(), AppError> {
    if approvers < threshold {
        let others = if act.excludes_subject() {
            "unrestricted admin(s) other than you and the subject"
        } else {
            "other unrestricted admin(s)"
        };
        return Err(AppError::Forbidden(format!(
            "{summary} needs consent from {threshold} {others}, and this \
             community has {approvers} ({}). Add another unrestricted admin with the \
             offline break-glass while the daemon is stopped — `vtc acl add --did <did> --role \
             admin` — and send this again",
            act.requirement()
        )));
    }
    Ok(())
}

/// Who may consent to `act` on `subject` now: every live unrestricted admin
/// but the requester (VTI-APV-007) — and, for a reduction, but the subject
/// (VTI-APV-019).
pub(crate) async fn approvers_for(
    state: &AppState,
    act: Act,
    requester: &str,
    subject: &str,
    now: u64,
) -> Result<Vec<String>, AppError> {
    Ok(unrestricted_admins(state, now)
        .await?
        .into_iter()
        .filter(|d| d != requester && !(act.excludes_subject() && d == subject))
        .collect())
}

/// The state a consent to `act` is pinned to: what the approvers saw, so a
/// change to it between the ask and the write invalidates the action.
pub(crate) async fn pin_for(
    state: &AppState,
    act: Act,
    subject: &str,
) -> Result<StatePin, AppError> {
    let value = match act {
        Act::GrantUnrestricted | Act::ReduceUnrestricted => {
            return state_pin(state, subject).await;
        }
        // VTI-APV-020: the consent is to lowering *this* threshold. Once it
        // moves, what the approvers agreed to is not what would happen.
        Act::LowerThreshold => json!(threshold(state).await?),
        Act::ChangeAuthorityPolicy(purpose) => json!(
            crate::policy::get_active_policy_id(&state.active_policies_ks, purpose)
                .await?
                .map(|id| id.to_string())
        ),
    };
    Ok(StatePin {
        resource: subject.to_string(),
        version: task_consent::domain_digest(SETTING_STATE_DOMAIN, subject, &value, None)?,
    })
}

/// The subject's ACL entry as the approvers see it, pinned. Any change to the
/// entry between the request and the write — its role, scopes, expiry, even its
/// label — changes the version, and an action raised over the old one is
/// invalidated (`vtc-action-list.md` §4.4).
async fn state_pin(state: &AppState, subject: &str) -> Result<StatePin, AppError> {
    let entry = get_acl_entry(&state.acl_ks, subject).await?;
    let value = serde_json::to_value(&entry)
        .map_err(|e| AppError::Internal(format!("serialise ACL entry for its state pin: {e}")))?;
    Ok(StatePin {
        resource: subject.to_string(),
        version: task_consent::domain_digest(STATE_DOMAIN, subject, &value, None)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(role: VtcRole, scopes: &[&str], expires_at: Option<u64>) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zSubject".into(),
            role,
            label: None,
            allowed_contexts: scopes.iter().map(|s| s.to_string()).collect(),
            created_at: 0,
            created_by: "did:key:zAdmin".into(),
            updated_at: None,
            updated_by: None,
            expires_at,
        }
    }

    /// The four ways an entry can come to be unrestricted, and the ones that
    /// only look like it.
    #[test]
    fn confers_unrestricted_only_where_act_scope_becomes_all() {
        let now = 1_000;
        // A new entry, unrestricted admin.
        assert!(confers_unrestricted(None, &VtcRole::Admin, &[], now));
        // A scoped admin widened to community-wide.
        let scoped = entry(VtcRole::Admin, &["ctx-a"], None);
        assert!(confers_unrestricted(
            Some(&scoped),
            &VtcRole::Admin,
            &[],
            now
        ));
        // A scopeless member promoted — the `is_empty()` trap: empty means
        // "nowhere" for the member and "everywhere" for the admin it becomes.
        let member = entry(VtcRole::Member, &[], None);
        assert!(confers_unrestricted(
            Some(&member),
            &VtcRole::Admin,
            &[],
            now
        ));
        // An expired unrestricted admin, granted again.
        let lapsed = entry(VtcRole::Admin, &[], Some(now));
        assert!(confers_unrestricted(
            Some(&lapsed),
            &VtcRole::Admin,
            &[],
            now
        ));

        // Already unrestricted and live: a label edit confers nothing.
        let live = entry(VtcRole::Admin, &[], None);
        assert!(!confers_unrestricted(
            Some(&live),
            &VtcRole::Admin,
            &[],
            now
        ));
        // A scoped admin grant is not unrestricted.
        assert!(!confers_unrestricted(
            None,
            &VtcRole::Admin,
            &["ctx-a".into()],
            now
        ));
        // A scopeless non-admin acts nowhere.
        assert!(!confers_unrestricted(None, &VtcRole::Member, &[], now));
    }

    /// Each act is raised as its own kind, and every (kind, task) a gate can
    /// raise has a summary template (VTI-APV-013).
    #[test]
    fn every_act_names_a_kind_with_a_template() {
        use crate::admin_actions::summary::template_for;
        use crate::policy::PolicyPurpose;
        use crate::trust_tasks as tt;
        for (act, uri) in [
            (Act::GrantUnrestricted, tt::ACL_GRANT_TYPE),
            (Act::GrantUnrestricted, tt::ACL_CHANGE_ROLE_TYPE),
            (Act::GrantUnrestricted, tt::ACL_UPDATE_TYPE),
            (Act::GrantUnrestricted, tt::admin_tasks::INVITES_CREATE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_REVOKE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_CHANGE_ROLE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_UPDATE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_GRANT_TYPE),
            (Act::ReduceUnrestricted, tt::MEMBER_ADMIN_REMOVE_TYPE),
            (Act::LowerThreshold, tt::admin_tasks::CONFIG_PATCH_TYPE),
            (Act::LowerThreshold, tt::CONFIG_IMPORT_TYPE),
            (
                Act::ChangeAuthorityPolicy(PolicyPurpose::Removal),
                tt::policy_tasks::POLICY_UPSERT_TYPE,
            ),
            (
                Act::ChangeAuthorityPolicy(PolicyPurpose::Join),
                tt::policy_tasks::POLICY_ACTIVATE_TYPE,
            ),
        ] {
            assert!(
                template_for(act.kind(uri), uri).is_some(),
                "no summary template for ({}, {uri})",
                act.kind(uri)
            );
        }
        assert_eq!(
            Act::GrantUnrestricted.kind(tt::admin_tasks::INVITES_CREATE_TYPE),
            "admin.invite.create"
        );
    }
}
