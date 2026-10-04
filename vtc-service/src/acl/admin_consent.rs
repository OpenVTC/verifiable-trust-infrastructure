//! Second-party consent for authority-conferring grants — **VTI-APV-018**, the
//! generalisation of **VTI-APV-014**.
//!
//! > Creating an entry with unrestricted act scope, or widening an entry to
//! > unrestricted act scope, MUST require consent from a party other than the
//! > requester. (VTI-APV-014)
//!
//! At a VTC, administration is role-based (`vtc-admin-roles.md`), so the trigger
//! is no longer "unrestricted act scope" but **an authority-conferring
//! capability** (§4): one whose holder can create authority — its own or someone
//! else's. Granting or widening one is an N-of-M action in every case. One stolen
//! credential must not be enough to make one. The requester's own passkey
//! gesture proves the requester is present; it says nothing about whether anyone
//! else agrees. This module is the anyone-else.
//!
//! Design: `docs/05-design-notes/vtc-action-list.md` §4 (the action list) over
//! `docs/05-design-notes/vtc-operation-bound-step-up.md` §4, with the approver
//! sets of `vtc-admin-roles.md` §7.
//!
//! ## One model, not a parallel one (VTI-VTC-020)
//!
//! It is the VTA's DTTE ceremony — `task-consent/{request,decision}` — with the
//! approver set fixed by the requirement rather than by a configured rule:
//!
//! - **Trigger** ([`newly_conferred`]): an `acl/grant`, `acl/update` or
//!   `acl/change-role` whose resulting entry holds an authority-conferring
//!   capability, at a covering qualifier, that the entry before it did not.
//! - **Stake**: the capabilities conferred. **Approvers**: every other live
//!   entry that holds *and may approve* each of them at a covering qualifier
//!   ([`approvers_for`]) — `excludeRequester` is always on (VTI-APV-007), and a
//!   qualifier-bound approver approves only inside its qualifier.
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
//! ## Single-administrator mode (VTI-APV-022)
//!
//! On a node configured on the host for it ([`crate::acl::single_admin`]), no
//! operation is parked for consent: once the requester's gesture bound to the
//! operation is spent, it stands in for the consent, and
//! [`ReadyGrant::spend`] audits the waiver at `Critical` — whether or not
//! other administrators' entries exist. The mode states that every
//! administrator is the same person, under as many identifiers as they hold,
//! and the node cannot tell one person's identifiers from two people's
//! (VTI-APV-022). Reductions ([`gate_reduction`]) take the unopposed
//! VTI-APV-019 path — the gesture, a notice to the subject, a `Critical` row —
//! and keep its cooling-off by default, a delay rather than a consent; the
//! requester may land one now, on a typed confirmation and a gesture bound to
//! the immediate variant (`immediate_reduction`, `vtc-action-list.md` §8.5).
//!
//! ## Suspension during a cooling-off
//!
//! The subject of an open cooling-off is suspended (`vtc-action-list.md`
//! §8.2): its entry authorizes nothing ([`VtcAclEntry::can`] answers `false`),
//! approves nothing ([`may_approve`]), and is no role assigner for the
//! attrition guard ([`role_assigners`]).
//!
//! ## The other acts it gates
//!
//! The same machinery also gates the acts that could otherwise undo APV-018
//! one step at a time (`vtc-action-list.md` §7b, §8.1). Each is an [`Act`];
//! what differs between them is only who may consent and what they are shown:
//!
//! - [`Act::ReduceUnrestricted`] — **VTI-APV-019**: removing, demoting or
//!   narrowing *another* subject's authority-conferring capabilities. The
//!   approvers hold what is being taken away, and exclude the subject as well as
//!   the requester, so neither party to the dispute can decide it. Where nobody
//!   is left, [`gate_reduction`] lets the requester's step-up suffice and the
//!   caller records it at `Critical` ([`record_unopposed_reduction`]).
//! - [`Act::LowerThreshold`] — **VTI-APV-020**: lowering
//!   `acl.unrestricted_admin_consent_threshold` needs consent at the threshold as
//!   it stands, which is what [`threshold`] reads, from the holders of
//!   `vtc.roles.assign`.
//! - [`Act::ChangeAuthorityPolicy`] — **VTI-VTC-022**: replacing or activating
//!   the policy that decides authority (role change, removal, join,
//!   cross-community roles, git namespaces), approved by the holders of
//!   `vtc.policy.admin @ policy:<purpose>`.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;
use trust_tasks_rs::specs::task_consent::decision::v0_1 as decision;
use trust_tasks_rs::specs::task_consent::decision::v0_2 as decision_v0_2;
use trust_tasks_rs::specs::task_consent::request::v0_1 as request;
use vti_common::audit::AuditEvent;
use vti_common::error::AppError;
use vti_common::task_consent::{self, effects::StatePin};

use super::{CapRef, Capability, ResourceQualifier, VtcAclEntry, get_acl_entry, list_acl_entries};
use crate::auth::session::now_epoch;
use crate::config_store::{ConfigStore, UNRESTRICTED_ADMIN_CONSENT_THRESHOLD};
use crate::server::AppState;

/// The approver set a request names: the holders of what is conferred. Not
/// configurable: VTI-APV-018 fixes who may consent, so there is no rule to look
/// it up in.
pub const APPROVER_SET: &str = "capability-holders";

/// `task-consent/request/0.1` — what this service signs and pushes to each
/// approver, best-effort, when an action is raised.
pub(crate) const REQUEST_TYPE: &str = <request::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `task-consent/decision/0.1` — what an approver answers with.
pub(crate) const DECISION_TYPE: &str = <decision::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `task-consent/decision/0.2` — 0.1 plus an optional `evidence` factor and
/// an optional `actionId` locator.
pub(crate) const DECISION_V0_2_TYPE: &str =
    <decision_v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The approver set a request to take authority-conferring capabilities away
/// from another subject names (VTI-APV-019): their holders other than the
/// requester **and the subject**.
pub const APPROVER_SET_EXCEPT_SUBJECT: &str = "capability-holders-except-subject";

/// Domain tag for the [`StatePin`] version over a subject's ACL entry.
const STATE_DOMAIN: &[u8] = b"vtc/acl-entry-state/v1\0";

/// Domain tag for the [`StatePin`] version over a piece of community state that
/// is not an ACL entry — the consent threshold, the active policy of a purpose.
const SETTING_STATE_DOMAIN: &[u8] = b"vtc/consent-setting-state/v1\0";

/// Which act a consent is asked for. The machinery is one; what differs is who
/// may consent, what they are shown, and what state the consent is pinned to.
///
/// The variant names predate role-based administration and are kept for the
/// stored action records: "unrestricted" now reads "authority-conferring".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Act {
    /// **VTI-APV-018** (generalising **VTI-APV-014**) — creating or widening an
    /// entry to hold an authority-conferring capability it did not hold. The
    /// subject is the DID that would hold it; the stake is what is conferred.
    GrantUnrestricted,
    /// **VTI-APV-019** — removing, demoting or narrowing another subject's
    /// authority-conferring capabilities. The subject is the DID that holds
    /// them, and never counts as an approver; the stake is what it loses.
    ReduceUnrestricted,
    /// **VTI-APV-020** — lowering the consent threshold. The subject is the
    /// threshold's config key; the consent is pinned to its current value.
    LowerThreshold,
    /// **VTI-VTC-022** — replacing or activating a policy that decides
    /// authority. The subject names the purpose; the consent is pinned to the
    /// revision active for it now.
    ChangeAuthorityPolicy(crate::policy::PolicyPurpose),
    /// **VTI-VTC-023** — an operator's offline write, surfaced to every
    /// remaining administrator to acknowledge. Nothing is consented to: it
    /// already happened. Never gated, never executed.
    OperatorWrite,
    /// **VTI-APV-018** applied to the authority vocabulary
    /// (`vtc-admin-roles.md` §6.2, §7) — defining, replacing or deleting a
    /// custom role. The subject is the role's name; the consent is pinned to
    /// its stored definition (or its absence).
    ChangeRoles,
    /// **VTI-APV-018** — restoring a backup (`vtc.backup.restore`), which
    /// replaces the whole ACL (`vtc-admin-roles.md` §4, §7). The subject is
    /// the bundle being restored.
    RestoreBackup,
    /// **VTI-ACL-071** — a departed granter's grants, raised for review
    /// (`vtc-admin-roles.md` §6.3). Approving re-affirms them under the
    /// approver's own authority; declining, or letting it lapse, withdraws
    /// them. Raised by the community itself, never by a requester's document.
    GrantsReview,
    /// A **queue** item (`vtc-action-list.md` §8.2, *Existing queues*): an
    /// unratified git-ns break-glass, for another administrator of the
    /// namespace to ratify or revoke (`git-ns/right/ratify/0.1`,
    /// `git-ns/right/revoke/0.3`). The subject is the record's subject, who
    /// never decides it. A decision, not a consent: it never expires into
    /// acceptance and is never gated (`crate::admin_actions::queues`).
    BreakGlassReview,
    /// A **queue** item: a join request referred for review
    /// (`admission: review`), decided by a holder of `vtc.join.decide` through
    /// the same `vtc/join-requests/decide` operation the Join requests page
    /// sends. The subject is the applicant.
    JoinReview,
    /// A **queue** item: a withdrawn vetting statement a current membership
    /// rests on (`vtc/vetting/revocations/list`, `needsReview`), for a holder
    /// of `vtc.vetting.manage` to keep the member or start their removal. The
    /// subject is the member.
    VettingReview,
}

impl Act {
    /// The requirement this act's consent implements, for refusals.
    pub(crate) fn requirement(self) -> &'static str {
        match self {
            Self::GrantUnrestricted => "VTI-APV-018",
            Self::ReduceUnrestricted => "VTI-APV-019",
            Self::LowerThreshold => "VTI-APV-020",
            Self::ChangeAuthorityPolicy(_) => "VTI-VTC-022",
            Self::OperatorWrite => "VTI-VTC-023",
            Self::ChangeRoles | Self::RestoreBackup => "VTI-APV-018",
            Self::GrantsReview => "VTI-ACL-071",
            // Queue items are decisions the community already asked for; what
            // they implement is the operation each one decides.
            Self::BreakGlassReview => "git-ns/right/ratify",
            Self::JoinReview => "vtc/join-requests/decide",
            Self::VettingReview => "vtc/vetting/revocations",
        }
    }

    pub(crate) fn approver_set(self) -> &'static str {
        match self {
            Self::ReduceUnrestricted | Self::GrantsReview => APPROVER_SET_EXCEPT_SUBJECT,
            Self::OperatorWrite => "administrators",
            Self::BreakGlassReview => "namespace-administrators-except-subject",
            Self::JoinReview => "join-deciders",
            Self::VettingReview => "vetting-managers-except-subject",
            _ => APPROVER_SET,
        }
    }

    /// Whether the subject is excluded from the approvers, beside the
    /// requester. For a reduction, where the subject is a party to it; and
    /// for a grants review, whose subject is the granter that left.
    pub(crate) fn excludes_subject(self) -> bool {
        matches!(
            self,
            Self::ReduceUnrestricted
                | Self::GrantsReview
                | Self::BreakGlassReview
                | Self::JoinReview
                | Self::VettingReview
        )
    }

    /// Whether this is a **queue** item (`vtc-action-list.md` §8.2): an
    /// existing human decision surfaced in the action list and made by one
    /// holder of the capability it is about. Not a consent, so its deciders
    /// are the capability's *holders* ([`may_decide`]), not its approvers.
    pub(crate) fn is_queue(self) -> bool {
        matches!(
            self,
            Self::BreakGlassReview | Self::JoinReview | Self::VettingReview
        )
    }

    /// The stake an act carries when the caller names none: what its approvers
    /// must hold (`vtc-admin-roles.md` §7). A grant and a reduction always name
    /// theirs — the capabilities conferred or taken away.
    pub(crate) fn default_stake(self) -> Vec<CapRef> {
        match self {
            Self::GrantUnrestricted
            | Self::ReduceUnrestricted
            | Self::LowerThreshold
            | Self::OperatorWrite
            | Self::GrantsReview => vec![CapRef::all(Capability::RolesAssign)],
            Self::ChangeAuthorityPolicy(purpose) => vec![CapRef::new(
                Capability::PolicyAdmin,
                Some(ResourceQualifier::Policy(purpose)),
            )],
            // §6.2: "only through an N-of-M action under vtc.roles.assign +
            // vtc.approvals.admin".
            Self::ChangeRoles => vec![
                CapRef::all(Capability::RolesAssign),
                CapRef::all(Capability::ApprovalsAdmin),
            ],
            Self::RestoreBackup => vec![CapRef::all(Capability::BackupRestore)],
            // A break-glass item is raised with its namespace's `git.ns.admin`
            // as its stake; unqualified is the community-wide holder.
            Self::BreakGlassReview => vec![CapRef::all(Capability::GitNsAdmin)],
            Self::JoinReview => vec![CapRef::all(Capability::JoinDecide)],
            Self::VettingReview => vec![CapRef::all(Capability::VettingManage)],
        }
    }

    /// `stake`, or [`Self::default_stake`] when it names nothing.
    pub(crate) fn stake_or_default(self, stake: &[CapRef]) -> Vec<CapRef> {
        if stake.is_empty() {
            self.default_stake()
        } else {
            stake.to_vec()
        }
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
            Self::OperatorWrite => s::KIND_OPERATOR_WRITE,
            Self::ChangeRoles if type_uri == crate::trust_tasks::role_tasks::DELETE_TYPE => {
                s::KIND_ROLE_DELETE
            }
            Self::ChangeRoles => s::KIND_ROLE_DEFINE,
            Self::RestoreBackup => s::KIND_BACKUP_RESTORE,
            Self::GrantsReview => s::KIND_GRANTS_REVIEW,
            Self::BreakGlassReview => s::KIND_BREAK_GLASS_REVIEW,
            Self::JoinReview => s::KIND_JOIN_REVIEW,
            Self::VettingReview => s::KIND_VETTING_REVIEW,
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

/// The authority-conferring capabilities `next` holds that `prev` did not hold
/// at a covering qualifier — **the VTI-APV-018 trigger**. Empty: no consent is
/// needed.
///
/// An expired `prev` holds nothing, so granting it again is a new conferral.
#[must_use]
pub fn newly_conferred(prev: Option<&VtcAclEntry>, next: &VtcAclEntry, now: u64) -> Vec<CapRef> {
    let held: Vec<CapRef> = prev
        .filter(|p| !p.is_expired(now))
        .map(|p| p.admin.conferring())
        .unwrap_or_default();
    next.admin
        .conferring()
        .into_iter()
        .filter(|c| !held.iter().any(|h| h.covers(c)))
        .collect()
}

/// The authority-conferring capabilities `prev` holds that `next` (`None`: the
/// entry is removed) no longer does — what a reduction takes away
/// (**VTI-APV-019**).
#[must_use]
pub fn lost_conferring(prev: &VtcAclEntry, next: Option<&VtcAclEntry>, now: u64) -> Vec<CapRef> {
    if prev.is_expired(now) {
        return vec![];
    }
    // A shorter life takes every capability away sooner: an expiry put on a
    // permanent entry, or brought forward, reduces all of them.
    let shortened = next.is_some_and(|n| match (prev.expires_at, n.expires_at) {
        (None, Some(_)) => true,
        (Some(was), Some(now)) => now < was,
        _ => false,
    });
    let kept: Vec<CapRef> = next
        .filter(|_| !shortened)
        .map(|n| n.admin.conferring())
        .unwrap_or_default();
    prev.admin
        .conferring()
        .into_iter()
        .filter(|c| !kept.iter().any(|k| k.covers(c)))
        .collect()
}

/// Whether `entry` may approve an action with this stake: live, and able to
/// approve every capability in it at a covering qualifier
/// (`vtc-admin-roles.md` §7).
///
/// Approve authority is **its own axis** (**VTI-ACL-040**): what decides
/// whether a subject may bless a change is its approve scope, not whether it
/// may also make the change. So the least-privilege approver — act `none`, an
/// approve scope (**VTI-ACL-041**; the built-in `approver` role, or any entry
/// granted `approveCapabilities` with act `none`) — counts for every kind of
/// action its approve scope reaches. Approve scope is itself bounded: by the
/// role's approve ceiling, and by the granter's own when it was conferred
/// (**VTI-ACL-042**), so it reaches no further than someone who held it chose.
///
/// A suspended entry approves nothing (`vtc-action-list.md` §8.2).
#[must_use]
pub fn may_approve(entry: &VtcAclEntry, stake: &[CapRef], now: u64) -> bool {
    !entry.is_expired(now) && stake.iter().all(|c| entry.can_approve(c))
}

/// Whether `entry` may decide an action of `act` with this stake. For a
/// consent, [`may_approve`]: approve authority, its own axis (VTI-ACL-040).
/// For a **queue** item, holding the capability it is about at a covering
/// qualifier: a queue item *is* the decision — the join review the Join
/// requests page has always taken to `vtc.join.decide` — so whoever may make
/// that decision decides it here (`vtc-action-list.md` §8.2).
#[must_use]
pub fn may_decide(entry: &VtcAclEntry, act: Act, stake: &[CapRef], now: u64) -> bool {
    if !act.is_queue() {
        return may_approve(entry, stake, now);
    }
    if entry.is_expired(now) {
        return false;
    }
    match act {
        // A criterion-qualified vetting manager manages vetting too; the
        // removal this item can start applies its own rules.
        Act::VettingReview => entry.can_any(Capability::VettingManage),
        _ => stake.iter().all(|c| entry.holds(c)),
    }
}

/// The DIDs of every live holder of `vtc.roles.assign`, unqualified — the
/// community's role assigners. The consent threshold is counted against them,
/// and the last of them is never removed.
///
/// A suspended entry is not one (`vtc-action-list.md` §8.2): while its
/// reduction cools off it can neither grant nor consent, so it never counts
/// toward the attrition guard either.
pub async fn role_assigners(state: &AppState, now: u64) -> Result<Vec<String>, AppError> {
    Ok(list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| is_live_role_assigner(e, now) && !e.is_suspended())
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
/// Counted against the role assigners, who are the approvers of the widest
/// grant: a requester is one of them and never counts, so at most
/// `assigners - 1` can approve. The minimum, 1, is always accepted: refusing it
/// would not make the community able to meet it, and there is no lower value to
/// choose instead.
pub async fn check_threshold_meetable(state: &AppState, threshold: u64) -> Result<(), AppError> {
    if threshold <= 1 {
        return Ok(());
    }
    let admins = role_assigners(state, now_epoch()).await?.len() as u64;
    if threshold > admins.saturating_sub(1) {
        return Err(AppError::Validation(format!(
            "{UNRESTRICTED_ADMIN_CONSENT_THRESHOLD} = {threshold} could never be met: a grant of \
             an authority-conferring capability would need {threshold} holders of \
             vtc.roles.assign besides the one asking, and this community has {admins} in total. \
             Grant more community administrators first, or set it to at most {}",
            admins.saturating_sub(1).max(1)
        )));
    }
    Ok(())
}

/// Whether `entry` is a live holder of `vtc.roles.assign`, unqualified.
#[must_use]
pub fn is_live_role_assigner(entry: &VtcAclEntry, now: u64) -> bool {
    !entry.is_expired(now) && entry.admin.can(Capability::RolesAssign, None)
}

/// Refuse a change that takes `subject` — a live holder of `vtc.roles.assign`
/// — out of the role assigners, when what is left could never consent to
/// anything: nobody else holding it at all, or fewer than the threshold needs.
///
/// The attrition half of VTI-APV-009: a rule must not become unsatisfiable by
/// removal any more than by being written that way, and the community must never
/// lose its last holder of `vtc.roles.assign` (`vtc-admin-roles.md` C1 §3).
/// Callers are every door that can end one — a revocation, a removal from the
/// community, a demotion, a narrowing update — and each must hold the admin-set
/// lock ([`crate::ceremony::lock_admin_set`]) from this check through its
/// write, or two such changes could each pass it and together strand the
/// community.
///
/// A threshold of 1 needs only one other assigner, the same bound the
/// write-time check accepts, so a two-admin community can still remove a
/// compromised one. Above 1 the threshold has to come down first.
pub async fn check_attrition(state: &AppState, subject: &str) -> Result<(), AppError> {
    let remaining = role_assigners(state, now_epoch())
        .await?
        .into_iter()
        .filter(|d| d != subject)
        .count() as u64;
    if remaining == 0 {
        return Err(AppError::Conflict(format!(
            "refusing to end the last administrator holding vtc.roles.assign ({subject}): nobody would be \
             left who could grant or consent to authority (VTI-APV-009). Make another community \
             administrator first"
        )));
    }
    let threshold = threshold(state).await?;
    if threshold > 1 && threshold > remaining.saturating_sub(1) {
        return Err(AppError::Conflict(format!(
            "refusing to end {subject}'s vtc.roles.assign: {remaining} holder(s) would remain, so \
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
///
/// Or, in single-administrator mode, the requester's own operation-bound
/// gesture standing in for that consent (**VTI-APV-022**).
#[derive(Debug)]
#[must_use = "a ReadyGrant authorizes nothing until it is spent with the write"]
pub struct ReadyGrant {
    ready: Ready,
}

#[derive(Debug)]
enum Ready {
    /// An approved action executing (VTI-APV-017).
    Approved { action_id: String },
    /// Consent waived by single-administrator mode (VTI-APV-022).
    Waived(Box<crate::admin_actions::Waiver>),
    /// A reduction landing now, without its cooling-off, in
    /// single-administrator mode (`vtc-action-list.md` §8.5).
    Immediate(Box<crate::admin_actions::Immediate>),
}

impl ReadyGrant {
    pub(crate) fn approved(action_id: String) -> Self {
        Self {
            ready: Ready::Approved { action_id },
        }
    }

    /// Whether this is single-administrator mode's waiver rather than other
    /// administrators' consent.
    pub fn is_waived(&self) -> bool {
        matches!(self.ready, Ready::Waived(_))
    }

    /// Spend the consent. Call it with the write, after every other check.
    ///
    /// The action itself is closed — and each approver's challenge consumed, as
    /// `task-consent/decision` requires — by the executor once the write has
    /// landed, under the same status transition that made this execution the
    /// only one ([`crate::admin_actions`]). This records that the gate was
    /// reached on the way.
    ///
    /// A waiver (VTI-APV-022 item 4) is audited here at `Critical`, and the
    /// operation is entered in the action list's history once its write lands
    /// ([`crate::admin_actions::record_effect`]).
    pub async fn spend(self, state: &AppState) -> Result<(), AppError> {
        match self.ready {
            Ready::Approved { action_id } => {
                crate::admin_actions::note_gate_spent(&action_id);
                Ok(())
            }
            Ready::Waived(waiver) => crate::admin_actions::spend_waiver(state, *waiver).await,
            Ready::Immediate(imm) => crate::admin_actions::spend_immediate(state, *imm).await,
        }
    }
}

/// Whether this node runs in **single-administrator mode** (VTI-APV-022).
///
/// Host configuration, read once at start: `[acl] single_admin_mode` is not in
/// the runtime config registry, so nothing on the operation surface — a
/// `config/patch`, an import, a reload — changes the value held here.
pub async fn single_admin_mode(state: &AppState) -> bool {
    state.config.read().await.acl.single_admin_mode
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

/// The signed door's gate for a grant of authority-conferring capabilities:
/// the requester's operation-bound gesture, then the action their other
/// holders approve. `stake` is what is conferred ([`newly_conferred`]).
///
/// Parked comes back as [`AppError::ApprovalRequired`] carrying
/// [`crate::admin_actions::ACTION_PARKED`], which the dispatcher answers with a
/// `trust-task-next-step/0.1`.
pub async fn gesture_then_consent(
    state: &AppState,
    requester: &str,
    subject: &str,
    stake: &[CapRef],
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<SignedGate, AppError> {
    gesture_then_consent_for(
        state,
        Act::GrantUnrestricted,
        stake,
        requester,
        subject,
        op,
        gesture_reason,
        consent_summary,
    )
    .await
}

/// [`gesture_then_consent`] for any [`Act`]. An empty `stake` takes the act's
/// [`Act::default_stake`].
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
#[allow(clippy::too_many_arguments)]
pub async fn gesture_then_consent_for(
    state: &AppState,
    act: Act,
    stake: &[CapRef],
    requester: &str,
    subject: &str,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<SignedGate, AppError> {
    use super::bound_step_up::{self, EvidencedGate};

    let stake = act.stake_or_default(stake);

    if let Some(exec) = crate::admin_actions::executing() {
        let action_id =
            crate::admin_actions::recheck(state, &exec, act, requester, subject, op).await?;
        return Ok(SignedGate::Ready(ReadyGrant::approved(action_id)));
    }

    // The same operation already waiting: point at it, and ask nothing again.
    if let Some(open) = crate::admin_actions::open_for(state, requester, op).await? {
        return Err(crate::admin_actions::parked_error(state, &open).await);
    }

    let now = now_epoch();
    // A consent nobody can give makes the gesture pointless, so say so before
    // asking the requester for one.
    let approvers = approvers_for(state, act, &stake, requester, subject, now).await?;
    let threshold = threshold(state).await?;
    // VTI-APV-022: single-administrator mode waives the consent whether or not
    // other administrators' entries exist — the mode states they are all the
    // same person, under as many identifiers as they hold, and the node cannot
    // tell one person's identifiers from two people's. The requester's gesture
    // bound to this operation still stands in for it, and the waiver is
    // audited at `Critical`.
    let waive = single_admin_mode(state).await;
    if !waive {
        refuse_if_unmeetable(
            act,
            &stake,
            approvers.len() as u64,
            threshold,
            consent_summary,
        )?;
        // §7a.1: the action-list limits, before the gesture too.
        crate::admin_actions::check_limits(state, act, requester, subject).await?;
    }

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

    if waive {
        // The requester's gesture, bound to this operation and now spent,
        // stands in for the consent nobody else could give (VTI-APV-022).
        // Spending the grant audits it at `Critical`.
        return Ok(SignedGate::Ready(ReadyGrant {
            ready: Ready::Waived(Box::new(crate::admin_actions::Waiver::new(
                act,
                stake,
                requester,
                subject,
                op,
                consent_summary,
                evidence,
            )?)),
        }));
    }

    let pin = pin_for(state, act, subject).await?;
    let action = crate::admin_actions::park(
        state,
        crate::admin_actions::Parking {
            act,
            stake,
            requester,
            subject,
            op,
            summary: consent_summary,
            evidence,
            approvers,
            threshold,
            pin,
            cooling_off: None,
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
    /// The subject loses no authority-conferring capability (or is the
    /// requester): the gesture is the whole gate.
    StepUpOnly,
    /// Another holder of what the subject loses, neither the requester nor the
    /// subject, consented. Spend it with the write.
    Consented(ReadyGrant),
    /// The subject loses authority-conferring capabilities and nobody else is
    /// left who could consent. The gesture sufficed — after the cooling-off,
    /// when one is configured (`acl.removal_cooling_off`, §8.2), in which case
    /// this is the parked action landing and carries its grant. Once the write
    /// lands the caller records it at `Critical` and notifies the subject
    /// ([`after_reduction`]).
    Unopposed(Option<ReadyGrant>),
}

/// Whether anyone other than the requester and the subject agreed to a
/// reduction — the `agreement` an authority-reduced notice carries
/// (VTI-APV-019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// Another holder of what the subject lost consented.
    Consented,
    /// The subject lost nothing authority-conferring: the requester's gesture
    /// is the whole gate, and no third party reviewed it.
    StepUpOnly,
    /// The subject lost authority-conferring capabilities and nobody else
    /// could consent: audited at `Critical`.
    Unopposed,
}

impl Agreement {
    /// The notice's `agreement`: `consented` only when a third party agreed.
    /// A step-up-only reduction is reported `unopposed` — nobody but the
    /// decider reviewed it, which is the distinction the subject is owed.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Consented => "consented",
            Self::StepUpOnly | Self::Unopposed => "unopposed",
        }
    }
}

impl Reduction {
    /// Spend the consent, if this reduction carries one. Call it with the
    /// write, after every other check. What it comes to for the notice and
    /// the audit ([`after_reduction`]).
    pub async fn spend(self, state: &AppState) -> Result<Agreement, AppError> {
        match self {
            Self::StepUpOnly => Ok(Agreement::StepUpOnly),
            Self::Consented(ready) => ready.spend(state).await.map(|()| Agreement::Consented),
            Self::Unopposed(ready) => {
                if let Some(ready) = ready {
                    ready.spend(state).await?;
                }
                Ok(Agreement::Unopposed)
            }
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
/// subject is **another** live entry that loses an authority-conferring
/// capability (`after`: the entry as it will be, `None` for a removal), it is
/// also parked for the consent of a holder of what is lost who is neither the
/// requester nor the subject (**VTI-APV-019**), through the same machinery as
/// APV-018 ([`Act::ReduceUnrestricted`]).
///
/// Where no such holder exists — two community administrators in all — the VTC
/// cannot tell a removal of a compromised co-admin from a compromised admin's
/// removal of the other, and must not make the first impossible. So the gesture
/// alone suffices, but not at once: the reduction is parked for a
/// **cooling-off** (`acl.removal_cooling_off`, default 24 h, §8.2) that both
/// can see, and lands by itself when it ends unless the requester cancels it.
/// The subject is suspended meanwhile, so it can neither block it nor answer
/// with a counter-request; only one cooling-off runs on a subject at a time,
/// and raising one checks the attrition guard as though the subject were
/// already gone. A cooling-off of zero lands it at once
/// ([`Reduction::Unopposed`]), and so does `ext["org.openvtc"].immediate` in
/// single-administrator mode (`immediate_reduction`, §8.5).
///
/// The attrition guard ([`check_attrition`]) is asked first as well when the
/// subject loses `vtc.roles.assign`, so a reduction that would strand the
/// community is refused before anybody is asked for a gesture. It is not a
/// substitute for the caller's own check under the admin-set lock, which still
/// runs.
///
/// Call it after every check that decides whether the act may happen, and
/// before anything is written.
pub async fn gate_reduction(
    state: &AppState,
    requester: &str,
    subject: &VtcAclEntry,
    after: Option<&VtcAclEntry>,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<ReductionGate, AppError> {
    use super::bound_step_up::{self, EvidencedGate, Gate};

    let now = now_epoch();
    let lost = if subject.did == requester {
        vec![]
    } else {
        lost_conferring(subject, after, now)
    };
    let executing = crate::admin_actions::executing();
    // "Remove now" (`vtc-action-list.md` §8.5): asked for in the payload, so
    // the requester's gesture is bound to the immediate variant and never to
    // the delayed one (VTI-APV-015). Only single-administrator mode offers it.
    let immediate = crate::admin_actions::immediate_request(op.payload)?;
    if immediate.is_some() && executing.is_none() && !single_admin_mode(state).await {
        return Err(AppError::Forbidden(format!(
            "removing or reducing an administrator now, without its cooling-off \
             (ext.org.openvtc.immediate), is offered only in single-administrator mode \
             (VTI-APV-022), which is set on the host ([acl] single_admin_mode in config.toml) and \
             cannot be changed through this service. Without it the reduction of {} waits out \
             its cooling-off ({}), during which they are suspended — send it again without \
             `immediate`",
            subject.did,
            crate::config_store::REMOVAL_COOLING_OFF
        )));
    }
    if !lost.is_empty() {
        if is_live_role_assigner(subject, now)
            && !after.is_some_and(|a| is_live_role_assigner(a, now))
        {
            check_attrition(state, &subject.did).await?;
        }
        // A cooling-off landing: the reduction it parked, unopposed, now.
        if let Some(exec) = executing.as_ref().filter(|e| e.cooling_off) {
            let action_id =
                crate::admin_actions::recheck_cooling_off(state, exec, requester, &subject.did, op)
                    .await?;
            return Ok(ReductionGate::Cleared(Reduction::Unopposed(Some(
                ReadyGrant::approved(action_id),
            ))));
        }
        // VTI-APV-019 asks a third party's consent "wherever such a party
        // exists"; single-administrator mode does not require it (VTI-APV-022):
        // another of the requester's own entries is no third party. The
        // reduction then takes the unopposed path — the requester's gesture,
        // the subject told, a `Critical` row and the cooling-off, which is a
        // delay, not a consent, and stays.
        let third = if single_admin_mode(state).await {
            0
        } else {
            approvers_for(
                state,
                Act::ReduceUnrestricted,
                &lost,
                requester,
                &subject.did,
                now,
            )
            .await?
            .len()
        };
        // First to act wins (§8.2): with nobody else to decide, a
        // counter-request lands the earlier one.
        if executing.is_none() && third == 0 {
            crate::admin_actions::refuse_if_reduced_first(state, requester, &subject.did).await?;
        }
        // Remove now, in single-administrator mode (checked above): no
        // cooling-off, on a typed confirmation and the requester's gesture
        // bound to this immediate operation (`vtc-action-list.md` §8.5).
        if let Some(imm) = immediate.as_ref()
            && executing.is_none()
        {
            return immediate_reduction(
                state,
                requester,
                subject,
                op,
                imm,
                lost,
                gesture_reason,
                consent_summary,
            )
            .await;
        }
        // An approved action executing this reduction goes through its consent
        // whatever the count is now: approvals that no longer suffice fail it
        // closed, rather than letting the unopposed path run it on the gesture
        // the requester made when there *were* approvers (VTI-APV-017).
        if third > 0 || executing.is_some() {
            return Ok(
                match gesture_then_consent_for(
                    state,
                    Act::ReduceUnrestricted,
                    &lost,
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
        let window = crate::config_store::live_action_setting(
            crate::config_store::REMOVAL_COOLING_OFF,
            &state.config.read().await.clone(),
            &ConfigStore::new(state.config_ks.clone()),
        )
        .await?;
        if window > 0 {
            // The same operation already cooling off: point at it.
            if let Some(open) = crate::admin_actions::open_for(state, requester, op).await? {
                return Err(crate::admin_actions::parked_error(state, &open).await);
            }
            // One reduction cools off on a subject at a time: it is what
            // suspends them, and a second would only race the first.
            if let Some(other) =
                crate::admin_actions::open_cooling_off_on(state, &subject.did).await?
            {
                return Err(AppError::Conflict(format!(
                    "a reduction of {} is already cooling off ({}, requested by {}, lands {}), and \
                     they are suspended until it lands or is cancelled. Cancel that one first \
                     (vtc/admin/actions/cancel) to ask for something different",
                    subject.did,
                    other.id,
                    other.requester,
                    crate::admin_actions::rfc3339(other.cooling_off_until.unwrap_or_default()),
                )));
            }
            // The subject is suspended from the moment this is raised, so it
            // stops counting toward the attrition guard now, whatever the
            // reduction leaves it when it lands (`vtc-action-list.md` §8.2).
            if is_live_role_assigner(subject, now)
                && after.is_some_and(|a| is_live_role_assigner(a, now))
            {
                check_attrition(state, &subject.did).await?;
            }
            crate::admin_actions::check_limits(
                state,
                Act::ReduceUnrestricted,
                requester,
                &subject.did,
            )
            .await?;
            let evidence = match bound_step_up::redeem_or_request_with_evidence(
                state,
                requester,
                op.type_uri,
                op.payload,
                gesture_reason,
            )
            .await?
            {
                EvidencedGate::Required(request) => {
                    return Ok(ReductionGate::StepUpRequired(request));
                }
                EvidencedGate::Satisfied(evidence) => evidence,
            };
            warn!(
                requester,
                subject = %subject.did,
                task = op.type_uri,
                window,
                "ending an unrestricted admin's authority with nobody else left to consent \
                 (VTI-APV-019): parked for its cooling-off, the subject suspended until it lands"
            );
            let pin = pin_for(state, Act::ReduceUnrestricted, &subject.did).await?;
            let action = crate::admin_actions::park(
                state,
                crate::admin_actions::Parking {
                    act: Act::ReduceUnrestricted,
                    stake: lost.clone(),
                    requester,
                    subject: &subject.did,
                    op,
                    summary: consent_summary,
                    evidence,
                    approvers: Vec::new(),
                    threshold: 0,
                    pin,
                    cooling_off: Some(window),
                },
            )
            .await?;
            return Err(crate::admin_actions::parked_error(state, &action).await);
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
            Gate::Satisfied if !lost.is_empty() => {
                warn!(
                    requester,
                    subject = %subject.did,
                    task = op.type_uri,
                    "taking authority-conferring capabilities away with nobody else left to \
                     consent (VTI-APV-019), with no cooling-off configured: the requester's \
                     step-up is the only gate"
                );
                ReductionGate::Cleared(Reduction::Unopposed(None))
            }
            Gate::Satisfied => ReductionGate::Cleared(Reduction::StepUpOnly),
            Gate::Required(r) => ReductionGate::StepUpRequired(r),
        },
    )
}

/// "Remove now" (`vtc-action-list.md` §8.5): a reduction of another
/// administrator that lands at once instead of waiting out its cooling-off —
/// or that lands an open cooling-off of the same operation now. Offered only in
/// single-administrator mode (the caller has checked it), where the cooling-off
/// is a delay one person imposes on themselves (VTI-APV-022).
///
/// It asks two deliberate things, in this order, before anything is written:
///
/// 1. a typed confirmation in the payload — the subject's DID, or the id of the
///    cooling-off being landed — refused without a gesture when it does not
///    match, so a slip costs nothing;
/// 2. the requester's gesture bound to **this** operation (VTI-APV-015), whose
///    payload carries `ext.org.openvtc.immediate`: a gesture made for the
///    delayed removal is bound to a different digest and is never spent here,
///    and this one is never spent on the delayed removal.
///
/// The attrition guard has already run ([`gate_reduction`]). Spending the grant
/// writes a `Critical` `SingleAdminMode { event: reductionImmediate }` row before
/// the write; the caller then records the unopposed reduction at `Critical` and
/// notifies the subject (VTI-APV-019, [`after_reduction`]).
#[allow(clippy::too_many_arguments)]
async fn immediate_reduction(
    state: &AppState,
    requester: &str,
    subject: &VtcAclEntry,
    op: Operation<'_>,
    imm: &crate::admin_actions::ImmediateRequest,
    lost: Vec<CapRef>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<ReductionGate, AppError> {
    use super::bound_step_up::{self, EvidencedGate};

    let confirmed =
        imm.confirm == subject.did || imm.action_id.as_deref().is_some_and(|id| imm.confirm == id);
    if !confirmed {
        return Err(AppError::Validation(format!(
            "the confirmation does not match. To make this change now, without its cooling-off \
             ({consent_summary}), type the subject's DID ({}){} as \
             ext.org.openvtc.immediate.confirm",
            subject.did,
            imm.action_id
                .as_deref()
                .map(|id| format!(" or the action's id ({id})"))
                .unwrap_or_default(),
        )));
    }
    let target = crate::admin_actions::cooling_off_to_land(
        state,
        &subject.did,
        op,
        imm.action_id.as_deref(),
    )
    .await?;
    let evidence = match bound_step_up::redeem_or_request_with_evidence(
        state,
        requester,
        op.type_uri,
        op.payload,
        &format!("{gesture_reason} — now, without the cooling-off"),
    )
    .await?
    {
        EvidencedGate::Required(request) => return Ok(ReductionGate::StepUpRequired(request)),
        EvidencedGate::Satisfied(evidence) => evidence,
    };
    warn!(
        requester,
        subject = %subject.did,
        task = op.type_uri,
        landing = target.as_deref().unwrap_or("-"),
        "reducing an administrator now, without the cooling-off — single-administrator mode \
         (VTI-APV-022, VTI-APV-019)"
    );
    Ok(ReductionGate::Cleared(Reduction::Unopposed(Some(
        ReadyGrant {
            ready: Ready::Immediate(Box::new(crate::admin_actions::Immediate::new(
                lost,
                requester,
                &subject.did,
                op,
                consent_summary,
                evidence,
                target,
            )?)),
        },
    ))))
}

/// [`gate_reduction`] for a door about to end or reduce `prior` (to `after`,
/// `None` for a removal), settled to one answer: `Ok(None)` when nothing gated
/// it (not a live administrator's entry), `Ok(Some(agreement))` to go ahead and
/// then [`after_reduction`], or the refusal — [`TaskError::StepUp`] with the
/// ceremony inline when no gesture is recorded yet, or the parked action (an
/// approval, or a cooling-off).
///
/// Only an **administrator**'s live entry is gated (`vtc-action-list.md` §7b
/// item 1); ending an expired entry, or one with no administrative role, is
/// unchanged, and answers `Ok(None)` without asking anything. Call it last
/// before the write.
///
/// [`TaskError::StepUp`]: crate::error::TaskError::StepUp
pub async fn settle_reduction(
    state: &AppState,
    requester: &str,
    prior: &VtcAclEntry,
    after: Option<&VtcAclEntry>,
    op: Operation<'_>,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<Option<Agreement>, crate::error::TaskError> {
    if !prior.is_administrator() {
        return Ok(None);
    }
    match gate_reduction(
        state,
        requester,
        prior,
        after,
        op,
        gesture_reason,
        consent_summary,
    )
    .await?
    {
        ReductionGate::Cleared(reduction) => Ok(Some(reduction.spend(state).await?)),
        ReductionGate::StepUpRequired(request) => Err(crate::error::TaskError::step_up(request)),
    }
}

/// Once a gated reduction's write has landed: an unopposed one is recorded at
/// `Critical` ([`record_unopposed_reduction`], VTI-APV-019), and — unless the
/// subject was removed from the community, which the removal notice tells them
/// (`notify: false`) — the subject is sent `vtc/members/authority-reduced-notice`
/// saying what happened, on whose authority and whether anyone else agreed.
///
/// `after` is the subject's entry now (`None`: revoked). Called after the
/// write, never before: a refusal later in the write must not leave a row or a
/// notice claiming it happened. The notice is best-effort and durable; nothing
/// here undoes the write.
#[allow(clippy::too_many_arguments)]
pub async fn after_reduction(
    state: &AppState,
    decided_by: &str,
    prior: &VtcAclEntry,
    after: Option<&VtcAclEntry>,
    agreement: Agreement,
    task: &str,
    reason: Option<&str>,
    notify: bool,
) -> Result<(), AppError> {
    if agreement == Agreement::Unopposed {
        record_unopposed_reduction(state, decided_by, prior, task).await?;
    }
    if notify {
        crate::ceremony::authority_reduced_notice::send(
            state,
            prior,
            after,
            agreement,
            decided_by,
            chrono::Utc::now(),
            reason,
        )
        .await;
    }
    Ok(())
}

/// Record an unopposed reduction once its write has landed: a `Critical`
/// audit row (**VTI-APV-019**).
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
                    prior_role: prior
                        .admin
                        .admin_role
                        .as_ref()
                        .map(|r| r.to_string())
                        .unwrap_or_else(|| prior.role.to_string()),
                    // A VTC entry has no context scopes; what it held is its
                    // capabilities, recorded in the same slot.
                    prior_scopes: prior
                        .admin
                        .effective()
                        .iter()
                        .map(CapRef::display)
                        .collect(),
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
    stake: &[CapRef],
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
        return Ok(ReadyGrant::approved(action_id));
    }
    let stake = Act::GrantUnrestricted.stake_or_default(stake);
    // A consent nobody could give is the more useful thing to say first.
    let approvers = approvers_for(
        state,
        Act::GrantUnrestricted,
        &stake,
        requester,
        subject,
        now_epoch(),
    )
    .await?
    .len() as u64;
    // Single-administrator mode waives the consent only on a passkey gesture
    // bound to the operation (VTI-APV-022, VTI-APV-015) — which only a signed
    // document carries.
    if single_admin_mode(state).await {
        return Err(AppError::Forbidden(format!(
            "{summary} needs, in single-administrator mode, your passkey gesture bound to the \
             operation (VTI-APV-022), which only a signed {} document can carry",
            op.type_uri
        )));
    }
    refuse_if_unmeetable(
        Act::GrantUnrestricted,
        &stake,
        approvers,
        threshold(state).await?,
        summary,
    )?;
    Err(AppError::Forbidden(format!(
        "{summary} needs the approval of another holder of {} (VTI-APV-018), which only a \
         signed {} document can wait for",
        stake_list(&stake),
        op.type_uri
    )))
}

fn stake_list(stake: &[CapRef]) -> String {
    stake
        .iter()
        .map(CapRef::display)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Refuse, naming the fix, when there are fewer possible approvers than the
/// threshold needs. The operator's way out is the offline break-glass, which is
/// not reachable by a stolen session or key.
pub(crate) fn refuse_if_unmeetable(
    act: Act,
    stake: &[CapRef],
    approvers: u64,
    threshold: u64,
    summary: &str,
) -> Result<(), AppError> {
    if approvers < threshold {
        let others = if act.excludes_subject() {
            "holder(s) other than you and the subject"
        } else {
            "other holder(s)"
        };
        return Err(AppError::Forbidden(format!(
            "{summary} needs consent from {threshold} {others} of {}, and this community has \
             {approvers} ({}). Add another community administrator with the offline \
             break-glass while the daemon is stopped — `vtc acl add --did <did> --admin-role \
             community-admin` — and send this again",
            stake_list(stake),
            act.requirement()
        )));
    }
    Ok(())
}

/// Who may consent to `act` on `subject` now: every live entry that holds and
/// may approve all of `stake` ([`may_approve`]), but the requester
/// (VTI-APV-007) — and, for a reduction, but the subject (VTI-APV-019).
pub(crate) async fn approvers_for(
    state: &AppState,
    act: Act,
    stake: &[CapRef],
    requester: &str,
    subject: &str,
    now: u64,
) -> Result<Vec<String>, AppError> {
    let stake = act.stake_or_default(stake);
    Ok(list_acl_entries(&state.acl_ks)
        .await?
        .into_iter()
        .filter(|e| may_decide(e, act, &stake, now))
        .map(|e| e.did)
        .filter(|d| d != requester && !(act.excludes_subject() && d == subject))
        .collect())
}

/// Whether the requester of a parked `act` still holds the authority it needs:
/// live, and — for a grant — still holding what it would confer, since a
/// granter may grant only what it holds (VTI-ACL-071). The handler re-checks
/// everything when the action executes; this closes an action that can no
/// longer succeed (`vtc-action-list.md` §4.4).
pub(crate) fn requester_still_authorized(
    entry: &VtcAclEntry,
    act: Act,
    stake: &[CapRef],
    now: u64,
) -> bool {
    // A suspended requester authorizes nothing while its own reduction cools
    // off (`vtc-action-list.md` §8.2), so what it asked for can no longer run
    // as it.
    if entry.is_expired(now) || !entry.admin.is_administrator() || entry.is_suspended() {
        return false;
    }
    match act {
        Act::GrantUnrestricted => {
            entry.admin.can_any(Capability::RolesAssign)
                && act
                    .stake_or_default(stake)
                    .iter()
                    .all(|c| entry.admin.holds(c))
        }
        Act::ReduceUnrestricted => entry.admin.can_any(Capability::RolesAssign),
        Act::LowerThreshold => entry.admin.can(Capability::ConfigAdmin, None),
        Act::ChangeAuthorityPolicy(p) => entry
            .admin
            .can(Capability::PolicyAdmin, Some(&ResourceQualifier::Policy(p))),
        // An operator write has no requester authority to lose: it is an item
        // to acknowledge (VTI-VTC-023).
        Act::OperatorWrite => true,
        Act::ChangeRoles => {
            entry.admin.can(Capability::RolesAssign, None)
                && entry.admin.can(Capability::ApprovalsAdmin, None)
        }
        Act::RestoreBackup => entry.admin.can(Capability::BackupRestore, None),
        // Raised by the community itself: there is no requester to lose
        // anything (`requester_still_authorized` is never asked of it — see
        // `crate::admin_actions::settle`).
        Act::GrantsReview => true,
        // Queue items are raised by the community about a record; their
        // requester is the party the record is about, and is never asked this.
        Act::BreakGlassReview | Act::JoinReview | Act::VettingReview => true,
    }
}

/// The state a consent to `act` is pinned to: what the approvers saw, so a
/// change to it between the ask and the write invalidates the action.
pub(crate) async fn pin_for(
    state: &AppState,
    act: Act,
    subject: &str,
) -> Result<StatePin, AppError> {
    let value = match act {
        Act::GrantUnrestricted | Act::ReduceUnrestricted | Act::OperatorWrite => {
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
        // The consent is to changing *this* definition: once it moves, what
        // the approvers agreed to is not what would happen.
        Act::ChangeRoles => json!(super::roles::get(&state.acl_ks, subject).await?),
        // Nothing to pin beside the bundle itself, whose bytes are fixed by
        // its committed digest: the restore replaces the ACL wholesale, and a
        // changed ACL in the meantime is exactly what it overwrites.
        Act::RestoreBackup => json!(subject),
        // A review re-affirms what is still under review at execution, and
        // nothing else; a change to one entry must not void the rest.
        Act::GrantsReview => json!(subject),
        // A queue item is settled against its record, never a pin
        // (`crate::admin_actions::queues::resolution`).
        Act::BreakGlassReview | Act::JoinReview | Act::VettingReview => json!(subject),
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
    use crate::acl::{AdminAuthority, AdminRole, CapabilityScope, VtcRole};

    fn entry(admin: AdminAuthority, expires_at: Option<u64>) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zSubject".into(),
            role: VtcRole::Member,
            label: None,
            admin,
            delegated_by: None,
            created_at: 0,
            created_by: "did:key:zAdmin".into(),
            updated_at: None,
            updated_by: None,
            expires_at,
            resource_grants: Vec::new(),
            label_set_by_subject: false,
            suspension: None,
        }
    }

    fn listed(caps: &[&str]) -> CapabilityScope {
        CapabilityScope::listed(
            caps.iter()
                .map(|c| c.parse::<CapRef>().unwrap().into())
                .collect(),
        )
        .unwrap()
    }

    /// VTI-APV-018: the trigger is an authority-conferring capability the entry
    /// did not hold before — and only that.
    #[test]
    fn vti_apv_018_newly_conferred_is_the_new_authority_conferring_capabilities() {
        let now = 1_000;
        let admin = entry(AdminAuthority::community_admin(), None);
        // A new community administrator confers every authority-conferring cap.
        let fresh = newly_conferred(None, &admin, now);
        assert!(fresh.contains(&CapRef::all(Capability::RolesAssign)));
        assert!(fresh.contains(&CapRef::all(Capability::ConfigAdmin)));
        assert!(!fresh.contains(&CapRef::all(Capability::AuditRead)));

        // Already held and live: a label edit confers nothing.
        assert!(newly_conferred(Some(&admin), &admin, now).is_empty());

        // An expired holder, granted again, is a new conferral.
        let lapsed = entry(AdminAuthority::community_admin(), Some(now));
        assert!(!newly_conferred(Some(&lapsed), &admin, now).is_empty());

        // A moderator holds nothing authority-conferring.
        let moderator = entry(AdminAuthority::for_role(AdminRole::Moderator), None);
        assert!(newly_conferred(None, &moderator, now).is_empty());

        // A narrowed community-admin widened to include vtc.roles.assign.
        let mut narrow = AdminAuthority::community_admin();
        narrow.capabilities = listed(&["vtc.audit.read"]);
        let narrow = entry(narrow, None);
        let mut wider = AdminAuthority::community_admin();
        wider.capabilities = listed(&["vtc.audit.read", "vtc.roles.assign"]);
        let wider = entry(wider, None);
        assert_eq!(
            newly_conferred(Some(&narrow), &wider, now),
            vec![CapRef::all(Capability::RolesAssign)]
        );

        // A qualified repo manager confers git.ns.admin within its namespace.
        let mut rm = AdminAuthority::for_role(AdminRole::RepoManager);
        rm.capabilities = listed(&["git.ns.admin@git-ns:github.com/acme"]);
        assert_eq!(
            newly_conferred(None, &entry(rm, None), now),
            vec!["git.ns.admin@git-ns:github.com/acme".parse().unwrap()]
        );
    }

    /// VTI-APV-019: what a reduction takes away.
    #[test]
    fn vti_apv_019_lost_conferring_is_what_the_reduction_takes_away() {
        let now = 1_000;
        let admin = entry(AdminAuthority::community_admin(), None);
        assert!(lost_conferring(&admin, None, now).contains(&CapRef::all(Capability::RolesAssign)));
        let mut narrow = AdminAuthority::community_admin();
        narrow.capabilities = listed(&["vtc.audit.read"]);
        assert!(!lost_conferring(&admin, Some(&entry(narrow, None)), now).is_empty());
        assert!(lost_conferring(&admin, Some(&admin), now).is_empty());
        let moderator = entry(AdminAuthority::for_role(AdminRole::Moderator), None);
        assert!(lost_conferring(&moderator, None, now).is_empty());
    }

    /// Approvers hold and may approve what is at stake, at a covering
    /// qualifier (`vtc-admin-roles.md` §7).
    #[test]
    fn may_approve_needs_the_capability_and_approve_authority() {
        let now = 1_000;
        let stake = vec![CapRef::all(Capability::RolesAssign)];
        assert!(may_approve(
            &entry(AdminAuthority::community_admin(), None),
            &stake,
            now
        ));
        assert!(!may_approve(
            &entry(AdminAuthority::for_role(AdminRole::Moderator), None),
            &stake,
            now
        ));
        // Holds it, but approves nothing (VTI-ACL-040).
        let mut no_approve = AdminAuthority::community_admin();
        no_approve.approve = crate::acl::VtcActScope::None;
        assert!(!may_approve(&entry(no_approve, None), &stake, now));

        // A qualifier-bound approver approves only inside its qualifier.
        let mut rm = AdminAuthority::for_role(AdminRole::RepoManager);
        rm.capabilities = listed(&["git.ns.admin@git-ns:github.com/acme"]);
        rm.approve_capabilities = listed(&["git.ns.admin@git-ns:github.com/acme"]);
        let rm = entry(rm, None);
        let inside: Vec<CapRef> = vec!["git.ns.admin@git-ns:github.com/acme".parse().unwrap()];
        let outside: Vec<CapRef> = vec!["git.ns.admin@git-ns:github.com/other".parse().unwrap()];
        assert!(may_approve(&rm, &inside, now));
        assert!(!may_approve(&rm, &outside, now));
    }

    /// VTI-ACL-041: the least-privilege approver — act `none`, an approve
    /// scope — is an approver for every kind its approve scope reaches, though
    /// it holds nothing.
    #[test]
    fn vti_acl_041_a_least_privilege_approver_counts_for_every_act() {
        use crate::policy::PolicyPurpose;
        let now = 1_000;
        let approver = entry(AdminAuthority::for_role(AdminRole::Approver), None);
        assert!(!approver.admin.can(Capability::RolesAssign, None));
        for act in [
            Act::GrantUnrestricted,
            Act::ReduceUnrestricted,
            Act::LowerThreshold,
            Act::ChangeAuthorityPolicy(PolicyPurpose::Removal),
            Act::ChangeRoles,
            Act::RestoreBackup,
            Act::GrantsReview,
        ] {
            assert!(may_approve(&approver, &act.default_stake(), now), "{act:?}");
        }
        // Narrowed to approving vetting only, it approves nothing else.
        let mut vetting_only = AdminAuthority::for_role(AdminRole::Approver);
        vetting_only.approve_capabilities = listed(&["vtc.vetting.manage"]);
        let vetting_only = entry(vetting_only, None);
        assert!(may_approve(
            &vetting_only,
            &[CapRef::all(Capability::VettingManage)],
            now
        ));
        assert!(!may_approve(
            &vetting_only,
            &Act::GrantUnrestricted.default_stake(),
            now
        ));
        // An auditor approves nothing.
        let auditor = entry(AdminAuthority::for_role(AdminRole::Auditor), None);
        assert!(!may_approve(
            &auditor,
            &Act::LowerThreshold.default_stake(),
            now
        ));
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
            (Act::GrantUnrestricted, tt::ACL_GRANT_V0_2_TYPE),
            (Act::GrantUnrestricted, tt::ACL_CHANGE_ROLE_V0_2_TYPE),
            (Act::GrantUnrestricted, tt::ACL_UPDATE_V0_2_TYPE),
            (Act::GrantUnrestricted, tt::admin_tasks::INVITES_CREATE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_REVOKE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_REVOKE_V0_2_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_CHANGE_ROLE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_CHANGE_ROLE_V0_2_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_UPDATE_TYPE),
            (Act::ReduceUnrestricted, tt::ACL_UPDATE_V0_2_TYPE),
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
