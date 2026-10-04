//! **Single-administrator mode on the git side** — **VTI-APV-022** applied to
//! separation of duties (fixed rule 7 of `git-ns/right/grant/0.3`).
//!
//! Rule 7 says nobody records an elevated git right (`git.ns.admin`,
//! `git.repo.create`, `git.repo.own`, or a right the role map projects to the
//! forge's `admin`) for themselves; another administrator does it, or the
//! actor breaks the glass and another administrator ratifies. A community run
//! by one person has no other administrator, so the rule would leave its
//! administrator unable to adopt their own repository, own what they create or
//! reseat a namespace to themselves — and every break-glass would wait forever
//! for a ratification nobody can give.
//!
//! On a node in single-administrator mode (`[acl] single_admin_mode`, host
//! configuration — [`crate::acl::single_admin`]) rule 7 is waived for one
//! operation under exactly the discipline the consent waiver keeps
//! ([`crate::acl::admin_consent::gesture_then_consent_for`]):
//!
//! 1. **only where nobody else is eligible** ([`others_eligible`]) — no other
//!    live entry that could decide the break-glass this would otherwise be
//!    (the namespace's administrators and the community-wide `git.ns.admin`
//!    holders, [`Act::BreakGlassReview`]), none that could approve a grant of
//!    `git.ns.admin` on the namespace ([`Act::GrantUnrestricted`]'s approve
//!    scope), and no other member whose git rights carry the authority to make
//!    this grant (fixed rules 1 and 2). One such party and the refusal stands,
//!    exactly as with the mode off;
//! 2. **on the requester's operation-bound step-up** (VTI-APV-015,
//!    [`crate::acl::bound_step_up`]) — the same passkey gesture break-glass
//!    takes, bound by digest to the document as sent, asked for after every
//!    check that decides whether the act is allowed and before anything is
//!    written;
//! 3. **audited at `Critical` before the write** — a `SingleAdminMode {
//!    event: selfGrantWaived }` row naming the rule, the task, its digest, the
//!    git-ns action, the right and the resource. If it cannot be written, the
//!    operation is refused and nothing is recorded;
//! 4. **marked** — the record carries [`SingleAdminMark`] (never published),
//!    the task's response carries `ext.org.openvtc.selfGrantWaived`, the
//!    `git-ns/view` 0.4/0.5 answer lists such records under the same `ext`
//!    member, the ACL entry's resource grant says `selfGrantWaived: true`, and
//!    a `gitNs.right.selfGrantWaived` activity item follows the write.
//!
//! The rest of the rights model still applies: rules 1, 2 and 5, the
//! granter-covers floor, the consent-class gate and the community's policy.
//!
//! A record made this way **counts** toward the last-owner and last-admin
//! invariants (rules 3 and 4), unlike an unratified break-glass record: in a
//! one-administrator community it is how rights are normally held, and there is
//! nobody else whose revocation the invariants would need to make room for.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use tracing::warn;
use vti_common::audit::{AuditEvent, SingleAdminModeData};
use vti_common::error::AppError;

use crate::acl::admin_consent::{self, Act};
use crate::acl::bound_step_up::{self, EvidencedGate};
use crate::server::AppState;

use super::model::{Namespace, Resource, Right, RightRow, SingleAdminMark};
use super::ops::{self, Audit, OpError, OpResult, Standing, standing};
use super::rules::{self, RuleSettings};
use super::store::Snapshot;

/// The rule the waiver lifts, as the audit row names it.
pub const REQUIREMENT: &str = "git-ns/right/grant/0.3#rule-7";
/// The `SingleAdminMode` audit row's `event`.
pub const AUDIT_EVENT: &str = "selfGrantWaived";
/// The `ext.org.openvtc` member that marks a waived operation and record.
pub const EXT_MARKER: &str = "selfGrantWaived";
/// The `GitNsOperation` action the activity list shows.
pub const ACTIVITY_ACTION: &str = "gitNs.right.selfGrantWaived";

/// Single-administrator mode's leave to record one elevated `right` on one
/// `resource` for `actor` themselves. Only [`waivable`] makes one, after the
/// mode and the eligibility test; a fixed rule given one lifts rule 7 for that
/// grant and no other ([`Self::covers`]).
#[derive(Debug, Clone)]
pub struct Waivable {
    actor: String,
    right: Right,
    resource: Resource,
}

impl Waivable {
    /// Whether this is leave for `actor` to grant `right` on `target` to
    /// `subject` — themselves.
    pub fn covers(&self, actor: &str, subject: &str, right: Right, target: &Resource) -> bool {
        self.actor == actor && subject == actor && self.right == right && self.resource == *target
    }

    pub fn right(&self) -> Right {
        self.right
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    #[cfg(test)]
    pub(crate) fn for_test(actor: &str, right: Right, resource: Resource) -> Self {
        Self {
            actor: actor.to_string(),
            right,
            resource,
        }
    }
}

/// Everyone but `actor` who could stand in for them here: who could make this
/// grant, or decide the break-glass it would otherwise be.
///
/// The consent gate's own notion of eligibility
/// ([`admin_consent::approvers_for`]) over the namespace's `git.ns.admin` —
/// both the deciders of a break-glass on it ([`Act::BreakGlassReview`]: its
/// administrators and the community-wide holders) and whoever's approve scope
/// reaches it ([`Act::GrantUnrestricted`]) — together with every other member
/// whose git rights carry the authority to grant `right` on `target` (fixed
/// rules 1 and 2: an owner of an existing repository can make another owner).
pub async fn others_eligible(
    state: &AppState,
    snap: &Snapshot,
    ns: &Namespace,
    actor: &str,
    right: Right,
    target: &Resource,
    settings: RuleSettings,
) -> Result<Vec<String>, AppError> {
    let now_epoch = crate::auth::session::now_epoch();
    let stake = vec![super::break_glass::review_stake(ns)];
    let mut out = BTreeSet::new();
    for act in [Act::BreakGlassReview, Act::GrantUnrestricted] {
        out.extend(
            admin_consent::approvers_for(state, act, &stake, actor, actor, now_epoch).await?,
        );
    }
    let t = ops::now();
    let mut seen = BTreeSet::new();
    for set in snap.rights.values() {
        for row in &set.rows {
            if row.subject == actor || out.contains(&row.subject) {
                continue;
            }
            if !seen.insert(row.subject.clone()) {
                continue;
            }
            if rules::authority_to_grant(snap, &row.subject, right, target, settings, t).is_ok()
                && standing(state, &row.subject).await?.member
            {
                out.insert(row.subject.clone());
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// Leave to record `right` on `target` for `actor` themselves, or `None` — the
/// refusal stands — when the mode is off, the actor is not a current member,
/// or anyone else is eligible ([`others_eligible`]).
pub async fn waivable(
    state: &AppState,
    snap: &Snapshot,
    ns: &Namespace,
    actor: &Standing,
    right: Right,
    target: &Resource,
    settings: RuleSettings,
) -> Result<Option<Waivable>, AppError> {
    if !admin_consent::single_admin_mode(state).await || !actor.member {
        return Ok(None);
    }
    if !others_eligible(state, snap, ns, &actor.did, right, target, settings)
        .await?
        .is_empty()
    {
        return Ok(None);
    }
    Ok(Some(Waivable {
        actor: actor.did.clone(),
        right,
        resource: target.clone(),
    }))
}

/// The operation a waiver is spent on: the document the requester signed —
/// what the step-up is bound to and the audit row names — and the git-ns
/// action it is.
#[derive(Debug, Clone, Copy)]
pub struct WaivedOp<'a> {
    pub type_uri: &'a str,
    pub payload: &'a Value,
    /// `right.grant`, `repo.create`, `repo.adopt`, `namespace.reseat`,
    /// `drift.adopt`.
    pub kind: &'a str,
}

/// Spend the waiver: the requester's operation-bound step-up, then the
/// `Critical` audit row. Call it after every other check and immediately
/// before the write; set the returned mark on the record written.
///
/// No step-up yet: [`OpError::StepUpRequired`], and the identical document
/// re-sent once the gesture is recorded proceeds. An audit row that cannot be
/// written refuses the operation — the gesture is spent, and nothing is
/// recorded (VTI-APV-022 item 4).
pub async fn authorize(
    state: &AppState,
    waiver: &Waivable,
    op: WaivedOp<'_>,
) -> OpResult<SingleAdminMark> {
    let (right, resource) = (waiver.right, &waiver.resource);
    let reason = format!(
        "SINGLE-ADMINISTRATOR MODE: record {right} on {resource} for yourself. Nobody else in \
         this community could grant it, so your passkey gesture stands in for a second \
         administrator; it is audited."
    );
    match bound_step_up::redeem_or_request_with_evidence(
        state,
        &waiver.actor,
        op.type_uri,
        op.payload,
        &reason,
    )
    .await?
    {
        EvidencedGate::Satisfied(_) => {}
        EvidencedGate::Required(request) => {
            return Err(OpError::StepUpRequired {
                message: format!(
                    "single-administrator mode: nobody else can grant {right} on {resource}, so \
                     recording it for yourself needs a passkey gesture bound to this request \
                     (VTI-APV-022) in place of another administrator"
                ),
                request,
            });
        }
    }
    let digest = vti_common::task_consent::payload_digest(op.type_uri, op.payload)?;
    warn!(
        actor = %waiver.actor,
        right = %right,
        resource = %resource,
        task = %op.type_uri,
        "separation of duties waived — single-administrator mode (VTI-APV-022): nobody else \
         could grant this, and the requester's operation-bound step-up stands in"
    );
    if let Some(writer) = state.audit_writer.as_ref() {
        writer
            .write(
                &waiver.actor,
                Some(&waiver.actor),
                AuditEvent::SingleAdminMode(SingleAdminModeData {
                    event: AUDIT_EVENT.into(),
                    requirement: Some(REQUIREMENT.into()),
                    task: Some(op.type_uri.to_string()),
                    digest: Some(digest),
                    kind: Some(op.kind.to_string()),
                    right: Some(right.as_str().to_string()),
                    resource: Some(resource.to_string()),
                }),
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    "the single-administrator waiver's audit row could not be written; refusing"
                );
                OpError::Internal(e)
            })?;
    }
    Ok(SingleAdminMark {
        at: ops::now(),
        task: op.type_uri.to_string(),
    })
}

/// The activity item that follows a waived write. Best-effort, as every
/// `GitNsOperation` row is: the `Critical` row is already written.
pub async fn note(state: &AppState, waiver: &Waivable, ns: &Namespace, kind: &str) {
    ops::audit(
        state,
        &waiver.actor,
        Some(&waiver.actor),
        Audit {
            action: ACTIVITY_ACTION,
            namespace: Some(&ns.id),
            resource: Some(waiver.resource.to_string()),
            right: Some(waiver.right),
            policy_version: None,
            detail: Some(kind.to_string()),
        },
    )
    .await;
}

/// `ext.org.openvtc.selfGrantWaived` for a task's response.
pub fn response_ext(waiver: &Waivable) -> Value {
    json!({
        "org.openvtc": {
            EXT_MARKER: {
                "mode": "singleAdministrator",
                "requirement": REQUIREMENT,
                "right": waiver.right.as_str(),
                "resource": waiver.resource.to_string(),
            }
        }
    })
}

/// One waived record, as the `git-ns/view` answer's `ext` lists it.
pub fn view_entry(row: &RightRow, resource: &Resource) -> Option<Value> {
    let mark = row.single_admin.as_ref()?;
    Some(json!({
        "subject": row.subject,
        "right": row.right.as_str(),
        "resource": resource.to_string(),
        "at": super::wire::timestamp(mark.at),
        "task": mark.task,
    }))
}
