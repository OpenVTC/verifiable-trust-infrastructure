//! **Direct admission** — an administrator admitting a DID without a join
//! request, as a governed ceremony (`vtc.admission`).
//!
//! Two operations, one spine:
//!
//! - **Add a member** (`vtc/members/admit/0.1`): a DID with no ACL entry is
//!   admitted at a role the administrator names — the ACL entry, the member
//!   record and the membership credentials (VMC + role VAC + revocation slot),
//!   exactly what a completed join leaves behind. A former member (a removed
//!   record, no entry) is re-admitted as a rejoin would re-admit them.
//! - **Make this a membership** (`vtc/members/make-membership/0.1`): an ACL
//!   entry with no member record — the bootstrap administrator is the case
//!   that prompted it — gets the member record and credentials, at the role it
//!   already holds. The entry itself (role, authority, resource grants, label,
//!   expiry) is left exactly as it is.
//!
//! ## Why it is a ceremony
//!
//! Both bypass the join criteria and vetting, which is what the criteria
//! exist to prevent, so the community decides whether its administrators may
//! do it alone. The decision is the `admission` policy (the console's
//! *Policies* screen), run over [`Facts`](super::Facts) like every other
//! ceremony:
//!
//! - `allow` admits now;
//! - `refer` parks the operation in the action list
//!   ([`crate::admin_actions`], [`Act::DirectAdmission`]) after the
//!   requester's passkey gesture bound to it (VTI-APV-015), for another holder
//!   of `vtc.members.manage` — never the requester, never the subject — to
//!   approve. On the approval it runs itself, every check below re-run against
//!   the community as it is then (VTI-APV-017);
//! - `deny` refuses it.
//!
//! The default policy admits (`policies/default/admission.rego`). Changing it
//! is itself an authority change (`PolicyPurpose::decides_authority`,
//! VTI-VTC-022).
//!
//! ## What no policy can change
//!
//! Checked before the policy runs, so a refusal is the operator's to read
//! rather than the policy's, and again on an approved execution:
//!
//! - the actor holds `vtc.members.manage` (the dispatcher's gate, and
//!   [`Act::DirectAdmission`]'s requester check);
//! - a role other than `member` is **assigning a role**: it takes
//!   `vtc.roles.assign`, and the entry it seats is bounded by the actor's own
//!   ([`crate::acl::granting::check_write`], `vtc-admin-roles.md` §6.3,
//!   VTI-ACL-071) — the rule `routes::invitations` applies to an invitation's
//!   role;
//! - `admin`, or any role whose authority would confer authority-conferring
//!   capabilities, is never seated this way: admit the member, then promote
//!   them with `acl/change-role`, which carries its own step-up and consent
//!   (VTI-APV-018). A role that carries administrative authority at all takes
//!   the requester's operation-bound gesture (VTI-OPS-051), as `acl/grant`
//!   does;
//! - an `application` entry is not a membership to make: it joins through the
//!   join flow (VTI-ACL-037);
//! - a live membership is never duplicated, and a removed one is never
//!   overwritten in place by *Make this a membership* (see
//!   [`MakeMembershipRefusal::Removed`]).

use serde_json::json;
use tracing::{info, warn};
use vti_common::audit::{AuditEvent, MemberAdmittedDirectlyData};

use super::effects::{ADMISSION_ADD, ADMISSION_MAKE_MEMBERSHIP, EffectPlan};
use super::execute::{self, AdmitOutcome, EffectOutcome};
use super::{Evidence, FactsInputs, Purpose, Verdict, VerifiedFacts, assemble_facts, decide};
use crate::acl::admin_consent::{self, Act, Operation, SignedGate};
use crate::acl::{Capability, VtcAclEntry, VtcRole, get_acl_entry};
use crate::auth::session::now_epoch;
use crate::error::{AppError, TaskError};
use crate::members::get_member;
use crate::policy::{PolicyPurpose, load_active_compiled};
use crate::server::AppState;

/// The longest label an added member's entry may carry — `acl/grant/0.2`'s.
pub const LABEL_MAX: usize = 256;

/// What the administrator asked for.
#[derive(Debug, Clone)]
pub enum AdmissionRequest {
    /// Admit a DID with no ACL entry, at `role`.
    Add {
        subject: String,
        role: VtcRole,
        label: Option<String>,
    },
    /// Make an existing ACL entry with no member record a membership.
    MakeMembership { subject: String },
}

impl AdmissionRequest {
    pub fn subject(&self) -> &str {
        match self {
            Self::Add { subject, .. } | Self::MakeMembership { subject } => subject,
        }
    }

    /// `evidence.request.action`, and the audit's `action`.
    pub fn action(&self) -> &'static str {
        match self {
            Self::Add { .. } => ADMISSION_ADD,
            Self::MakeMembership { .. } => ADMISSION_MAKE_MEMBERSHIP,
        }
    }
}

/// How the admission was allowed to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// The `admission` policy allowed it outright.
    PolicyAllowed,
    /// Another administrator approved the parked action (VTI-APV-017).
    Approved,
    /// Single-administrator mode waived the approval the policy asked for
    /// (VTI-APV-022), on the requester's bound gesture.
    Waived,
}

impl Approval {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAllowed => "policyAllowed",
            Self::Approved => "approved",
            Self::Waived => "waived",
        }
    }
}

/// A completed direct admission.
#[derive(Debug)]
pub struct Admitted {
    pub subject: String,
    pub role: VtcRole,
    pub label: Option<String>,
    /// The subject had been a member before and was removed.
    pub returning: bool,
    pub approval: Approval,
    pub creds: AdmitOutcome,
}

/// Why `vtc/members/make-membership` refused, before the policy ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MakeMembershipRefusal {
    /// No ACL entry to make a membership of.
    NoEntry,
    /// An `application` entry: a non-member holding git rights.
    Application,
    /// Already a member.
    AlreadyMember,
    /// A removed member record exists. Refused rather than overwritten: the
    /// removal is a decision on the record, and re-admitting a former member
    /// is a rejoin — the join flow, or *Add a member* once the entry is gone —
    /// whose own rules (the criteria, or this ceremony's `add`) apply to it.
    Removed,
    /// The entry has expired, or is suspended by a cooling-off reduction.
    NotLive,
}

/// The declared error codes of the two tasks. Local to this service until the
/// specifications are published (see `crate::trust_tasks::admission_tasks`).
pub mod codes {
    pub const ADMIT_HAS_ENTRY: &str = "vtc/members/admit:hasEntry";
    pub const ADMIT_ALREADY_MEMBER: &str = "vtc/members/admit:alreadyMember";
    pub const ADMIT_ROLE_NOT_PERMITTED: &str = "vtc/members/admit:roleNotPermitted";
    pub const ADMIT_DENIED_BY_POLICY: &str = "vtc/members/admit:deniedByPolicy";
    pub const MAKE_NO_ENTRY: &str = "vtc/members/make-membership:noEntry";
    pub const MAKE_APPLICATION_ENTRY: &str = "vtc/members/make-membership:applicationEntry";
    pub const MAKE_ALREADY_MEMBER: &str = "vtc/members/make-membership:alreadyMember";
    pub const MAKE_REMOVED_MEMBER: &str = "vtc/members/make-membership:removedMember";
    pub const MAKE_ENTRY_NOT_LIVE: &str = "vtc/members/make-membership:entryNotLive";
    pub const MAKE_DENIED_BY_POLICY: &str = "vtc/members/make-membership:deniedByPolicy";
}

/// What the checks before the policy settled.
struct Checked {
    /// The role the membership will hold.
    role: VtcRole,
    /// The subject had been a member before and was removed.
    returning: bool,
    /// The role carries administrative authority (a fact for the policy).
    administrative: bool,
    /// The admission *grants* administrative authority — an add at a role
    /// that implies some — so the requester's gesture bound to the operation
    /// is asked for (VTI-OPS-051). Making an entry a membership grants
    /// nothing: its authority is already held.
    grants_authority: bool,
}

/// Run a direct admission: the host's checks, the `admission` policy, the
/// approval it may ask for, the write, the audit and the credentials'
/// delivery. `op` is the signed document's type and payload — what a gesture
/// and an approval are bound to.
pub async fn admit_directly(
    state: &AppState,
    actor_did: &str,
    req: AdmissionRequest,
    op: Operation<'_>,
    reason: Option<&str>,
) -> Result<Admitted, TaskError> {
    let audit_writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::Internal("audit_writer not initialised".into()))?;
    let subject = req.subject().to_string();
    vti_common::identifier::validate_did("subject", &subject)?;

    let actor = get_acl_entry(&state.acl_ks, actor_did)
        .await?
        .ok_or_else(|| {
            crate::acl::capability_refusal(actor_did, Capability::MembersManage, None)
        })?;
    let now = now_epoch();
    if actor.is_expired(now) || actor.is_suspended() || !actor.can(Capability::MembersManage, None)
    {
        return Err(
            crate::acl::capability_refusal(actor_did, Capability::MembersManage, None).into(),
        );
    }

    let checked = match &req {
        AdmissionRequest::Add { role, label, .. } => {
            check_add(state, &actor, &subject, role, label.as_deref(), now).await?
        }
        AdmissionRequest::MakeMembership { .. } => {
            check_make_membership(state, &subject, now).await?
        }
    };

    // ── the community's decision ──────────────────────────────────────────
    let verdict = decide_admission(state, &actor, &req, &checked).await?;
    let denied = match &req {
        AdmissionRequest::Add { .. } => codes::ADMIT_DENIED_BY_POLICY,
        AdmissionRequest::MakeMembership { .. } => codes::MAKE_DENIED_BY_POLICY,
    };
    let summary = summary_of(&req, &checked);
    let executing = crate::admin_actions::executing().is_some();
    let approval = match verdict {
        Verdict::Allow(_) => {
            // A role carrying administrative authority takes the requester's
            // gesture bound to this operation (VTI-OPS-051), as `acl/grant`
            // does. An approved action already spent one when it was parked.
            if checked.grants_authority && !executing {
                match crate::acl::bound_step_up::redeem_or_request(
                    state,
                    actor_did,
                    op.type_uri,
                    op.payload,
                    &summary,
                )
                .await?
                {
                    crate::acl::bound_step_up::Gate::Satisfied => {}
                    crate::acl::bound_step_up::Gate::Required(request) => {
                        return Err(TaskError::step_up(request));
                    }
                }
            }
            Approval::PolicyAllowed
        }
        Verdict::Refer(r) => {
            info!(
                subject = %subject,
                action = req.action(),
                queue = %r.queue,
                "direct admission referred for approval by the admission policy"
            );
            match admin_consent::gesture_then_consent_for(
                state,
                Act::DirectAdmission,
                &[],
                actor_did,
                &subject,
                op,
                &summary,
                &summary,
            )
            .await?
            {
                SignedGate::StepUpRequired(request) => return Err(TaskError::step_up(request)),
                SignedGate::Ready(ready) => {
                    let approval = if ready.is_waived() {
                        Approval::Waived
                    } else {
                        Approval::Approved
                    };
                    ready.spend(state).await?;
                    approval
                }
            }
        }
        Verdict::Deny(d) => {
            return Err(TaskError::declared(
                denied,
                AppError::Forbidden(format!(
                    "this community's admission policy refuses it ({}{})",
                    d.code,
                    d.reason.map(|r| format!(": {r}")).unwrap_or_default()
                )),
            ));
        }
        Verdict::RequestMore(_) => {
            return Err(AppError::Internal(
                "the admission policy returned request_more; a direct admission presents no \
                 evidence to add"
                    .into(),
            )
            .into());
        }
    };

    // ── the write ─────────────────────────────────────────────────────────
    let (plan, label) = match &req {
        AdmissionRequest::Add { role, label, .. } => (
            EffectPlan::Admit {
                subject: subject.clone(),
                role: role.to_string(),
                obligations: vec![],
                // The member's to give, never an administrator's.
                publish_consent: false,
                label: label.clone(),
            },
            label.clone(),
        ),
        AdmissionRequest::MakeMembership { .. } => (
            EffectPlan::Enrol {
                subject: subject.clone(),
            },
            None,
        ),
    };
    let EffectOutcome::Admitted(creds) = execute::apply(state, plan, actor_did).await? else {
        return Err(AppError::Internal("admit effect did not produce credentials".into()).into());
    };
    // R2.1: an approved action's effect is on record the moment it lands.
    crate::admin_actions::record_effect(state).await;

    // ── the trail ─────────────────────────────────────────────────────────
    let action_id = crate::admin_actions::executing().map(|e| e.action_id);
    audit_writer
        .write(
            actor_did,
            Some(&subject),
            AuditEvent::MemberAdmittedDirectly({
                let mut data = MemberAdmittedDirectlyData::new(
                    req.action(),
                    checked.role.to_string(),
                    approval.as_str(),
                );
                data.label = label.clone();
                data.returning = checked.returning;
                data.action_id = action_id.clone();
                data.reason = reason.map(str::to_string);
                data
            }),
        )
        .await?;
    crate::join::emit_admit_audit(
        audit_writer,
        actor_did,
        &subject,
        &creds,
        &checked.role.to_string(),
        None,
    )
    .await?;

    // The credentials are issued and returned inline; delivery to the
    // member's wallet is best-effort, as on a join approval.
    if let Err(e) =
        crate::credentials::delivery::deliver_membership_credentials(state, &subject, &creds).await
    {
        warn!(
            subject = %subject,
            error = %e,
            "membership-credential delivery failed on a direct admission; credentials issued and \
             returned inline"
        );
    }

    info!(
        subject = %subject,
        admin = %actor_did,
        action = req.action(),
        role = %checked.role,
        returning = checked.returning,
        approval = approval.as_str(),
        status_list_index = creds.status_list_index,
        "member admitted directly"
    );

    Ok(Admitted {
        subject,
        role: checked.role,
        label,
        returning: checked.returning,
        approval,
        creds: *creds,
    })
}

/// *Add a member*'s checks: no entry, no live membership, and a role the actor
/// may seat.
async fn check_add(
    state: &AppState,
    actor: &VtcAclEntry,
    subject: &str,
    role: &VtcRole,
    label: Option<&str>,
    now: u64,
) -> Result<Checked, TaskError> {
    if let Some(label) = label
        && (label.trim().is_empty() || label.chars().count() > LABEL_MAX)
    {
        return Err(AppError::Validation(format!(
            "label must be 1 to {LABEL_MAX} characters, not blank"
        ))
        .into());
    }

    let not_permitted = |message: String| {
        TaskError::declared(
            codes::ADMIT_ROLE_NOT_PERMITTED,
            AppError::Forbidden(message),
        )
    };
    if !role.is_assignable() {
        return Err(not_permitted(
            "`application` is not a membership: it marks a non-member holding git rights".into(),
        ));
    }
    if matches!(role, VtcRole::Admin) {
        return Err(not_permitted(format!(
            "a direct admission never seats `admin`: add {subject} as a member, then promote them \
             with acl/change-role, which takes its own passkey gesture and another \
             administrator's consent (VTI-APV-018)"
        )));
    }
    let seated = VtcAclEntry::new(subject, role.clone(), role.implied_authority(), &actor.did);
    if !matches!(role, VtcRole::Member) {
        // Conferring a role is assigning one, and a role that implies
        // administrative authority is a grant of it, bounded by the actor's own
        // entry like any grant (vtc-admin-roles.md §6.3, VTI-ACL-071) — the
        // rule an invitation's role is held to (`routes::invitations`).
        if !actor.can_any(Capability::RolesAssign) {
            return Err(not_permitted(format!(
                "admitting {subject} as `{role}` assigns a role, which takes vtc.roles.assign; \
                 without it you may add members only"
            )));
        }
        if let Err(refusal) = crate::acl::granting::check_write(actor, &seated, now) {
            return Err(not_permitted(format!(
                "admitting {subject} as `{role}` grants what that role implies: {refusal}"
            )));
        }
        let conferred = admin_consent::newly_conferred(None, &seated, now);
        if !conferred.is_empty() {
            return Err(not_permitted(format!(
                "`{role}` would give {subject} {}, which create authority; add them as a member \
                 and grant it with acl/grant, which takes other administrators' consent \
                 (VTI-APV-018)",
                conferred
                    .iter()
                    .map(crate::acl::CapRef::display)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }

    match get_acl_entry(&state.acl_ks, subject).await? {
        // A non-member holding git rights joins as a join would admit them:
        // the entry becomes a membership and keeps its grants.
        Some(e) if e.is_application() => {}
        Some(_) => {
            return Err(TaskError::declared(
                codes::ADMIT_HAS_ENTRY,
                AppError::Conflict(format!(
                    "{subject} already has an access-control entry; if it has no membership, \
                     make it one with vtc/members/make-membership {{\"subject\": \"{subject}\"}}, \
                     which keeps its role and authority"
                )),
            ));
        }
        None => {}
    }
    let returning = match get_member(&state.members_ks, subject).await? {
        Some(m) if m.is_removed() => true,
        Some(_) => {
            return Err(TaskError::declared(
                codes::ADMIT_ALREADY_MEMBER,
                AppError::Conflict(format!("{subject} is already a member")),
            ));
        }
        None => false,
    };
    Ok(Checked {
        role: role.clone(),
        returning,
        administrative: seated.is_administrator(),
        grants_authority: seated.is_administrator(),
    })
}

/// *Make this a membership*'s checks: a live, non-application entry with no
/// member record.
async fn check_make_membership(
    state: &AppState,
    subject: &str,
    now: u64,
) -> Result<Checked, TaskError> {
    let refuse = |why: MakeMembershipRefusal, message: String| {
        let (code, error) = match why {
            MakeMembershipRefusal::NoEntry => (codes::MAKE_NO_ENTRY, AppError::NotFound(message)),
            MakeMembershipRefusal::Application => {
                (codes::MAKE_APPLICATION_ENTRY, AppError::Conflict(message))
            }
            MakeMembershipRefusal::AlreadyMember => {
                (codes::MAKE_ALREADY_MEMBER, AppError::Conflict(message))
            }
            MakeMembershipRefusal::Removed => {
                (codes::MAKE_REMOVED_MEMBER, AppError::Conflict(message))
            }
            MakeMembershipRefusal::NotLive => {
                (codes::MAKE_ENTRY_NOT_LIVE, AppError::Conflict(message))
            }
        };
        TaskError::declared(code, error)
    };
    let Some(entry) = get_acl_entry(&state.acl_ks, subject).await? else {
        return Err(refuse(
            MakeMembershipRefusal::NoEntry,
            format!(
                "{subject} has no access-control entry; add them as a member with \
                 vtc/members/admit instead"
            ),
        ));
    };
    if entry.is_application() {
        return Err(refuse(
            MakeMembershipRefusal::Application,
            format!(
                "{subject}'s entry is an application entry — git rights held by a non-member \
                 (VTI-ACL-037). It becomes a membership through the join flow, or with \
                 vtc/members/admit, which keeps its grants"
            ),
        ));
    }
    if entry.is_expired(now) || entry.is_suspended() {
        return Err(refuse(
            MakeMembershipRefusal::NotLive,
            format!("{subject}'s entry has expired or is suspended; it authorizes nothing now"),
        ));
    }
    match get_member(&state.members_ks, subject).await? {
        Some(m) if m.is_removed() => {
            return Err(refuse(
                MakeMembershipRefusal::Removed,
                format!(
                    "{subject} was a member and was removed{}. Making their entry a membership \
                     would undo that removal without the decision re-admitting a former member \
                     takes. Re-admit them through the join flow, or revoke the entry and add \
                     them with vtc/members/admit, which the admission policy decides",
                    m.removed_at
                        .map(|t| format!(" on {}", t.to_rfc3339()))
                        .unwrap_or_default()
                ),
            ));
        }
        Some(_) => {
            return Err(refuse(
                MakeMembershipRefusal::AlreadyMember,
                format!("{subject} is already a member"),
            ));
        }
        None => {}
    }
    Ok(Checked {
        administrative: entry.is_administrator(),
        grants_authority: false,
        role: entry.role,
        returning: false,
    })
}

/// Run the `admission` policy over the request.
async fn decide_admission(
    state: &AppState,
    actor: &VtcAclEntry,
    req: &AdmissionRequest,
    checked: &Checked,
) -> Result<Verdict, AppError> {
    let subject = req.subject();
    let prior = get_member(&state.members_ks, subject).await?;
    let facts = assemble_facts(
        state,
        FactsInputs {
            purpose: Purpose::Admission,
            actor_did: actor.did.clone(),
            actor_role: Some(actor.role.to_string()),
            subject_did: subject.to_string(),
            // A former member's removed record, as the policy should see it;
            // nobody admitted here holds a live one.
            subject_member: prior
                .as_ref()
                .map(|m| super::member_state(checked.role.to_string(), Some(m))),
            evidence: Evidence {
                request: Some(json!({
                    "action": req.action(),
                    "role": checked.role.to_string(),
                    "administrative": checked.administrative,
                    "returning": checked.returning,
                })),
                ..Evidence::default()
            },
            // Synchronous: the administrator's signed document is the whole
            // exchange.
            thread_id: None,
        },
    )
    .await?;
    let verified = VerifiedFacts::assemble(facts)?;
    let policy = load_active_compiled(
        &state.active_policies_ks,
        &state.policies_ks,
        PolicyPurpose::Admission,
    )
    .await?;
    decide(&verified, &policy)
}

/// What the approvers and the requester's gesture are shown.
fn summary_of(req: &AdmissionRequest, checked: &Checked) -> String {
    match req {
        AdmissionRequest::Add { subject, .. } => format!(
            "Add {subject} as a member holding {}, without a join request{}",
            checked.role,
            if checked.returning {
                " (a former member)"
            } else {
                ""
            }
        ),
        AdmissionRequest::MakeMembership { subject } => format!(
            "Make {subject}'s access-control entry a membership, at its role {}",
            checked.role
        ),
    }
}
