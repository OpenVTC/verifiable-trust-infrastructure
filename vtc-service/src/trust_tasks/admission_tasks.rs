//! Direct admission on the signed-document spine — an administrator admitting
//! a DID without a join request ([`crate::ceremony::admission`]).
//!
//! | task | authority (the signer's live entry, read now) |
//! |---|---|
//! | `vtc/members/admit/0.1` | `vtc.members.manage`; a role beyond `member` also `vtc.roles.assign`, bounded by the signer's own entry |
//! | `vtc/members/make-membership/0.1` | `vtc.members.manage` |
//!
//! Both are decided by the community's `admission` policy, which may refer
//! them to the action list for another holder of `vtc.members.manage` to
//! approve (`vtc-action-list.md`; [`crate::acl::admin_consent::Act::DirectAdmission`]).
//! A referred one is answered `trust-task-next-step/0.1`, as every parked
//! operation is, after the requester's operation-bound passkey gesture.
//!
//! # Wire types are local, for now
//!
//! Neither task has a published specification yet: no existing task fits
//! cleanly. `acl/grant` writes an ACL entry and nothing else, and carrying "and
//! admit them" in its `ext` would make a membership — credentials, a
//! revocation slot, a policy decision — ride on a member an older service is
//! free to ignore. `vtc/members/update` edits a membership that exists, and
//! the join tasks are an applicant's. So the payload and response types below
//! are written here, held to `deny_unknown_fields`, until the specifications
//! (drafted in the pull request that added them) are published in
//! dtgwg-trust-tasks-tf and `trust-tasks-rs` generates them.
//!
//! TODO: replace with generated trust-tasks types
//! (`trust_tasks_rs::specs::vtc::members::{admit, make_membership}`).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use super::helpers::{TrustTaskOutcome, parse_payload, success_response, task_error_to_reject};
use super::{JoinAuthCtx, capable_signer};
use crate::acl::admin_consent::Operation;
use crate::acl::{Capability, VtcRole};
use crate::ceremony::admission::{self, AdmissionRequest, Admitted, codes};
use crate::error::{AppError, TaskError};
use crate::server::AppState;

/// `vtc/members/admit/0.1` — add a member directly, without a join request.
pub(crate) const ADMIT_TYPE: &str = "https://trusttasks.org/spec/vtc/members/admit/0.1";
/// `vtc/members/make-membership/0.1` — make an existing ACL entry with no
/// member record a membership.
pub(crate) const MAKE_MEMBERSHIP_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/make-membership/0.1";

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[ADMIT_TYPE, MAKE_MEMBERSHIP_TYPE];

/// The document requirements both drafts declare, enforced by the spine as a
/// published specification's are ([`super::spec_policy_for`]): a `proof`
/// (an administrator's act is attributable past the transport hop), a
/// `recipient` naming this community, and `issuedAt`. Not a bearer task.
///
/// TODO: replace with generated trust-tasks types — this goes with them.
pub(crate) fn local_spec_policy(type_uri: &str) -> Option<trust_tasks_rs::SpecPolicy> {
    URIS.contains(&type_uri)
        .then_some(trust_tasks_rs::SpecPolicy {
            is_bearer: false,
            is_proof_required: true,
            is_recipient_required: true,
            is_issued_at_required: true,
        })
}

/// The longest `reason` either task accepts.
const REASON_MAX: usize = 1024;

/// `vtc/members/admit/0.1` request payload.
///
/// TODO: replace with generated trust-tasks types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmitPayload {
    /// The DID to admit.
    pub subject: String,
    /// The community role it will hold (`member`, `moderator`, `issuer`,
    /// `custom:<name>`). Required, so what an approver is shown is what was
    /// asked for — the console defaults it to `member`.
    pub role: String,
    /// The new entry's label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Why, for the audit trail and the approvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Vendor extensions (SPEC §4.5.1). None is read today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Map<String, Value>>,
}

/// `vtc/members/make-membership/0.1` request payload.
///
/// TODO: replace with generated trust-tasks types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MakeMembershipPayload {
    /// The DID whose ACL entry becomes a membership.
    pub subject: String,
    /// Why, for the audit trail and the approvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Vendor extensions (SPEC §4.5.1). None is read today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Map<String, Value>>,
}

/// The response of `vtc/members/admit/0.1` and
/// `vtc/members/make-membership/0.1`: the membership as admitted, with the
/// credentials issued for it, as `vtc/join-requests/decide` returns them.
///
/// TODO: replace with generated trust-tasks types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmittedResponse {
    pub subject: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Always `admitted`.
    pub status: String,
    /// The subject had been a member before and was removed.
    pub returning: bool,
    /// How it was allowed: `policyAllowed`, `approved` or `waived`.
    pub approval: String,
    pub status_list_index: u32,
    pub vmc: Value,
    pub role_vac: Value,
}

impl AdmittedResponse {
    fn from_admitted(a: Admitted) -> Result<Self, AppError> {
        let to_value = |vc: &affinidi_vc::VerifiableCredential| {
            serde_json::to_value(vc)
                .map_err(|e| AppError::Internal(format!("serialise credential for response: {e}")))
        };
        Ok(Self {
            subject: a.subject,
            role: a.role.to_string(),
            label: a.label,
            status: "admitted".into(),
            returning: a.returning,
            approval: a.approval.as_str().into(),
            status_list_index: a.creds.status_list_index,
            vmc: to_value(&a.creds.vmc)?,
            role_vac: to_value(&a.creds.role_vac)?,
        })
    }
}

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    if !URIS.contains(&type_uri) {
        return None;
    }
    Some(handle(state, ctx, doc, type_uri).await)
}

/// The request a payload asks for, and its reason.
fn read_request(
    doc: &TrustTask<Value>,
    type_uri: &str,
) -> Result<(AdmissionRequest, Option<String>), TrustTaskOutcome> {
    let (request, reason) = if type_uri == ADMIT_TYPE {
        let p: AdmitPayload = parse_payload(doc)?;
        let role = p.role.parse::<VtcRole>().map_err(|_| {
            task_error_to_reject(
                doc,
                &TaskError::declared(
                    codes::ADMIT_ROLE_NOT_PERMITTED,
                    AppError::Validation(format!("unknown role `{}`", p.role)),
                ),
            )
        })?;
        (
            AdmissionRequest::Add {
                subject: p.subject,
                role,
                label: p.label,
            },
            p.reason,
        )
    } else {
        let p: MakeMembershipPayload = parse_payload(doc)?;
        (
            AdmissionRequest::MakeMembership { subject: p.subject },
            p.reason,
        )
    };
    if reason
        .as_ref()
        .is_some_and(|r| r.chars().count() > REASON_MAX)
    {
        return Err(task_error_to_reject(
            doc,
            &AppError::Validation(format!("reason exceeds {REASON_MAX} characters")).into(),
        ));
    }
    Ok((request, reason))
}

async fn handle(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> TrustTaskOutcome {
    // Read from the acting administrator's live entry — the signer's own, or
    // the delegating administrator's for a console key — before the payload
    // is acted on.
    let actor = match capable_signer(state, ctx, &doc, Capability::MembersManage, None).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let (request, reason) = match read_request(&doc, type_uri) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let outcome = admission::admit_directly(
        state,
        &actor.did,
        request,
        Operation {
            type_uri,
            payload: &doc.payload,
        },
        reason.as_deref(),
    )
    .await;
    match outcome.and_then(|a| AdmittedResponse::from_admitted(a).map_err(TaskError::from)) {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}
