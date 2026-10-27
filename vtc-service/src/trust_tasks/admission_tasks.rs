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
//! # Wire types
//!
//! Payloads, responses, document requirements and error codes are the ones
//! `trust-tasks-rs` generates from the published specifications
//! (trust-tasks-tf #784): [`admit`] and [`make`]. A payload is validated
//! against its schema before it is parsed, so a `subject` that is no DID or is
//! over 2048 characters, and a `role` over 128, are `malformedRequest` — the
//! document is malformed before any role is considered.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::vtc::members::admit::v0_1 as admit;
use trust_tasks_rs::specs::vtc::members::make_membership::v0_1 as make;

use super::helpers::{TrustTaskOutcome, success_response, task_error_to_reject};
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::admin_consent::Operation;
use crate::acl::{Capability, VtcRole};
use crate::ceremony::admission::{self, AdmissionRequest, Admitted, codes};
use crate::error::{AppError, TaskError};
use crate::server::AppState;

/// `vtc/members/admit/0.1` — add a member directly, without a join request.
pub(crate) const ADMIT_TYPE: &str = <admit::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/members/make-membership/0.1` — make an existing ACL entry with no
/// member record a membership.
pub(crate) const MAKE_MEMBERSHIP_TYPE: &str = <make::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[ADMIT_TYPE, MAKE_MEMBERSHIP_TYPE];

/// `fn $name`: the generated response of `$m` (`admit` or `make`, whose
/// `AdmittedMembership` types are distinct) for a completed admission.
macro_rules! admitted_response {
    ($name:ident, $m:ident) => {
        pub(crate) fn $name(a: Admitted) -> Result<$m::Response, AppError> {
            let label = a
                .label
                .map(|l| l.parse::<$m::AdmittedMembershipLabel>())
                .transpose()
                .map_err(|e| AppError::Internal(format!("admitted label: {e}")))?;
            $m::AdmittedMembership::builder()
                .subject(a.subject.as_str())
                .role(a.role.to_string())
                .label(label)
                .status($m::AdmittedMembershipStatus::Admitted)
                .returning(a.returning)
                .approval(a.approval.as_str())
                .status_list_index(u64::from(a.creds.status_list_index))
                .vmc(credential_object(&a.creds.vmc)?)
                .role_vac(credential_object(&a.creds.role_vac)?)
                .try_into()
                .map($m::Response)
                .map_err(|e: $m::error::ConversionError| {
                    AppError::Internal(format!("admitted membership out of schema: {e}"))
                })
        }
    };
}

admitted_response!(admit_response, admit);
admitted_response!(make_response, make);

/// A credential as the JSON object the response carries it as.
fn credential_object(
    vc: &affinidi_vc::VerifiableCredential,
) -> Result<serde_json::Map<String, Value>, AppError> {
    match serde_json::to_value(vc) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(AppError::Internal("credential is not a JSON object".into())),
        Err(e) => Err(AppError::Internal(format!(
            "serialise credential for response: {e}"
        ))),
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

/// The request a payload asks for, and its reason. The payload is read
/// against its published schema first ([`parse_spec_payload`]).
fn read_request(
    doc: &TrustTask<Value>,
    type_uri: &str,
) -> Result<(AdmissionRequest, Option<String>), TrustTaskOutcome> {
    if type_uri == ADMIT_TYPE {
        let p: admit::Payload = parse_spec_payload(doc)?;
        let role = p.role.parse::<VtcRole>().map_err(|_| {
            task_error_to_reject(
                doc,
                &TaskError::declared(
                    codes::ADMIT_ROLE_NOT_PERMITTED,
                    AppError::Validation(format!("unknown role `{}`", *p.role)),
                ),
            )
        })?;
        Ok((
            AdmissionRequest::Add {
                subject: p.subject.to_string(),
                role,
                label: p.label.map(String::from),
            },
            p.reason.map(String::from),
        ))
    } else {
        let p: make::Payload = parse_spec_payload(doc)?;
        Ok((
            AdmissionRequest::MakeMembership {
                subject: p.subject.to_string(),
            },
            p.reason.map(String::from),
        ))
    }
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
    let admitted = match outcome {
        Ok(a) => a,
        Err(e) => return task_error_to_reject(&doc, &e),
    };
    let response = if type_uri == ADMIT_TYPE {
        admit_response(admitted).map(|r| success_response(&doc, r))
    } else {
        make_response(admitted).map(|r| success_response(&doc, r))
    };
    response.unwrap_or_else(|e| task_error_to_reject(&doc, &TaskError::from(e)))
}
