//! `vtc/members/role/set/0.1` — an administrator moves a subject's
//! **community** role, compare-and-swapped on the role it holds.
//!
//! The community role is the role a membership holds — the one its role
//! credential states — and at this community it also implies an administrative
//! role (`admin` → `community-admin`, `moderator` → `moderator`, `issuer` →
//! `credential-officer`). The move carries that administrative authority only
//! where the entry's authority is exactly the one its current role implies
//! (item 8); `acl/change-role/0.2` moves the administrative role on its own.
//!
//! The handler makes the specification's checks 1–7 in its order, each with
//! its declared code; [`crate::routes::acl::set_community_role`] runs the
//! role-change ceremony for the rest (items 8–18): the bound on the requester
//! (`delegationExceedsGranter`), the last role assigner, the community's
//! role-change policy, a passkey gesture bound to this one document
//! (**VTI-OPS-050/051**), other administrators' consent for a move that confers
//! or withdraws authority-conferring capabilities (**VTI-APV-018**,
//! **VTI-APV-019**), the serialised write, the role credential and the notice a
//! demoted administrator is sent.

use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_specs::vtc::members::role::set::v0_1 as role_set;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    reject_with_code_because, success_response,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::{Capability, VtcAclEntry, VtcRole, get_acl_entry};
use crate::auth::session::now_epoch;
use crate::ceremony::RoleChangeRefusal;
use crate::error::AppError;
use crate::routes::acl::{self as ops, RoleSetOutcome};
use crate::server::AppState;
use vta_sdk::protocols::trust_task_reject_reasons as reasons;

/// `vtc/members/role/set/0.1`.
pub(crate) const ROLE_SET_TYPE: &str = <role_set::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The codes `vtc/members/role/set/0.1` declares, for the tests that witness
/// each one (`error_code_census`).
pub mod codes {
    use vti_specs::vtc::members::role::set::v0_1::error_codes as c;

    pub const ROLE_SET_NOT_FOUND: &str = c::NOT_FOUND.code;
    pub const ROLE_SET_STATE_MISMATCH: &str = c::STATE_MISMATCH.code;
    pub const ROLE_SET_ROLE_NOT_RECOGNIZED: &str = c::ROLE_NOT_RECOGNIZED.code;
    pub const ROLE_SET_ROLE_NOT_ASSIGNABLE: &str = c::ROLE_NOT_ASSIGNABLE.code;
    pub const ROLE_SET_DELEGATION_EXCEEDS_GRANTER: &str = c::DELEGATION_EXCEEDS_GRANTER.code;
    pub const ROLE_SET_LAST_ROLE_ASSIGNER: &str = c::LAST_ROLE_ASSIGNER.code;
    pub const ROLE_SET_DENIED_BY_POLICY: &str = c::DENIED_BY_POLICY.code;
}

use role_set::error_codes as declared;

fn coded(
    doc: &TrustTask<Value>,
    code: trust_tasks_rs::DeclaredErrorCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code.code), message, details)
}

fn permission_denied(doc: &TrustTask<Value>, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: message.into(),
        },
    )
}

/// A role named on the wire, read as this community's (item 4).
fn recognise(doc: &TrustTask<Value>, role: &str) -> Result<VtcRole, TrustTaskOutcome> {
    role.parse::<VtcRole>().map_err(|e| {
        coded(
            doc,
            declared::ROLE_NOT_RECOGNIZED,
            e.to_string(),
            Some(json!({ "offendingRole": role })),
        )
    })
}

/// `vtc/members/role/set/0.1` — move a subject's community role.
pub(super) async fn handle_role_set(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: role_set::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let subject = checked.subject.as_str();
    let now = now_epoch();

    // 1. The requester holds `vtc.roles.assign`, read from its live entry (or
    //    the one a console key acts for) now. An expired or suspended entry
    //    holds nothing.
    let actor_entry = match get_acl_entry(&state.acl_ks, &actor.did).await {
        Ok(Some(e))
            if !e.is_expired(now) && !e.is_suspended() && e.can_any(Capability::RolesAssign) =>
        {
            e
        }
        Ok(_) => {
            return permission_denied(
                &doc,
                crate::acl::capability_refusal(&actor.did, Capability::RolesAssign, None)
                    .to_string(),
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    // 2. Nobody moves their own community role, in either direction
    //    (VTI-OPS-050, VTI-ACL-052).
    if actor.did == subject {
        return permission_denied(
            &doc,
            "you cannot move your own community role (VTI-ACL-052) — another administrator \
             holding vtc.roles.assign sends vtc/members/role/set for you",
        );
    }

    // 3. The subject holds an entry.
    let entry: VtcAclEntry = match get_acl_entry(&state.acl_ks, subject).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return reject_with_code_because(
                &doc,
                extended_code(declared::NOT_FOUND.code),
                format!("{subject} holds no access-control entry at this community"),
                None,
                reasons::NOT_FOUND,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    // 4. The roles are recognised and assignable.
    let from = match recognise(&doc, checked.from_role.as_str()) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let to = match recognise(&doc, checked.to_role.as_str()) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    if !to.is_assignable() || !entry.role.is_assignable() {
        return coded(
            &doc,
            declared::ROLE_NOT_ASSIGNABLE,
            "`application` marks a non-member the community records for its resource grants, \
             not a role a member holds: no role moves onto or off it. Make a non-member a \
             member with vtc/members/admit",
            None,
        );
    }

    // 5. The compare-and-swap.
    if entry.role != from {
        return coded(
            &doc,
            declared::STATE_MISMATCH,
            format!(
                "{subject} holds the role {}, not {from}. Re-read the member and send the move \
                 from the role it holds",
                entry.role
            ),
            Some(json!({ "currentRole": entry.role.to_string() })),
        );
    }

    // 6. The requester covers the entry (VTI-ACL-050): moving a role re-grants
    //    it, and nobody re-grants authority they could not have granted.
    if !crate::acl::granting::covers_entry(&actor_entry, &entry, now) {
        return permission_denied(
            &doc,
            format!(
                "{subject} holds authority outside yours — only an administrator holding \
                 vtc.roles.assign over everything it holds can move its role (VTI-ACL-050)"
            ),
        );
    }

    // 7. A move to the role already held changes nothing, and asks for nothing.
    if from == to {
        return respond(&doc, &entry, &from, &to, false, None, None);
    }

    let outcome = ops::set_community_role(
        state,
        &actor,
        &entry,
        &to,
        checked.reason.as_deref().map(|r| r.as_str()),
        ROLE_SET_TYPE,
        &doc.payload,
    )
    .await;
    match outcome {
        Ok(RoleSetOutcome::Changed { entry, result }) => {
            let role_vac = match result.role_vac.as_ref().map(serde_json::to_value) {
                Some(Ok(v)) => Some(v),
                Some(Err(e)) => {
                    return app_error_to_reject(
                        &doc,
                        &AppError::Internal(format!("serialise role credential: {e}")),
                    );
                }
                None => None,
            };
            respond(
                &doc,
                &entry,
                &from,
                &to,
                true,
                Some(result.approval.as_str()),
                role_vac,
            )
        }
        // 12. A gesture bound to this document, delivered inline.
        Ok(RoleSetOutcome::StepUpRequired(request)) => reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            "a passkey gesture bound to this role change is required",
            Some(crate::acl::bound_step_up::refusal_details(&request)),
        ),
        Ok(RoleSetOutcome::Refused(refusal)) => refuse(&doc, refusal),
        // 13. A parked move is answered `trust-task-next-step` by the renderer.
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

fn refuse(doc: &TrustTask<Value>, refusal: RoleChangeRefusal) -> TrustTaskOutcome {
    match refusal {
        RoleChangeRefusal::StateMismatch { current } => coded(
            doc,
            declared::STATE_MISMATCH,
            format!(
                "the subject's role moved to {current} while this move was being decided. \
                 Re-read the member and send the move from the role it holds"
            ),
            Some(json!({ "currentRole": current })),
        ),
        RoleChangeRefusal::DelegationExceedsGranter { axes, message } => coded(
            doc,
            declared::DELEGATION_EXCEEDS_GRANTER,
            message,
            Some(json!({ "axes": axes })),
        ),
        RoleChangeRefusal::LastRoleAssigner(message) => {
            coded(doc, declared::LAST_ROLE_ASSIGNER, message, None)
        }
        RoleChangeRefusal::DeniedByPolicy(message) => {
            coded(doc, declared::DENIED_BY_POLICY, message, None)
        }
    }
}

/// The `#response`: the role as it now stands and the entry that holds it,
/// every authority axis explicit.
fn respond(
    doc: &TrustTask<Value>,
    entry: &VtcAclEntry,
    from: &VtcRole,
    to: &VtcRole,
    changed: bool,
    approval: Option<&str>,
    role_vac: Option<Value>,
) -> TrustTaskOutcome {
    match role_set_response(entry, from, to, changed, approval, role_vac) {
        Ok(r) => success_response(doc, r),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

/// The `vtc/members/role/set/0.1#response` payload, held to the generated type.
pub(crate) fn role_set_response(
    entry: &VtcAclEntry,
    from: &VtcRole,
    to: &VtcRole,
    changed: bool,
    approval: Option<&str>,
    role_vac: Option<Value>,
) -> Result<Value, AppError> {
    let mut body = json!({
        "subject": entry.did,
        "role": to.to_string(),
        "previousRole": from.to_string(),
        "changed": changed,
        "entry": ops::render_v0_2(entry, None),
    });
    if let Some(approval) = approval {
        body["approval"] = json!(approval);
    }
    if let Some(vac) = role_vac {
        body["roleVac"] = vac;
    }
    ops::conform::<role_set::Response>(body).map(|r| json!(r))
}
