//! The canonical `acl/*` family on the signed-document spine:
//! `acl/{grant,change-role,show,list,update,revoke}` at **0.1 and 0.2**.
//!
//! 0.2 is AclEntry 0.2 — role-based administration with every axis stated
//! (`docs/05-design-notes/vtc-admin-roles.md`). 0.1 keeps working through the
//! mapping `acl/_shared/0.2` CONVENTIONS §8 describes, in [`crate::routes::acl`].
//!
//! Every handler is the same shape: authority from the **verified signer's ACL
//! row**, read now ([`super::admin_signer`]); the payload held to its
//! published schema ([`super::parse_spec_payload`]); then the one shared
//! operation in [`crate::routes::acl`]. Writing an entry takes
//! `vtc.roles.assign` and is bounded by the writer's own entry
//! ([`crate::acl::granting`], §6.3). Reading the ACL takes any administrative
//! role. The ACL has no REST route: this is the only door, on every transport.
//!
//! A passkey gesture is one **bound to this document's payload**
//! ([`settle_signed_gate`]), never a session's; granting an
//! authority-conferring capability also parks for its other holders' consent
//! (**VTI-APV-018**).

use serde_json::{Value, json};
use trust_tasks_rs::specs::acl::{
    change_role::v0_1 as acl_change_role, change_role::v0_2 as acl_change_role_v0_2,
    grant::v0_1 as acl_grant, grant::v0_2 as acl_grant_v0_2, list::v0_1 as acl_list,
    list::v0_2 as acl_list_v0_2, revoke::v0_1 as acl_revoke, revoke::v0_2 as acl_revoke_v0_2,
    show::v0_1 as acl_show, show::v0_2 as acl_show_v0_2, update::v0_1 as acl_update,
    update::v0_2 as acl_update_v0_2,
};
use trust_tasks_rs::{RejectReason, StandardCode, TrustTask, TrustTaskCode};
use vti_common::auth::extractor::AuthClaims;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, parse_payload, reject_with,
    reject_with_code, success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::capability::CeilingError;
use crate::acl::granting::GrantRefusal;
use crate::error::{AppError, TaskError};
use crate::routes::acl::{self as ops, EntryParseError, WriteError};
use crate::server::AppState;

// ─── reading ─────────────────────────────────────────────────────────────

/// `acl/show/0.1` — one entry. An entry 0.1 cannot express is refused, naming
/// `acl/show/0.2`.
pub(super) async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: acl_show::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match ops::show_entry(state, &actor, checked.subject.as_str()).await {
        Ok(envelope) => success_response(&doc, envelope),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `acl/list/0.1` — the entries 0.1 can express, filtered and paged.
pub(super) async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let _checked: acl_list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let query: ops::ListAclQuery = match parse_payload(&doc) {
        Ok(q) => q,
        Err(reject) => return reject,
    };
    match ops::list_entries(state, &actor, &query).await {
        Ok(page) => success_response(&doc, page),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `acl/show/0.2` — one entry with every axis stated, or `entry: null`.
pub(super) async fn handle_show_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: acl_show_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let rendered = ops::show_entry_v0_2(state, &actor.did, checked.subject.as_str())
        .await
        .and_then(ops::conform::<acl_show_v0_2::Response>);
    match rendered {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `acl/list/0.2` — every entry the filters match. The filters include
/// `capability` and `resource` (with `direction`), the questions role-based
/// administration asks: who holds `git.repo.manage` inside a namespace, who can
/// assign roles.
pub(super) async fn handle_list_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let query: acl_list_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let rendered = ops::list_entries_v0_2(state, &actor.did, &query)
        .await
        .and_then(ops::conform::<acl_list_v0_2::Response>);
    match rendered {
        Ok(response) => success_response(&doc, response),
        Err(AppError::InvalidCursor) => reject_with_code(
            &doc,
            extended_code(acl_list_v0_2::error_codes::CURSOR_MISMATCH.code),
            "the cursor was minted under other filters, or by another node",
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── writing, 0.1 ────────────────────────────────────────────────────────

/// Render a write refusal for a 0.1 door. 0.1 declares only
/// `roleNotRecognized` (grant); every bound the granter's entry sets is
/// `permissionDenied`, with the reason in the message.
fn refuse_v0_1(
    doc: &TrustTask<Value>,
    e: WriteError,
    role_not_recognized: Option<&'static str>,
) -> TrustTaskOutcome {
    match e {
        WriteError::Task(t) => task_error_to_reject(doc, &t),
        WriteError::Refused(GrantRefusal::Ceiling(CeilingError::RoleNotRecognized(r)))
            if role_not_recognized.is_some() =>
        {
            reject_with_code(
                doc,
                extended_code(role_not_recognized.unwrap_or_default()),
                format!("'{r}' is not a role this community can grant"),
                None,
            )
        }
        WriteError::Refused(r) => app_error_to_reject(doc, &AppError::Forbidden(r.to_string())),
    }
}

/// `acl/grant/0.1` — write the entry the maintainer should hold for a subject.
///
/// The 0.1 entry is a community role: its administrative authority is what the
/// role implies (`routes::acl` module docs). A grant that confers
/// administrative authority needs a passkey gesture **bound to this grant**,
/// and one that confers an authority-conferring capability also the consent of
/// its other holders.
pub(super) async fn handle_grant(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let _checked: acl_grant::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    // The generated entry also carries the VTA's `approve`, `stepUp` and
    // `allowedKeys`, which a 0.1 VTC entry has no field for, so they are
    // refused rather than dropped.
    let body: ops::CreateAclRequest = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let plan = match ops::plan_grant(state, &actor, body).await {
        Ok(p) => p,
        Err(e) => {
            return refuse_v0_1(
                &doc,
                e,
                Some(acl_grant::error_codes::ROLE_NOT_RECOGNIZED.code),
            );
        }
    };
    let reduced = match settle_signed_gate(state, &actor, &doc, &plan).await {
        Ok(u) => u,
        Err(refusal) => return refusal,
    };
    commit_settled(state, &actor, &doc, plan, reduced, Render::V0_1).await
}

/// `acl/update/0.1` — amend an existing entry's label or expiry.
///
/// `scopes` names contexts a community does not hold, and is refused. An entry
/// 0.1 cannot express is refused too: use `acl/update/0.2`.
pub(super) async fn handle_update(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use acl_update::error_codes;

    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    // Named before the schema check, which would otherwise answer "unknown
    // field" for the one mistake this task declares a code for.
    if doc.payload.get("role").is_some() {
        return task_error_to_reject(
            &doc,
            &TaskError::declared(
                error_codes::ROLE_CHANGE_NOT_PERMITTED.code,
                AppError::Validation(
                    "acl/update does not change a role — use acl/change-role, which takes the \
                     current role as a compare-and-swap"
                        .into(),
                ),
            ),
        );
    }
    let _checked: acl_update::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    for member in ["allowedKeys", "approve", "stepUp"] {
        if doc.payload.get(member).is_some() {
            return app_error_to_reject(
                &doc,
                &AppError::Validation(format!(
                    "acl/update/0.1 cannot set `{member}` on a community entry — use \
                     acl/update/0.2, which states every axis"
                )),
            );
        }
    }
    let req: ops::UpdateEntryRequest = match parse_payload(&doc) {
        Ok(r) => r,
        Err(reject) => return reject,
    };
    let plan = match ops::plan_update(state, &actor, req).await {
        Ok(p) => p,
        Err(e) => return refuse_v0_1(&doc, e, None),
    };
    let reduced = match settle_signed_gate(state, &actor, &doc, &plan).await {
        Ok(u) => u,
        Err(refusal) => return refusal,
    };
    commit_settled(state, &actor, &doc, plan, reduced, Render::V0_1).await
}

/// `acl/revoke/0.1` — remove an entry. A community entry holds no scopes, so
/// a scope reduction names nothing held.
///
/// The last holder of `vtc.roles.assign` is protected
/// (`acl/revoke:lastAuthorityProtected`, VTI-APV-009), and a member's entry is
/// refused in favour of the leave ceremony. Revoking an **administrator** takes
/// a passkey gesture bound to this document, and taking authority-conferring
/// capabilities away also the consent of another of their holders
/// (**VTI-APV-019**).
pub(super) async fn handle_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let req: acl_revoke::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let scopes: Vec<String> = req.scopes.iter().map(|s| s.to_string()).collect();
    let reason = req.reason.as_ref().map(|r| r.to_string());
    match ops::revoke_entry(
        state,
        &actor,
        &req.subject,
        (!scopes.is_empty()).then_some(scopes.as_slice()),
        reason.as_deref(),
        crate::acl::admin_consent::Operation {
            type_uri: super::ACL_REVOKE_TYPE,
            payload: &doc.payload,
        },
    )
    .await
    {
        Ok(response) => success_response(&doc, response),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

/// `acl/change-role/0.1` — move a subject's **community** role, with the
/// administrative authority it implies, through the role-change ceremony.
pub(super) async fn handle_change_role(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: acl_change_role::Payload = match parse_spec_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };
    let mut body = doc.payload.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("subject");
    }
    let req: ops::UpdateAclRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("payload parse: {e}"),
                },
            );
        }
    };
    match ops::change_role_inner(
        state,
        &actor,
        checked.subject.as_str(),
        req,
        crate::ceremony::StepUpSource::BoundTo {
            type_uri: super::ACL_CHANGE_ROLE_TYPE,
            payload: &doc.payload,
        },
    )
    .await
    {
        Ok(ops::ChangeRoleOutcome::Changed(envelope)) => success_response(&doc, *envelope),
        Ok(ops::ChangeRoleOutcome::StepUpRequired(request)) => reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            "a passkey gesture bound to this role change is required",
            Some(crate::acl::bound_step_up::refusal_details(&request)),
        ),
        Err(AppError::Conflict(m)) if m.starts_with("state mismatch") => reject_with_code(
            &doc,
            extended_code(acl_change_role::error_codes::STATE_MISMATCH.code),
            m,
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── writing, 0.2 ────────────────────────────────────────────────────────

/// The declared codes of the 0.2 write task being answered: each `None` where
/// the task declares no such code, which then answers `permissionDenied` or
/// `malformedRequest` (CONVENTIONS §3: never borrow a code another slug
/// declares).
#[derive(Clone, Copy)]
struct V02Codes {
    role_not_recognized: Option<&'static str>,
    invalid_act_scope: Option<&'static str>,
    unknown_capability: Option<&'static str>,
    capability_outside_ceiling: Option<&'static str>,
    additive_within_ceiling: Option<&'static str>,
    additive_requires_unrestricted: Option<&'static str>,
    approve_wider_than_granter: Option<&'static str>,
    delegation_exceeds_granter: Option<&'static str>,
}

const GRANT_V0_2: V02Codes = {
    use acl_grant_v0_2::error_codes as c;
    V02Codes {
        role_not_recognized: Some(c::ROLE_NOT_RECOGNIZED.code),
        invalid_act_scope: Some(c::INVALID_ACT_SCOPE.code),
        unknown_capability: Some(c::UNKNOWN_CAPABILITY.code),
        capability_outside_ceiling: Some(c::CAPABILITY_OUTSIDE_CEILING.code),
        additive_within_ceiling: Some(c::ADDITIVE_WITHIN_CEILING.code),
        additive_requires_unrestricted: Some(c::ADDITIVE_REQUIRES_UNRESTRICTED.code),
        approve_wider_than_granter: Some(c::APPROVE_WIDER_THAN_GRANTER.code),
        delegation_exceeds_granter: Some(c::DELEGATION_EXCEEDS_GRANTER.code),
    }
};

const UPDATE_V0_2: V02Codes = {
    use acl_update_v0_2::error_codes as c;
    V02Codes {
        role_not_recognized: None,
        invalid_act_scope: Some(c::INVALID_ACT_SCOPE.code),
        unknown_capability: Some(c::UNKNOWN_CAPABILITY.code),
        capability_outside_ceiling: Some(c::CAPABILITY_OUTSIDE_CEILING.code),
        additive_within_ceiling: Some(c::ADDITIVE_WITHIN_CEILING.code),
        additive_requires_unrestricted: Some(c::ADDITIVE_REQUIRES_UNRESTRICTED.code),
        approve_wider_than_granter: Some(c::APPROVE_WIDER_THAN_GRANTER.code),
        delegation_exceeds_granter: Some(c::DELEGATION_EXCEEDS_GRANTER.code),
    }
};

const CHANGE_ROLE_V0_2: V02Codes = {
    use acl_change_role_v0_2::error_codes as c;
    V02Codes {
        role_not_recognized: Some(c::ROLE_NOT_RECOGNIZED.code),
        invalid_act_scope: None,
        unknown_capability: None,
        capability_outside_ceiling: Some(c::CAPABILITY_OUTSIDE_CEILING.code),
        additive_within_ceiling: Some(c::ADDITIVE_WITHIN_CEILING.code),
        additive_requires_unrestricted: None,
        approve_wider_than_granter: None,
        delegation_exceeds_granter: Some(c::DELEGATION_EXCEEDS_GRANTER.code),
    }
};

fn coded(
    doc: &TrustTask<Value>,
    code: Option<&'static str>,
    message: String,
    details: Option<Value>,
) -> TrustTaskOutcome {
    match code {
        Some(code) => reject_with_code(doc, extended_code(code), message, details),
        None => reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            message,
            None,
        ),
    }
}

fn malformed(doc: &TrustTask<Value>, reason: String) -> TrustTaskOutcome {
    reject_with(doc, RejectReason::MalformedRequest { reason })
}

/// Render a parse refusal in the codes of the task answered.
fn refuse_parse(doc: &TrustTask<Value>, e: EntryParseError, codes: V02Codes) -> TrustTaskOutcome {
    match e {
        EntryParseError::RoleNotRecognized(r) => coded(
            doc,
            codes.role_not_recognized,
            format!("'{r}' is not a role this community can grant"),
            Some(json!({
                "offendingRole": r,
                "knownRoles": std::iter::once(ops::NO_ADMIN_ROLE.to_string())
                    .chain(crate::acl::AdminRole::BUILT_IN.iter().map(|r| r.to_string()))
                    .collect::<Vec<_>>(),
            })),
        ),
        EntryParseError::InvalidActScope(member, contexts) => match codes.invalid_act_scope {
            Some(code) => reject_with_code(
                doc,
                extended_code(code),
                format!(
                    "a community holds no contexts (VTI-VTC-010): `{member}` is `all` or `none`"
                ),
                Some(json!({ "member": member, "offendingContexts": contexts })),
            ),
            None => malformed(
                doc,
                format!("`{member}` names contexts a community does not hold"),
            ),
        },
        EntryParseError::UnknownCapability(caps) => match codes.unknown_capability {
            Some(code) => reject_with_code(
                doc,
                extended_code(code),
                format!(
                    "{} {} not in this community's capability registry (VTI-ACL-032)",
                    caps.join(", "),
                    if caps.len() == 1 { "is" } else { "are" }
                ),
                Some(json!({ "capabilities": caps })),
            ),
            None => malformed(doc, format!("unknown capabilities: {}", caps.join(", "))),
        },
        EntryParseError::Malformed(m) => malformed(doc, m),
    }
}

/// Render a write refusal in the codes of the task answered.
fn refuse_write(
    doc: &TrustTask<Value>,
    e: WriteError,
    codes: V02Codes,
    role: &str,
) -> TrustTaskOutcome {
    let r = match e {
        WriteError::Task(t) => return task_error_to_reject(doc, &t),
        WriteError::Refused(r) => r,
    };
    let message = r.to_string();
    match r {
        GrantRefusal::PermissionDenied(m) => app_error_to_reject(doc, &AppError::Forbidden(m)),
        GrantRefusal::DelegationExceedsGranter { axes, .. } => coded(
            doc,
            codes.delegation_exceeds_granter,
            message,
            Some(json!({ "axes": axes })),
        ),
        GrantRefusal::ApproveWiderThanGranter(_) => {
            coded(doc, codes.approve_wider_than_granter, message, None)
        }
        GrantRefusal::AdditiveRequiresUnrestricted => {
            coded(doc, codes.additive_requires_unrestricted, message, None)
        }
        GrantRefusal::Ceiling(CeilingError::RoleNotRecognized(r)) => {
            refuse_parse(doc, EntryParseError::RoleNotRecognized(r), codes)
        }
        GrantRefusal::Ceiling(CeilingError::OutsideCeiling(caps)) => coded(
            doc,
            codes.capability_outside_ceiling,
            message,
            Some(json!({ "role": role, "capabilities": caps })),
        ),
        GrantRefusal::Ceiling(CeilingError::AdditiveWithinCeiling(caps)) => coded(
            doc,
            codes.additive_within_ceiling,
            message,
            Some(json!({ "capabilities": caps })),
        ),
        GrantRefusal::Ceiling(CeilingError::BadQualifier(_) | CeilingError::NeedsQualifiers(_)) => {
            malformed(doc, message)
        }
    }
}

/// `acl/grant/0.2` — the entry the maintainer should hold, every axis stated.
pub(super) async fn handle_grant_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    // Unknown capabilities are named under their own code (VTI-ACL-032), so
    // they are read before the schema's generic refusal could fire.
    if let Some(e) = doc.payload.get("entry") {
        for member in ["capabilities", "approveCapabilities"] {
            if let Some(v) = e.get(member)
                && let Err(err @ EntryParseError::UnknownCapability(_)) = ops::parse_capabilities(v)
            {
                return refuse_parse(&doc, err, GRANT_V0_2);
            }
        }
    }
    let _checked: acl_grant_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let next = match ops::entry_from_v0_2(&doc.payload["entry"]) {
        Ok(n) => n,
        Err(e) => return refuse_parse(&doc, e, GRANT_V0_2),
    };
    let role = ops::role_string(&next);
    let reason = doc.payload["reason"].as_str().map(str::to_string);
    let plan = match ops::plan_grant_v0_2(state, &actor.did, next, reason).await {
        Ok(p) => p,
        Err(e) => return refuse_write(&doc, e, GRANT_V0_2, &role),
    };
    let reduced = match settle_signed_gate(state, &actor, &doc, &plan).await {
        Ok(u) => u,
        Err(refusal) => return refusal,
    };
    commit_settled(state, &actor, &doc, plan, reduced, Render::Grant).await
}

/// `acl/update/0.2` — replace axes of an existing entry. Narrowing `act` is a
/// revocation (`narrowingNotPermitted`); every other axis may narrow here, as
/// a privilege reduction applied at the subject's next decision.
pub(super) async fn handle_update_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use acl_update_v0_2::error_codes;
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    if doc.payload.get("role").is_some() {
        return task_error_to_reject(
            &doc,
            &TaskError::declared(
                error_codes::ROLE_CHANGE_NOT_PERMITTED.code,
                AppError::Validation(
                    "acl/update does not change a role — use acl/change-role/0.2".into(),
                ),
            ),
        );
    }
    for member in ["capabilities", "approveCapabilities"] {
        if let Some(v) = doc.payload.get(member)
            && let Err(err @ EntryParseError::UnknownCapability(_)) = ops::parse_capabilities(v)
        {
            return refuse_parse(&doc, err, UPDATE_V0_2);
        }
    }
    let _checked: acl_update_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let plan = match ops::plan_update_v0_2(state, &actor.did, &doc.payload).await {
        Ok(p) => p,
        Err(ops::UpdateV02Error::Parse(e)) => return refuse_parse(&doc, e, UPDATE_V0_2),
        Err(ops::UpdateV02Error::NarrowingNotPermitted) => {
            return task_error_to_reject(
                &doc,
                &TaskError::declared(
                    error_codes::NARROWING_NOT_PERMITTED.code,
                    AppError::Validation(
                        "narrowing the act scope is a revocation: use acl/revoke/0.2 with \
                         {\"kind\": \"act\", \"act\": {\"scope\": \"none\"}}"
                            .into(),
                    ),
                ),
            );
        }
        Err(ops::UpdateV02Error::Write(e)) => {
            let role = doc.payload["subject"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            return refuse_write(&doc, e, UPDATE_V0_2, &role);
        }
    };
    let reduced = match settle_signed_gate(state, &actor, &doc, &plan).await {
        Ok(u) => u,
        Err(refusal) => return refusal,
    };
    commit_settled(state, &actor, &doc, plan, reduced, Render::Update).await
}

/// `acl/change-role/0.2` — move the **administrative** role, compare-and-swap
/// on `fromRole`. Every other axis is carried over and re-checked against the
/// new role's ceiling; the community role is unchanged.
pub(super) async fn handle_change_role_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use acl_change_role_v0_2::error_codes;
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: acl_change_role_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let to = match ops::parse_admin_role(checked.to_role.as_str()) {
        Ok(r) => r,
        Err(e) => return refuse_parse(&doc, e, CHANGE_ROLE_V0_2),
    };
    if let Err(e) = ops::parse_admin_role(checked.from_role.as_str()) {
        return refuse_parse(&doc, e, CHANGE_ROLE_V0_2);
    }
    let plan = match ops::plan_change_role_v0_2(
        state,
        &actor.did,
        checked.subject.as_str(),
        checked.from_role.as_str(),
        to,
    )
    .await
    {
        Ok(p) => p,
        Err(ops::ChangeRoleV02Error::StateMismatch(current)) => {
            return reject_with_code(
                &doc,
                extended_code(error_codes::STATE_MISMATCH.code),
                format!(
                    "state mismatch: {} currently holds role {current}, not {}",
                    checked.subject.as_str(),
                    checked.from_role.as_str()
                ),
                Some(json!({ "currentRole": current })),
            );
        }
        Err(ops::ChangeRoleV02Error::Write(e)) => {
            return refuse_write(&doc, e, CHANGE_ROLE_V0_2, checked.to_role.as_str());
        }
    };
    let reduced = match settle_signed_gate(state, &actor, &doc, &plan).await {
        Ok(u) => u,
        Err(refusal) => return refusal,
    };
    commit_settled(state, &actor, &doc, plan, reduced, Render::ChangeRole).await
}

/// `acl/revoke/0.2` — `{kind: entry}` removes the entry; `{kind: act}` narrows
/// its act scope (at a community node, `all` → `none`).
pub(super) async fn handle_revoke_v0_2(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use acl_revoke_v0_2::error_codes;
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let checked: acl_revoke_v0_2::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let subject = checked.subject.to_string();
    let revocation = &doc.payload["revocation"];
    let op = crate::acl::admin_consent::Operation {
        type_uri: super::ACL_REVOKE_V0_2_TYPE,
        payload: &doc.payload,
    };
    if revocation["kind"] == "entry" {
        let reason = doc.payload["reason"].as_str();
        return match ops::remove_entry(
            state,
            &actor.did,
            &subject,
            reason,
            op,
            error_codes::SUBJECT_NOT_PRESENT.code,
            error_codes::LAST_AUTHORITY_PROTECTED.code,
        )
        .await
        {
            Ok(()) => success_response(&doc, json!({ "entry": null })),
            Err(e) => task_error_to_reject(&doc, &e),
        };
    }
    let act = match ops::parse_scope(&revocation["act"], "act") {
        Ok(a) => a,
        Err(EntryParseError::InvalidActScope(_, contexts)) => {
            return reject_with_code(
                &doc,
                extended_code(error_codes::INVALID_ACT_SCOPE.code),
                "a community holds no contexts (VTI-VTC-010): narrow `act` to `none`",
                Some(json!({ "offendingContexts": contexts })),
            );
        }
        Err(_) => return malformed(&doc, "revocation.act is not an explicit scope".into()),
    };
    let plan = match ops::plan_narrow_act(state, &actor.did, &subject, act).await {
        Ok(p) => p,
        Err(ops::NarrowActError::NotPresent) => {
            return task_error_to_reject(
                &doc,
                &TaskError::declared(
                    error_codes::SUBJECT_NOT_PRESENT.code,
                    AppError::NotFound(format!("ACL entry not found for DID: {subject}")),
                ),
            );
        }
        Err(ops::NarrowActError::NotNarrowing) => {
            return reject_with_code(
                &doc,
                extended_code(error_codes::NOT_NARROWING.code),
                "the stated act scope is not strictly narrower than the entry's",
                None,
            );
        }
        Err(ops::NarrowActError::Write(e)) => {
            return match e {
                WriteError::Task(t) => task_error_to_reject(&doc, &t),
                WriteError::Refused(r) => {
                    app_error_to_reject(&doc, &AppError::Forbidden(r.to_string()))
                }
            };
        }
    };
    let reduced = match settle_signed_gate(state, &actor, &doc, &plan).await {
        Ok(u) => u,
        Err(refusal) => return refusal,
    };
    commit_settled(state, &actor, &doc, plan, reduced, Render::Revoke).await
}

// ─── rolling one's own entry to a new key ────────────────────────────────

/// `acl/swap-key/0.1` — the subject rolls its own entry to a new key, its
/// authority exactly as it was (**VTI-CLT-025 – 032**, VTI-ACL-052).
///
/// Signed by the subject itself — never a console key acting for it — and
/// carrying a link proof signed by the new key ([`ops::swap_key`]). No
/// gesture and no consent: nothing is granted, so there is nothing for anyone
/// else to agree to (VTI-APV-018 is about authority that did not exist before).
pub(super) async fn handle_swap_key(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use swap::error_codes as c;
    use trust_tasks_rs::specs::acl::swap_key::v0_1 as swap;
    let checked: swap::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let Some(signer) = ctx.verified_signer.as_deref() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let reason = doc.payload["reason"].as_str();
    let outcome = ops::swap_key(
        state,
        signer,
        checked.current_subject.as_str(),
        checked.new_subject.as_str(),
        doc.payload.get("linkProof"),
        reason,
    )
    .await;
    let (entry, repointed) = match outcome {
        Ok(ok) => ok,
        Err(ops::SwapError::NotHolder(m)) => {
            return reject_with_code(&doc, extended_code(c::NOT_HOLDER.code), m, None);
        }
        Err(ops::SwapError::SubjectNotFound(m)) => {
            return reject_with_code(&doc, extended_code(c::SUBJECT_NOT_FOUND.code), m, None);
        }
        Err(ops::SwapError::SubjectAlreadyInUse(m)) => {
            return reject_with_code(&doc, extended_code(c::SUBJECT_ALREADY_IN_USE.code), m, None);
        }
        Err(ops::SwapError::LinkProofRequired) => {
            return reject_with_code(
                &doc,
                extended_code(c::LINK_PROOF_REQUIRED.code),
                "this community requires a link proof: a VP-JWT (AclSwapRequest) signed by \
                 newSubject and addressed to this community (VTI-CLT-026)",
                None,
            );
        }
        Err(ops::SwapError::LinkProofInvalid(reason, m)) => {
            return reject_with_code(
                &doc,
                extended_code(c::LINK_PROOF_INVALID.code),
                m,
                Some(json!({ "reason": reason })),
            );
        }
        Err(ops::SwapError::App(e)) => return app_error_to_reject(&doc, &e),
    };
    let previous = checked.current_subject.to_string();
    let review = crate::acl::delegation::review_for(state, &entry.did)
        .await
        .ok()
        .flatten();
    let body = json!({
        "entry": ops::render_v0_1(entry.clone()),
        "previousSubject": previous,
        // 0.1's AclEntry cannot state an administrative role; the entry as it
        // now stands, every axis explicit, rides beside it.
        "ext": { "org.openvtc": {
            "entry": ops::render_v0_2(&entry, review.as_ref()),
            "delegationsRepointed": repointed,
        }},
    });
    match ops::conform::<swap::Response>(body) {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── the gate and the commit ─────────────────────────────────────────────

/// Settle what a planned ACL write needs before it may be written, on the
/// signed door.
///
/// - A write that **confers an authority-conferring capability** the subject
///   did not hold needs the requester's passkey gesture **and** the consent of
///   the capability's other holders at a covering qualifier (**VTI-APV-018**,
///   the generalised APV-014). It parks as an action and completes on the N-th
///   approval.
/// - A write that **takes authority away** from a live administrator needs the
///   gesture, and for authority-conferring capabilities their other holders'
///   consent, requester and subject excluded (**VTI-APV-019**).
///   `Ok(Some(prior))` means nobody else was left to give it: the caller
///   commits, then records the reduction at `Critical`.
/// - Any other widening of administrative authority needs the gesture.
///
/// Both are **bound to this document's type and payload** and spent by it
/// ([`crate::acl::bound_step_up`], [`crate::acl::admin_consent`]). Called after
/// every check that decides whether the write may happen and before any write.
/// `Ok(Some((prior, agreement)))` is a reduction of an administrator, cleared:
/// the caller commits, then tells the subject and records an unopposed one at
/// `Critical` ([`crate::acl::admin_consent::after_reduction`]).
pub(super) async fn settle_signed_gate(
    state: &AppState,
    actor: &AuthClaims,
    doc: &TrustTask<Value>,
    plan: &ops::GrantPlan,
) -> Result<
    Option<(
        crate::acl::VtcAclEntry,
        crate::acl::admin_consent::Agreement,
    )>,
    TrustTaskOutcome,
> {
    use crate::acl::bound_step_up::{self, Gate};

    let type_uri = doc.type_uri.to_string();
    let step_up_refusal = |request: &crate::acl::bound_step_up::ApproveRequest| {
        reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            "a passkey gesture bound to this operation is required",
            Some(bound_step_up::refusal_details(request)),
        )
    };
    let subject = &plan.entry.did;

    if !plan.conferred.is_empty() {
        use crate::acl::admin_consent::{self, Operation, SignedGate};
        let gate = admin_consent::gesture_then_consent(
            state,
            &actor.did,
            subject,
            &plan.conferred,
            Operation {
                type_uri: &type_uri,
                payload: &doc.payload,
            },
            &format!(
                "Give {subject} {}",
                plan.conferred
                    .iter()
                    .map(crate::acl::CapRef::display)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            &ops::conferral_summary(subject, &plan.conferred),
        )
        .await;
        let ready = match gate {
            Ok(SignedGate::Ready(ready)) => ready,
            Ok(SignedGate::StepUpRequired(request)) => return Err(step_up_refusal(&request)),
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        };
        ready
            .spend(state)
            .await
            .map_err(|e| app_error_to_reject(doc, &e))?;
    } else if let Some(prior) = plan.reduces_admin.as_ref() {
        // One gesture covers a rewrite that moves an administrator sideways —
        // some authority dropped, some conferred.
        let agreement = crate::acl::admin_consent::settle_reduction(
            state,
            &actor.did,
            prior,
            Some(&plan.entry),
            crate::acl::admin_consent::Operation {
                type_uri: &type_uri,
                payload: &doc.payload,
            },
            &format!("Reduce administrator {subject}'s authority"),
            &format!("Reduce administrator {subject}'s authority"),
        )
        .await
        .map_err(|e| task_error_to_reject(doc, &e))?;
        return Ok(agreement.map(|a| (prior.clone(), a)));
    } else if plan.widens {
        let reason = format!(
            "Grant administrative authority to {subject}: {}",
            crate::acl_cli::describe_authority(&plan.entry.admin)
        );
        match bound_step_up::redeem_or_request(state, &actor.did, &type_uri, &doc.payload, &reason)
            .await
        {
            Ok(Gate::Satisfied) => {}
            Ok(Gate::Required(request)) => return Err(step_up_refusal(&request)),
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        }
    }
    Ok(None)
}

/// The requester's bound gesture **and** the consent of the act's approvers,
/// both keyed on this document, settled on the signed door — the gate for the
/// acts that could undo APV-018 one step at a time: lowering the consent
/// threshold (**VTI-APV-020**) and changing a policy that decides authority
/// (**VTI-VTC-022**). Their approvers are the act's default stake
/// ([`crate::acl::admin_consent::Act::default_stake`]).
///
/// The consent is spent here, so call it last before the write.
pub(super) async fn settle_consent_gate(
    state: &AppState,
    actor: &AuthClaims,
    doc: &TrustTask<Value>,
    act: crate::acl::admin_consent::Act,
    subject: &str,
    gesture_reason: &str,
    consent_summary: &str,
) -> Result<(), TrustTaskOutcome> {
    use crate::acl::admin_consent::{self, Operation, SignedGate};
    let type_uri = doc.type_uri.to_string();
    let gate = admin_consent::gesture_then_consent_for(
        state,
        act,
        &[],
        &actor.did,
        subject,
        Operation {
            type_uri: &type_uri,
            payload: &doc.payload,
        },
        gesture_reason,
        consent_summary,
    )
    .await;
    let ready = match gate {
        Ok(SignedGate::Ready(ready)) => ready,
        Ok(SignedGate::StepUpRequired(request)) => {
            return Err(task_error_to_reject(doc, &TaskError::step_up(request)));
        }
        Err(e) => return Err(app_error_to_reject(doc, &e)),
    };
    ready
        .spend(state)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// How a committed write is answered: the 0.1 envelope, or the 0.2 response of
/// the task asked.
#[derive(Clone, Copy)]
enum Render {
    V0_1,
    Grant,
    Update,
    ChangeRole,
    Revoke,
}

/// Commit a planned ACL write whose gate ([`settle_signed_gate`]) has
/// settled, and record an unopposed reduction (VTI-APV-019) once it has
/// landed.
async fn commit_settled(
    state: &AppState,
    actor: &AuthClaims,
    doc: &TrustTask<Value>,
    plan: ops::GrantPlan,
    reduced: Option<(
        crate::acl::VtcAclEntry,
        crate::acl::admin_consent::Agreement,
    )>,
    render: Render,
) -> TrustTaskOutcome {
    let entry = match ops::commit_grant(state, &actor.did, plan).await {
        Ok((_status, entry)) => entry,
        Err(e) => return app_error_to_reject(doc, &e),
    };
    // A reduction of an administrator, once it has landed: the subject is
    // told, and an unopposed one is recorded at `Critical` (VTI-APV-019).
    if let Some((prior, agreement)) = reduced
        && let Err(e) = crate::acl::admin_consent::after_reduction(
            state,
            &actor.did,
            &prior,
            Some(&entry),
            agreement,
            &doc.type_uri.to_string(),
            doc.payload["reason"].as_str(),
            true,
        )
        .await
    {
        return app_error_to_reject(doc, &e);
    }
    if entry.admin.is_administrator()
        && let Err(e) = ops::ensure_admin_sister_record(state, &entry.did).await
    {
        return app_error_to_reject(doc, &e);
    }
    let v = || json!({ "entry": ops::render_v0_2(&entry, None) });
    let response = match render {
        Render::V0_1 => return success_response(doc, ops_v0_1(&entry)),
        Render::Grant => ops::conform::<acl_grant_v0_2::Response>(v()).map(|r| json!(r)),
        Render::Update => ops::conform::<acl_update_v0_2::Response>(v()).map(|r| json!(r)),
        Render::ChangeRole => ops::conform::<acl_change_role_v0_2::Response>(v()).map(|r| json!(r)),
        Render::Revoke => ops::conform::<acl_revoke_v0_2::Response>(v()).map(|r| json!(r)),
    };
    match response {
        Ok(r) => success_response(doc, r),
        Err(e) => app_error_to_reject(doc, &e),
    }
}

/// The 0.1 rendering of a just-written entry. A 0.1 write writes only what
/// 0.1 can express, so it always renders.
fn ops_v0_1(entry: &crate::acl::VtcAclEntry) -> ops::AclEntryEnvelope {
    ops::AclEntryEnvelope {
        entry: ops::render_v0_1(entry.clone()),
    }
}

/// Each `acl/*` task through the spine, as every transport hands it over.
///
/// The spine is the single place REST, DIDComm and TSP meet, so each task is
/// driven through [`super::dispatch_trust_task_core`] once per
/// [`crate::join::JoinTransport`]. The role-based behaviour through the real
/// router is `tests/it/admin_roles.rs`; the live-mediator round trip is
/// `tests/it/acl_trust_tasks.rs`.
#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use vti_rooms_dtg::test_support::Party;

    use super::super::members_admin_tests::{
        assert_conforms, error_code, payload_of, signed, unsigned,
    };
    use super::super::{
        ACL_GRANT_V0_2_TYPE, ACL_LIST_V0_2_TYPE, ACL_REVOKE_V0_2_TYPE, ACL_SHOW_V0_2_TYPE,
        ACL_UPDATE_V0_2_TYPE, JoinAuthCtx, TrustTaskOutcome, dispatch_trust_task_core,
    };
    use super::{acl_list_v0_2, acl_revoke_v0_2, acl_show_v0_2};
    use crate::acl::{
        AdminAuthority, AdminRole, VtcAclEntry, VtcRole, get_acl_entry, store_acl_entry,
    };
    use crate::join::JoinTransport;
    use crate::test_support::TestVtc;
    use trust_tasks_rs::TrustTask;

    const TRANSPORTS: [JoinTransport; 3] = [
        JoinTransport::Rest,
        JoinTransport::DIDComm,
        JoinTransport::Tsp,
    ];

    /// The subject every test acts on: an auditor.
    const TARGET: &str = "did:key:zAclTaskTarget";

    struct Fixture {
        vtc: TestVtc,
        /// A community administrator with the full ceiling.
        admin: Party,
        /// A member: authenticated, authorized for none of this.
        member: Party,
    }

    async fn seed(vtc: &TestVtc, did: &str, role: VtcRole, admin: AdminAuthority) {
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: did.into(),
                role,
                label: None,
                admin,
                delegated_by: None,
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
                resource_grants: Vec::new(),
            },
        )
        .await
        .expect("seed ACL row");
    }

    async fn fixture() -> Fixture {
        let vtc = TestVtc::builder()
            .with_audit(true)
            .with_signers(true)
            .build()
            .await;
        crate::policy::default::install_defaults(
            &vtc.state.policies_ks,
            &vtc.state.active_policies_ks,
        )
        .await
        .expect("install default policies");
        let (admin, member) = (Party::new(), Party::new());
        seed(
            &vtc,
            &admin.did,
            VtcRole::Admin,
            AdminAuthority::community_admin(),
        )
        .await;
        seed(&vtc, &member.did, VtcRole::Member, AdminAuthority::none()).await;
        seed(
            &vtc,
            TARGET,
            VtcRole::Member,
            AdminAuthority::for_role(AdminRole::Auditor),
        )
        .await;
        Fixture { vtc, admin, member }
    }

    fn ctx(transport: JoinTransport, from: &Party) -> JoinAuthCtx {
        match transport {
            JoinTransport::Rest => JoinAuthCtx::rest(),
            _ => JoinAuthCtx {
                transport,
                sender_did: Some(from.did.clone()),
                verified_signer: None,
            },
        }
    }

    async fn dispatch_doc(
        vtc: &TestVtc,
        transport: JoinTransport,
        from: &Party,
        doc: &TrustTask<Value>,
    ) -> TrustTaskOutcome {
        let body = serde_json::to_vec(doc).expect("a document serialises");
        dispatch_trust_task_core(&vtc.state, &ctx(transport, from), &body).await
    }

    async fn send(
        vtc: &TestVtc,
        transport: JoinTransport,
        from: &Party,
        uri: &str,
        payload: Value,
    ) -> TrustTaskOutcome {
        let doc = signed(from, uri, payload).await;
        dispatch_doc(vtc, transport, from, &doc).await
    }

    /// What the specifications declare, which the unsigned-document test
    /// below rests on.
    #[test]
    fn the_0_2_writes_declare_a_proof_and_the_reads_do_not() {
        let required = |uri| {
            trust_tasks_rs::schema_index::spec_policy_for(uri)
                .unwrap_or_else(|| panic!("{uri} has no published policy"))
                .is_proof_required
        };
        assert!(required(ACL_GRANT_V0_2_TYPE));
        assert!(required(ACL_UPDATE_V0_2_TYPE));
        assert!(required(ACL_REVOKE_V0_2_TYPE));
        assert!(!required(ACL_SHOW_V0_2_TYPE));
        assert!(!required(ACL_LIST_V0_2_TYPE));
    }

    /// `acl/show/0.2` and `acl/list/0.2` answer an administrator on every
    /// transport with responses that conform to the published schemas, and
    /// refuse a member.
    #[tokio::test]
    async fn the_0_2_reads_conform_on_every_transport() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let out = send(
                &fix.vtc,
                t,
                &fix.admin,
                ACL_SHOW_V0_2_TYPE,
                json!({ "subject": TARGET }),
            )
            .await;
            assert!(out.status.is_success(), "{t:?}: {}", payload_of(&out));
            assert_conforms::<acl_show_v0_2::Response>(&out);
            assert_eq!(payload_of(&out)["entry"]["role"], "auditor");

            let out = send(&fix.vtc, t, &fix.admin, ACL_LIST_V0_2_TYPE, json!({})).await;
            assert!(out.status.is_success(), "{t:?}: {}", payload_of(&out));
            assert_conforms::<acl_list_v0_2::Response>(&out);

            let out = send(&fix.vtc, t, &fix.member, ACL_LIST_V0_2_TYPE, json!({})).await;
            assert!(!out.status.is_success(), "{t:?}: a member reads nothing");
        }
    }

    /// `acl/update/0.2` narrows capabilities as a privilege reduction. The
    /// subject is an administrator, so the reduction takes the requester's
    /// bound gesture first (VTI-APV-019), and nothing moves without it.
    #[tokio::test]
    async fn narrowing_an_administrator_asks_for_a_bound_gesture() {
        let fix = fixture().await;
        let out = send(
            &fix.vtc,
            JoinTransport::Rest,
            &fix.admin,
            ACL_UPDATE_V0_2_TYPE,
            json!({ "subject": TARGET, "capabilities": {"scope": "none"} }),
        )
        .await;
        assert_eq!(error_code(&out).as_deref(), Some("permissionDenied"));
        // The fixture's administrator holds no passkey, so the refusal names
        // the gesture it cannot give (with one, it carries the ceremony as
        // `details.stepUpRequest`).
        assert!(
            payload_of(&out)["message"]
                .as_str()
                .is_some_and(|m| m.contains("step-up required")),
            "{}",
            payload_of(&out)
        );
        let entry = get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.admin, AdminAuthority::for_role(AdminRole::Auditor));
    }

    /// Writing a member entry with no administrative authority confers
    /// nothing, so no gesture is asked; the realized entry is answered in the
    /// 0.2 shape and conforms.
    #[tokio::test]
    async fn a_grant_conferring_nothing_lands_without_a_gesture() {
        let fix = fixture().await;
        let subject = Party::new();
        let out = send(
            &fix.vtc,
            JoinTransport::Rest,
            &fix.admin,
            ACL_GRANT_V0_2_TYPE,
            json!({ "entry": {
                "subject": subject.did,
                "role": "member",
                "act": {"scope": "none"},
                "keys": {"scope": "none"},
                "capabilities": {"scope": "none"},
            }}),
        )
        .await;
        assert!(out.status.is_success(), "{}", payload_of(&out));
        let entry = get_acl_entry(&fix.vtc.state.acl_ks, &subject.did)
            .await
            .unwrap()
            .expect("written");
        assert_eq!(entry.admin, AdminAuthority::none());
        assert_eq!(entry.delegated_by, None, "no authority, no delegation");
    }

    /// `acl/revoke/0.2` with `{kind: act}` and a `none` act scope on an entry
    /// already acting nowhere is not a narrowing.
    #[tokio::test]
    async fn revoke_0_2_refuses_a_narrowing_that_is_not_one() {
        let fix = fixture().await;
        let out = send(
            &fix.vtc,
            JoinTransport::Rest,
            &fix.admin,
            ACL_REVOKE_V0_2_TYPE,
            json!({ "subject": fix.member.did, "revocation": {"kind": "act", "act": {"scope": "none"}} }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(acl_revoke_v0_2::error_codes::NOT_NARROWING.code)
        );
        let out = send(
            &fix.vtc,
            JoinTransport::Rest,
            &fix.admin,
            ACL_REVOKE_V0_2_TYPE,
            json!({ "subject": "did:key:zNobody", "revocation": {"kind": "entry"} }),
        )
        .await;
        assert_eq!(
            error_code(&out).as_deref(),
            Some(acl_revoke_v0_2::error_codes::SUBJECT_NOT_PRESENT.code)
        );
    }

    /// VTI-OPS-020 / -021: the 0.2 writes declare a proof, and an unsigned one
    /// is refused on every transport before it reaches the ACL.
    #[tokio::test]
    async fn vti_ops_020_an_unsigned_0_2_document_is_refused() {
        for t in TRANSPORTS {
            let fix = fixture().await;
            let doc = unsigned(
                &fix.admin,
                ACL_UPDATE_V0_2_TYPE,
                json!({ "subject": TARGET, "label": "x" }),
            );
            let out = dispatch_doc(&fix.vtc, t, &fix.admin, &doc).await;
            assert_eq!(error_code(&out).as_deref(), Some("proofRequired"), "{t:?}");
        }
    }

    /// Over DIDComm and TSP the transport's sender must be the signer.
    #[tokio::test]
    async fn a_0_2_document_relayed_by_another_sender_is_refused() {
        for t in [JoinTransport::DIDComm, JoinTransport::Tsp] {
            let fix = fixture().await;
            let doc = signed(
                &fix.admin,
                ACL_REVOKE_V0_2_TYPE,
                json!({ "subject": TARGET, "revocation": {"kind": "entry"} }),
            )
            .await;
            let out = dispatch_doc(&fix.vtc, t, &fix.member, &doc).await;
            assert!(!out.status.is_success(), "{t:?}");
            assert!(
                get_acl_entry(&fix.vtc.state.acl_ks, TARGET)
                    .await
                    .unwrap()
                    .is_some(),
                "{t:?}"
            );
        }
    }
}
