//! Step-up approvers on the signed-document spine —
//! `auth/step-up/approver/{invite,redeem/start,redeem/finish,enroll,list,
//! revoke}/0.1`. The operations are [`crate::step_up_approver`]'s; this file
//! decides only who is asking.
//!
//! Every one arrives here the same way over TSP, DIDComm or HTTPS, and there is
//! no other door: no REST route issues, redeems, enrols, lists or revokes one.
//! Each declares its proof REQUIRED, so the spine has verified it before
//! dispatch.
//!
//! | task | signed by | authority |
//! |---|---|---|
//! | `invite` | a community administrator ([`admin_signer`]), never for themselves | their ACL row, **and** their own step-up bound to this document |
//! | `redeem/start`, `redeem/finish` | the invited subject's **own** DID — a console key is refused | the invite token, its claim code and the signer, together |
//! | `enroll` | the subject's **own** DID — a console key is refused | a step-up factor the subject already holds, bound to these terms |
//! | `list` | the subject (or a console key acting for them), or an administrator over the subject | the subject's own standing, or the administrator's ACL row |
//! | `revoke` | as `list` | as `list`, **and** the caller's own step-up bound to this document |

use serde_json::Value;
use trust_tasks_rs::specs::auth::step_up::approver::enroll::v0_1 as enroll;
use trust_tasks_rs::specs::auth::step_up::approver::invite::v0_1 as invite;
use trust_tasks_rs::specs::auth::step_up::approver::list::v0_1 as list;
use trust_tasks_rs::specs::auth::step_up::approver::redeem::finish::v0_1 as redeem_finish;
use trust_tasks_rs::specs::auth::step_up::approver::redeem::start::v0_1 as redeem_start;
use trust_tasks_rs::specs::auth::step_up::approver::revoke::v0_1 as revoke;
use trust_tasks_rs::{RejectReason, StandardCode, TrustTask, TrustTaskCode};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, declared_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, admin_signer, parse_spec_payload};
use crate::acl::bound_step_up::{self, Gate};
use crate::server::AppState;
use crate::step_up_approver::ApproverTaskError;

pub(crate) const INVITE_TYPE: &str = <invite::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const REDEEM_START_TYPE: &str =
    <redeem_start::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const REDEEM_FINISH_TYPE: &str =
    <redeem_finish::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const ENROLL_TYPE: &str = <enroll::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const LIST_TYPE: &str = <list::Payload as trust_tasks_rs::Payload>::TYPE_URI;
pub(crate) const REVOKE_TYPE: &str = <revoke::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    INVITE_TYPE,
    REDEEM_START_TYPE,
    REDEEM_FINISH_TYPE,
    ENROLL_TYPE,
    LIST_TYPE,
    REVOKE_TYPE,
];

/// Tasks whose response carries a bearer secret — the invite's token and claim
/// code, a redemption's `enrollmentId` and challenge. The duplicate-execution
/// record keeps no copy of these responses.
pub(crate) const SECRET_RESPONSES: &[&str] = &[INVITE_TYPE, REDEEM_START_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        INVITE_TYPE => handle_invite(state, ctx, doc).await,
        REDEEM_START_TYPE => handle_redeem_start(state, ctx, doc).await,
        REDEEM_FINISH_TYPE => handle_redeem_finish(state, ctx, doc).await,
        ENROLL_TYPE => handle_enroll(state, ctx, doc).await,
        LIST_TYPE => handle_list(state, ctx, doc).await,
        REVOKE_TYPE => handle_revoke(state, ctx, doc).await,
        _ => return None,
    })
}

/// An [`ApproverTaskError`] as the trust-task-error document it is.
fn refusal(doc: &TrustTask<Value>, e: &ApproverTaskError) -> TrustTaskOutcome {
    match e {
        ApproverTaskError::Refused {
            code,
            message,
            details,
        } => reject_with_code(doc, declared_code(code), message, details.clone()),
        ApproverTaskError::StepUp(request) => reject_with_code(
            doc,
            TrustTaskCode::Standard(StandardCode::PermissionDenied),
            "a step-up bound to this operation is required",
            Some(bound_step_up::refusal_details(request)),
        ),
        ApproverTaskError::App(e) => app_error_to_reject(doc, e),
    }
}

/// The verified signer, or the refusal for its absence.
fn signer_of(ctx: &JoinAuthCtx, doc: &TrustTask<Value>) -> Result<String, TrustTaskOutcome> {
    ctx.verified_signer
        .clone()
        .ok_or_else(|| reject_with(doc, RejectReason::ProofRequired))
}

/// The bound step-up `actor` owes for this document: `Ok(())` once spent, the
/// refusal that asks for it otherwise.
async fn gate(
    state: &AppState,
    actor: &str,
    doc: &TrustTask<Value>,
    reason: &str,
) -> Result<(), TrustTaskOutcome> {
    match bound_step_up::redeem_or_request(
        state,
        actor,
        &doc.type_uri.to_string(),
        &doc.payload,
        reason,
    )
    .await
    {
        Ok(Gate::Satisfied) => Ok(()),
        Ok(Gate::Required(request)) => Err(refusal(doc, &ApproverTaskError::StepUp(request))),
        Err(e) => Err(app_error_to_reject(doc, &e)),
    }
}

/// `auth/step-up/approver/invite/0.1`. Binding someone a factor is an act of
/// authority, so beyond the administrator's signature it takes a step-up of
/// their own bound to this document (invite/0.1, *Authorization*): a single
/// stolen administrator key cannot mint factors for others.
async fn handle_invite(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let actor = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let payload: invite::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    // Everything that decides whether the invite may be issued, before the
    // administrator is asked for a gesture over it.
    if let Err(e) = crate::step_up_approver::check_invite(state, &actor.did, &payload).await {
        return refusal(&doc, &e);
    }
    let reason = format!(
        "Invite {} to enrol a step-up approver",
        payload.subject.as_str()
    );
    if let Err(out) = gate(state, &actor.did, &doc, &reason).await {
        return out;
    }
    match crate::step_up_approver::issue_invite(state, &actor.did, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => refusal(&doc, &e),
    }
}

/// `auth/step-up/approver/redeem/start/0.1`, signed by the invited subject.
async fn handle_redeem_start(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let signer = match signer_of(ctx, &doc) {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let payload: redeem_start::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_approver::redeem_start(state, &signer, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => refusal(&doc, &e),
    }
}

/// `auth/step-up/approver/redeem/finish/0.1`, signed by the invited subject,
/// with the approver's statement carried exactly as received.
async fn handle_redeem_finish(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let signer = match signer_of(ctx, &doc) {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let payload: redeem_finish::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let statement = doc.payload.get("statement").cloned().unwrap_or(Value::Null);
    match crate::step_up_approver::redeem_finish(state, &signer, &payload, &statement).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => refusal(&doc, &e),
    }
}

/// `auth/step-up/approver/enroll/0.1`, signed by the subject's own DID.
async fn handle_enroll(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let signer = match signer_of(ctx, &doc) {
        Ok(s) => s,
        Err(reject) => return reject,
    };
    let payload: enroll::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_approver::enroll(state, &signer, &doc.payload, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => refusal(&doc, &e),
    }
}

/// Who a `list` or `revoke` is from: the verified signer, or — when that
/// signer holds no ACL row of its own and signed through a console key — the
/// administrator that key acts for (list/0.1 and revoke/0.1 item 1).
async fn identity_of(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome> {
    let signer = signer_of(ctx, doc)?;
    let has_own_row = crate::acl::get_acl_entry(&state.acl_ks, &signer)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
        .is_some();
    if !has_own_row
        && let Some(delegation) =
            crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, &signer)
                .await
                .map_err(|e| app_error_to_reject(doc, &e))?
    {
        crate::acl::console_key::touch_last_used(&state.console_keys_ks, &delegation).await;
        return Ok(delegation.admin_did);
    }
    Ok(signer)
}

/// Whether `identity` may act on `subject`'s approvers: their own, or an
/// administrator whose standing covers the subject. Read from this service's
/// own state, never the document.
async fn may_act_for(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    identity: &str,
    subject: &str,
) -> Result<bool, TrustTaskOutcome> {
    if identity == subject {
        return Ok(true);
    }
    let Ok(actor) = admin_signer(state, ctx, doc).await else {
        return Ok(false);
    };
    crate::step_up_approver::admin_covers(state, &actor, subject)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))
}

/// `auth/step-up/approver/list/0.1`. A subject other than the caller is
/// answered only to an administrator over them, and refused identically
/// whether or not the subject exists (item 3).
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let identity = match identity_of(state, ctx, &doc).await {
        Ok(i) => i,
        Err(reject) => return reject,
    };
    let payload: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let subject = payload
        .subject
        .as_ref()
        .map_or_else(|| identity.clone(), |s| s.to_string());
    match may_act_for(state, ctx, &doc, &identity, &subject).await {
        Ok(true) => {}
        Ok(false) => {
            return reject_with(
                &doc,
                RejectReason::PermissionDenied {
                    reason: "you may list only your own step-up approvers, or those of a member \
                             within your administrative authority"
                        .into(),
                },
            );
        }
        Err(reject) => return reject,
    }
    match crate::step_up_approver::list(state, &subject).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => refusal(&doc, &e),
    }
}

/// `auth/step-up/approver/revoke/0.1`: the subject's own approver, or an
/// administrator revoking one on a member's behalf. Behind the caller's own
/// step-up bound to this document (revoke/0.1, *Authorization*), so a stolen
/// signing key alone cannot strip a subject of the factors that protect them;
/// a subject whose only factor is the one being revoked answers with it.
async fn handle_revoke(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let identity = match identity_of(state, ctx, &doc).await {
        Ok(i) => i,
        Err(reject) => return reject,
    };
    let payload: revoke::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let subject = payload
        .subject
        .as_ref()
        .map_or_else(|| identity.clone(), |s| s.to_string());
    let not_found = || {
        refusal(
            &doc,
            &ApproverTaskError::Refused {
                code: revoke::error_codes::NOT_FOUND.code,
                message: "no binding of this approver that you may revoke".into(),
                details: None,
            },
        )
    };
    // Item 3: one answer for "never bound", "bound to someone else" and "no
    // authority over its subject", so the code cannot probe who holds what.
    match may_act_for(state, ctx, &doc, &identity, &subject).await {
        Ok(true) => {}
        Ok(false) => return not_found(),
        Err(reject) => return reject,
    }
    match crate::step_up_approver::check_revoke(state, &subject, payload.approver_did.as_str())
        .await
    {
        // Already revoked: succeed, changing nothing — no step-up for a no-op.
        Ok(Some(_)) => {}
        Ok(None) => {
            let reason = if identity == subject {
                format!(
                    "Revoke your step-up approver {}",
                    payload.approver_did.as_str()
                )
            } else {
                format!(
                    "Revoke the step-up approver {} of {subject}",
                    payload.approver_did.as_str()
                )
            };
            if let Err(out) = gate(state, &identity, &doc, &reason).await {
                return out;
            }
        }
        Err(e) => return refusal(&doc, &e),
    }
    match crate::step_up_approver::revoke(state, &identity, &subject, &payload).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => refusal(&doc, &e),
    }
}
