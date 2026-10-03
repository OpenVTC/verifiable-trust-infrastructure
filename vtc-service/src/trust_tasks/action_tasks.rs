//! The administrator action list on the signed-document spine —
//! `vtc/admin/actions/{list,show,cancel,acknowledge}` at 0.1 and 0.2 — and the
//! `task-consent/decision` (0.1, 0.2) that completes a parked operation on its
//! N-th approval (`docs/05-design-notes/vtc-action-list.md`, VTI-APV-017).
//!
//! Reads are authorized from the signer's ACL row, read now, exactly as every
//! other administrator verb ([`admin_signer`]); a console key may sign them,
//! acting for its administrator. A decision may not: it is the approver's own
//! attestation, and the spine refuses one signed by a delegated key before it
//! reaches [`handle_decision`].
//!
//! **Both versions are served.** Their request payloads and error codes are
//! the same; they differ in the `_shared` Action they answer with
//! ([`admin_actions::WireVersion`]). 0.2 represents a cooling-off in the
//! schema's own terms (category `coolingOff`, `landsAt`, `cancellableBy`,
//! `landedAfterCoolingOff`, `callerRole: subject`); 0.1 keeps answering as it
//! always did, with the cooling-off in `ext["org.openvtc"].coolingOff`.

use serde_json::{Value, json};
use trust_tasks_rs::specs::task_consent::decision::v0_2 as decision;
use trust_tasks_rs::specs::trust_task_next_step::v0_1 as next_step;
use trust_tasks_rs::specs::vtc::admin::actions::{
    acknowledge::v0_1 as acknowledge, acknowledge::v0_2 as acknowledge_v0_2,
    cancel::v0_1 as cancel, cancel::v0_2 as cancel_v0_2, list::v0_1 as list,
    list::v0_2 as list_v0_2, show::v0_1 as show, show::v0_2 as show_v0_2,
};
use trust_tasks_rs::{Payload, StandardCode, TrustTask, TrustTaskCode};
use vti_common::auth::extractor::AuthClaims;

use super::helpers::{app_error_to_reject, extended_code, reject_with_code, success_response};
use super::{JoinAuthCtx, TrustTaskOutcome, admin_signer, parse_spec_payload};
use crate::admin_actions::{
    self, AcknowledgeError, CancelError, Decided, DecisionError, DecisionInput, View, WireVersion,
};
use crate::server::AppState;

pub(crate) const LIST_TYPE: &str = <list::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_TYPE: &str = <show::Payload as Payload>::TYPE_URI;
pub(crate) const CANCEL_TYPE: &str = <cancel::Payload as Payload>::TYPE_URI;
pub(crate) const ACKNOWLEDGE_TYPE: &str = <acknowledge::Payload as Payload>::TYPE_URI;
pub(crate) const LIST_V0_2_TYPE: &str = <list_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const SHOW_V0_2_TYPE: &str = <show_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const CANCEL_V0_2_TYPE: &str = <cancel_v0_2::Payload as Payload>::TYPE_URI;
pub(crate) const ACKNOWLEDGE_V0_2_TYPE: &str = <acknowledge_v0_2::Payload as Payload>::TYPE_URI;
/// `trust-task-next-step/0.1` — the answer to a parked operation.
pub(crate) const NEXT_STEP_TYPE: &str = <next_step::Payload as Payload>::TYPE_URI;

/// Every URI this module routes (the decision versions are routed by the
/// dispatcher itself, beside them).
pub(crate) const URIS: &[&str] = &[
    LIST_TYPE,
    SHOW_TYPE,
    CANCEL_TYPE,
    ACKNOWLEDGE_TYPE,
    LIST_V0_2_TYPE,
    SHOW_V0_2_TYPE,
    CANCEL_V0_2_TYPE,
    ACKNOWLEDGE_V0_2_TYPE,
];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        LIST_TYPE => handle_list(state, ctx, doc, WireVersion::V0_1).await,
        SHOW_TYPE => handle_show(state, ctx, doc, WireVersion::V0_1).await,
        CANCEL_TYPE => handle_cancel(state, ctx, doc, WireVersion::V0_1).await,
        ACKNOWLEDGE_TYPE => handle_acknowledge(state, ctx, doc, WireVersion::V0_1).await,
        LIST_V0_2_TYPE => handle_list(state, ctx, doc, WireVersion::V0_2).await,
        SHOW_V0_2_TYPE => handle_show(state, ctx, doc, WireVersion::V0_2).await,
        CANCEL_V0_2_TYPE => handle_cancel(state, ctx, doc, WireVersion::V0_2).await,
        ACKNOWLEDGE_V0_2_TYPE => handle_acknowledge(state, ctx, doc, WireVersion::V0_2).await,
        _ => return None,
    })
}

fn refuse(doc: &TrustTask<Value>, code: &str, message: impl Into<String>) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, None)
}

/// The signer, held to being an administrator (any administrative role), and
/// whether they hold `vtc.audit.read` — the capability that lets them observe
/// every action, not only their own and those they may decide.
async fn administrator(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
    not_administrator: &str,
) -> Result<(AuthClaims, bool), TrustTaskOutcome> {
    // A member of the community is told what they are not, under the task's
    // own code, rather than the generic refusal a stranger gets.
    if let Some(signer) = ctx.verified_signer.as_deref()
        && let Ok(Some(entry)) = crate::acl::get_acl_entry(&state.acl_ks, signer).await
        && !entry.is_administrator()
    {
        return Err(refuse(
            doc,
            not_administrator,
            "only an administrator of this community has an action list",
        ));
    }
    let claims = admin_signer(state, ctx, doc).await?;
    let observer = crate::acl::get_acl_entry(&state.acl_ks, &claims.did)
        .await
        .map_err(|e| app_error_to_reject(doc, &e))?
        .is_some_and(|e| e.can(crate::acl::Capability::AuditRead, None));
    Ok((claims, observer))
}

/// `vtc/admin/actions/list/0.1` and `/0.2` — one request payload, two
/// Action shapes. The 0.1 payload type parses both: the request is unchanged.
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    version: WireVersion,
) -> TrustTaskOutcome {
    use list::error_codes as codes;
    let (caller, unrestricted) =
        match administrator(state, ctx, &doc, codes::NOT_ADMINISTRATOR.code).await {
            Ok(c) => c,
            Err(reject) => return reject,
        };
    let payload: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let (view, view_name) = match payload.view {
        list::PayloadView::WaitingForMe => (View::WaitingForMe, "waitingForMe"),
        list::PayloadView::RequestedByMe => (View::RequestedByMe, "requestedByMe"),
        list::PayloadView::History => (View::History, "history"),
        list::PayloadView::All => (View::All, "all"),
        _ => {
            return refuse(
                &doc,
                codes::INVALID_FILTER.code,
                "this community does not serve that view",
            );
        }
    };
    // `since` belongs to `history` alone; elsewhere it is refused rather than
    // ignored, so a caller never reads an unfiltered page as a filtered one.
    let since_raw = doc.payload["since"].as_str().map(str::to_string);
    if since_raw.is_some() && view != View::History {
        return refuse(
            &doc,
            codes::INVALID_FILTER.code,
            "`since` is accepted only with `view: history`",
        );
    }
    let since = payload.since.map(|s| s.timestamp().max(0) as u64);
    let offset = match payload.cursor.as_ref() {
        None => 0,
        Some(c) => {
            match admin_actions::decode_cursor(c.as_str(), view_name, since_raw.as_deref()) {
                Some(o) => o,
                None => {
                    return refuse(
                        &doc,
                        codes::INVALID_CURSOR.code,
                        "the cursor was not issued for this view and filter",
                    );
                }
            }
        }
    };
    let limit = usize::try_from(payload.limit.get()).unwrap_or(100).min(100);
    let page = match admin_actions::list(
        state,
        &caller.did,
        unrestricted,
        view,
        since,
        offset,
        limit,
        version,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    let mut response = json!({
        "actions": page.actions,
        "counts": {
            "waitingForMe": page.waiting_for_me,
            "requestedByMe": page.requested_by_me,
        },
    });
    // What the console's banners need beyond the counts: operator writes still
    // to acknowledge (VTI-VTC-023) and cooling-offs against the caller
    // (VTI-APV-019).
    response["ext"] = json!({ "org.openvtc": page.ext });
    if let Some(next) = page.next_offset {
        response["nextCursor"] = json!(admin_actions::encode_cursor(
            view_name,
            since_raw.as_deref(),
            next
        ));
    }
    success_response(&doc, response)
}

/// `vtc/admin/actions/show/0.1` — the read a requester follows from the
/// next-step a parked operation was answered with.
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    version: WireVersion,
) -> TrustTaskOutcome {
    use show::error_codes as codes;
    let (caller, unrestricted) =
        match administrator(state, ctx, &doc, codes::NOT_ADMINISTRATOR.code).await {
            Ok(c) => c,
            Err(reject) => return reject,
        };
    let payload: show::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match admin_actions::show(
        state,
        &caller.did,
        unrestricted,
        payload.action_id.as_str(),
        version,
    )
    .await
    {
        Ok(Some(action)) => success_response(&doc, json!({ "action": action })),
        // Absent and not the caller's to see answer alike.
        Ok(None) => refuse(&doc, codes::NOT_FOUND.code, "no such action"),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/admin/actions/cancel/0.1` — the requester withdraws their own open
/// action. A console key may sign it: withdrawing confers nothing.
async fn handle_cancel(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    version: WireVersion,
) -> TrustTaskOutcome {
    use cancel::error_codes as codes;
    let (caller, unrestricted) = match administrator(
        state,
        ctx,
        &doc,
        // Cancel declares no `notAdministrator`; a non-administrator has no
        // action to find.
        codes::NOT_FOUND.code,
    )
    .await
    {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    let payload: cancel::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let reason = payload.reason.as_ref().map(|r| r.to_string());
    match admin_actions::cancel(
        state,
        &caller.did,
        unrestricted,
        payload.action_id.as_str(),
        reason,
    )
    .await
    {
        Ok(rec) => match admin_actions::view_one(state, &caller.did, &rec, version).await {
            Ok(action) => success_response(&doc, json!({ "action": action })),
            Err(e) => app_error_to_reject(&doc, &e),
        },
        Err(CancelError::NotFound) => refuse(&doc, codes::NOT_FOUND.code, "no such action"),
        Err(CancelError::NotRequester) => refuse(
            &doc,
            codes::NOT_REQUESTER.code,
            "only the administrator who asked for this can withdraw it; a queue item (a \
             break-glass, join or vetting review) is decided, never withdrawn",
        ),
        Err(CancelError::NotOpen) => {
            refuse(&doc, codes::NOT_OPEN.code, "this action is no longer open")
        }
        Err(CancelError::Internal(e)) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/admin/actions/acknowledge/0.1` — an administrator records that they
/// have seen an operator's offline write (**VTI-VTC-023**,
/// `vtc-admin-roles.md` §2). A console key may sign it: acknowledging confers
/// nothing.
async fn handle_acknowledge(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    version: WireVersion,
) -> TrustTaskOutcome {
    use acknowledge::error_codes as codes;
    let (caller, unrestricted) = match administrator(state, ctx, &doc, codes::NOT_FOUND.code).await
    {
        Ok(c) => c,
        Err(reject) => return reject,
    };
    let payload: acknowledge::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match admin_actions::acknowledge(state, &caller.did, unrestricted, payload.action_id.as_str())
        .await
    {
        Ok(rec) => match admin_actions::view_one(state, &caller.did, &rec, version).await {
            Ok(action) => success_response(&doc, json!({ "action": action })),
            Err(e) => app_error_to_reject(&doc, &e),
        },
        Err(AcknowledgeError::NotFound) => refuse(&doc, codes::NOT_FOUND.code, "no such action"),
        Err(AcknowledgeError::NotAcknowledgeable) => refuse(
            &doc,
            codes::NOT_ACKNOWLEDGEABLE.code,
            "this action is not an operator's write waiting for your acknowledgement: it is \
             decided by approval, no longer open, or not addressed to you",
        ),
        Err(AcknowledgeError::AlreadyAcknowledged) => refuse(
            &doc,
            codes::ALREADY_ACKNOWLEDGED.code,
            "you have already acknowledged this; the earlier acknowledgement stands",
        ),
        Err(AcknowledgeError::Internal(e)) => app_error_to_reject(&doc, &e),
    }
}

/// `task-consent/decision/0.1` and `/0.2` — an approver's answer to an action.
///
/// The approver is the document's proven signer: their own DID (the spine has
/// already refused a delegated console key here), resolved through the ACL as
/// every signed administrator verb is. Which operation the decision concerns
/// is this service's record of the action, found by the salted digest. The
/// approval that reaches the threshold executes it (VTI-APV-017).
pub(super) async fn handle_decision(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use decision::error_codes as codes;
    use trust_tasks_rs::specs::task_consent::decision::v0_1 as decision_v0_1;

    let v0_2 = doc.type_uri.to_string() == crate::acl::admin_consent::DECISION_V0_2_TYPE;
    let approver = match admin_signer(state, ctx, &doc).await {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    let input = if v0_2 {
        let p: decision::Payload = match parse_spec_payload(&doc) {
            Ok(p) => p,
            Err(reject) => return reject,
        };
        DecisionInput {
            challenge: p.challenge.to_string(),
            payload_digest: p.payload_digest.to_string(),
            approve: p.decision == decision::Decision::Approve,
            reason: p.reason.as_ref().map(|r| r.to_string()),
            action_id: p.action_id.as_ref().map(|a| a.to_string()),
            evidence: doc.payload.get("evidence").cloned(),
        }
    } else {
        let p: decision_v0_1::Payload = match parse_spec_payload(&doc) {
            Ok(p) => p,
            Err(reject) => return reject,
        };
        DecisionInput {
            challenge: p.challenge.to_string(),
            payload_digest: p.payload_digest.to_string(),
            approve: p.decision == decision_v0_1::Decision::Approve,
            reason: p.reason.as_ref().map(|r| r.to_string()),
            action_id: None,
            evidence: None,
        }
    };

    let answer = |status: &str, digest: &str, action_id: &str, extra: Value| {
        let mut body = json!({ "status": status, "payloadDigest": digest });
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                body[k] = v.clone();
            }
        }
        if v0_2 {
            body["actionId"] = json!(action_id);
        } else if let Some(map) = body.as_object_mut() {
            map.remove("ext");
        }
        success_response(&doc, body)
    };

    match admin_actions::decide(state, &approver.did, input).await {
        Ok(Decided::Granted {
            action_id,
            payload_digest,
            approvals,
            completed,
            message,
        }) => {
            let mut ext = json!({ "actionStatus": if completed { "completed" } else { "failed" } });
            if let Some(m) = message {
                ext["closedMessage"] = json!(m);
            }
            answer(
                "granted",
                &payload_digest,
                &action_id,
                json!({ "approvals": approvals, "ext": { "org.openvtc": ext } }),
            )
        }
        Ok(Decided::Pending {
            action_id,
            payload_digest,
            approvals,
            needed,
        }) => answer(
            "pending",
            &payload_digest,
            &action_id,
            json!({ "approvals": approvals, "needed": needed }),
        ),
        Ok(Decided::Denied {
            action_id,
            payload_digest,
        }) => answer("denied", &payload_digest, &action_id, json!({})),
        Err(DecisionError::NoPending) => refuse(
            &doc,
            codes::NO_PENDING.code,
            "no open action is waiting on this digest; it has been decided, has lapsed, or was \
             never raised",
        ),
        Err(DecisionError::ChallengeMismatch) => refuse(
            &doc,
            codes::CHALLENGE_MISMATCH.code,
            "the challenge does not match the action",
        ),
        Err(DecisionError::NotAnApprover) => refuse(
            &doc,
            codes::NOT_AN_APPROVER.code,
            "only an administrator this action was raised for, still holding what it is about, \
             can decide it, with the challenge they were shown",
        ),
        Err(DecisionError::RequesterExcluded) => refuse(
            &doc,
            codes::REQUESTER_EXCLUDED.code,
            "the administrator who asked for this cannot approve it",
        ),
        Err(DecisionError::ActionMismatch) => refuse(
            &doc,
            codes::ACTION_MISMATCH.code,
            "the actionId names a different action than the digest and challenge do",
        ),
        Err(DecisionError::EvidenceInvalid(hint)) => reject_with_code(
            &doc,
            extended_code(codes::EVIDENCE_INVALID.code),
            "the decision's evidence did not verify",
            Some(json!({ "reason": hint })),
        ),
        Err(DecisionError::RateLimited) => reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::Unavailable),
            format!(
                "you have decided {} actions in the last minute; wait before deciding another",
                admin_actions::DECISIONS_PER_MINUTE
            ),
            None,
        ),
        // A queue item's own operation refused the decision: nothing was
        // written and the item still waits (`vtc-action-list.md` §8.2).
        Err(DecisionError::Refused(message)) => {
            app_error_to_reject(&doc, &vti_common::error::AppError::Conflict(message))
        }
        Err(DecisionError::Internal(e)) => app_error_to_reject(&doc, &e),
    }
}
