//! DIDComm handler functions dispatched by [`super::router::dispatch`].
//!
//! No handler here authorises on the DIDComm sender. The only authorised
//! surface is [`handle_trust_task`]: the Trust-Task envelope, whose document
//! must carry a Data Integrity proof bound to the sender
//! (`trust_tasks::bind_document_to_sender`). The rest are unauthenticated by
//! nature: trust-ping and problem reports.

use crate::messaging::shim::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, ProblemReport,
    ServiceProblemReport,
};
use affinidi_messaging_didcomm::Message;
use tracing::warn;

use crate::error::AppError;
use crate::server::AppState;

type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

/// Helper to convert non-domain errors (serde, base64, missing subsystem)
/// into `DIDCommServiceError::Handler`, which the transport renders as
/// `e.p.msg.internal-error`.
fn handler_err(e: impl std::fmt::Display) -> DIDCommServiceError {
    DIDCommServiceError::Handler(e.to_string())
}

/// DIDComm `type` for Trust-Tasks envelopes, per the framework binding
/// `https://trusttasks.org/binding/didcomm/0.1`: a single reserved type
/// whose `body` carries the full `TrustTask<P>` JSON. Conformant
/// consumers reject any other type. Mirrors
/// The DIDComm binding's envelope `type`, re-exported so the rest of the crate
/// has one name for it.
///
/// This was a hand-written copy of the URI, as were three others across the
/// workspace. That duplication is what let the consent push send its message
/// with the *task* type instead of the envelope type — which a conformant peer
/// rejects silently, because "not an envelope" is indistinguishable from "not
/// addressed to me". Sourced from the crate that defines it so a copy cannot
/// drift again.
use trust_tasks_didcomm::ENVELOPE_TYPE as TRUST_TASK_ENVELOPE_TYPE;

/// Generic DIDComm handler for the Trust-Tasks surface.
///
/// Routed at the single binding envelope type [`TRUST_TASK_ENVELOPE_TYPE`];
/// the message body carries the full `TrustTask<Value>` envelope
/// (identical to the REST `POST /api/trust-tasks` body, whose own `type`
/// field selects the operation). The authcrypt sender is the
/// authenticated caller.
///
/// Delegates to the shared `dispatch_trust_task_core` so REST and
/// DIDComm run byte-identical routing + authorization, then returns the
/// framework result/error document — itself a trust-task envelope — as
/// the reply body. The document is self-describing (its own `type` +
/// status `code`), so the HTTP status the core attaches is dropped on
/// the DIDComm wire.
pub async fn handle_trust_task(
    _ctx: HandlerContext,
    message: Message,
    Extension(app_state): Extension<AppState>,
) -> HandlerResult {
    // The DIDComm message body IS the trust-task envelope.
    let body = serde_json::to_vec(&message.body).map_err(handler_err)?;

    // The DIDComm sender is a claim, not a proof of who composed the
    // document: `accept_from_proven_sender` requires the document's own Data
    // Integrity proof to verify as its `issuer`, and that issuer to be this
    // sender, before the sender resolves to any authority. Only then does it
    // resolve `AuthClaims` (role + allowed contexts from the ACL, expiry
    // enforced — same as REST), through `auth_for_trust_task_envelope` so a
    // ceremony task (a `task-consent/decision`, a step-up `approve-response`)
    // from an approver with no ACL standing is dispatched on a zero-authority
    // claim. A refusal is a Trust-Task error *envelope*, not a DIDComm
    // problem-report — a conformant Trust-Task client only understands binding
    // envelopes.
    //
    // `message.from` here is the transport-reported sender — `handle_didcomm`
    // overwrites the plaintext `from` with it (or `None`) before routing.
    let authenticated = match message.from.as_deref() {
        Some(sender) => Ok(sender),
        None => Err(AppError::Authentication(
            "message has no sender (from)".into(),
        )),
    };

    let response = match authenticated {
        // Whether this is a request to authorize, a response to deliver or an
        // error to stop at is the spine's to read. Authcrypt sealed this
        // envelope to the VTA's own key, so no intermediary — mediator included
        // — held the plaintext.
        Ok(sender) => {
            crate::trust_tasks::transport::with_binding(
                "didcomm",
                crate::trust_tasks::accept_from_proven_sender(
                    &app_state,
                    sender,
                    &body,
                    crate::trust_tasks::transport::TransportConfidentiality::EndToEnd,
                ),
            )
            .await
        }
        Err(e) => {
            crate::trust_tasks::sign_response(
                &app_state,
                crate::trust_tasks::reject_trust_task(
                    &body,
                    trust_tasks_rs::RejectReason::PermissionDenied {
                        reason: e.to_string(),
                    },
                ),
            )
            .await
        }
    };

    // The dispatch core returns a typed `TrustTaskOutcome`; its `body` is
    // already the serialised framework trust-task document, so we parse it
    // straight into the DIDComm reply — no round-trip through an
    // `axum::Response` to re-extract the JSON. The self-describing document
    // (its own `type` + status `code`) carries the result; the HTTP status the
    // core attaches is dropped on the DIDComm wire.
    let doc: serde_json::Value = serde_json::from_slice(&response.body).map_err(handler_err)?;

    // The reply is itself a trust-task envelope; the service sets `thid`
    // from the inbound message id for client correlation.
    Ok(Some(DIDCommResponse::new(TRUST_TASK_ENVELOPE_TYPE, doc)))
}

// ---------------------------------------------------------------------------
// Problem report & fallback
// ---------------------------------------------------------------------------

pub async fn handle_problem_report(_ctx: HandlerContext, message: Message) -> HandlerResult {
    let code = message
        .body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let comment = message
        .body
        .get("comment")
        .and_then(|v| v.as_str())
        .unwrap_or("no details provided");
    let from = message.from.as_deref().unwrap_or("unknown");
    let thid = message.thid.as_deref().unwrap_or("none");
    warn!(from, code, comment, thid, msg_type = %message.typ, "received problem-report");
    Ok(None)
}

pub async fn handle_unknown(_ctx: HandlerContext, message: Message) -> HandlerResult {
    let from = message.from.as_deref().unwrap_or("unknown");
    let thid = message.thid.as_deref().unwrap_or("none");

    // Extract problem-report details if present in the body
    if message.typ.contains("problem-report") {
        let code = message
            .body
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let comment = message
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .unwrap_or("no details provided");
        warn!(
            from,
            code,
            comment,
            thid,
            msg_type = %message.typ,
            "received unhandled problem-report"
        );
        return Ok(None);
    }

    // A Trust Task typed as itself instead of carried in the binding envelope.
    // `bindings/didcomm/0.2` §2/§4: the envelope is the only DIDComm carriage,
    // and any other type is refused at the DIDComm layer — no
    // `trust-task-error`, the document never reaches the pipeline. But a bare
    // "unsupported message type" reads as "this VTA does not do that task",
    // which is false; name the carriage it needs (Keyring VTI-42).
    if let Some(comment) = trust_task_needs_envelope(&message.typ) {
        warn!(
            from,
            msg_type = %message.typ,
            "Trust Task arrived typed as its task URI, not in the DIDComm binding envelope — refused"
        );
        return Ok(Some(
            DIDCommResponse::problem_report(ProblemReport::bad_request(comment))
                .thid(message.id.clone()),
        ));
    }

    warn!(from, thid, msg_type = %message.typ, "unknown message type — ignoring");
    Ok(Some(
        DIDCommResponse::problem_report(ProblemReport::bad_request(format!(
            "unsupported message type: {}",
            message.typ
        )))
        .thid(message.id.clone()),
    ))
}

/// Every published Trust Task type URI starts with this.
const TRUST_TASK_SPEC_PREFIX: &str = "https://trusttasks.org/spec/";

/// The problem-report comment for a DIDComm message whose `type` is a Trust
/// Task URI, or `None` when it is not one.
///
/// Keyed on the published-spec prefix rather than on `dispatched_uris()`: the
/// carriage is wrong for *every* Trust Task URI, served or not, and an
/// unserved task sent in the envelope gets the spine's own `trust-task-error`,
/// which is the better answer.
pub(crate) fn trust_task_needs_envelope(typ: &str) -> Option<String> {
    typ.starts_with(TRUST_TASK_SPEC_PREFIX).then(|| {
        format!(
            "unsupported message type: {typ} — Trust Tasks must be carried in the DIDComm \
             binding envelope `{TRUST_TASK_ENVELOPE_TYPE}` with the task document as the body"
        )
    })
}
