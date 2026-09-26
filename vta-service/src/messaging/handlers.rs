//! DIDComm handler functions dispatched by [`super::router::dispatch`].
//!
//! No handler here authorises on the DIDComm sender. The only authorised
//! surface is [`handle_trust_task`]: the Trust-Task envelope, whose document
//! must carry a Data Integrity proof bound to the sender
//! (`trust_tasks::bind_document_to_sender`). The rest are unauthenticated by
//! nature: problem reports, TEE status/attestation, and the credential-exchange
//! holder side, which acts on the VTA's own authority and uses the sender only
//! as a label.

#[cfg(feature = "tee")]
use std::sync::Arc;

use crate::messaging::shim::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, ProblemReport,
    ServiceProblemReport,
};
use affinidi_messaging_didcomm::Message;
use tracing::{info, warn};

use crate::acl::Role;
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

#[cfg(feature = "tee")]
use super::router::VtaState;

use vta_sdk::protocols::credential_exchange;

type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

/// Helper to convert non-domain errors (serde, base64, missing subsystem)
/// into `DIDCommServiceError::Handler`, which the transport renders as
/// `e.p.msg.internal-error`. For domain errors (`AppError`) use [`app_try!`]
/// so the caller receives a typed problem-report code (`e.p.msg.conflict`,
/// `e.p.msg.not-found`, etc.) instead of an opaque internal-error.
fn handler_err(e: impl std::fmt::Display) -> DIDCommServiceError {
    DIDCommServiceError::Handler(e.to_string())
}

/// Map an [`AppError`] to its typed [`ProblemReport`] so the client sees the
/// right `e.p.msg.*` code (conflict/not-found/unauthorized/forbidden/
/// bad-request) instead of everything collapsing into `internal-error`.
///
/// Split out from [`app_err_to_response`] so the variant → code contract can
/// be unit-tested on `ProblemReport`'s public fields (the `DIDCommResponse`
/// body is `pub(crate)` in the transport crate and not inspectable here).
fn app_err_to_problem_report(e: &AppError) -> ProblemReport {
    match e {
        // No `gone` code exists in the affinidi taxonomy, and no DIDComm
        // surface produces `Gone` today (its producers — the TEE bootstrap
        // carve-out and the one-shot backup blob slots — are REST-only). Ride
        // with `conflict` rather than the `internal-error` fallback, which
        // would tell the caller a permanently-consumed resource was a server
        // bug worth retrying.
        AppError::Conflict(msg) | AppError::Gone(msg) => ProblemReport::conflict(msg.clone()),
        AppError::NotFound(msg) => ProblemReport::not_found(msg.clone()),
        AppError::Authentication(msg) | AppError::Unauthorized(msg) => {
            ProblemReport::unauthorized(msg.clone())
        }
        // The affinidi taxonomy doesn't define a `forbidden` code,
        // but collapsing into `unauthorized` means SDK clients see
        // "Token may be expired" for what's actually a permission /
        // privilege-laundering rejection. Emit a workspace-specific
        // `e.p.msg.forbidden` code; SDK clients that don't know it
        // fall back to `DidcommRemote { code, comment }` cleanly.
        // Step-up-required is a policy refusal (the op needs an AAL2 session
        // the caller doesn't have). Surface it as `forbidden` rather than
        // `internal-error` — DIDComm sender-auth can't be elevated to AAL2,
        // so the comment directs the caller to the REST step-up path.
        AppError::Forbidden(msg) | AppError::StepUpRequired(msg) => ProblemReport {
            code: vta_sdk::protocols::problem_report_codes::FORBIDDEN.to_string(),
            comment: msg.clone(),
            args: Vec::new(),
            escalate_to: None,
        },
        AppError::Validation(msg) => ProblemReport::bad_request(msg.clone()),
        // A rejected pagination cursor is a caller fault — REST already
        // answers 400. Collapsed into `internal-error` it reads as a
        // server fault the caller should retry, when the correct
        // response is to restart from the first page.
        AppError::InvalidCursor => ProblemReport::bad_request(e.to_string()),
        _ => ProblemReport::internal_error(e.to_string()),
    }
}

/// Wrap [`app_err_to_problem_report`] in a [`DIDCommResponse::problem_report`].
///
/// Call via the [`app_try!`] macro at operation, auth, and role-check sites.
fn app_err_to_response(e: AppError) -> DIDCommResponse {
    DIDCommResponse::problem_report(app_err_to_problem_report(&e))
}

/// `?`-style early-return for `Result<T, AppError>` inside a `HandlerResult`.
/// On `Err`, returns `Ok(Some(problem_report))` with the correct typed code.
macro_rules! app_try {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(err) => return Ok(Some($crate::messaging::handlers::app_err_to_response(err))),
        }
    };
}

/// Helper to build a typed response from a serializable result.
#[cfg(feature = "tee")]
fn response<T: serde::Serialize>(
    msg_type: &str,
    result: &T,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let body = serde_json::to_value(result).map_err(handler_err)?;
    Ok(Some(DIDCommResponse::new(msg_type, body)))
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
// TEE Attestation (feature-gated, unauthenticated)
// ---------------------------------------------------------------------------

#[cfg(feature = "tee")]
pub async fn handle_tee_status(
    _ctx: HandlerContext,
    _message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let tee_state = state
        .tee_state
        .as_ref()
        .ok_or_else(|| handler_err("TEE attestation is not enabled on this VTA"))?;
    let status = operations::attestation::get_tee_status(tee_state);
    response(
        vta_sdk::protocols::attestation_management::GET_TEE_STATUS_RESULT,
        &status,
    )
}

#[cfg(feature = "tee")]
pub async fn handle_request_attestation(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let tee_state = state
        .tee_state
        .as_ref()
        .ok_or_else(|| handler_err("TEE attestation is not enabled on this VTA"))?;
    let body: crate::tee::types::AttestationRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = app_try!(
        operations::attestation::generate_attestation_report(tee_state, &state.config, &body.nonce)
            .await
    );
    response(
        vta_sdk::protocols::attestation_management::ATTESTATION_RESULT,
        &result,
    )
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

// ---------------------------------------------------------------------------
// Credential exchange (no authorisation on the sender)
// ---------------------------------------------------------------------------

/// Holder-side receive of a credential delivered over DIDComm
/// (`credential-exchange/issue`, spec §6 / task 3.3).
///
/// The authcrypt sender (`message.from`) is the issuer; unpacking already
/// proved that DID cryptographically, so there is **no ACL gate** — the issuer
/// is a credential counterparty, not an operator of this VTA. The proven sender
/// DID is recorded as the stored credential's provenance (falling back to the
/// exchange thread id). The credential format is inferred and the body stored
/// through the format-agnostic vault by
/// [`operations::credential_exchange::receive_issued_credential`].
///
/// `issue` is a one-way deposit: it returns `Ok(None)` (no response body) on
/// success, or a typed problem-report on a validation failure.
pub async fn handle_credential_issue(
    _ctx: HandlerContext,
    message: Message,
    Extension(app_state): Extension<AppState>,
) -> HandlerResult {
    let body: credential_exchange::IssueBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    // Provenance: the cryptographically-proven issuer DID, else the thread id.
    let source = message.from.clone().or_else(|| message.thid.clone());
    let stored = app_try!(
        operations::credential_exchange::receive_issued_credential(
            &app_state.vault_ks,
            &body,
            app_state.did_resolver.as_ref(),
            source,
            chrono::Utc::now(),
        )
        .await
    );
    info!(
        credential_id = %stored.id,
        format = ?stored.format,
        from = message.from.as_deref().unwrap_or("unknown"),
        "received issued credential into vault via DIDComm"
    );
    Ok(None)
}

/// `credential-exchange/offer` over DIDComm (Phase 3, task 3.2) — the holder side
/// of the issuance negotiation: an issuer offered a credential, and the VTA
/// answers with a `request` carrying a key-binding proof.
///
/// **Opt-in**: the VTA accepts an offer only when `credential_holder_did` is
/// configured — the registered VTA-managed holder identity the new credential
/// binds to. With it unset (the default), an unsolicited offer is declined; the
/// VTA does not auto-request credentials from arbitrary issuers. When set, the
/// VTA acts with its own authority, signs an `openid4vci-proof+jwt` bound to that
/// holder key + the offer's issuer/pre-auth code, and replies `request/1.0`
/// on-thread. The issuer's redeem path returns the credential via `issue/1.0`,
/// which [`handle_credential_issue`] receives.
pub async fn handle_credential_offer(
    _ctx: HandlerContext,
    message: Message,
    Extension(app_state): Extension<AppState>,
) -> HandlerResult {
    let body: credential_exchange::OfferBody =
        serde_json::from_value(message.body).map_err(handler_err)?;

    let subject_did = match app_state.config.read().await.credential_holder_did.clone() {
        Some(did) => did,
        None => {
            info!(
                from = message.from.as_deref().unwrap_or("unknown"),
                "credential offer received but no credential_holder_did configured — declining"
            );
            return Ok(Some(DIDCommResponse::problem_report(
                ProblemReport::bad_request(
                    "this VTA does not accept unsolicited credential offers \
                     (no credential_holder_did configured)"
                        .to_string(),
                ),
            )));
        }
    };

    // The VTA accepts on its own behalf (super-admin over its own contexts); the
    // holder-key resolution is still ACL-gated to the subject's context.
    let auth = crate::auth::AuthClaims {
        role: Role::Admin,
        allowed_contexts: Vec::new(),
        ..Default::default()
    };

    let request = app_try!(
        operations::credential_exchange::build_credential_request_for_offer(
            &app_state.keys_ks,
            &app_state.contexts_ks,
            &app_state.seed_store,
            &app_state.audit_sink,
            &auth,
            &body.credential_offer,
            &subject_did,
            chrono::Utc::now(),
        )
        .await
    );

    let request_body = serde_json::to_value(&request).map_err(handler_err)?;
    info!(
        from = message.from.as_deref().unwrap_or("unknown"),
        subject = %subject_did,
        "answered credential offer with a request"
    );
    Ok(Some(
        DIDCommResponse::new(credential_exchange::REQUEST, request_body).thid(message.id),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::protocols::problem_report_codes as codes;

    /// Pins the `AppError` → `e.p.msg.*` code contract for the shared DIDComm
    /// error mapping that every `dispatch`-based handler funnels through. A
    /// regression here would silently change the problem-report code SDK
    /// clients switch on (e.g. forbidden collapsing back into unauthorized).
    #[test]
    fn app_error_maps_to_byte_identical_codes() {
        let cases = [
            (AppError::Conflict("c".into()), codes::CONFLICT, "c"),
            // The taxonomy has no `gone`; what matters is that it does not
            // land in the `internal-error` fallback and read as a server bug.
            (AppError::Gone("g".into()), codes::CONFLICT, "g"),
            (AppError::NotFound("n".into()), codes::NOT_FOUND, "n"),
            (
                AppError::Authentication("a".into()),
                codes::UNAUTHORIZED,
                "a",
            ),
            (AppError::Unauthorized("u".into()), codes::UNAUTHORIZED, "u"),
            (AppError::Forbidden("f".into()), codes::FORBIDDEN, "f"),
            (AppError::StepUpRequired("s".into()), codes::FORBIDDEN, "s"),
            (AppError::Validation("v".into()), codes::BAD_REQUEST, "v"),
        ];
        for (err, expected_code, expected_comment) in cases {
            let report = app_err_to_problem_report(&err);
            assert_eq!(report.code, expected_code, "code for {err:?}");
            assert_eq!(report.comment, expected_comment, "comment for {err:?}");
        }
    }

    /// A rejected pagination cursor is a caller fault. REST answers 400;
    /// this transport must not report it as an internal error, which
    /// would tell the caller to retry the same cursor instead of
    /// restarting from the first page.
    #[test]
    fn invalid_cursor_is_a_bad_request_not_an_internal_error() {
        let report = app_err_to_problem_report(&AppError::InvalidCursor);
        assert_eq!(report.code, codes::BAD_REQUEST);
        assert_ne!(report.code, codes::INTERNAL);
    }

    /// Catch-all variants collapse to `internal-error` with the `Display`
    /// string as the comment — matches the prior `_ => internal_error(...)`.
    #[test]
    fn app_error_catch_all_is_internal_error() {
        let report = app_err_to_problem_report(&AppError::Internal("boom".into()));
        assert_eq!(report.code, codes::INTERNAL);
        assert_eq!(report.comment, "internal error: boom");
    }
}
