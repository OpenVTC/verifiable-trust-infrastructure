#![allow(clippy::result_large_err)]

//! The VTC join-request **Trust Task document** dispatcher.
//!
//! This is the wire adapter the join ceremony grew up into: each holder- or
//! public-facing verb (`submit`/`request`, `accept`, `manifest`, `status`)
//! is a [`trust_tasks_rs::TrustTask`] document. The success reply is a
//! framework `#response` document (a [`VerdictResponse`] for `submit`, a
//! read body for `accept`/`manifest`/`status`); every failure — invalid
//! VIC, expired, malformed, duplicate — is a framework `trust-task-error`
//! document, never a DIDComm problem-report and never a `deny` verdict
//! (`deny` is a *policy* refusal of a verified request; an error means the
//! request never reached the policy). See
//! `docs/05-design-notes/vtc-ceremony-protocol.md` §3.
//!
//! ## Transports
//!
//! Both REST and DIDComm render from the one [`dispatch_trust_task_core`]:
//! - **REST**: the request body is the document; the holder is authenticated
//!   by the document's `eddsa-jcs-2022` proof ([`verify_trust_task_proof`]).
//! - **DIDComm**: the message `type` is the Trust Task URL, the body is the
//!   document, and the authcrypt sender authenticates the holder.
//!
//! ## Auth is per-verb (unlike the VTA's uniform-`AuthClaims` dispatcher)
//!
//! The join family is mostly unauthenticated/holder-bound: `submit`,
//! `accept`, `status` are bound to the holder DID (no ACL entry needed);
//! `manifest` is public. The operator-facing `approve`/`reject`/`list`/
//! `show` verbs stay on their existing JWT-gated REST routes and are *not*
//! routed here. `present` belongs to the `credential-exchange` family and is
//! handled there.

mod helpers;

use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};

use vti_common::error::AppError;

use vta_sdk::protocols::join_requests::{
    self as jr, JoinRequestStatusBody, JoinRequestSubmitBody, VerdictResponse,
};

use crate::join::{JoinSubmitOutcome, JoinTransport};
use crate::server::AppState;

pub(crate) use helpers::TrustTaskOutcome;
use helpers::{
    app_error_to_reject, body_parse_error_response, parse_payload, reject_with, success_response,
    verdict_response, verify_trust_task_proof,
};

/// The transport-resolved caller identity threaded into the dispatcher.
///
/// `sender_did` is the DIDComm authcrypt sender (already cryptographically
/// authenticated); it is `None` over REST, where the holder is recovered
/// from the document proof instead.
pub(crate) struct JoinAuthCtx {
    pub transport: JoinTransport,
    pub sender_did: Option<String>,
}

impl JoinAuthCtx {
    /// The DIDComm context: the authcrypt sender is the proven holder.
    pub fn didcomm(sender_did: String) -> Self {
        Self {
            transport: JoinTransport::DIDComm,
            sender_did: Some(sender_did),
        }
    }

    /// The REST context: the holder is proven by the document proof.
    // Consumed by the REST transport adapter (the per-verb routes' rewire to
    // the document endpoint); kept here as the symmetric counterpart to
    // [`Self::didcomm`].
    #[allow(dead_code)]
    pub fn rest() -> Self {
        Self {
            transport: JoinTransport::Rest,
            sender_did: None,
        }
    }
}

/// The transport-neutral dispatch spine. Parses the document, runs the
/// framework's basic validation (expiry + recipient), then routes by
/// `type` to the matching verb handler.
pub(crate) async fn dispatch_trust_task_core(
    state: &AppState,
    ctx: &JoinAuthCtx,
    body: &[u8],
) -> TrustTaskOutcome {
    // 1. Parse the envelope.
    let doc: TrustTask<Value> = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => return body_parse_error_response(&e.to_string()),
    };

    // 2. Framework §7.2 — expiry + recipient enforcement. The recipient
    //    binding (document `recipient` must equal this VTC's DID) is the
    //    replay defence that the bespoke `audience` field used to provide.
    //    Skipped while the VTC has no DID configured (setup).
    if let Some(vtc_did) = state.config.read().await.vtc_did.clone()
        && let Err(reason) = doc.validate_basic(chrono::Utc::now(), &vtc_did)
    {
        return reject_with(&doc, reason);
    }

    // 3. Dispatch by type URI.
    let type_uri = doc.type_uri.to_string();
    match type_uri.as_str() {
        jr::JOIN_REQUEST_SUBMIT_TYPE => handle_submit(state, ctx, doc).await,
        jr::JOIN_REQUEST_ACCEPT_TYPE => handle_accept(state, ctx, doc).await,
        jr::JOIN_REQUEST_MANIFEST_TYPE => handle_manifest(state, doc).await,
        jr::JOIN_REQUEST_STATUS_TYPE => handle_status(state, ctx, doc).await,
        other => reject_with(
            &doc,
            RejectReason::UnsupportedType {
                type_uri: other.to_string(),
            },
        ),
    }
}

/// The join-request Trust Task URIs this dispatcher routes. Kept in lockstep
/// with the `match` above by the `dispatcher_routes_every_join_uri` test.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const DISPATCHED_URIS: &[&str] = &[
    jr::JOIN_REQUEST_SUBMIT_TYPE,
    jr::JOIN_REQUEST_ACCEPT_TYPE,
    jr::JOIN_REQUEST_MANIFEST_TYPE,
    jr::JOIN_REQUEST_STATUS_TYPE,
];

/// Resolve the proven holder DID for a holder-bound verb. DIDComm → the
/// authcrypt sender; REST → the document proof signer. When the document
/// carries an `issuer`, it must match the proven identity (anti-spoof).
async fn resolve_holder(
    ctx: &JoinAuthCtx,
    doc: &TrustTask<Value>,
) -> Result<String, TrustTaskOutcome> {
    let proven = match &ctx.sender_did {
        Some(did) => did.clone(),
        None => match verify_trust_task_proof(doc).await {
            Ok(did) => did,
            Err(e) => return Err(app_error_to_reject(doc, &e)),
        },
    };
    if let Some(issuer) = doc.issuer.as_deref() {
        let issuer_base = issuer.split('#').next().unwrap_or(issuer);
        if issuer_base != proven {
            return Err(reject_with(
                doc,
                RejectReason::PermissionDenied {
                    reason: format!(
                        "document issuer ({issuer_base}) does not match the authenticated holder ({proven})"
                    ),
                },
            ));
        }
    }
    Ok(proven)
}

// ─── submit / request ────────────────────────────────────────────────────

async fn handle_submit(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: JoinRequestSubmitBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    // Both transports authenticate the holder (REST proof / DIDComm sender)
    // and bind audience + freshness via the document recipient + expiry, so
    // the spine runs with no separate holder-binding signature.
    let outcome = match crate::join::submit_inner(
        state,
        applicant_did,
        body.vp,
        body.registry_consent,
        body.extensions,
        None,
        ctx.transport,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    match outcome_to_verdict(&outcome) {
        Ok(v) => verdict_response(&doc, v),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// Map the ceremony spine's [`JoinSubmitOutcome`] onto the wire
/// [`VerdictResponse`]. Auto-admit → `allow` (credentials inline);
/// `Pending` → `refer`; `Deferred` → `request_more`; `Rejected` → `deny`.
fn outcome_to_verdict(outcome: &JoinSubmitOutcome) -> Result<VerdictResponse, AppError> {
    use crate::ceremony::verdict::Verdict as PolicyVerdict;

    let request_id = outcome.request.id;

    if let Some(admit) = &outcome.admit {
        let role = outcome
            .request
            .policy_decision
            .clone()
            .and_then(|pd| serde_json::from_value::<PolicyVerdict>(pd).ok())
            .and_then(|v| match v {
                PolicyVerdict::Allow(a) => a.role,
                _ => None,
            });
        let vmc = serde_json::to_value(&admit.vmc)
            .map_err(|e| AppError::Internal(format!("serialise VMC: {e}")))?;
        let role_vec = serde_json::to_value(&admit.role_vec)
            .map_err(|e| AppError::Internal(format!("serialise role VEC: {e}")))?;
        return Ok(VerdictResponse::allow(
            request_id,
            role,
            Some(vmc),
            Some(role_vec),
        ));
    }

    // No auto-admit: shape the verdict from the persisted decision.
    let decision = outcome
        .request
        .policy_decision
        .clone()
        .and_then(|pd| serde_json::from_value::<PolicyVerdict>(pd).ok());

    let verdict = match decision {
        Some(PolicyVerdict::RequestMore(rm)) => VerdictResponse {
            request_id,
            verdict: jr::Verdict {
                effect: jr::VerdictEffect::RequestMore,
                with: jr::VerdictWith {
                    needs: rm.needs,
                    presentation_definition: Some(rm.presentation_definition),
                    ..Default::default()
                },
            },
        },
        Some(PolicyVerdict::Deny(d)) => VerdictResponse {
            request_id,
            verdict: jr::Verdict {
                effect: jr::VerdictEffect::Deny,
                with: jr::VerdictWith {
                    code: Some(d.code),
                    reason: d.reason,
                    ..Default::default()
                },
            },
        },
        Some(PolicyVerdict::Refer(r)) => {
            VerdictResponse::refer(request_id, r.queue, r.reason.unwrap_or_default())
        }
        // A `Pending` request with an `Allow`/absent decision (no auto-admit
        // path) is still queued for an admin: surface as `refer`.
        _ => VerdictResponse::refer(
            request_id,
            "admin-review",
            "queued for an admin decision (approve/reject)",
        ),
    };
    Ok(verdict)
}

// ─── accept ──────────────────────────────────────────────────────────────

async fn handle_accept(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let member_did = match resolve_holder(ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: jr::JoinRequestAcceptBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    let outcome = match crate::routes::join_requests::accept::accept_inner(
        state,
        body.request_id,
        member_did,
        body.vmc_id,
        body.vc,
        None,
        ctx.transport,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return app_error_to_reject(&doc, &e),
    };

    success_response(
        &doc,
        jr::JoinRequestAcceptReceiptBody {
            request_id: outcome.request_id,
            status: "accepted".to_string(),
            reciprocal_vc_id: outcome.reciprocal_vc_id,
        },
    )
}

// ─── manifest (public) ─────────────────────────────────────────────────────

async fn handle_manifest(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    match crate::routes::join_requests::manifest::manifest_inner(state).await {
        Ok(body) => success_response(&doc, body),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

// ─── status ────────────────────────────────────────────────────────────────

async fn handle_status(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let applicant_did = match resolve_holder(ctx, &doc).await {
        Ok(did) => did,
        Err(reject) => return reject,
    };
    let body: JoinRequestStatusBody = match parse_payload(&doc) {
        Ok(b) => b,
        Err(reject) => return reject,
    };

    match crate::routes::join_requests::status::status_inner(
        state,
        body.request_id,
        applicant_did,
        None,
    )
    .await
    {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every URI the dispatcher declares as routed must be one of the SDK's
    /// join-request request URIs, and vice-versa — so a new verb can't be
    /// added to one side without the other.
    #[test]
    fn dispatcher_routes_every_join_uri() {
        let sdk = [
            jr::JOIN_REQUEST_SUBMIT_TYPE,
            jr::JOIN_REQUEST_ACCEPT_TYPE,
            jr::JOIN_REQUEST_MANIFEST_TYPE,
            jr::JOIN_REQUEST_STATUS_TYPE,
        ];
        for u in DISPATCHED_URIS {
            assert!(sdk.contains(u), "dispatched URI not a known join URI: {u}");
        }
        assert_eq!(DISPATCHED_URIS.len(), sdk.len());
    }

    /// The request URIs must parse as framework `TypeUri`s (the `/spec/`
    /// path shape), otherwise an inbound document would never deserialise.
    #[test]
    fn join_uris_are_canonical_type_uris() {
        for u in DISPATCHED_URIS {
            let parsed: Result<trust_tasks_rs::TypeUri, _> = u.parse();
            assert!(parsed.is_ok(), "join URI is not a canonical TypeUri: {u}");
        }
    }
}
