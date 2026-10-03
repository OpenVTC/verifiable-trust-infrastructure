//! First-admin onboarding on the signed-document spine: `vtc/install/claim/
//! {start,finish}/0.2` and `/0.3`, and `vtc/admin/bootstrap/0.1`.
//!
//! 0.3 claims the community under a DID the founder **already controls** — a
//! persona their VTA wallet holds — with a step-up approver as their step-up
//! factor (approver design note §6b, R1). Unlike 0.2 its finish is signed, by
//! that DID, and verified against the DID's **live** document: the spine
//! resolves it afresh before verifying ([`refresh_founder_did`]). The binding
//! the finish parks takes effect only when `vtc/admin/bootstrap` consumes the
//! setup-session token (`crate::step_up_approver`).
//!
//! Every one of these is pre-session in the same sense the auth family is
//! (see [`super::auth_tasks`]): there is no ACL entry, no admin, sometimes no
//! community DID yet, so there is nothing for [`super::admin_signer`] to
//! resolve. Each verb's own bearer artifact — the install JWT, the
//! `registrationId` a `start` minted, the setup-session JWT a `finish` minted
//! — is the credential a caller presents; no document proof is required or
//! read (`ctx.verified_signer` is ignored throughout this module).
//!
//! The WebAuthn ceremony itself (`navigator.credentials.create()`) runs
//! client-side regardless of which wire envelope carries its challenge and
//! response, so wrapping the same request/response bodies
//! `routes::install::{claim_start,claim_finish}` already built in a signed
//! Trust Task document changes nothing about the ceremony — only the
//! transport. `routes::admin::bootstrap::bootstrap` needed no such
//! adaptation; it already took nothing but the setup-session token.

use serde_json::Value;
use trust_tasks_rs::specs::vtc::admin::bootstrap::v0_1 as bootstrap;
use trust_tasks_rs::specs::vtc::install::claim::{
    finish::v0_2 as claim_finish, finish::v0_3 as claim_finish_v0_3, start::v0_2 as claim_start,
    start::v0_3 as claim_start_v0_3,
};
use trust_tasks_rs::{Payload, RejectReason, TrustTask};

use super::helpers::{TrustTaskOutcome, reject_with, success_response, task_error_to_reject};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::routes::admin::bootstrap::BootstrapRequest;
use crate::routes::install::{ClaimFinishRequest, ClaimStartRequest};
use crate::server::AppState;

pub(crate) const CLAIM_START_TYPE: &str = <claim_start::Payload as Payload>::TYPE_URI;
pub(crate) const CLAIM_FINISH_TYPE: &str = <claim_finish::Payload as Payload>::TYPE_URI;
pub(crate) const BOOTSTRAP_TYPE: &str = <bootstrap::Payload as Payload>::TYPE_URI;
pub(crate) const CLAIM_START_V0_3_TYPE: &str = <claim_start_v0_3::Payload as Payload>::TYPE_URI;
pub(crate) const CLAIM_FINISH_V0_3_TYPE: &str = <claim_finish_v0_3::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[
    CLAIM_START_TYPE,
    CLAIM_FINISH_TYPE,
    CLAIM_START_V0_3_TYPE,
    CLAIM_FINISH_V0_3_TYPE,
    BOOTSTRAP_TYPE,
];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CLAIM_START_TYPE => handle_claim_start(state, doc).await,
        CLAIM_FINISH_TYPE => handle_claim_finish(state, doc).await,
        CLAIM_START_V0_3_TYPE => handle_claim_start_v0_3(state, doc).await,
        CLAIM_FINISH_V0_3_TYPE => handle_claim_finish_v0_3(state, ctx, doc).await,
        BOOTSTRAP_TYPE => handle_bootstrap(state, doc).await,
        _ => return None,
    })
}

/// An approver task refusal as its trust-task-error document.
fn approver_refusal(
    doc: &TrustTask<Value>,
    e: &crate::step_up_approver::ApproverTaskError,
) -> TrustTaskOutcome {
    use crate::step_up_approver::ApproverTaskError;
    match e {
        ApproverTaskError::Refused {
            code,
            message,
            details,
        } => super::helpers::reject_with_code(
            doc,
            super::helpers::declared_code(code),
            message,
            details.clone(),
        ),
        ApproverTaskError::StepUp(_) => super::helpers::app_error_to_reject(
            doc,
            &vti_common::error::AppError::Internal("an install claim takes no step-up".into()),
        ),
        ApproverTaskError::App(e) => super::helpers::app_error_to_reject(doc, e),
    }
}

/// `vtc/install/claim/start/0.3` — the install token and its claim code open a
/// claim under the DID the token names.
async fn handle_claim_start_v0_3(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: claim_start_v0_3::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match crate::step_up_approver::claim_start_v0_3(state, &payload).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => approver_refusal(&doc, &e),
    }
}

/// `vtc/install/claim/finish/0.3` — signed by the founder's DID (the spine has
/// verified the proof against its live document), carrying the approver's
/// enrolment statement exactly as received.
async fn handle_claim_finish_v0_3(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let Some(signer) = ctx.verified_signer.clone() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let payload: claim_finish_v0_3::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let statement = doc.payload.get("statement").cloned().unwrap_or(Value::Null);
    match crate::step_up_approver::claim_finish_v0_3(state, &signer, &payload, &statement).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => approver_refusal(&doc, &e),
    }
}

/// Before the spine verifies a `vtc/install/claim/finish/0.3` proof: resolve
/// the founder's DID **afresh** — evicting any cached document, so the proof is
/// checked against the DID's live document and never one cached before this
/// request (claim/finish 0.3 consumer item 3) — and answer `didUnresolvable`
/// when it does not resolve, consuming nothing.
///
/// Only for a document whose `claimId` names an open claim and whose `issuer`
/// is the DID that claim names; anything else goes on to the ordinary
/// verification and the handler's own refusals. A `did:key` or `did:peer`
/// carries its keys in its identifier and has nothing to refresh.
pub(super) async fn refresh_founder_did(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Option<TrustTaskOutcome> {
    let claim_id = doc.payload.get("claimId")?.as_str()?;
    let issuer = doc.issuer.as_deref()?;
    let admin_did = crate::step_up_approver::claim_admin_did(state, claim_id)
        .await
        .ok()
        .flatten()?;
    if admin_did != issuer || issuer.starts_with("did:key:") || issuer.starts_with("did:peer:") {
        return None;
    }
    let unresolvable = || {
        super::helpers::reject_with_code(
            doc,
            super::helpers::extended_code(claim_finish_v0_3::error_codes::DID_UNRESOLVABLE.code),
            "the DID the install token names could not be resolved to its live document;              nothing was consumed — try again",
            None,
        )
    };
    let Some(resolver) = state.did_resolver.as_ref() else {
        return Some(unresolvable());
    };
    resolver.remove(issuer).await;
    match resolver.resolve(issuer).await {
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(did = %issuer, error = %e, "install claim 0.3: founder DID unresolvable");
            Some(unresolvable())
        }
    }
}

async fn handle_claim_start(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: claim_start::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let req = ClaimStartRequest {
        install_token: payload.install_token.to_string(),
        claim_secret: payload.claim_secret.as_ref().map(|s| s.to_string()),
    };
    match crate::routes::install::claim_start(state, req).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

async fn handle_claim_finish(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: claim_finish::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let webauthn_response = match serde_json::from_value(Value::Object(payload.webauthn_response)) {
        Ok(r) => r,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("webauthnResponse: {e}"),
                },
            );
        }
    };
    let req = ClaimFinishRequest {
        install_token: payload.install_token.to_string(),
        registration_id: payload.registration_id.to_string(),
        webauthn_response,
    };
    match crate::routes::install::claim_finish(state, req).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}

async fn handle_bootstrap(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: bootstrap::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let req = BootstrapRequest {
        setup_session_token: payload.setup_session_token.to_string(),
    };
    match crate::routes::admin::bootstrap::bootstrap(state, req).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}
