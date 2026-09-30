//! First-admin onboarding on the signed-document spine: `vtc/install/claim/
//! {start,finish}/0.2` and `vtc/admin/bootstrap/0.1`.
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
    finish::v0_2 as claim_finish, start::v0_2 as claim_start,
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

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[CLAIM_START_TYPE, CLAIM_FINISH_TYPE, BOOTSTRAP_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    _ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CLAIM_START_TYPE => handle_claim_start(state, doc).await,
        CLAIM_FINISH_TYPE => handle_claim_finish(state, doc).await,
        BOOTSTRAP_TYPE => handle_bootstrap(state, doc).await,
        _ => return None,
    })
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
