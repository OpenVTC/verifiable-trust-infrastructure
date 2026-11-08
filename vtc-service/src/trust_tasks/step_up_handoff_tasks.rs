//! The step-up hand-off on the signed-document spine —
//! `auth/step-up/requests/show/0.1` (VTI-LNK-125 – VTI-LNK-131).
//!
//! A step-up refused to a party that cannot answer it — a key the subject
//! delegated, such as an assistant's — carries a single-use handle beside the
//! inline request ([`bound_step_up::refusal_details`]). That party shows the
//! subject a `step-up` trigger link, and the subject's wallet sends this task
//! with the handle, signed by a fresh `did:key` (VTI-LNK-054). It gets back
//! the step-up request as a document this community signs, addressed to the
//! subject, and the operation exactly as received, so it can show the
//! operation itself and recompute the binding (VTI-LNK-130). The answer is the
//! ordinary `auth/step-up/approve-response/0.7`, signed by the subject.
//!
//! | task | signed by | authority |
//! |---|---|---|
//! | `requests/show` | any key — typically one made for this exchange | possession of a live handle, which authorizes this one read and nothing else |
//!
//! The read spends the handle whoever sends it (consumer item 1), and every
//! handle that answers nothing gets the one `notFound` (item 2), so a handle
//! tells nobody which of unknown, spent, expired or settled it was. Reading is
//! no part of an approval (item 5): the step-up is still recorded only from an
//! approve-response meeting that task's own checks.

use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_specs::auth::step_up::approve_request::v0_5 as approve_request;
use vti_specs::auth::step_up::requests::show::v0_1 as show;

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, declared_code, reject_with, reject_with_code,
    success_response,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::acl::bound_step_up::{self, HandoffShown};
use crate::server::AppState;
use vti_common::error::AppError;

pub(crate) const SHOW_TYPE: &str = <show::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const APPROVE_REQUEST_TYPE: &str = <approve_request::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[SHOW_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        SHOW_TYPE => handle_show(state, ctx, doc).await,
        _ => return None,
    })
}

/// `auth/step-up/requests/show/0.1`.
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // The proof is REQUIRED, so the spine verified it; who signed is recorded
    // only so the spend is attributable, and confers nothing.
    let Some(signer) = ctx.verified_signer.as_deref() else {
        return reject_with(&doc, RejectReason::ProofRequired);
    };
    let payload: show::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let shown = match bound_step_up::take_handoff(state, &payload.handle).await {
        Ok(Some(shown)) => shown,
        Ok(None) => {
            return reject_with_code(
                &doc,
                declared_code(show::error_codes::NOT_FOUND.code),
                "no pending step-up answers to this handle",
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, &e),
    };
    tracing::info!(
        subject = %shown.subject,
        task = %shown.type_uri,
        reader = %signer,
        "step-up hand-off read"
    );
    match response_for(state, shown).await {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// The response: the inline request as an `approve-request/0.5` document this
/// community signs, addressed to the subject (consumer item 3), and the
/// operation exactly as received (item 4).
async fn response_for(state: &AppState, shown: HandoffShown) -> Result<show::Response, AppError> {
    let signer = state.credential_signer.as_deref().ok_or_else(|| {
        AppError::Internal("this community has no signing key to sign the step-up request".into())
    })?;
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .ok_or_else(|| AppError::Internal("this community has no DID configured".into()))?;
    let mut request = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": APPROVE_REQUEST_TYPE,
        "issuer": vtc_did,
        "recipient": shown.subject,
        "expiresAt": bound_step_up::rfc3339(shown.expires_at),
        "payload": shown.request,
    });
    signer.sign_operational_doc(&mut request).await?;
    let response = json!({
        "request": request,
        "operation": { "type": shown.type_uri, "payload": shown.payload },
    });
    use trust_tasks_rs::validate::ValidatedPayload as _;
    show::Response::validate_value(&response)
        .map_err(|e| AppError::Internal(format!("requests/show response does not conform: {e}")))?;
    serde_json::from_value(response)
        .map_err(|e| AppError::Internal(format!("requests/show response does not parse: {e}")))
}
