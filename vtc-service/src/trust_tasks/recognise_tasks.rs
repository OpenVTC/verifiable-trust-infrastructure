//! Cross-community recognition on the signed-document spine:
//! `vtc/auth/recognise/challenge/0.1` and `vtc/auth/recognise/0.2`.
//!
//! Both are pre-session in the same sense the auth family is (see
//! [`super::auth_tasks`]): the caller is a foreign community's member, who
//! has no ACL row here to resolve. Neither task's own document requires a
//! proof — the authority is the holder-signed W3C Verifiable Presentation
//! `recognise`'s payload carries, verified by `crate::credentials::exchange::
//! verify_vp_token` exactly as the (now-removed) REST route did.

use serde_json::Value;
use trust_tasks_rs::specs::vtc::auth::recognise::{
    challenge::v0_1 as recognise_challenge, v0_2 as recognise,
};
use trust_tasks_rs::{Payload, TrustTask};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, parse_spec_payload};
use crate::server::AppState;

pub(crate) const CHALLENGE_TYPE: &str = <recognise_challenge::Payload as Payload>::TYPE_URI;
pub(crate) const RECOGNISE_TYPE: &str = <recognise::Payload as Payload>::TYPE_URI;

/// Exactly what [`dispatch`] routes.
pub(crate) const URIS: &[&str] = &[CHALLENGE_TYPE, RECOGNISE_TYPE];

pub(super) async fn dispatch(
    state: &AppState,
    _ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
    type_uri: &str,
) -> Option<TrustTaskOutcome> {
    Some(match type_uri {
        CHALLENGE_TYPE => handle_challenge(state, doc).await,
        RECOGNISE_TYPE => handle_recognise(state, doc).await,
        _ => return None,
    })
}

async fn handle_challenge(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    if let Err(reject) = parse_spec_payload::<recognise_challenge::Payload>(&doc) {
        return reject;
    }
    match crate::routes::recognise::recognise_challenge(state).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

async fn handle_recognise(state: &AppState, doc: TrustTask<Value>) -> TrustTaskOutcome {
    let payload: recognise::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let presentation = Value::Object(payload.presentation);
    match crate::routes::recognise::recognise(state, presentation).await {
        Ok(resp) => success_response(&doc, resp),
        Err(e) => task_error_to_reject(&doc, &e),
    }
}
