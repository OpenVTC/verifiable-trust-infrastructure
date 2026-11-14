//! Cross-community recognition on the signed-document spine:
//! `vtc/auth/recognise/challenge/0.2` and `vtc/auth/recognise/0.3`.
//!
//! Both are pre-session in the same sense the auth family is (see
//! [`super::auth_tasks`]): the caller is a foreign community's member, who
//! has no ACL row here to resolve. Neither task's own document requires a
//! proof — the authority is the holder-signed W3C Verifiable Presentation
//! `recognise`'s payload carries, verified by `crate::credentials::exchange::
//! verify_vp_token` exactly as the (now-removed) REST route did.

use super::routing::{Routes, on};
use serde_json::Value;
use trust_tasks_rs::{Payload, TrustTask};
use vti_specs::vtc::auth::recognise::{challenge::v0_2 as recognise_challenge, v0_3 as recognise};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, success_response, task_error_to_reject,
};
use super::parse_spec_payload;
use crate::server::AppState;

#[cfg(test)]
pub(crate) const CHALLENGE_TYPE: &str = <recognise_challenge::Payload as Payload>::TYPE_URI;

pub(crate) const RECOGNISE_TYPE: &str = <recognise::Payload as Payload>::TYPE_URI;

/// Tasks whose response carries a cross-community access token. The
/// duplicate-execution record keeps no copy of these; a redelivery is answered
/// `204`.
pub(crate) const SECRET_RESPONSES: &[&str] = &[RECOGNISE_TYPE];

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes =
        on!(routes, recognise_challenge::Payload => |state, _, doc| handle_challenge(state, doc));
    on!(routes, recognise::Payload => |state, _, doc| handle_recognise(state, doc))
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
