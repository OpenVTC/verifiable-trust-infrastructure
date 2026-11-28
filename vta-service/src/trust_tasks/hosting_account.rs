//! `did-management/account/expiry-notice/0.1` — the DID hosting service this
//! VTA self-registered with, warning that its account is about to be disabled,
//! has been, or is about to be purged.
//!
//! A counterparty task (`is_counterparty_task`): the host holds no ACL entry
//! here, so the notice is dispatched on a zero-authority claim, and the
//! transport has already bound the document to its sender. What decides
//! whether it is kept is [`crate::hosting_account::receive_notice`]: only a
//! notice from the host this VTA registered with, compared as identities.
//! One-way: answered with nothing, kept or not, so a reply tells no one when
//! this VTA was online. A kept notice also triggers an immediate renewal,
//! which restores an account the lifecycle disabled.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::auth::AuthClaims;

use super::helpers::{TrustTaskOutcome, parse_payload, silence};
use crate::server::AppState;

/// The notice's Type URI.
pub(crate) const TASK_ACCOUNT_EXPIRY_NOTICE_0_1: &str =
    "https://trusttasks.org/spec/did-management/account/expiry-notice/0.1";

/// Whether `type_uri` is the notice: sent by a DID host, which holds no ACL entry.
pub(crate) fn is_counterparty_task(type_uri: &str) -> bool {
    type_uri == TASK_ACCOUNT_EXPIRY_NOTICE_0_1
}

pub(super) async fn handle_expiry_notice(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let payload = match parse_payload::<
        vti_specs::did_management::account::expiry_notice::v0_1::Payload,
    >(&doc)
    {
        Ok(p) => p,
        Err(r) => return r,
    };
    let stage = serde_json::to_value(payload.stage)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let account = serde_json::to_value(payload.account).unwrap_or(Value::Null);
    match crate::hosting_account::receive_notice(state, &auth.did, &stage, account).await {
        Ok(true) => {
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::hosting_account::refresh(&state, true).await {
                    tracing::warn!(error = %e, "renewal after a hosting expiry notice failed");
                }
            });
        }
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "could not record a hosting expiry notice"),
    }
    silence()
}
