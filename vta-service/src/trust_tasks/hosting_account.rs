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

/// `vta/hosting-account/get/0.1`.
pub(crate) const TASK_VTA_HOSTING_ACCOUNT_GET_0_1: &str =
    "https://trusttasks.org/spec/vta/hosting-account/get/0.1";

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
    let received = crate::hosting_account::receive_notice(state, &auth.did, &stage, account).await;
    // Audited whatever became of it: a notice kept says the VTA's DID is at risk,
    // and one dropped says a party other than the host claimed to speak for it.
    let outcome = match &received {
        Ok(true) => "accepted",
        Ok(false) => "dropped",
        Err(_) => "failure",
    };
    if let Err(e) = crate::audit::record_with_detail(
        &state.audit_sink,
        "hosting.expiry_notice",
        &auth.did,
        None,
        outcome,
        Some(super::helpers::TRANSPORT_TRUST_TASK),
        None,
        Some(&stage),
    )
    .await
    {
        tracing::warn!(error = %e, "audit emission failed for hosting.expiry_notice");
    }
    match received {
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

/// `vta/hosting-account/get/0.1`: this VTA's self-registered hosting account,
/// for its principal. Admin only. With `refresh`, the account is read from the
/// host first (`account/status`, which keeps nothing alive) — never renewed.
pub(super) async fn handle_get(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use super::helpers::{app_error_to_reject, reject_declared, success_response};
    use vti_specs::vta::hosting_account::get::v0_1 as spec;

    if let Err(e) = auth.require_admin() {
        return app_error_to_reject(&doc, e);
    }
    let payload = match parse_payload::<spec::Payload>(&doc) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let record = if payload.refresh == Some(true) {
        match crate::hosting_account::refresh(state, false).await {
            Ok(r) => Some(r),
            // No account: the plain answer, not a failure.
            Err(vti_common::error::AppError::NotFound(_))
                if matches!(
                    crate::hosting_account::load(&state.service_state_ks).await,
                    Ok(None)
                ) =>
            {
                None
            }
            Err(e) => {
                return reject_declared(
                    &doc,
                    spec::error_codes::HOST_UNREACHABLE,
                    format!("could not read the hosting account from the host: {e}"),
                );
            }
        }
    } else {
        match crate::hosting_account::load(&state.service_state_ks).await {
            Ok(r) => r,
            Err(e) => return app_error_to_reject(&doc, e),
        }
    };
    let body = match record {
        None => serde_json::json!({ "registered": false }),
        Some(r) => {
            // The spec's record, member by member: `serverId` is this VTA's own
            // index into its server list, which means nothing to the principal.
            let mut hosting = serde_json::json!({
                "serverDid": r.server_did,
                "domain": r.domain,
                "registeredAt": r.registered_at,
            });
            if let Some(account) = r.account {
                hosting["account"] = account;
            }
            if let Some(t) = r.checked_at {
                hosting["checkedAt"] = serde_json::json!(t);
            }
            if let Some(t) = r.renewed_at {
                hosting["renewedAt"] = serde_json::json!(t);
            }
            if let Some(n) = r.last_notice {
                hosting["lastNotice"] =
                    serde_json::json!({ "stage": n.stage, "receivedAt": n.received_at });
            }
            if let Some(e) = r.last_error {
                hosting["lastError"] = serde_json::json!(e.chars().take(1024).collect::<String>());
            }
            serde_json::json!({ "registered": true, "hosting": hosting })
        }
    };
    match serde_json::from_value::<spec::Response>(body) {
        Ok(response) => success_response(&doc, response),
        Err(e) => app_error_to_reject(
            &doc,
            vti_common::error::AppError::Internal(format!(
                "the hosting account record does not match vta/hosting-account/get: {e}"
            )),
        ),
    }
}
