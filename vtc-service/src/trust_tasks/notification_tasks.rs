//! `notifications/notify/0.1` and `notifications/relay/0.1` addressed to this community
//! (VTI-NTF-020 – 046, trust-tasks-tf #1012): verified layer by layer, held by the stated
//! acceptance policy (`crate::notifications::inbox`), and answered with the same receipt
//! whether held, declined or discarded (VTI-NTF-023).
//!
//! The sender is a party that usually holds no ACL entry here — another community, a network —
//! so these sit on the open door beside the join tasks; the proof the spine verified binds the
//! document to its issuer, and the acceptance policy, not the ACL, decides what is kept.

use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::notifications::{ChainError, verify_delivery};
use vti_specs::notifications as wire;

use super::JoinAuthCtx;
use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response,
};
use crate::server::AppState;

async fn handle(state: &AppState, doc: TrustTask<Value>, relay: bool) -> TrustTaskOutcome {
    // The document as received: what this community keeps, and would relay, whole
    // (VTI-NTF-041). Its typed form re-serialised would rewrite the timestamps its issuer signed.
    let received = crate::admin_actions::received_document()
        .map(|r| (*r).clone())
        .unwrap_or_else(|| serde_json::to_value(&doc).unwrap_or(Value::Null));
    let delivery = match verify_delivery(&received, &state.trust_task_vm_resolver()).await {
        Ok(d) => d,
        Err(e) => return refuse(&doc, &e, relay),
    };
    let receipt = json!({
        "notificationId": delivery.notification().notification_id.to_string(),
        "revision": delivery.notification().revision.get(),
    });
    match crate::notifications::inbox::receive(state, &delivery, chrono::Utc::now()).await {
        Ok(disposition) => tracing::debug!(?disposition, relay, "notification received"),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    if relay {
        match serde_json::from_value::<wire::relay::v0_1::Response>(receipt) {
            Ok(r) => success_response(&doc, r),
            Err(e) => internal(&doc, e),
        }
    } else {
        match serde_json::from_value::<wire::notify::v0_1::Response>(receipt) {
            Ok(r) => success_response(&doc, r),
            Err(e) => internal(&doc, e),
        }
    }
}

fn internal(doc: &TrustTask<Value>, e: serde_json::Error) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::InternalError {
            reason: format!("receipt does not match its schema: {e}"),
        },
    )
}

fn refuse(doc: &TrustTask<Value>, e: &ChainError, relay: bool) -> TrustTaskOutcome {
    if relay && e.is_chain_invalid() {
        let code = wire::relay::v0_1::error_codes::CHAIN_INVALID;
        return reject_with_code(
            doc,
            extended_code(&format!("{}:{}", code.namespace(), code.local())),
            e.to_string(),
            None,
        );
    }
    match e {
        ChainError::Proof { .. } => reject_with(
            doc,
            RejectReason::ProofInvalid {
                reason: e.to_string(),
            },
        ),
        _ => reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: e.to_string(),
            },
        ),
    }
}

/// `notifications/notify/0.1`.
pub(super) async fn handle_notify(
    state: &AppState,
    _ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    handle(state, doc, false).await
}

/// `notifications/relay/0.1`.
pub(super) async fn handle_relay(
    state: &AppState,
    _ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    handle(state, doc, true).await
}
