// Handlers share the `Result<_, Response>` shape via `parse_payload`.
#![allow(clippy::result_large_err)]

//! The notifications slice (VTI-NTF-001 – 063, trust-tasks-tf #1012).
//!
//! - `notifications/notify/0.1` and `notifications/relay/0.1` — what an originator or a relayer
//!   sends this VTA. **Counterparty tasks** ([`is_counterparty_task`]): the sender is a
//!   community, group or network that usually holds no ACL entry here, so a sender the ACL does
//!   not know dispatches on a zero-authority claim, and the acceptance policy — not the ACL —
//!   decides whether anything is kept (VTI-NTF-030). Every layer is verified first
//!   ([`vta_sdk::notifications::verify_delivery`]); a verified document is answered with the
//!   same receipt whether it was held, declined or discarded (VTI-NTF-023).
//! - `vta/notifications/{list,show,dismiss}/0.1` — the principal's clients, with standing in the
//!   context the notification is held in (VTI-NTF-050, VTI-NTF-051).
//!
//! Nothing here sends a message: receiving, reading and dismissing a notification tell nobody
//! anything (VTI-NTF-053).

use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::notifications::{ChainError, verify_delivery};
use vti_specs::notifications as wire;
use vti_specs::vta::notifications as spec;

use crate::auth::AuthClaims;
use crate::operations::notifications::{self as engine, Disposition, ListFilter, ReadError};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared,
    reject_with, success_response,
};

/// The tasks an originator or a relayer sends this VTA: dispatched on a zero-authority claim
/// when the ACL does not know the sender (`messaging::auth::resolve_trust_task_sender`). The
/// handlers read the proven sender as nothing but the party to answer.
pub(crate) fn is_counterparty_task(type_uri: &str) -> bool {
    type_uri == vta_sdk::trust_tasks::TASK_NOTIFICATIONS_NOTIFY_0_1
        || type_uri == vta_sdk::trust_tasks::TASK_NOTIFICATIONS_RELAY_0_1
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn respond<R: serde::de::DeserializeOwned + serde::Serialize>(
    doc: &TrustTask<Value>,
    value: Value,
) -> TrustTaskOutcome {
    match serde_json::from_value::<R>(value) {
        Ok(r) => success_response(doc, r),
        Err(e) => reject_with(
            doc,
            RejectReason::InternalError {
                reason: format!("{} response does not match its schema: {e}", doc.type_uri),
            },
        ),
    }
}

async fn audit(state: &AppState, action: &str, actor: &str, context: Option<&str>, detail: &str) {
    vta_audit::record_with_detail_best_effort(
        &state.audit_sink,
        action,
        actor,
        None,
        "success",
        Some(TRANSPORT_TRUST_TASK),
        context,
        Some(detail),
    )
    .await;
}

/// `notifications/notify/0.1` and `notifications/relay/0.1`: verify, decide, answer the receipt.
async fn handle_delivery(state: &AppState, doc: TrustTask<Value>, relay: bool) -> TrustTaskOutcome {
    let received = super::received::document_as_received(&doc);
    let delivery = match verify_delivery(&received, &state.trust_task_vm_resolver()).await {
        Ok(d) => d,
        Err(e) => return refuse_chain(&doc, &e, relay),
    };
    let notification_id = delivery.notification().notification_id.to_string();
    let revision = delivery.notification().revision.get();
    match engine::receive(state, &delivery, chrono::Utc::now()).await {
        Ok(disposition) => {
            if let Disposition::Held { record_id } | Disposition::Replaced { record_id } =
                &disposition
            {
                audit(
                    state,
                    "notifications.receive",
                    delivery.delivered_by(),
                    None,
                    &format!(
                        "record {record_id}, kind {}, originator {}",
                        delivery.notification().kind.as_str(),
                        delivery.originator()
                    ),
                )
                .await;
            }
            tracing::debug!(?disposition, relay, "notification received");
        }
        Err(e) => return app_error_to_reject(&doc, e),
    }
    // The same receipt whatever `receive` did (VTI-NTF-023).
    let body = json!({ "notificationId": notification_id, "revision": revision });
    if relay {
        respond::<wire::relay::v0_1::Response>(&doc, body)
    } else {
        respond::<wire::notify::v0_1::Response>(&doc, body)
    }
}

fn refuse_chain(doc: &TrustTask<Value>, e: &ChainError, relay: bool) -> TrustTaskOutcome {
    if relay && e.is_chain_invalid() {
        return reject_declared(
            doc,
            wire::relay::v0_1::error_codes::CHAIN_INVALID,
            e.to_string(),
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
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = parse_payload::<wire::notify::v0_1::Payload>(&doc) {
        return r;
    }
    handle_delivery(state, doc, false).await
}

/// `notifications/relay/0.1`.
pub(super) async fn handle_relay(
    state: &AppState,
    _auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = parse_payload::<wire::relay::v0_1::Payload>(&doc) {
        return r;
    }
    handle_delivery(state, doc, true).await
}

fn refuse_read(
    doc: &TrustTask<Value>,
    e: ReadError,
    unknown: Option<trust_tasks_rs::DeclaredErrorCode>,
) -> TrustTaskOutcome {
    match e {
        ReadError::PermissionDenied => reject_with(
            doc,
            RejectReason::PermissionDenied {
                reason: "no standing in this context".into(),
            },
        ),
        ReadError::Unknown => match unknown {
            Some(code) => reject_declared(
                doc,
                code,
                "no notification is held under that record identifier in this context",
            ),
            None => reject_with(
                doc,
                RejectReason::InternalError {
                    reason: "an unknown record reached a task that names none".into(),
                },
            ),
        },
        ReadError::CursorInvalid => reject_with(
            doc,
            RejectReason::MalformedRequest {
                reason: "this cursor was not issued for these filters; list again without one"
                    .into(),
            },
        ),
        ReadError::App(a) => app_error_to_reject(doc, a),
    }
}

/// `vta/notifications/list/0.1`.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::list::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let context = str_of(p, "contextId").unwrap_or_default().to_string();
    let filter = ListFilter {
        kind: str_of(p, "kind").map(str::to_string),
        held_by: str_of(p, "heldBy").map(str::to_string),
        include_dismissed: p["includeDismissed"].as_bool().unwrap_or(false),
        include_lapsed: p["includeLapsed"].as_bool().unwrap_or(false),
    };
    let limit = p["limit"].as_u64().map(|n| n as usize);
    match engine::list(
        state,
        auth,
        &context,
        &filter,
        str_of(p, "cursor"),
        limit,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(page) => {
            let mut body = json!({
                "items": page.items.iter().map(engine::HeldRecord::to_wire).collect::<Vec<_>>(),
            });
            if let Some(c) = page.next_cursor {
                body["nextCursor"] = json!(c);
            }
            respond::<t::Response>(&doc, body)
        }
        Err(e) => refuse_read(&doc, e, None),
    }
}

/// `vta/notifications/show/0.1`.
pub(super) async fn handle_show(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::show::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let context = str_of(&doc.payload, "contextId")
        .unwrap_or_default()
        .to_string();
    let record_id = str_of(&doc.payload, "recordId")
        .unwrap_or_default()
        .to_string();
    match engine::show(state, auth, &context, &record_id).await {
        Ok(rec) => respond::<t::Response>(
            &doc,
            json!({ "item": rec.to_wire(), "document": rec.document }),
        ),
        Err(e) => refuse_read(&doc, e, Some(t::error_codes::NOTIFICATION_UNKNOWN)),
    }
}

/// `vta/notifications/dismiss/0.1`.
pub(super) async fn handle_dismiss(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::dismiss::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let context = str_of(&doc.payload, "contextId")
        .unwrap_or_default()
        .to_string();
    let record_id = str_of(&doc.payload, "recordId")
        .unwrap_or_default()
        .to_string();
    match engine::dismiss(state, auth, &context, &record_id, chrono::Utc::now()).await {
        Ok(changed) => {
            if changed {
                audit(
                    state,
                    "notifications.dismiss",
                    &auth.did,
                    Some(&context),
                    &format!("record {record_id}"),
                )
                .await;
            }
            respond::<t::Response>(&doc, json!({ "recordId": record_id, "changed": changed }))
        }
        Err(e) => refuse_read(&doc, e, Some(t::error_codes::NOTIFICATION_UNKNOWN)),
    }
}

#[cfg(test)]
#[path = "notifications_tests.rs"]
mod tests;
