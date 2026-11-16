//! `notifications/notify/0.1` and `notifications/relay/0.1` addressed to this community
//! (VTI-NTF-020 – 046, trust-tasks-tf #1012): verified layer by layer, held by the stated
//! acceptance policy (`crate::notifications::inbox`), and answered with the same receipt
//! whether held, declined or discarded (VTI-NTF-023).
//!
//! The sender is a party that usually holds no ACL entry here — another community, a network —
//! so these sit on the open door beside the join tasks; the proof the spine verified binds the
//! document to its issuer, and the acceptance policy, not the ACL, decides what is kept.
//!
//! The administrators' tasks over what is held (trust-tasks-tf #1017, VTI-NTF-070 – 074):
//!
//! | task | authority (read now from the signer's entry) |
//! |---|---|
//! | `vtc/notifications/list/0.1`, `show/0.1` | `vtc.notifications.read` |
//! | `vtc/notifications/relay/0.1` | `vtc.notifications.relay` for the selection — unqualified for `allMembers` and `role`, or at `group:<groupId>` for that group; `allMembers` also takes the requester's step-up bound to the document (VTI-NTF-074) |

use super::routing::{Routes, on};
use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
use vta_sdk::notifications::{ChainError, verify_delivery};
use vti_specs::notifications as wire;

use trust_tasks_rs::validate::ValidatedPayload;
use trust_tasks_rs::{StandardCode, TrustTaskCode};
use vti_specs::vtc::notifications::{list::v0_1 as list, relay::v0_1 as relay, show::v0_1 as show};

use super::helpers::{
    TrustTaskOutcome, app_error_to_reject, extended_code, reject_with, reject_with_code,
    success_response, task_error_to_reject,
};
use super::{JoinAuthCtx, capable_signer, parse_spec_payload};
use crate::acl::{Capability, ResourceQualifier};
use crate::error::TaskError;
use crate::notifications::inbox::{self, ListError, ListFilter, RelayError, Selection};
use crate::server::AppState;

/// The extended codes these tasks declare (the error-code census checks they agree with the
/// generated constants).
pub(crate) const SHOW_ERR_UNKNOWN: &str = "vtc/notifications/show:notificationUnknown";
pub(crate) const RELAY_ERR_UNKNOWN: &str = "vtc/notifications/relay:notificationUnknown";
pub(crate) const RELAY_ERR_NOT_RELAYABLE: &str = "vtc/notifications/relay:notRelayable";
pub(crate) const RELAY_ERR_LAPSED: &str = "vtc/notifications/relay:lapsed";
pub(crate) const RELAY_ERR_NOT_ACKNOWLEDGED: &str =
    "vtc/notifications/relay:disclosureNotAcknowledged";
pub(crate) const RELAY_ERR_GROUP_UNKNOWN: &str = "vtc/notifications/relay:groupUnknown";

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

// ─── the administrators' view (VTI-NTF-070 – 074) ───────────────────────────

/// Register every task this family serves (#2579).
pub(super) fn register(routes: Routes) -> Routes {
    let routes = on!(routes, wire::notify::v0_1::Payload => handle_notify);
    let routes = on!(routes, wire::relay::v0_1::Payload => handle_relay);
    let routes = on!(routes, list::Payload => |state, ctx, doc| handle_list(state, ctx, doc));
    let routes = on!(routes, show::Payload => |state, ctx, doc| handle_show(state, ctx, doc));
    on!(routes, relay::Payload => |state, ctx, doc| handle_admin_relay(state, ctx, doc))
}

/// Answer with `body` held to the generated `#response` type and its schema.
fn respond<R>(doc: &TrustTask<Value>, body: Value) -> TrustTaskOutcome
where
    R: serde::de::DeserializeOwned + serde::Serialize + ValidatedPayload,
{
    let checked = R::validate_value(&body)
        .map_err(|e| e.to_string())
        .and_then(|()| serde_json::from_value::<R>(body).map_err(|e| e.to_string()));
    match checked {
        Ok(response) => success_response(doc, response),
        Err(e) => {
            tracing::error!(task = %doc.type_uri, error = %e, "response does not match its published schema");
            reject_with(
                doc,
                RejectReason::InternalError {
                    reason: format!("response does not match its published schema: {e}"),
                },
            )
        }
    }
}

fn declared(
    doc: &TrustTask<Value>,
    code: &str,
    message: &str,
    details: Option<Value>,
) -> TrustTaskOutcome {
    reject_with_code(doc, extended_code(code), message, details)
}

/// `vtc/notifications/list/0.1`.
async fn handle_list(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::NotificationsRead, None).await
    {
        return reject;
    }
    let _checked: list::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let p = &doc.payload;
    let filter = ListFilter {
        kind: p["kind"].as_str().map(str::to_string),
        held_by: p["heldBy"].as_str().map(str::to_string),
        include_lapsed: p["includeLapsed"].as_bool().unwrap_or(false),
    };
    let limit = p["limit"].as_u64().map(|n| n as usize);
    let now = chrono::Utc::now();
    match inbox::list_page(state, &filter, p["cursor"].as_str(), limit, now).await {
        Ok((items, next)) => {
            let mut body = json!({
                "items": items.iter().map(|r| r.to_wire(now)).collect::<Vec<_>>(),
            });
            if let Some(c) = next {
                body["nextCursor"] = json!(c);
            }
            respond::<list::Response>(&doc, body)
        }
        Err(ListError::CursorInvalid) => reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "this cursor was not issued for these filters; list again without one"
                    .into(),
            },
        ),
        Err(ListError::App(e)) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/notifications/show/0.1`.
async fn handle_show(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(reject) = capable_signer(state, ctx, &doc, Capability::NotificationsRead, None).await
    {
        return reject;
    }
    let checked: show::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    match inbox::get(state, &checked.record_id).await {
        Ok(Some(rec)) => respond::<show::Response>(
            &doc,
            json!({ "item": rec.to_wire(chrono::Utc::now()), "document": rec.document }),
        ),
        Ok(None) => declared(
            &doc,
            SHOW_ERR_UNKNOWN,
            "the community holds no notification under that record identifier",
            None,
        ),
        Err(e) => app_error_to_reject(&doc, &e),
    }
}

/// `vtc/notifications/relay/0.1` — an administrator's relay decision.
async fn handle_admin_relay(
    state: &AppState,
    ctx: &JoinAuthCtx,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let checked: relay::Payload = match parse_spec_payload(&doc) {
        Ok(p) => p,
        Err(reject) => return reject,
    };
    let selection: Selection = match serde_json::from_value(doc.payload["recipients"].clone()) {
        Ok(s) => s,
        Err(e) => {
            return reject_with(
                &doc,
                RejectReason::MalformedRequest {
                    reason: format!("recipients: {e}"),
                },
            );
        }
    };
    // Consumer item 1: the authority for the selection named, from the live entry. A holding
    // qualified by a group covers only that group (VTI-ACL-035).
    let resource = match &selection {
        Selection::Group { group_id } => Some(ResourceQualifier::Group(group_id.clone())),
        Selection::AllMembers | Selection::Role { .. } => None,
    };
    let actor = match capable_signer(
        state,
        ctx,
        &doc,
        Capability::NotificationsRelay,
        resource.as_ref(),
    )
    .await
    {
        Ok(a) => a,
        Err(reject) => return reject,
    };
    // `groupUnknown`: no such group, or one the caller may not see.
    if let Selection::Group { group_id } = &selection {
        let visible = match crate::groups::get(state.directory.ks(), group_id).await {
            Ok(Some(group)) => match crate::groups::Standing::read(state, &actor.did).await {
                Ok(standing) => {
                    standing.sees(&group) || standing.can(Capability::NotificationsRelay)
                }
                Err(e) => return app_error_to_reject(&doc, &e),
            },
            Ok(None) => false,
            Err(e) => return app_error_to_reject(&doc, &e),
        };
        if !visible {
            return declared(
                &doc,
                RELAY_ERR_GROUP_UNKNOWN,
                "the selection names no community group you may see",
                None,
            );
        }
    }
    // An irreversible disclosure is refused rather than made unaudited (VTI-NTF-073).
    if state.audit_writer.is_none() {
        return reject_with_code(
            &doc,
            TrustTaskCode::Standard(StandardCode::Unavailable),
            "the audit log is not configured; a relay decision is refused rather than made \
             unaudited",
            None,
        );
    }
    let acknowledged = checked.disclosure_acknowledged.unwrap_or(false);
    // Refuse what the record itself rules out before asking for a gesture over it.
    let now = chrono::Utc::now();
    match inbox::get(state, &checked.record_id).await {
        Ok(Some(rec)) => {
            if let Err(e) = precheck(&rec, acknowledged, now) {
                return refuse_relay(&doc, e);
            }
        }
        Ok(None) => return refuse_relay(&doc, RelayError::Unknown),
        Err(e) => return app_error_to_reject(&doc, &e),
    }
    // VTI-NTF-074: a decision that reaches every member takes the requester's step-up, bound
    // to this one document, as the community's other irreversible acts do.
    if matches!(selection, Selection::AllMembers) {
        use crate::acl::bound_step_up::{self, Gate};
        match bound_step_up::redeem_or_request(
            state,
            &actor.did,
            &doc.type_uri.to_string(),
            &doc.payload,
            "Relay a notification the community received to all of its members",
        )
        .await
        {
            Ok(Gate::Satisfied) => {}
            Ok(Gate::Required(request)) => {
                return task_error_to_reject(&doc, &TaskError::step_up(request));
            }
            Err(e) => return app_error_to_reject(&doc, &e),
        }
    }
    match inbox::relay(
        state,
        &checked.record_id,
        &actor.did,
        &selection,
        acknowledged,
        now,
    )
    .await
    {
        Ok(outcome) => respond::<relay::Response>(
            &doc,
            json!({
                "recordId": checked.record_id.as_str(),
                "revision": outcome.revision,
                "recipientCount": outcome.recipient_count,
            }),
        ),
        Err(e) => refuse_relay(&doc, e),
    }
}

/// The record's own refusals, in the order the relay engine applies them.
fn precheck(
    rec: &inbox::ReceivedNotification,
    acknowledged: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), RelayError> {
    if !rec.chain_admits_relay() {
        return Err(RelayError::NotRelayable);
    }
    if rec.is_lapsed(now) {
        return Err(RelayError::Lapsed);
    }
    match inbox::disclosure(rec) {
        Some(statement) if !acknowledged => Err(RelayError::DisclosureNotShown(statement)),
        _ => Ok(()),
    }
}

fn refuse_relay(doc: &TrustTask<Value>, e: RelayError) -> TrustTaskOutcome {
    match e {
        RelayError::Unknown => declared(
            doc,
            RELAY_ERR_UNKNOWN,
            "the community holds no notification under that record identifier",
            None,
        ),
        RelayError::NotRelayable => declared(
            doc,
            RELAY_ERR_NOT_RELAYABLE,
            "the community may not relay this notification: it may not be relayed, or it \
             already carries four relays (VTI-NTF-041)",
            None,
        ),
        RelayError::Lapsed => declared(
            doc,
            RELAY_ERR_LAPSED,
            "the notification is withdrawn or its period has ended",
            None,
        ),
        RelayError::DisclosureNotShown(statement) => declared(
            doc,
            RELAY_ERR_NOT_ACKNOWLEDGED,
            "a relay of this notification discloses something about the community; show the \
             administrator `details.relayDisclosure` and send the decision with \
             disclosureAcknowledged true (VTI-NTF-046)",
            Some(json!({ "relayDisclosure": statement })),
        ),
        RelayError::GroupUnknown => declared(
            doc,
            RELAY_ERR_GROUP_UNKNOWN,
            "the selection names no community group you may see",
            None,
        ),
        RelayError::App(e) => app_error_to_reject(doc, &e),
    }
}
