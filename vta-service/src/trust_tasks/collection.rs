// Handlers share the `Result<_, Response>` shape via `parse_payload`.
#![allow(clippy::result_large_err)]

//! The collection slice (VTI-NTF-080 – 093, trust-tasks-tf #1023, #1024).
//!
//! - `vta/collection/{claim,release,list}/0.1` — a client of the principal, with
//!   standing in the identifier's context, claims, releases or lists who holds a
//!   persona DID's one mediator connection ([`crate::operations::collection`]).
//!   Served whether or not collection by default is enabled (VTI-NTF-093).
//! - [`answer_collected`] — what the VTA does with a document it collected for a
//!   persona DID (`crate::messaging::collector`). A `notifications/notify` or
//!   `notifications/relay` is taken **exactly** as a deposit is: every layer
//!   verified, this node's receipt checks applied at the time of collection,
//!   the acceptance policy counting the party that delivered it, one record,
//!   and the same receipt (VTI-NTF-086). Every other operation is refused as one
//!   the identifier does not serve (VTI-NTF-087, VTI-OPS-081) — never performed,
//!   held or relayed, whatever authority its sender holds here. Every answer is
//!   made **as the persona**: its issuer is the persona and its proof the
//!   persona's key, and nothing in it names this VTA.

use serde_json::{Value, json};
use trust_tasks_rs::{RejectReason, TrustTask};
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use vta_sdk::notifications::{identity, verify_delivery};
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use vti_specs::notifications as wire;
use vti_specs::vta::collection as spec;

use crate::auth::AuthClaims;
use crate::operations::collection::{self as engine, CollectionError};
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use crate::operations::notifications as held;
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_declared,
    reject_with, success_response,
};

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

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

async fn audit(state: &AppState, action: &str, actor: &str, context: &str, detail: &str) {
    vta_audit::record_with_detail_best_effort(
        &state.audit_sink,
        action,
        actor,
        None,
        "success",
        Some(TRANSPORT_TRUST_TASK),
        Some(context),
        Some(detail),
    )
    .await;
}

fn permission_denied(doc: &TrustTask<Value>) -> TrustTaskOutcome {
    reject_with(
        doc,
        RejectReason::PermissionDenied {
            reason: "no standing in this context".into(),
        },
    )
}

/// `vta/collection/claim/0.1`. See [`engine::claim`].
pub(super) async fn handle_claim(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::claim::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let context = str_of(p, "contextId").unwrap_or_default().to_string();
    let identifier = str_of(p, "identifier").unwrap_or_default().to_string();
    let duration = p["durationSeconds"].as_i64();
    match engine::claim(
        state,
        auth,
        &context,
        &identifier,
        duration,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(grant) => {
            audit(
                state,
                "collection.claim",
                &auth.did,
                &context,
                &format!(
                    "{} {} until {}",
                    if grant.renewed { "renewed" } else { "granted" },
                    grant.identifier,
                    rfc3339(grant.ends_at)
                ),
            )
            .await;
            let mut body = json!({
                "identifier": grant.identifier,
                "endsAt": rfc3339(grant.ends_at),
            });
            if grant.renewed {
                body["renewed"] = json!(true);
            }
            respond::<t::Response>(&doc, body)
        }
        Err(CollectionError::PermissionDenied) => permission_denied(&doc),
        Err(CollectionError::NotCollectable) => reject_declared(
            &doc,
            t::error_codes::NOT_COLLECTABLE,
            "this VTA does not collect for that identifier in this context (VTI-NTF-080)",
        ),
        Err(CollectionError::ClaimHeld) => reject_declared(
            &doc,
            t::error_codes::CLAIM_HELD,
            "another client holds a collection claim for this identifier that is in force",
        ),
        Err(CollectionError::ClaimNotRenewable) => reject_declared(
            &doc,
            t::error_codes::CLAIM_NOT_RENEWABLE,
            "this claim was released by another party and ends at its end without renewal",
        ),
        Err(CollectionError::CursorInvalid) => reject_with(
            &doc,
            RejectReason::InternalError {
                reason: "a claim carries no cursor".into(),
            },
        ),
        Err(CollectionError::App(e)) => app_error_to_reject(&doc, e),
    }
}

/// `vta/collection/release/0.1`. See [`engine::release`].
pub(super) async fn handle_release(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec::release::v0_1 as t;
    if let Err(r) = parse_payload::<t::Payload>(&doc) {
        return r;
    }
    let p = &doc.payload;
    let context = str_of(p, "contextId").unwrap_or_default().to_string();
    let identifier = str_of(p, "identifier").unwrap_or_default().to_string();
    match engine::release(state, auth, &context, &identifier, chrono::Utc::now()).await {
        Ok(released) => {
            let mut body = json!({ "identifier": released.identifier });
            if let (Some(ends_at), Some(claimant)) = (released.ends_at, &released.claimant) {
                // Consumer item 6: the caller and the claimant, both named.
                audit(
                    state,
                    "collection.release",
                    &auth.did,
                    &context,
                    &format!(
                        "released {} held by {claimant}; ends {}",
                        released.identifier,
                        rfc3339(ends_at)
                    ),
                )
                .await;
                body["endsAt"] = json!(rfc3339(ends_at));
            }
            respond::<t::Response>(&doc, body)
        }
        Err(CollectionError::PermissionDenied) => permission_denied(&doc),
        Err(CollectionError::NotCollectable) => reject_declared(
            &doc,
            t::error_codes::NOT_COLLECTABLE,
            "this VTA does not collect for that identifier in this context (VTI-NTF-080)",
        ),
        Err(CollectionError::App(e)) => app_error_to_reject(&doc, e),
        Err(other) => reject_with(
            &doc,
            RejectReason::InternalError {
                reason: format!("unexpected refusal of a release: {other:?}"),
            },
        ),
    }
}

/// `vta/collection/list/0.1`. See [`engine::list`].
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
    let filter = engine::ListFilter {
        identifier: str_of(p, "identifier").map(str::to_string),
        collector: str_of(p, "collector").map(str::to_string),
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
                "items": page.items.iter().map(engine::Entry::to_wire).collect::<Vec<_>>(),
            });
            if let Some(c) = page.next_cursor {
                body["nextCursor"] = json!(c);
            }
            respond::<t::Response>(&doc, body)
        }
        Err(CollectionError::PermissionDenied) => permission_denied(&doc),
        Err(CollectionError::CursorInvalid) => reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "this cursor was not issued for these filters; list again without one"
                    .into(),
            },
        ),
        Err(CollectionError::App(e)) => app_error_to_reject(&doc, e),
        Err(other) => reject_with(
            &doc,
            RejectReason::InternalError {
                reason: format!("unexpected refusal of a listing: {other:?}"),
            },
        ),
    }
}

// ── Documents collected for a persona ──────────────────────────────────────

#[cfg(any(feature = "didcomm", feature = "tsp"))]
/// The identifier a document was collected for, and the keys the VTA answers
/// with as it.
pub(crate) struct CollectedIdentity {
    pub context_id: String,
    /// The identifier as the principal gives it out.
    pub identifier: String,
    /// Its `did:webvh` log.
    pub log_did: String,
    /// The secrets the identifier signs with, by method id — every form of the
    /// identifier its methods are registered under.
    pub signing: Vec<affinidi_tdk::secrets_resolver::secrets::Secret>,
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
impl std::fmt::Debug for CollectedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectedIdentity")
            .field("context_id", &self.context_id)
            .field("identifier", &self.identifier)
            .field("signing", &self.signing.len())
            .finish()
    }
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
impl CollectedIdentity {
    /// The secret to answer a document addressed to `recipient` with: the one
    /// under the form the sender used, else the first.
    fn signer_for(
        &self,
        recipient: Option<&str>,
    ) -> Option<&affinidi_tdk::secrets_resolver::secrets::Secret> {
        let wanted = recipient.map(identity);
        self.signing
            .iter()
            .find(|s| {
                wanted
                    .as_deref()
                    .is_some_and(|w| identity(s.id.split('#').next().unwrap_or_default()) == w)
            })
            .or_else(|| self.signing.first())
    }

    fn addressed_here(&self, recipient: Option<&str>) -> bool {
        recipient.is_some_and(|r| {
            let r = identity(r);
            r == identity(&self.identifier) || r == identity(&self.log_did)
        })
    }
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
/// Sign `outcome`'s document as the persona. `None` when there is nothing to
/// send, or it could not be signed: an unsigned answer as the persona would be
/// bytes rather than evidence, and an answer signed by this VTA would name it
/// (VTI-NTF-087).
async fn as_persona(
    me: &CollectedIdentity,
    recipient: Option<&str>,
    outcome: TrustTaskOutcome,
) -> Option<Vec<u8>> {
    if outcome.body.is_empty() {
        return None;
    }
    let secret = me.signer_for(recipient)?;
    let mut doc: Value = serde_json::from_slice(&outcome.body).ok()?;
    if !super::sign_as_authentication(
        secret,
        &mut doc,
        vti_common::trust_task::envelope::EnvelopeRole::Response,
    )
    .await
    {
        tracing::warn!(identifier = %me.identifier, "could not sign an answer as a collected identifier");
        return None;
    }
    serde_json::to_vec(&doc).ok()
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
/// What the VTA answers, as `me`, to a document `sender` delivered to a persona
/// it collects for (see the module docs). `None`: nothing goes back — an error
/// or a reply is terminal, and a sender without standing past its budget is
/// not answered (VTI-TRN-029).
pub(crate) async fn answer_collected(
    state: &AppState,
    me: &CollectedIdentity,
    sender: &str,
    body: &[u8],
) -> Option<Vec<u8>> {
    use vta_sdk::inbound::{Inbound, classify};
    let received: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            let outcome = super::reject_trust_task(
                body,
                RejectReason::MalformedRequest {
                    reason: format!("not a Trust Task document: {e}"),
                },
            );
            return as_persona(me, None, outcome).await;
        }
    };
    if !matches!(classify(&received), Inbound::Request) {
        // The VTA sends nothing as a persona, so no reply is awaited, and an
        // error is terminal.
        return None;
    }
    let recipient = received["recipient"].as_str().map(str::to_string);
    let type_uri = received["type"].as_str().unwrap_or_default().to_string();

    // One bound for the node, whatever identifier a message was collected for
    // (VTI-NTF-088): a sender with no entry here counts against the bound for
    // senders without standing.
    let now_unix = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default();
    let has_standing = vti_common::acl::get_acl_entry(&state.acl_ks, sender)
        .await
        .ok()
        .flatten()
        .is_some_and(|e| !e.is_expired(now_unix));
    let caller = if has_standing {
        super::operation_budget::Caller::Client(sender)
    } else {
        super::operation_budget::Caller::Unauthenticated
    };
    if let Err(refused) = state.operation_budget.charge(caller, &type_uri) {
        if refused.scope == super::operation_budget::Scope::Unauthenticated {
            return None;
        }
        let retry_after = chrono::Duration::from_std(refused.retry_after)
            .ok()
            .and_then(|d| chrono::Utc::now().checked_add_signed(d));
        let outcome = super::reject_trust_task(body, RejectReason::Unavailable { retry_after });
        return as_persona(me, recipient.as_deref(), outcome).await;
    }

    let doc: TrustTask<Value> = match serde_json::from_value(received.clone()) {
        Ok(d) => d,
        Err(e) => {
            let outcome = super::reject_trust_task(
                body,
                RejectReason::MalformedRequest {
                    reason: format!("not a Trust Task document: {e}"),
                },
            );
            return as_persona(me, recipient.as_deref(), outcome).await;
        }
    };
    let relay = type_uri == vta_sdk::trust_tasks::TASK_NOTIFICATIONS_RELAY_0_1;
    let notify = type_uri == vta_sdk::trust_tasks::TASK_NOTIFICATIONS_NOTIFY_0_1;
    let outcome = if !(notify || relay) {
        // VTI-NTF-087: not performed, not held, not relayed — refused as an
        // operation this identifier does not serve (VTI-OPS-081).
        tracing::info!(identifier = %me.identifier, %type_uri,
            "refused an operation collected for a persona: only notifications are taken");
        reject_with(
            &doc,
            RejectReason::UnsupportedType {
                type_uri: doc.type_uri.to_string(),
            },
        )
    } else if !me.addressed_here(recipient.as_deref()) {
        reject_with(
            &doc,
            RejectReason::MalformedRequest {
                reason: "the document is not addressed to this identifier".into(),
            },
        )
    } else {
        take_delivery(state, me, sender, &doc, (&received, body), relay).await
    };
    as_persona(me, recipient.as_deref(), outcome).await
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
/// A collected notify or relay, taken as a deposit is (VTI-NTF-086).
async fn take_delivery(
    state: &AppState,
    me: &CollectedIdentity,
    sender: &str,
    doc: &TrustTask<Value>,
    (received, body): (&Value, &[u8]),
    relay: bool,
) -> TrustTaskOutcome {
    let parsed = if relay {
        parse_payload::<wire::relay::v0_1::Payload>(doc).map(|_| ())
    } else {
        parse_payload::<wire::notify::v0_1::Payload>(doc).map(|_| ())
    };
    if let Err(r) = parsed {
        return r;
    }
    // The transport proved the sender; the document must prove its composer is
    // that sender, as on every other path a document reaches this node by.
    if let Err(reason) = super::bind_document_to_sender(state, sender, body).await {
        return reject_with(doc, reason);
    }
    let delivery = match verify_delivery(received, &state.trust_task_vm_resolver()).await {
        Ok(d) => d,
        Err(e) => return super::notifications::refuse_chain(doc, &e, relay),
    };
    let now = chrono::Utc::now();
    // This node's own receipt checks, at the time of collection in the place
    // of the hand-over (VTI-NTF-055 as VTI-NTF-086 applies it).
    let first_seen = match super::admit_carried_document(state, doc, now).await {
        Ok(claim) => claim,
        Err(reason) => return reject_with(doc, reason),
    };
    let notification_id = delivery.notification().notification_id.to_string();
    let revision = delivery.notification().revision.get();
    if let Some(claim) = first_seen {
        match held::receive(state, &delivery, now).await {
            Ok(disposition) => {
                claim.completed(None).await;
                vta_audit::record_with_detail_best_effort(
                    &state.audit_sink,
                    "notifications.collect",
                    delivery.delivered_by(),
                    None,
                    "success",
                    Some("collection"),
                    Some(&me.context_id),
                    Some(&format!(
                        "{}; collected for {}, kind {}, originator {}",
                        super::notifications::disposition_label(&disposition),
                        me.identifier,
                        delivery.notification().kind.as_str(),
                        delivery.originator()
                    )),
                )
                .await;
            }
            Err(e) => {
                claim.release().await;
                return app_error_to_reject(doc, e);
            }
        }
    }
    // The same receipt whatever `receive` did, and whoever collected
    // (VTI-NTF-023, VTI-NTF-086).
    let body = json!({ "notificationId": notification_id, "revision": revision });
    if relay {
        respond::<wire::relay::v0_1::Response>(doc, body)
    } else {
        respond::<wire::notify::v0_1::Response>(doc, body)
    }
}

#[cfg(all(test, any(feature = "didcomm", feature = "tsp")))]
#[path = "collection_tests.rs"]
mod tests;
