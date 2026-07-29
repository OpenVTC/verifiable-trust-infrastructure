//! Mint the `task-consent/request/0.1` document an approver renders and signs.
//!
//! The document is **signed by the VTA**, and that signature is the whole point.
//! A consent surface renders `effects` as the basis of a human's decision, so an
//! unsigned request would let anyone who can reach the approver's device author
//! the prose the human reads — including the relying party whose task is being
//! approved — while every downstream signature still verified.
//!
//! Step-up's `approveRequest` is signed the same way (see
//! `super::step_up::mint_pending_step_up`): both request legs put prose in
//! front of a human, so both must be attributable to their issuer, and the
//! signed request doubles as retainable evidence of exactly what was asked.
//! The challenge binding still carries each decision's freshness — the
//! signature authenticates the ask, the challenge scopes the approval.

// Only the DIDComm delivery paths below bound their sends.
#[cfg(feature = "didcomm")]
use std::time::Duration;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions, crypto_suites::CryptoSuite};
use serde_json::{Value, json};
use vti_common::error::AppError;

/// How long the delivery layer keeps retrying the task-consent push *hop* to the
/// mediator across websocket reconnects before the outbox entry settles
/// `Unconfirmed` and the relay fallback carries the request. Bounds hop-retry,
/// not the request's own validity (the mediator holds a hop-accepted push for
/// the device to collect whenever it next connects). Matches the step-up push
/// window (`STEP_UP_TTL_SECS`).
#[cfg(feature = "didcomm")]
const CONSENT_PUSH_DELIVER_BY_SECS: u64 = 300;

use crate::policy::consent::PendingTaskConsent;
use crate::policy::effects::Effect;
use crate::policy::types::TaskClass;
use crate::server::AppState;

pub(super) const TASK_CONSENT_REQUEST_0_1: &str =
    "https://trusttasks.org/spec/task-consent/request/0.1";

/// Fire-and-forget notice to the **requester** that its task is now approved and
/// a grant is ready. Lets the requester re-submit the moment the approval lands
/// instead of polling for it.
#[cfg(feature = "didcomm")]
pub(super) const TASK_CONSENT_GRANTED_0_1: &str =
    "https://trusttasks.org/spec/task-consent/granted/0.1";

/// Build one signed `task-consent/request` per eligible approver.
///
/// One document per approver rather than one broadcast document, because the
/// envelope names its `recipient` and an approver should be able to verify a
/// request was addressed to *them* — a document addressed to someone else,
/// replayed at a second device, would otherwise look identical.
///
/// Approvers barred by `excludeRequester` are dropped here rather than left for
/// the device to refuse: there is no reason to ask someone a question whose
/// answer we would not accept.
pub(super) async fn mint_signed_requests(
    state: &AppState,
    pending: &PendingTaskConsent,
    members: &[String],
    class: TaskClass,
    effects: &[Effect],
    subject: Option<&str>,
    origin: Option<&str>,
) -> Result<Vec<Value>, AppError> {
    let vta_did =
        state.config.read().await.vta_did.clone().ok_or_else(|| {
            AppError::Internal("VTA DID not configured; cannot sign consent".into())
        })?;

    let secret =
        crate::operations::credentials::load_vta_issuer_secret(state, &vta_did, "task-consent")
            .await?;

    let class_value = serde_json::to_value(class)
        .map_err(|e| AppError::Internal(format!("serialize task class: {e}")))?;
    let expires_at = chrono::DateTime::from_timestamp(pending.expires_at as i64, 0)
        .ok_or_else(|| AppError::Internal("consent expiry out of range".into()))?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut signed = Vec::new();
    for approver in members {
        if pending.exclude_requester && approver == &pending.requester_did {
            continue;
        }

        let mut payload = json!({
            "challenge": pending.challenge,
            "taskType": pending.type_uri,
            // The salted digest — the only one that ever leaves this process.
            "payloadDigest": pending.wire_digest,
            "sideEffects": class_value.get("sideEffects"),
            "exposure": class_value.get("exposure"),
            "effects": effects,
            "requester": pending.requester_did,
            "approverSet": pending.approver_set,
            "minApprovals": pending.min_approvals,
            "excludeRequester": pending.exclude_requester,
            "expiresAt": expires_at,
        });
        if let Some(s) = subject {
            payload["subject"] = json!(s);
        }
        if let Some(o) = origin {
            payload["origin"] = json!(o);
        }
        if let Some(pin) = &pending.state_pin {
            payload["statePin"] = serde_json::to_value(pin)
                .map_err(|e| AppError::Internal(format!("serialize state pin: {e}")))?;
        }

        let unsigned = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": TASK_CONSENT_REQUEST_0_1,
            "issuer": vta_did,
            "recipient": approver,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload,
        });

        let proof = DataIntegrityProof::sign(
            &unsigned,
            &secret,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .map_err(|e| AppError::Internal(format!("sign task-consent request: {e}")))?;

        let mut doc = unsigned;
        doc["proof"] = serde_json::to_value(&proof)
            .map_err(|e| AppError::Internal(format!("serialize proof: {e}")))?;
        signed.push(doc);
    }

    Ok(signed)
}

/// Deliver the signed requests to the approvers' devices.
///
/// **The same document the reject carries.** The relay fallback and the push are
/// two transports for one signed object, not two descriptions of one event — a
/// device must not be able to see different effects depending on how the request
/// reached it.
///
/// Best-effort and fire-and-forget: an approver replies later with a separate
/// `task-consent/decision`, and the requester still holds the relay copy if none
/// of this works. A push failure must never turn into a task failure.
///
/// Mirrors [`super::step_up::maybe_push_step_up`]: buffer at the approver's
/// mediator, send it, then ring the doorbell. The buffer alone does not reach a
/// device, and the wake alone has nothing to collect.
pub(super) async fn push_signed_requests(state: &AppState, requests: &[Value]) {
    for request in requests {
        let Some(approver) = request.get("recipient").and_then(Value::as_str) else {
            continue;
        };
        push_one(state, approver, request).await;
    }
}

async fn push_one(
    state: &AppState,
    approver: &str,
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))] request: &Value,
) {
    let mediator_did = {
        let cfg = state.config.read().await;
        super::step_up::approver_mediator(
            approver,
            cfg.messaging.as_ref().map(|m| m.mediator_did.as_str()),
        )
    };
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))]
    let Some(mediator_did) = mediator_did else {
        tracing::debug!(
            approver = %approver,
            "no mediator route for consent approver; the relay fallback applies"
        );
        return;
    };

    // Prefer TSP when the approver's device was recently seen on it
    // (learn-from-inbound); otherwise fall through to DIDComm below.
    #[cfg(feature = "tsp")]
    if super::step_up::try_push_over_tsp(state, approver, &mediator_did, request).await {
        #[cfg(feature = "didcomm")]
        super::step_up::trigger_gateway_wake(state, approver, &mediator_did).await;
        return;
    }

    #[cfg(feature = "didcomm")]
    {
        // `webvh`, not `didcomm` — see the note on the granted-notice buffer
        // below. The Guaranteed send that follows is the delivery-critical
        // path and stays on `didcomm`.
        #[cfg(feature = "webvh")]
        {
            let pending = crate::messaging::registry::PendingResponse {
                recipient_did: approver.to_string(),
                message_type: TASK_CONSENT_REQUEST_0_1.to_string(),
                body: request.clone(),
                thread_id: request
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            };
            if let Err(e) = state
                .mediator_registry
                .buffer_outbound(&mediator_did, pending)
                .await
            {
                tracing::warn!(
                    error = %e, approver = %approver, mediator = %mediator_did,
                    "failed to buffer task-consent request; relay fallback applies"
                );
            }
        }

        // Delivery-critical, so it goes Guaranteed: durably queued + retried
        // across websocket reconnects (a bare send silently dropped the frame
        // mid-reconnect — R1.1), keyed by the request id so retries dedup. The
        // `deliver_by` bounds how long we retry the *hop* to the mediator (which
        // then holds it for the device); the relay fallback covers a lapse.
        if let Err(e) = state
            .didcomm_bridge
            .send_guaranteed(
                "vta-main",
                approver,
                TASK_CONSENT_REQUEST_0_1,
                request.clone(),
                request
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                Duration::from_secs(CONSENT_PUSH_DELIVER_BY_SECS),
            )
            .await
        {
            tracing::warn!(
                error = %e, approver = %approver,
                "task-consent request enqueue failed; relay fallback applies"
            );
        }

        // Ring the doorbell so a backgrounded device rouses now rather than on
        // its next voluntary pickup. Contentless by design — the wake says only
        // "you have mail", never what the task is or who is asking.
        super::step_up::trigger_gateway_wake(state, approver, &mediator_did).await;
    }
}

/// Notify the **requester** that its task has reached the approval threshold and
/// a grant is waiting, so it can re-submit immediately rather than poll.
///
/// Best-effort and **non-load-bearing**: the requester still re-submits and the
/// single-use grant check is the real gate, so a lost or spurious notice costs
/// at most one poll cycle — the authcrypt sender (this VTA) is the only
/// attribution the device needs, and it carries only the salted `wire_digest`
/// the requester already holds. Mirrors [`push_one`]: buffer at the requester's
/// mediator, send Guaranteed, ring the doorbell.
pub(super) async fn push_granted(
    state: &AppState,
    #[cfg_attr(not(feature = "didcomm"), allow(unused))] requester: &str,
    #[cfg_attr(not(feature = "didcomm"), allow(unused))] wire_digest: &str,
    #[cfg_attr(not(feature = "didcomm"), allow(unused))] type_uri: &str,
) {
    let mediator_did = {
        let cfg = state.config.read().await;
        super::step_up::approver_mediator(
            requester,
            cfg.messaging.as_ref().map(|m| m.mediator_did.as_str()),
        )
    };
    #[cfg_attr(not(feature = "didcomm"), allow(unused))]
    let Some(mediator_did) = mediator_did else {
        tracing::debug!(
            requester = %requester,
            "no mediator route for consent requester; skipping granted notice (it will re-submit on its own)"
        );
        return;
    };

    #[cfg(feature = "didcomm")]
    {
        // A full Trust Task document, not a bare payload: the DIDComm binding
        // deserialises the body as `TrustTask<P>`, and the request push above
        // already sends complete documents. (The pre-spec shape was the bare
        // `{status, payloadDigest, taskType}` object; the payload is unchanged,
        // it just gained the envelope `task-consent/granted/0.1` requires.)
        // Unsigned by design — the notice is non-load-bearing (the grant check
        // at re-submit is the real gate) and the authcrypt sender is the only
        // attribution the requester needs; the spec makes proof OPTIONAL.
        let mut body = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": TASK_CONSENT_GRANTED_0_1,
            "threadId": wire_digest,
            "recipient": requester,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {
                "status": "granted",
                "payloadDigest": wire_digest,
                "taskType": type_uri,
            },
        });
        if let Some(vta_did) = state.config.read().await.vta_did.clone() {
            body["issuer"] = serde_json::json!(vta_did);
        }
        // `webvh`, not `didcomm`: `AppState::mediator_registry` exists only under
        // `webvh`, while `PendingResponse`'s module needs only `didcomm`. The
        // enclosing block gates on the latter, so this line compiled in a
        // didcomm-without-webvh build against a field that was not there.
        //
        // The `send_guaranteed` below is the durable path and stays on
        // `didcomm`; the registry buffer is a fast-path optimisation for a
        // requester whose listener is already attached, so dropping it without
        // `webvh` costs latency, not delivery.
        #[cfg(feature = "webvh")]
        {
            let pending = crate::messaging::registry::PendingResponse {
                recipient_did: requester.to_string(),
                message_type: TASK_CONSENT_GRANTED_0_1.to_string(),
                body: body.clone(),
                thread_id: Some(wire_digest.to_string()),
            };
            if let Err(e) = state
                .mediator_registry
                .buffer_outbound(&mediator_did, pending)
                .await
            {
                tracing::warn!(
                    error = %e, requester = %requester, mediator = %mediator_did,
                    "failed to buffer granted notice; requester falls back to re-submit"
                );
            }
        }

        if let Err(e) = state
            .didcomm_bridge
            .send_guaranteed(
                "vta-main",
                requester,
                TASK_CONSENT_GRANTED_0_1,
                body,
                Some(format!("granted:{wire_digest}")),
                Duration::from_secs(CONSENT_PUSH_DELIVER_BY_SECS),
            )
            .await
        {
            tracing::warn!(
                error = %e, requester = %requester,
                "granted notice enqueue failed; requester falls back to re-submit"
            );
        }

        super::step_up::trigger_gateway_wake(state, requester, &mediator_did).await;
    }
}
