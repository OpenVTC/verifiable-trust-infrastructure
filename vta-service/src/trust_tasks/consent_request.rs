//! Mint the `task-consent/request/0.1` document an approver renders and signs.
//!
//! The document is **signed by the VTA**, and that signature is the whole point.
//! A consent surface renders `effects` as the basis of a human's decision, so an
//! unsigned request would let anyone who can reach the approver's device author
//! the prose the human reads — including the relying party whose task is being
//! approved — while every downstream signature still verified.
//!
//! Note the contrast with step-up, whose `approveRequest` is deliberately
//! unsigned: there the challenge is the binding and the approver signs the
//! *response*, and nothing in the request is load-bearing for the decision.
//! Here the request *is* the decision's basis, so it has to be attributable.

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
const CONSENT_PUSH_DELIVER_BY_SECS: u64 = 300;

use crate::policy::consent::PendingTaskConsent;
use crate::policy::effects::Effect;
use crate::policy::types::TaskClass;
use crate::server::AppState;

pub(super) const TASK_CONSENT_REQUEST_0_1: &str =
    "https://trusttasks.org/spec/task-consent/request/0.1";

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
    #[cfg_attr(not(feature = "didcomm"), allow(unused))] request: &Value,
) {
    let mediator_did = {
        let cfg = state.config.read().await;
        super::step_up::approver_mediator(
            approver,
            cfg.messaging.as_ref().map(|m| m.mediator_did.as_str()),
        )
    };
    #[cfg_attr(not(feature = "didcomm"), allow(unused))]
    let Some(mediator_did) = mediator_did else {
        tracing::debug!(
            approver = %approver,
            "no mediator route for consent approver; the relay fallback applies"
        );
        return;
    };

    #[cfg(feature = "didcomm")]
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
