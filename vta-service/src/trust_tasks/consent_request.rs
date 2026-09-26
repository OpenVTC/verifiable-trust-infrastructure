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

// Only the device pushes below bound their delivery.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
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
#[cfg(any(feature = "didcomm", feature = "tsp"))]
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
#[cfg(any(feature = "didcomm", feature = "tsp"))]
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

    let secret = super::load_operational_secret(state, &vta_did, "task-consent").await?;

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
                .with_proof_purpose("authentication")
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
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    match super::step_up::push_to_device(
        state,
        approver,
        request,
        Duration::from_secs(CONSENT_PUSH_DELIVER_BY_SECS),
    )
    .await
    {
        // Said once the push is queued: beyond it the message is the push
        // engine's to deliver and the device's to collect — but "we tried, to
        // this DID, via this mediator" must be on the record either way, so a
        // missing prompt can be attributed to a side rather than argued about.
        super::step_up::DevicePush::Queued { push, mediator } => tracing::info!(
            approver = %approver, mediator = %mediator, push = %push,
            "consent request queued for approver"
        ),
        // `warn`, not `debug`. This is the VTA deciding not to notify anybody
        // about a consent request it is now holding — the approver will never
        // learn of it unless the requester relays, and a CLI requester cannot.
        // At debug it is invisible on a normal deployment, so the symptom
        // ("nothing pops up") is indistinguishable from a sleeping device, and
        // the operator has no way to tell which. That is not routine.
        super::step_up::DevicePush::NoRoute {
            configured_mediator,
        } => tracing::warn!(
            approver = %approver,
            configured_mediator = ?configured_mediator,
            "no mediator route for consent approver — NOT notifying; the approver \
             learns of this request only if the requester relays it (a CLI cannot). \
             A did:key approver routes via the VTA's own [messaging] mediator_did, \
             so an unset config produces this; any other approver routes via the \
             mediator its own DID document advertises, so a document carrying no \
             DIDCommMessaging service — or one that would not resolve — produces \
             it too. The preceding log line says which."
        ),
        super::step_up::DevicePush::Refused => {}
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
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))] requester: &str,
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))] wire_digest: &str,
    // The ceremony's minted correlator, used as the notice's `threadId`.
    // Deliberately separate from `wire_digest`, which stays the payload digest
    // the notice carries in its body — see `PendingTaskConsent::correlator`.
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))] correlator: &str,
    #[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(unused))] type_uri: &str,
) {
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    {
        // A full Trust Task document, not a bare payload: every binding carries
        // a `TrustTask<P>`. Unsigned by design — the notice is non-load-bearing
        // (the grant check at re-submit is the real gate), the spec makes proof
        // OPTIONAL, and on DIDComm and TSP the transport authenticates this VTA
        // as the sender.
        let mut body = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": TASK_CONSENT_GRANTED_0_1,
            "threadId": correlator,
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
        match super::step_up::push_to_device(
            state,
            requester,
            &body,
            Duration::from_secs(CONSENT_PUSH_DELIVER_BY_SECS),
        )
        .await
        {
            super::step_up::DevicePush::Queued { push, .. } => tracing::debug!(
                requester = %requester, push = %push,
                "granted notice queued for the requester"
            ),
            super::step_up::DevicePush::NoRoute { .. } => tracing::debug!(
                requester = %requester,
                "no mediator route for consent requester; skipping granted notice \
                 (it will re-submit on its own)"
            ),
            super::step_up::DevicePush::Refused => {}
        }
    }
}

#[cfg(all(test, feature = "didcomm", feature = "webvh"))]
mod tests {
    use crate::messaging::registry::MediatorBinding;

    const MEDIATOR: &str = "did:example:mediator";
    const REQUESTER: &str = "did:key:zRequester";

    /// The granted notice goes out under the **envelope** type, with the task
    /// type inside the document.
    ///
    /// It had the same defect as the request push (#900) and was invisible for
    /// the same reason: a conformant peer that cannot read the envelope drops it
    /// silently, and the requester's fallback is to re-submit anyway — so the
    /// only symptom was a poll cycle nobody was measuring.
    #[tokio::test]
    async fn granted_notice_is_pushed_to_the_requester() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;

        state
            .mediator_registry
            .record_activate(MediatorBinding {
                mediator_did: MEDIATOR.into(),
                endpoint: "https://mediator.test".into(),
            })
            .await;
        {
            let mut cfg = state.config.write().await;
            cfg.messaging = Some(vti_common::config::MessagingConfig {
                mediator_url: String::new(),
                mediator_did: MEDIATOR.into(),
                mediator_host: None,
                setup_acl: false,
                drain_inbox_on_start: false,
            });
        }

        super::push_granted(
            &state,
            REQUESTER,
            "digest-abc",
            "urn:uuid:correlator-abc",
            "https://example.org/task/1.0",
        )
        .await;

        let pushed = crate::messaging::push::take_pushes(&state);
        assert_eq!(pushed.len(), 1, "the requester is notified exactly once");
        assert_eq!(
            pushed[0].body.get("type").and_then(|t| t.as_str()),
            Some(super::TASK_CONSENT_GRANTED_0_1),
            "the task type belongs in the enveloped document, not on the envelope"
        );
        assert_eq!(pushed[0].recipient_did, REQUESTER);
        // The payload the requester acts on must survive the re-wrap.
        assert_eq!(
            pushed[0].body["payload"]["payloadDigest"].as_str(),
            Some("digest-abc")
        );
    }

    /// The notice's `threadId` is the minted correlator, never the digest.
    ///
    /// Framework 0.5.0 (*Identifier correlation and linkability*) requires a
    /// `threadId` to be freshly minted and forbids deriving one from subject
    /// data. This notice used to thread on `wire_digest` — salted, so not
    /// recoverable, but still a function of the payload and the *same string*
    /// the document carries as `payloadDigest`.
    ///
    /// A mediator sees `threadId` as routing metadata. With the digest there it
    /// could tie the routing it performs to the digest it forwards and link
    /// every counterparty in the ceremony, which is the linkage the rule exists
    /// to remove. The body still carries `payloadDigest`, so a requester that
    /// matches on the digest is unaffected.
    #[tokio::test]
    async fn the_notice_threads_on_the_correlator_not_the_digest() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        state
            .mediator_registry
            .record_activate(MediatorBinding {
                mediator_did: MEDIATOR.into(),
                endpoint: "https://mediator.test".into(),
            })
            .await;
        {
            let mut cfg = state.config.write().await;
            cfg.messaging = Some(vti_common::config::MessagingConfig {
                mediator_url: String::new(),
                mediator_did: MEDIATOR.into(),
                mediator_host: None,
                setup_acl: false,
                drain_inbox_on_start: false,
            });
        }

        super::push_granted(
            &state,
            REQUESTER,
            "digest-abc",
            "urn:uuid:correlator-abc",
            "https://example.org/task/1.0",
        )
        .await;

        let pushed = crate::messaging::push::take_pushes(&state);
        let one = pushed.first().expect("a notice was pushed");
        assert_eq!(
            one.body["threadId"], "urn:uuid:correlator-abc",
            "the document must thread on the minted correlator: {}",
            one.body
        );
        assert_eq!(
            one.body["payload"]["payloadDigest"], "digest-abc",
            "the body still carries the digest, so a requester matching on it \
             is unaffected: {}",
            one.body
        );
    }
}
