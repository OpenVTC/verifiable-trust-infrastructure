//! The one place this service packs a Trust Task for the wire.
//!
//! # Why a seam, when the code it replaces was short
//!
//! It was short *twice*. `registry::messaging::send_didcomm` and
//! `hooks::writer::send_envelope` were byte-identical apart from the error type
//! they mapped into — same envelope, same `pack_encrypted` arguments, same
//! `Delivery::BestEffort`, same four failure strings. A third caller would have
//! been a third copy, and the copies are not merely wasteful: each one is a
//! place where the envelope `type` could be got wrong, and getting it wrong
//! fails *silently* (a conformant peer cannot distinguish "not an envelope" from
//! "not addressed to me", so it drops the message and answers nothing).
//!
//! `vta-service` reached this conclusion first, and its `operations::outbound`
//! module header says what this one is repeating: "`room_host` hand-rolled REST,
//! `webvh_didcomm` hand-rolled DIDComm, and the TSP path hand-rolled its own
//! carriage — three carriages for one wire contract, and a fourth service would
//! have been a fourth."
//!
//! # What this is not, yet
//!
//! Not transport *selection*. `vta-service`'s seam picks a protocol by
//! intersecting `Protocol::PREFERENCE_ORDER` with what the peer advertises; here
//! the two callers still choose (the registry client selects, the hook writer is
//! DIDComm by construction). Selection is the next step and belongs on top of
//! this, not mixed into it — this change is about there being one packer, which
//! is the precondition.

use affinidi_messaging_delivery::Delivery;
use affinidi_messaging_didcomm::Message;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;
use vti_common::capability_client::TRUST_TASK_ENVELOPE_TYPE;

use crate::messaging::VtcMessaging;

/// What can go wrong putting a document on the wire.
///
/// Deliberately three variants and not this service's richer error types: a
/// caller knows whether its own failure is transient, and mapping one of these
/// into that is a line. Returning `RegistryError` from here would have made the
/// hook writer depend on the registry's vocabulary for no reason.
#[derive(Debug)]
pub(crate) enum OutboundError {
    /// The document would not serialise. Not retriable: it will not serialise
    /// next time either.
    Serialise(String),
    /// The envelope would not encrypt to the recipient — an unresolvable DID,
    /// or no key agreement in its document.
    Pack(String),
    /// The delivery layer would not accept it.
    Send(String),
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialise(e) => write!(f, "serialise envelope body: {e}"),
            Self::Pack(e) => write!(f, "pack failed: {e}"),
            Self::Send(e) => write!(f, "send failed: {e}"),
        }
    }
}

/// Pack `doc` in the DIDComm **binding envelope** and hand it to the delivery
/// layer, addressed to `recipient_did`.
///
/// `Delivery::BestEffort`: every current caller owns its own durability (the
/// hook queue retries, the registry client correlates a reply and gives up on a
/// timeout). A caller needing `Guaranteed` should say so through an argument
/// rather than by writing a second copy of this.
///
/// # The envelope type is not a parameter
///
/// It is `TRUST_TASK_ENVELOPE_TYPE` and nothing else. A caller cannot pass a
/// message type, so the mistake that motivates this module — typing a message
/// with the *task* URI instead of the binding's — is unrepresentable here rather
/// than merely avoided. `thid` is the document's own id, which is what a reply
/// threads on.
pub(crate) async fn send_trust_task_didcomm(
    messaging: &VtcMessaging,
    recipient_did: &str,
    doc: &TrustTask<Value>,
) -> Result<(), OutboundError> {
    let body = serde_json::to_value(doc).map_err(|e| OutboundError::Serialise(e.to_string()))?;
    let envelope = Message::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        TRUST_TASK_ENVELOPE_TYPE.to_string(),
        body,
    )
    .from(messaging.vtc_did.clone())
    .to(recipient_did.to_string())
    .thid(doc.id.clone())
    .finalize();

    let (packed, _) = messaging
        .atm
        .pack_encrypted(
            &envelope,
            recipient_did,
            Some(&messaging.vtc_did),
            Some(&messaging.vtc_did),
        )
        .await
        .map_err(|e| OutboundError::Pack(e.to_string()))?;

    messaging
        .service
        .send(recipient_did, packed.into_bytes(), Delivery::BestEffort)
        .await
        .map_err(|e| OutboundError::Send(e.to_string()))?;
    Ok(())
}

/// Seal `doc` in the **TSP** binding envelope, ready to route.
///
/// Returns the bytes rather than sending them: a TSP send needs the hop list,
/// which is the caller's (it knows the peer's advertised mediator). The part
/// worth sharing is the carriage, and that is all this does.
///
/// # Why this is not a local `json!`
///
/// It was. `registry::messaging` mirrored `trust_tasks_tsp::ENVELOPE_TYPE` as a
/// local `const` and built the wrapper by hand, with a test pinning the string —
/// but the test compared a literal to a literal, so it could not detect the
/// upstream drift it was written to catch. `vta_sdk::tsp_binding` is the
/// workspace's one implementation, its constant comes from the binding crate,
/// and it serialises the document bytes without reparsing them (which is the
/// only step in the path that could change what was signed).
#[cfg(feature = "tsp")]
pub(crate) fn seal_trust_task_tsp(doc: &TrustTask<Value>) -> Result<Vec<u8>, OutboundError> {
    let document = serde_json::to_vec(doc).map_err(|e| OutboundError::Serialise(e.to_string()))?;
    Ok(vta_sdk::tsp_binding::wrap_envelope(&document))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seal is the published binding, read from the crate that defines it.
    ///
    /// Replaces a test that compared one local literal to another local literal
    /// — which passes whatever upstream does, and so could never have caught the
    /// drift it named.
    #[cfg(feature = "tsp")]
    #[test]
    fn the_tsp_seal_is_the_published_envelope() {
        let doc: TrustTask<Value> = TrustTask::new(
            "urn:uuid:1".to_string(),
            "https://trusttasks.org/spec/registry/record/put/0.1"
                .parse()
                .expect("valid type URI"),
            serde_json::json!({}),
        );

        let sealed = seal_trust_task_tsp(&doc).expect("seals");
        let parsed: Value = serde_json::from_slice(&sealed).expect("is JSON");

        assert_eq!(
            parsed["type"],
            vta_sdk::tsp_binding::ENVELOPE_TYPE,
            "the wrapper must carry the binding's own type"
        );
        assert_eq!(
            parsed["document"]["id"], "urn:uuid:1",
            "and the document must survive the wrapping unchanged"
        );
    }
}
