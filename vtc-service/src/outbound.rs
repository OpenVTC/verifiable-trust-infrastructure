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

/// A peer reached by DID over messaging, one signed Trust Task at a time: the
/// transport chosen from its DID document, the document signed by this VTC, and
/// its correlated reply awaited.
///
/// This is the selection the module header names as the next step, for the
/// callers that address a peer only by DID and need nothing else of it: the git
/// bridge and the community's VTA. The trust-registry client keeps its own,
/// which also records what each selection saw for its diagnostics page and has
/// a REST arm.
///
/// A reply is released to the waiter only when the peer's own proof on it
/// verifies (`PendingReplies::complete_verified`), so what comes back here was
/// signed by the DID it was sent to. A send returning `Ok` means accepted
/// locally (R1.1); the call is complete when that reply arrives. No reply in the
/// window is [`PeerError::Transient`]: the caller owns any retry.
#[derive(Clone)]
pub(crate) struct PeerTasks {
    pub(crate) didcomm: std::sync::Arc<tokio::sync::OnceCell<std::sync::Arc<VtcMessaging>>>,
    pub(crate) signer: Option<std::sync::Arc<crate::credentials::LocalSigner>>,
    pub(crate) replies: crate::hooks::PendingReplies,
    pub(crate) resolver: Option<affinidi_did_resolver_cache_sdk::DIDCacheClient>,
}

/// Why a [`PeerTasks::exchange`] produced no reply.
#[derive(Debug, Clone)]
pub enum PeerError {
    /// Worth another attempt: messaging not up, no reply in the window, a send
    /// that failed below the Trust Task layer.
    Transient(String),
    /// No transport in common with the peer. Not retried: it changes only when
    /// one side advertises another.
    NoMatchingProtocol(String),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(m) | Self::NoMatchingProtocol(m) => f.write_str(m),
        }
    }
}

impl PeerTasks {
    /// Which transport reaches `peer_did`: the highest-preference one both of us
    /// advertise, matched on service type. Over messaging only; a peer that
    /// speaks only REST has nothing in common with this client, which is said
    /// rather than guessed around.
    pub(crate) async fn select(
        &self,
        peer_did: &str,
    ) -> Result<vta_sdk::protocol::matching::ProtocolMatch, PeerError> {
        use vta_sdk::protocol::matching::{ServiceCapabilities, select_protocol};
        let resolver = self.resolver.as_ref().ok_or_else(|| {
            PeerError::Transient(
                "no DID resolver configured — cannot read the peer's advertised transports".into(),
            )
        })?;
        let resolved = resolver
            .resolve(peer_did)
            .await
            .map_err(|e| PeerError::Transient(format!("could not resolve {peer_did}: {e}")))?;
        let doc = serde_json::to_value(&resolved.doc)
            .map_err(|e| PeerError::Transient(format!("unreadable DID document: {e}")))?;
        let theirs = ServiceCapabilities::from_did_document(&doc);
        let up = self.didcomm.get().is_some();
        let ours = ServiceCapabilities {
            tsp: (up && cfg!(feature = "tsp")).then(|| peer_did.to_string()),
            didcomm: up.then(|| peer_did.to_string()),
            rest: None,
        };
        if ours.advertised().is_empty() {
            return Err(PeerError::Transient(
                "VTC messaging is not running yet".into(),
            ));
        }
        select_protocol(&ours, &theirs, peer_did)
            .map_err(|e| PeerError::NoMatchingProtocol(e.to_string()))
    }

    /// Sign one document of `type_uri` to `peer_did`, send it, and await the
    /// peer's signed reply for up to `timeout`.
    pub(crate) async fn exchange(
        &self,
        peer_did: &str,
        type_uri: &str,
        payload: &Value,
        timeout: std::time::Duration,
    ) -> Result<TrustTask<Value>, PeerError> {
        use vta_sdk::protocol::matching::Protocol;
        let messaging = self
            .didcomm
            .get()
            .ok_or_else(|| PeerError::Transient("VTC messaging is not running yet".into()))?;
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| PeerError::Transient("this VTC has no signing key yet".into()))?;
        let matched = self.select(peer_did).await?;

        let doc = vti_common::capability_client::build_document(
            &messaging.vtc_did,
            peer_did,
            type_uri,
            payload.clone(),
        );
        let mut value = serde_json::to_value(&doc)
            .map_err(|e| PeerError::Transient(format!("serialise document: {e}")))?;
        signer
            .sign_operational_doc(&mut value)
            .await
            .map_err(|e| PeerError::Transient(format!("sign document: {e}")))?;
        let doc: TrustTask<Value> = serde_json::from_value(value)
            .map_err(|e| PeerError::Transient(format!("reparse signed document: {e}")))?;

        // Registered before sending: a reply can land while the send returns.
        let receiver = self.replies.register(&doc.id, peer_did);
        let sent = match matched.protocol {
            #[cfg(feature = "tsp")]
            Protocol::Tsp => {
                let body =
                    seal_trust_task_tsp(&doc).map_err(|e| PeerError::Transient(e.to_string()))?;
                // `peer_endpoint` is the peer's TSP mediator; a peer on another
                // mediator is reached through it (VTI-56).
                vti_common::tsp_route::send_reestablishing(
                    &messaging.atm,
                    &messaging.profile,
                    &messaging.mediator_did,
                    peer_did,
                    Some(matched.peer_endpoint.as_str()),
                    &body,
                )
                .await
                .map(|_| ())
                .map_err(|e| PeerError::Transient(format!("TSP send failed: {e}")))
            }
            Protocol::Didcomm => send_trust_task_didcomm(messaging, peer_did, &doc)
                .await
                .map_err(|e| PeerError::Transient(e.to_string())),
            _ => Err(PeerError::NoMatchingProtocol(format!(
                "{peer_did} can be reached by no transport this VTC speaks"
            ))),
        };
        if let Err(e) = sent {
            self.replies.abandon(&doc.id);
            return Err(e);
        }
        match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => {
                self.replies.abandon(&doc.id);
                Err(PeerError::Transient("reply channel closed".into()))
            }
            Err(_) => {
                self.replies.abandon(&doc.id);
                Err(PeerError::Transient(format!(
                    "no reply from {peer_did} within {}s",
                    timeout.as_secs()
                )))
            }
        }
    }
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
