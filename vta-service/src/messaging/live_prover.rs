//! Live delivery-layer [`ListenerProver`] implementation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! "Mediator handshake before promotion", steps 2–5.
//!
//! **D2 P2a cut-over**: this used to drive the framework `DIDCommService`
//! (`add_listener` → `wait_connected` → trust-ping → `remove_listener`). It now
//! drives the delivery-layer [`MessagingService`] held by the outbound
//! [`DIDCommBridge`]:
//!
//! 1. (Step 1, DID resolution, is performed by
//!    [`super::handshake::mediator_handshake`] before this prover is invoked.)
//! 2. **Connect + register**: build a [`DidCommTransport`] for the candidate
//!    mediator (a fresh [`ATMProfile`] + bounded websocket on the VTA's existing
//!    ATM, whose secrets resolver already holds the signing/KA keys) and
//!    `add_transport(candidate_id, …)` — it starts receiving immediately via the
//!    merged dispatcher but is NOT yet the outbound primary.
//! 3. **Trust-ping**: `request_via(candidate_id, self_vta_did, ping, thid,
//!    timeout)` sends the ping over the CANDIDATE transport and awaits the pong
//!    on the merged dispatcher (the main inbound loop answers the self-ping).
//! 4. On success the candidate transport is left installed for the caller
//!    (`update_didcomm`) to `promote`; on any-stage failure it is
//!    `remove_transport`-ed so the registry doesn't promote a mediator the VTA
//!    can't reach.
//!
//! Behind the `didcomm` feature gate so non-DIDComm builds don't pull in the
//! delivery-layer surface.

#![cfg(feature = "didcomm")]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::MessageTransport;
use affinidi_tdk::messaging::DidCommTransport;
use affinidi_tdk::messaging::profiles::ATMProfile;
use async_trait::async_trait;
use serde_json::json;

use crate::didcomm_bridge::DIDCommBridge;
use crate::messaging::handshake::{
    HandshakeStage, ListenerProver, ProverFailure, ResolvedMediator,
};

/// Trust-ping protocol identifiers from didcomm.org.
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PING_RESPONSE_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

/// Live prover over the delivery-layer [`MessagingService`] (via the outbound
/// [`DIDCommBridge`]). Use when DIDComm is already running (`mediator migrate`,
/// `mediator rollback`); use [`super::handshake::AlwaysOkProver`] when DIDComm
/// isn't running yet (first `services enable didcomm`, which goes through
/// [`super::transient_handshake`]).
pub struct DIDCommServiceProver {
    bridge: Arc<DIDCommBridge>,
    #[allow(dead_code)]
    vta_did: String,
}

impl DIDCommServiceProver {
    pub fn new(bridge: Arc<DIDCommBridge>, vta_did: impl Into<String>) -> Self {
        Self {
            bridge,
            vta_did: vta_did.into(),
        }
    }
}

#[async_trait]
impl ListenerProver for DIDCommServiceProver {
    async fn prove(
        &self,
        resolved: &ResolvedMediator,
        vta_did: &str,
        timeout: Duration,
    ) -> Result<(), ProverFailure> {
        let service = self
            .bridge
            .messaging_handle()
            .ok_or_else(|| ProverFailure {
                stage: HandshakeStage::Connect,
                cause: "delivery-layer messaging service is not running".to_string(),
            })?;
        let atm = self.bridge.atm().ok_or_else(|| ProverFailure {
            stage: HandshakeStage::Connect,
            cause: "ATM unavailable (messaging not started)".to_string(),
        })?;
        let candidate_id = resolved.mediator_did.clone();

        // Step 2: build a candidate transport + bounded websocket. The ATM's
        // secrets resolver already holds the VTA's signing/KA keys, so the
        // candidate profile needs no fresh secrets.
        let profile = match ATMProfile::new(
            &atm,
            Some(candidate_id.clone()),
            vta_did.to_string(),
            Some(candidate_id.clone()),
        )
        .await
        {
            Ok(p) => Arc::new(p),
            Err(e) => {
                return Err(ProverFailure {
                    stage: HandshakeStage::Connect,
                    cause: format!("create candidate profile: {e}"),
                });
            }
        };
        match tokio::time::timeout(timeout, atm.profile_enable_websocket(&profile)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(ProverFailure {
                    stage: HandshakeStage::Connect,
                    cause: format!("enable candidate websocket: {e}"),
                });
            }
            Err(_) => {
                return Err(ProverFailure {
                    stage: HandshakeStage::Connect,
                    cause: "timeout enabling candidate mediator websocket".to_string(),
                });
            }
        }
        let transport: Arc<dyn MessageTransport> =
            match DidCommTransport::new(atm.clone(), profile.clone()).await {
                Ok(t) => Arc::new(t),
                Err(e) => {
                    return Err(ProverFailure {
                        stage: HandshakeStage::Connect,
                        cause: format!("bind candidate DidComm transport: {e}"),
                    });
                }
            };
        service.add_transport(candidate_id.clone(), transport);

        // Steps 4-5: trust-ping the VTA via the candidate transport; the main
        // inbound loop answers the self-ping and the pong routes back through the
        // merged dispatcher, demuxed to this waiter by thread id.
        let result = self
            .bridge
            .send_and_wait_via(
                &candidate_id,
                vta_did, // recipient = self; the mediator forwards it back
                TRUST_PING_TYPE,
                json!({ "response_requested": true }),
                TRUST_PING_RESPONSE_TYPE,
                PROBLEM_REPORT_TYPE,
                timeout.as_secs(),
            )
            .await;

        if let Err(e) = result {
            // Best-effort cleanup so the registry doesn't promote an
            // unreachable mediator.
            service.remove_transport(&candidate_id);
            return Err(ProverFailure {
                stage: HandshakeStage::TrustPing,
                cause: format!("trust-ping round-trip failed: {e}"),
            });
        }

        // The candidate transport stays installed — the caller (`update_didcomm`)
        // will `promote` it in the registry + delivery service on success.
        Ok(())
    }
}

/// Best-effort assembly of a [`DIDCommServiceProver`] from the outbound bridge.
///
/// Returns `None` when the delivery-layer messaging service isn't running yet
/// (the caller then falls back to [`super::handshake::AlwaysOkProver`]). The
/// `secrets_resolver` / vm-id parameters are retained for call-site parity —
/// the ATM behind the bridge already carries the VTA's keys, so the prover no
/// longer needs them threaded through.
pub async fn try_build_from_parts(
    bridge: &Arc<DIDCommBridge>,
    vta_did: &str,
    _secrets_resolver: &Arc<affinidi_tdk::secrets_resolver::ThreadedSecretsResolver>,
    _signing_vm_id: &str,
    _ka_vm_id: &str,
) -> Option<DIDCommServiceProver> {
    // Only meaningful once the delivery-layer service is published.
    bridge.messaging_handle()?;
    Some(DIDCommServiceProver::new(Arc::clone(bridge), vta_did))
}

#[cfg(test)]
mod tests {
    use crate::messaging::handshake::HandshakeStage;

    /// Sentinel: the failure stages this prover produces are still present.
    #[test]
    fn handshake_stages_used_by_prover() {
        let stages = [HandshakeStage::Connect, HandshakeStage::TrustPing];
        assert_eq!(stages.len(), 2);
    }
}
