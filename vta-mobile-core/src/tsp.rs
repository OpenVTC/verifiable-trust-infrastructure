//! Mediator-connected **TSP** session for the mobile approver.
//!
//! The TSP analogue of [`crate::mediator::MediatorSession`]: same purpose —
//! connect to the holder's mediator and pull VTA-pushed messages (e.g. a
//! `task-consent/request/0.1` delivered for a delegated DID edit) — but over
//! the TSP transport instead of DIDComm. It wraps `vta-sdk`'s
//! [`TspSession`](vta_sdk::session::TspSession) so the phone rides the same TSP
//! client the VTA and `pnm health` use, rather than reimplementing TSP framing
//! in the host language.
//!
//! Receive-only for now: TSP inbound is the missing half of "the VTA should use
//! TSP when it can" for device push. The reply path (a TSP `confirm/decision`
//! back to the VTA) still rides the existing REST/DIDComm sender; a TSP send
//! FFI lands with the VTA's outbound TSP work.

use std::sync::Arc;

use vta_sdk::session::TspSession;

use crate::error::FfiError;

/// A live TSP session to a mediator, scoped to one holder identity.
#[derive(uniffi::Object)]
pub struct TspMediatorSession {
    inner: TspSession,
}

#[uniffi::export(async_runtime = "tokio")]
impl TspMediatorSession {
    /// Connect the holder's TSP websocket to `mediator_did` and open delivery.
    ///
    /// - `holder_did`: the holder's `did:key`.
    /// - `holder_signing_private_ed25519`: the holder's 32-byte Ed25519 seed
    ///   (the key behind its `did:key`). It stays in the engine; only derived
    ///   TSP secrets reach the client.
    /// - `mediator_did`: the mediator to connect through — the VTA's `#tsp`
    ///   service endpoint (the same mediator the VTA is a local account on).
    ///
    /// Unlike [`MediatorSession::connect`](crate::mediator::MediatorSession),
    /// no `vta_did` is needed: a TSP receive session takes whatever the mediator
    /// delivers to this holder and doesn't gate on a conversing peer. The peer
    /// DID becomes relevant only for the reply/send path.
    #[uniffi::constructor]
    pub async fn connect(
        holder_did: String,
        holder_signing_private_ed25519: Vec<u8>,
        mediator_did: String,
    ) -> Result<Arc<Self>, FfiError> {
        let private_key_mb =
            multibase::encode(multibase::Base::Base58Btc, &holder_signing_private_ed25519);
        let inner = TspSession::connect(&holder_did, &private_key_mb, &mediator_did)
            .await
            .map_err(|e| FfiError::Transport {
                reason: e.to_string(),
            })?;
        Ok(Arc::new(Self { inner }))
    }

    /// Wait up to `timeout_secs` for the next inbound TSP message from the
    /// mediator. Returns the unpacked Trust-Task document as JSON — the phone
    /// parses it exactly as it parses a DIDComm-delivered one (its own
    /// `type`/`issuer` fields), with the difference that TSP carries the inner
    /// document directly rather than inside a DIDComm envelope's `body`. Returns
    /// `None` if nothing arrived within the timeout. Call again to keep polling.
    pub async fn receive_next(&self, timeout_secs: u64) -> Result<Option<String>, FfiError> {
        self.inner
            .receive_next(timeout_secs)
            .await
            .map_err(|e| FfiError::Transport {
                reason: e.to_string(),
            })
    }

    /// Announce this holder's TSP reachability to `vta_did` (routed through
    /// `mediator_did`) so the VTA's device-push prefers TSP for this device
    /// (learn-from-inbound). Sends a session-less ping frame; the VTA records
    /// our proven DID and replies with a pong that `receive_next` harmlessly
    /// ignores. Call right after connecting the inbox, and periodically, so the
    /// VTA's reachability record for this device stays fresh.
    pub async fn announce(&self, vta_did: String, mediator_did: String) -> Result<(), FfiError> {
        self.inner
            .announce(&vta_did, &mediator_did)
            .await
            .map_err(|e| FfiError::Transport {
                reason: e.to_string(),
            })
    }

    /// Gracefully close the mediator connection (the TSP websocket).
    pub async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}
