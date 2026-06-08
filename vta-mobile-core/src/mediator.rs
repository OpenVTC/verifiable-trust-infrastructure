//! Mediator-connected DIDComm session for the mobile approver.
//!
//! Wraps `vta-sdk`'s [`DIDCommSession`] (the affinidi ATM client) so iOS /
//! Android can connect to the holder's mediator and pull VTA-pushed messages —
//! e.g. an `auth/step-up/approve-request/0.1` delivered for the proxied
//! step-up. The session authenticates to the mediator as the holder and opens
//! live delivery; [`MediatorSession::receive_next`] yields the next inbound
//! message already unpacked under the holder key.
//!
//! Reusing `vta-sdk`'s session (rather than reimplementing the affinidi
//! mediator protocol — challenge auth + message-pickup 3.0 + WebSocket — in the
//! host language) keeps the engine and the VTA on one client.

use std::sync::Arc;

use vta_sdk::didcomm_session::DIDCommSession;

use crate::error::FfiError;

/// A live DIDComm session to a mediator, scoped to one holder identity.
#[derive(uniffi::Object)]
pub struct MediatorSession {
    inner: DIDCommSession,
}

#[uniffi::export(async_runtime = "tokio")]
impl MediatorSession {
    /// Connect to `mediator_did` as the holder and open live delivery.
    ///
    /// - `holder_did`: the holder's `did:key`.
    /// - `holder_signing_private_ed25519`: the holder's 32-byte Ed25519 seed
    ///   (the key behind its `did:key`). It stays in the engine; only derived
    ///   DIDComm secrets reach the ATM secrets resolver.
    /// - `vta_did`: the peer (VTA) this holder converses with.
    /// - `mediator_did`: the mediator to connect through.
    #[uniffi::constructor]
    pub async fn connect(
        holder_did: String,
        holder_signing_private_ed25519: Vec<u8>,
        vta_did: String,
        mediator_did: String,
    ) -> Result<Arc<Self>, FfiError> {
        let private_key_mb =
            multibase::encode(multibase::Base::Base58Btc, &holder_signing_private_ed25519);
        let inner = DIDCommSession::connect(&holder_did, &private_key_mb, &vta_did, &mediator_did)
            .await
            .map_err(|e| FfiError::Transport {
                reason: e.to_string(),
            })?;
        Ok(Arc::new(Self { inner }))
    }

    /// Wait up to `timeout_secs` for the next inbound DIDComm message from the
    /// mediator. Returns the unpacked message as JSON (`{ id, type, body, … }`)
    /// — the application Trust Task (e.g. the approve-request) rides in `body` —
    /// or `None` if nothing arrived within the timeout. Call again to keep
    /// polling.
    pub async fn receive_next(&self, timeout_secs: u64) -> Result<Option<String>, FfiError> {
        self.inner
            .receive_next(timeout_secs)
            .await
            .map_err(|e| FfiError::Transport {
                reason: e.to_string(),
            })
    }

    /// Gracefully close the mediator connection (live-delivery WebSocket).
    pub async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live: connect a fresh `did:key` holder to a real mediator and poll once,
    /// reproducing exactly what the iOS app's `connectMediator` does — on the
    /// host, to isolate iOS-specific failures from the affinidi-ATM client path.
    /// Ignored by default (network + a real mediator). Run:
    /// `cargo test -p vta-mobile-core -- --ignored connects_to_mediator --nocapture`
    /// Override the mediator with `VTA_TEST_MEDIATOR`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "network: connects to a live mediator as a fresh did:key"]
    async fn connects_to_mediator_as_fresh_did_key() {
        use ed25519_dalek::SigningKey;
        use multibase::Base;

        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(sk.verifying_key().as_bytes());
        let holder_did = format!("did:key:{}", multibase::encode(Base::Base58Btc, &mc));

        let mediator = std::env::var("VTA_TEST_MEDIATOR").unwrap_or_else(|_| {
            "did:webvh:QmTS3a3H9Dk4ZMPAZ8jNWGeyPbuKrPbrPZcSbg8CJ6yynD:webvh.storm.ws:mediator"
                .to_string()
        });

        eprintln!("connecting holder={holder_did} → mediator={mediator}");
        let session = MediatorSession::connect(
            holder_did.clone(),
            seed.to_vec(),
            holder_did, // vta_did is unused for the connect itself; a valid did:key
            mediator,
        )
        .await
        .expect("connect to the mediator as a fresh did:key");

        eprintln!("connected; polling once (5s)…");
        let got = session
            .receive_next(5)
            .await
            .expect("receive_next should not error");
        eprintln!("receive_next → {got:?}");
        session.shutdown().await;
    }
}
