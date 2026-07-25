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

/// The DIDComm message type that carries a Trust Task document to the VTA.
/// Its `handle_trust_task` handler unwraps the body and runs it through the
/// same `dispatch_trust_task_core` that backs `POST /api/trust-tasks`, so a
/// document submitted this way takes an identical path to the REST one.
const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// A live DIDComm session to a mediator, scoped to one holder identity.
#[derive(uniffi::Object)]
pub struct MediatorSession {
    inner: DIDCommSession,
    /// The peer this session converses with. `DIDCommSession` knows it too, but
    /// only `pub(crate)` to `vta-sdk`; `send_one_way` needs it as an explicit
    /// recipient, so keep the copy the constructor already has in hand.
    vta_did: String,
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
        Ok(Arc::new(Self { inner, vta_did }))
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

    /// Submit a Trust Task document to the VTA over this mediator session and
    /// wait up to `timeout_secs` for its `#response`. Returns the framework
    /// response document as JSON — the same bytes `POST /api/trust-tasks`
    /// returns over REST, so callers parse it identically.
    ///
    /// `doc_json` is a complete, already-signed Trust Task document (e.g. what
    /// `build_approve_response_did_signed` produces). It rides as the body of a
    /// [`TRUST_TASK_ENVELOPE_TYPE`] DIDComm message; the VTA's
    /// `messaging::handlers::handle_trust_task` unwraps it into the same
    /// `dispatch_trust_task_core` the REST route calls.
    ///
    /// **No bearer token.** The message is authcrypt-packed, so the VTA proves
    /// the sender DID cryptographically and derives authorization from it
    /// (intrinsic-sender auth) — this is what lets a device operate with no VTA
    /// REST API at all.
    ///
    /// Safe to call while a [`receive_next`](Self::receive_next) loop is
    /// running: the reply is demuxed to this caller by `thid`, so it can't be
    /// stolen by (or steal from) the unsolicited inbound stream.
    pub async fn send_trust_task(
        &self,
        doc_json: String,
        timeout_secs: u64,
    ) -> Result<String, FfiError> {
        let doc: serde_json::Value =
            serde_json::from_str(&doc_json).map_err(|e| FfiError::Transport {
                reason: format!("trust task document is not valid JSON: {e}"),
            })?;

        let response: serde_json::Value = self
            .inner
            .send_and_wait(
                TRUST_TASK_ENVELOPE_TYPE,
                doc,
                TRUST_TASK_ENVELOPE_TYPE,
                timeout_secs,
            )
            .await
            .map_err(|e| FfiError::Transport {
                reason: e.to_string(),
            })?;

        serde_json::to_string(&response).map_err(|e| FfiError::Transport {
            reason: format!("could not re-serialize the VTA response: {e}"),
        })
    }

    /// Send a Trust Task document without awaiting a response — the
    /// fire-and-forget counterpart to
    /// [`send_trust_task`](Self::send_trust_task), for documents whose outcome
    /// the caller doesn't need (or will pick up off the inbox itself).
    pub async fn send_trust_task_one_way(&self, doc_json: String) -> Result<(), FfiError> {
        let doc: serde_json::Value =
            serde_json::from_str(&doc_json).map_err(|e| FfiError::Transport {
                reason: format!("trust task document is not valid JSON: {e}"),
            })?;

        self.inner
            .send_one_way(&self.vta_did, TRUST_TASK_ENVELOPE_TYPE, doc)
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

    /// Live: the whole no-REST loop against a real VTA — connect the mediator,
    /// submit a holder-signed `whoami` Trust Task over DIDComm, and read the
    /// `#response`. This is exactly what the iOS app's post-connect handshake
    /// does, minus Swift.
    ///
    /// Proves in one shot: the mediator round-trips, `send_trust_task`'s `thid`
    /// correlation works, and the VTA authorizes purely from the authcrypt
    /// sender DID (intrinsic-sender auth) with no bearer token anywhere.
    ///
    /// Ignored by default (network + a real VTA). Run:
    /// `cargo test -p vta-mobile-core -- --ignored whoami_over_didcomm --nocapture`
    /// Override with `VTA_TEST_DID` / `VTA_TEST_MEDIATOR` / `VTA_TEST_SEED`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "network: submits a whoami to a live VTA over its mediator"]
    async fn whoami_over_didcomm_without_rest() {
        use crate::keys::Signer;
        use ed25519_dalek::{Signer as _, SigningKey};
        use multibase::Base;

        let seed_byte: u8 = std::env::var("VTA_TEST_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(11);
        let seed = [seed_byte; 32];
        let sk = SigningKey::from_bytes(&seed);
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(sk.verifying_key().as_bytes());
        let holder_did = format!("did:key:{}", multibase::encode(Base::Base58Btc, &mc));

        let vta_did = std::env::var("VTA_TEST_DID").unwrap_or_else(|_| {
            "did:webvh:QmWoJD2kpP6AJknNtj7UFERUstEen258ywj3ruHoh1ZAqr:webvh.storm.ws:glenn-vta"
                .to_string()
        });
        let mediator = std::env::var("VTA_TEST_MEDIATOR").unwrap_or_else(|_| {
            "did:webvh:QmTS3a3H9Dk4ZMPAZ8jNWGeyPbuKrPbrPZcSbg8CJ6yynD:webvh.storm.ws:mediator"
                .to_string()
        });

        eprintln!("holder   = {holder_did}");
        eprintln!("vta      = {vta_did}");
        eprintln!("mediator = {mediator}");
        eprintln!("\n(enrol this holder first: pnm acl create --did {holder_did})\n");

        struct Stub {
            sk: SigningKey,
            did: String,
        }
        impl Signer for Stub {
            fn did(&self) -> String {
                self.did.clone()
            }
            fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, FfiError> {
                Ok(self.sk.sign(&payload).to_bytes().to_vec())
            }
        }

        let session =
            MediatorSession::connect(holder_did.clone(), seed.to_vec(), vta_did.clone(), mediator)
                .await
                .expect("connect to the mediator");
        eprintln!("✅ mediator connected");

        let env = crate::session::AuthEnvelope {
            id: format!(
                "urn:uuid:test-whoami-{seed_byte}-{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ),
            holder_did: holder_did.clone(),
            vta_did: vta_did.clone(),
            issued_at: chrono::Utc::now().to_rfc3339(),
        };
        let doc = crate::session::build_whoami(
            env,
            Box::new(Stub {
                sk,
                did: holder_did.clone(),
            }),
        )
        .expect("build a signed whoami document");
        eprintln!("→ submitting whoami ({} bytes)", doc.len());

        let result = session.send_trust_task(doc, 30).await;
        session.shutdown().await;

        match result {
            Ok(response) => eprintln!("\n✅ VTA replied over DIDComm, no REST:\n{response}"),
            Err(e) => panic!("send_trust_task failed: {e}"),
        }
    }
}
