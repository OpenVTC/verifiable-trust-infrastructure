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
//! Bidirectional: [`TspMediatorSession::receive_next`] pulls VTA-pushed
//! requests, and [`TspMediatorSession::send_trust_task`] submits the signed
//! decision back the same way. Because TSP proves the sender, the VTA
//! authorizes on the sealed `sender_vid` alone (intrinsic-sender auth) — so a
//! device can run this loop with no VTA REST API and no bearer token.
//!
//! The asymmetry worth knowing: sends are fire-and-forget. TSP has no `thid`
//! demux, so the VTA's reply comes back as an ordinary inbound frame and the
//! caller correlates it off the inbox. See `send_trust_task`.

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

    /// Submit an already-signed Trust Task document to `vta_did`, routed through
    /// `mediator_did`. TSP carries the document bytes directly — no DIDComm
    /// envelope — so the VTA's `tsp_inbound::dispatch_one` hands the payload
    /// straight to the same `dispatch_trust_task_core` that backs
    /// `POST /api/trust-tasks`.
    ///
    /// **No bearer token.** TSP proves the sender, and the VTA derives
    /// authorization from that sealed `sender_vid` (intrinsic-sender auth).
    ///
    /// **Fire-and-forget, unlike the DIDComm
    /// [`send_trust_task`](crate::mediator::MediatorSession::send_trust_task).**
    /// The VTA seals its reply and routes it back over TSP, so the response
    /// document arrives on [`receive_next`](Self::receive_next) like any other
    /// frame — a caller that needs the outcome must match it off the inbox (on
    /// the document's `id`/`type`) rather than awaiting it here. TSP has no
    /// `thid` demux, and `receive_next` holds the socket lock for its whole
    /// budget, so an in-place wait would deadlock against a running inbox loop.
    ///
    /// Sending itself takes no socket lock, so this *is* safe to call while
    /// that loop is blocked in `receive_next`.
    pub async fn send_trust_task(
        &self,
        vta_did: String,
        mediator_did: String,
        doc_json: String,
    ) -> Result<(), FfiError> {
        self.inner
            .send_document(&vta_did, &mediator_did, doc_json.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Live: the no-REST loop over **TSP** — connect the inbox, announce, submit
    /// a holder-signed `whoami`, then read the reply back off the inbox.
    ///
    /// This is the TSP counterpart of
    /// `mediator::tests::whoami_over_didcomm_without_rest`, and it exists to
    /// validate the one assumption the Swift `TspReplyRouter` is built on:
    /// **that the VTA's TSP reply carries `threadId` echoing our request `id`**.
    /// TSP has no `thid` demux, so if that echo isn't there, correlation on the
    /// device is impossible and the router design is wrong. The polling loop
    /// below is deliberately the same rule the router implements.
    ///
    /// Ignored by default (network + a real VTA). Run:
    /// `cargo test -p vta-mobile-core -- --ignored whoami_over_tsp --nocapture`
    /// Override with `VTA_TEST_DID` / `VTA_TEST_MEDIATOR` / `VTA_TEST_SEED`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "network: submits a whoami to a live VTA over TSP"]
    async fn whoami_over_tsp_without_rest() {
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
            TspMediatorSession::connect(holder_did.clone(), seed.to_vec(), mediator.clone())
                .await
                .expect("connect the TSP inbox");
        eprintln!("✅ TSP inbox connected");

        // Learn-from-inbound: makes the VTA record us as TSP-reachable. Also the
        // cheapest proof that outbound TSP works at all, before we send the real
        // document.
        session
            .announce(vta_did.clone(), mediator.clone())
            .await
            .expect("announce TSP reachability");
        eprintln!("✅ announced reachability");

        // Drain the announce's pong FIRST, so the channel is proven live at the
        // moment we submit. Without this, a failure can't distinguish "the
        // whoami broke the channel" from "the channel was never working".
        match session.receive_next(15).await {
            Ok(Some(f)) => eprintln!("✅ channel proven live (pong: {})", &f[..f.len().min(90)]),
            Ok(None) => eprintln!("⚠️  no pong before submit — channel may be dead already"),
            Err(e) => eprintln!("⚠️  pong read error: {e}"),
        }

        // Unique per run: once the DID is enrolled the replay guard
        // (`check_and_record(auth.did, doc.id)`) is reachable, so a fixed id would
        // pass once and then be rejected as a replay on every rerun.
        let request_id = format!(
            "urn:uuid:test-tsp-whoami-{seed_byte}-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let env = crate::session::AuthEnvelope {
            id: request_id.clone(),
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

        eprintln!(
            "→ submitting whoami over TSP ({} bytes), id={request_id}",
            doc.len()
        );
        session
            .send_trust_task(vta_did.clone(), mediator.clone(), doc)
            .await
            .expect("send the whoami over TSP");
        eprintln!("✅ sent (fire-and-forget); polling the inbox for the reply…\n");

        // The router's rule, in miniature: match a frame whose `threadId` equals
        // the id we sent. Anything else is unsolicited traffic (e.g. the pong
        // from `announce`) and is skipped.
        let mut correlated: Option<String> = None;
        for attempt in 1..=6 {
            match session.receive_next(10).await {
                Ok(Some(frame)) => {
                    let thread = serde_json::from_str::<serde_json::Value>(&frame)
                        .ok()
                        .and_then(|v| v.get("threadId").and_then(|t| t.as_str()).map(String::from));
                    eprintln!("  [{attempt}] frame threadId={thread:?}\n      {frame}");
                    if thread.as_deref() == Some(request_id.as_str()) {
                        correlated = Some(frame);
                        break;
                    }
                    eprintln!("      (not ours — skipping, as the router would)");
                }
                Ok(None) => eprintln!("  [{attempt}] nothing within 10s"),
                Err(e) => {
                    eprintln!("  [{attempt}] receive error: {e}");
                    break;
                }
            }
        }
        session.shutdown().await;

        match correlated {
            Some(reply) => {
                eprintln!("\n✅ correlated TSP reply by threadId, no REST:\n{reply}");
            }
            None => panic!(
                "no TSP frame carried threadId={request_id}. The Swift TspReplyRouter \
                 correlates on exactly this echo, so it would never resolve a submit."
            ),
        }
    }
}
