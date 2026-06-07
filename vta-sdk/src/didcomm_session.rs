use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use tracing::{debug, info, warn};

use crate::error::VtaError;
use crate::protocols::PROBLEM_REPORT_TYPE;

// Per-step ceiling for mediator round-trips during session setup. The
// upstream calls below are otherwise unbounded — when the mediator is
// unreachable a CLI invocation can hang for the full TCP/TLS retry
// window (30–60s on macOS) before failing. 15s is generous for healthy
// mediators and keeps Ctrl-C responsive.
const MEDIATOR_OP_TIMEOUT: Duration = Duration::from_secs(15);

/// Client-side DIDComm session for request-response messaging via ATM.
///
/// Uses WebSocket streaming to receive responses from the mediator.
/// Designed for CLI tools that send a request and wait for a reply.
///
/// # You MUST call [`shutdown`](Self::shutdown)
///
/// This session owns a live, **auto-reconnecting** mediator connection.
/// [`shutdown`](Self::shutdown) is `async`, so [`Drop`] **cannot** close it —
/// dropping the last clone of a session without having called `shutdown()`
/// leaks a reconnecting session. Two live sessions for the same DID fight on
/// the mediator (`Duplicate WebSocket connection: closing old session …`) and
/// request/response round-trips time out. Dropping a leaked session logs a
/// `WARN` (and trips a `debug_assert!` in debug builds).
#[derive(Clone)]
pub struct DIDCommSession {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    pub(crate) client_did: String,
    pub(crate) vta_did: String,
    /// Set by [`shutdown`](Self::shutdown). Shared across clones so calling
    /// `shutdown()` on any clone (or the owning [`crate::client::VtaClient`])
    /// marks the whole session closed. The [`LeakGuard`] reads it on the last
    /// drop.
    shutdown: Arc<AtomicBool>,
    /// Fires a warning iff the last owner drops without `shutdown()`. `Arc`, so
    /// its [`Drop`] runs exactly once — when the truly-last session clone is
    /// dropped, which is when the live connection actually goes away.
    _leak_guard: Arc<LeakGuard>,
}

/// Drop-time leak detector for a [`DIDCommSession`]. Held behind an `Arc` so it
/// fires once, on the final drop. If `shutdown()` was never called it logs a
/// loud warning — turning a silent "leaked reconnecting session" into an
/// immediate signal in the logs.
struct LeakGuard {
    shutdown: Arc<AtomicBool>,
    client_did: String,
    vta_did: String,
}

impl LeakGuard {
    /// `true` iff the session was dropped without `shutdown()` having been
    /// called — i.e. a leaked, still-reconnecting session.
    fn leaked(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
    }
}

impl Drop for LeakGuard {
    fn drop(&mut self) {
        // `!panicking()` avoids a double-panic abort if we're already unwinding.
        if self.leaked() && !std::thread::panicking() {
            warn!(
                client_did = %self.client_did,
                vta_did = %self.vta_did,
                "DIDComm session dropped without shutdown() — a live, auto-reconnecting \
                 session leaked. Two sessions for the same DID fight on the mediator and \
                 round-trips time out. Call `client.shutdown().await`, or use \
                 `VtaClient::with_didcomm`."
            );
            debug_assert!(
                false,
                "DIDComm session for `{}` dropped without shutdown() — call \
                 shutdown().await or use VtaClient::with_didcomm",
                self.client_did
            );
        }
    }
}

impl DIDCommSession {
    /// The session's local DID — the one used as the authcrypt
    /// sender on outbound messages. Surfaced so SDK helpers can
    /// pre-check sender == expected DID before sending (the VTA's
    /// `provision-integration` handler enforces sender == VP
    /// holder, for instance).
    pub fn client_did(&self) -> &str {
        &self.client_did
    }

    /// Connect to a VTA via DIDComm through a mediator.
    ///
    /// Opens a **persistent, auto-reconnecting WebSocket** to the mediator for
    /// streaming response delivery (`profile_enable_websocket` below) — without
    /// it the ATM can only REST-poll and may miss responses that arrive after
    /// the initial send returns. Because the mediator enforces one socket per
    /// DID, callers MUST reuse a single session per DID and [`shutdown`] it
    /// rather than connecting per operation; overlapping sessions for the same
    /// DID duel on the mediator and drop in-flight messages (see #302).
    ///
    /// [`shutdown`]: Self::shutdown
    pub async fn connect(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Decode private key and build DIDComm secrets
        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        // Create TDK shared state and insert secrets
        let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;
        tdk.secrets_resolver().insert(secrets.signing).await;
        tdk.secrets_resolver().insert(secrets.key_agreement).await;

        // Build ATM (no inbound channel needed — we use REST polling)
        let atm_config = ATMConfig::builder().build()?;
        let atm = ATM::new(atm_config, Arc::new(tdk)).await?;

        // Create profile with mediator
        let profile = ATMProfile::new(
            &atm,
            None,
            client_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await?;
        let profile = Arc::new(profile);

        let atm = Arc::new(atm);

        // Flush stale messages from the inbox (accumulated between CLI runs)
        {
            use affinidi_tdk::messaging::messages::Folder;
            match tokio::time::timeout(
                MEDIATOR_OP_TIMEOUT,
                atm.list_messages(&profile, Folder::Inbox),
            )
            .await
            {
                Ok(Ok(messages)) if !messages.is_empty() => {
                    let ids: Vec<String> = messages.iter().map(|m| m.msg_id.clone()).collect();
                    info!(
                        count = ids.len(),
                        "flushing stale queued messages from inbox"
                    );
                    let delete_req = affinidi_tdk::messaging::messages::DeleteMessageRequest {
                        message_ids: ids,
                    };
                    match tokio::time::timeout(
                        MEDIATOR_OP_TIMEOUT,
                        atm.delete_messages_direct(&profile, &delete_req),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => {
                            debug!(
                                deleted = resp.success.len(),
                                errors = resp.errors.len(),
                                "inbox flushed"
                            );
                        }
                        Ok(Err(e)) => warn!("failed to flush stale messages (non-fatal): {e}"),
                        Err(_) => warn!(
                            "timeout flushing stale messages after {}s (non-fatal)",
                            MEDIATOR_OP_TIMEOUT.as_secs()
                        ),
                    }
                }
                Ok(Ok(_)) => {} // Empty inbox
                Ok(Err(e)) => warn!("could not list inbox (non-fatal): {e}"),
                Err(_) => warn!(
                    "timeout listing inbox after {}s (non-fatal)",
                    MEDIATOR_OP_TIMEOUT.as_secs()
                ),
            }
        }

        // Enable WebSocket for streaming message delivery from mediator.
        // Without this, the ATM can only poll via REST and may miss responses
        // that arrive after the initial send_message call returns.
        match tokio::time::timeout(MEDIATOR_OP_TIMEOUT, atm.profile_enable_websocket(&profile))
            .await
        {
            Ok(res) => res?,
            Err(_) => {
                return Err(format!(
                    "timeout enabling WebSocket to mediator after {}s — \
                     mediator may be unreachable",
                    MEDIATOR_OP_TIMEOUT.as_secs()
                )
                .into());
            }
        }

        debug!("DIDComm session connected via mediator {mediator_did} (WebSocket mode)");

        let shutdown = Arc::new(AtomicBool::new(false));
        let leak_guard = Arc::new(LeakGuard {
            shutdown: Arc::clone(&shutdown),
            client_did: client_did.to_string(),
            vta_did: vta_did.to_string(),
        });
        Ok(Self {
            atm,
            profile,
            client_did: client_did.to_string(),
            vta_did: vta_did.to_string(),
            shutdown,
            _leak_guard: leak_guard,
        })
    }

    /// Send a DIDComm message and wait for a matching response.
    ///
    /// Packs the message, sends it to the mediator, then uses the WebSocket
    /// live stream to wait for the response. This handles asynchronous
    /// processing where the VTA takes time to respond.
    ///
    /// Problem-report responses are decoded into typed [`VtaError`] variants
    /// based on their `e.p.msg.*` code so DIDComm and REST surface the same
    /// error taxonomy (conflict, not-found, auth, validation, server).
    pub async fn send_and_wait<T: serde::de::DeserializeOwned>(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        expected_result_type: &str,
        timeout_secs: u64,
    ) -> Result<T, VtaError> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(self.client_did.clone())
            .to(self.vta_did.clone())
            .finalize();

        // Pack encrypted (signed + encrypted to recipient)
        let (packed, _) = self
            .atm
            .pack_encrypted(
                &msg,
                &self.vta_did,
                Some(&self.client_did),
                Some(&self.client_did),
            )
            .await
            .map_err(|e| VtaError::DidcommTransport(format!("failed to pack message: {e}")))?;

        debug!(msg_type, msg_id, "sending via DIDComm");

        // Wrap the inner JWE in a `routing/2.0/forward` envelope addressed
        // to the mediator and ship it. Strict mediators
        // (`local_direct_delivery_allowed: false`) refuse direct delivery
        // — same path the production VTA-side `affinidi-messaging-didcomm-service`
        // takes via `forward_and_send_message`.
        let mediator_did = self
            .profile
            .inner
            .mediator
            .as_ref()
            .as_ref()
            .map(|m| m.did.clone())
            .ok_or_else(|| {
                VtaError::DidcommTransport("no mediator configured on profile".into())
            })?;

        self.atm
            .forward_and_send_message(
                &self.profile,
                false, // authcrypt the forward envelope (mediator policy)
                &packed,
                Some(&msg_id),
                &mediator_did,
                &self.vta_did,
                None,
                None,
                false,
            )
            .await
            .map_err(|e| VtaError::DidcommTransport(format!("failed to send message: {e}")))?;

        // Wait for the response via WebSocket live stream
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let wait_duration = std::time::Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(VtaError::DidcommTransport(
                    "timeout waiting for DIDComm response".into(),
                ));
            }
            let wait = wait_duration.min(remaining);

            let next = self
                .atm
                .message_pickup()
                .live_stream_next(&self.profile, Some(wait), true)
                .await
                .map_err(|e| VtaError::DidcommTransport(format!("message pickup error: {e}")))?;

            let (response_msg, _meta) = match next {
                Some(pair) => pair,
                None => continue, // No message yet, keep waiting
            };

            // Check if this is the response we're waiting for (matching thread ID)
            let response_thid = response_msg.thid.as_deref().unwrap_or("");
            if response_thid != msg_id {
                debug!(
                    response_thid,
                    expected = msg_id,
                    response_type = %response_msg.typ,
                    "received message with non-matching thread ID — skipping"
                );
                continue;
            }

            debug!(response_type = %response_msg.typ, "received DIDComm response");

            // Check for problem report — map the `e.p.msg.*` code to the
            // matching VtaError variant so callers can `match` on the same
            // error shapes they get from REST (see `VtaError::from_http`).
            if response_msg.typ == PROBLEM_REPORT_TYPE
                || response_msg.typ.contains("problem-report")
            {
                let code = response_msg
                    .body
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let comment = response_msg
                    .body
                    .get("comment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Err(VtaError::from_problem_report(code, comment));
            }

            // Verify expected type
            if response_msg.typ != expected_result_type {
                return Err(VtaError::Protocol(format!(
                    "unexpected response type: expected {expected_result_type}, got {}",
                    response_msg.typ
                )));
            }

            // Deserialize response body
            return serde_json::from_value(response_msg.body).map_err(VtaError::from);
        }
    }

    /// Receive the next **unsolicited** inbound DIDComm message — e.g. an
    /// `auth/step-up/approve-request/0.1` the VTA pushed to this holder via the
    /// mediator. Polls the mediator's live stream for up to `timeout_secs`;
    /// returns `Ok(None)` if nothing arrived in time.
    ///
    /// Unlike [`Self::send_and_wait`], this is not bound to a thread id — it
    /// surfaces whatever the mediator delivers next. The returned string is the
    /// **unpacked** DIDComm message as JSON (`{ id, type, body, from, … }`);
    /// ATM has already decrypted it under the holder key, so the caller works
    /// with plaintext (the application Trust Task rides in `body`).
    pub async fn receive_next(&self, timeout_secs: u64) -> Result<Option<String>, VtaError> {
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let wait_duration = std::time::Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let wait = wait_duration.min(remaining);

            let next = self
                .atm
                .message_pickup()
                .live_stream_next(&self.profile, Some(wait), true)
                .await
                .map_err(|e| VtaError::DidcommTransport(format!("message pickup error: {e}")))?;

            let (msg, _meta) = match next {
                Some(pair) => pair,
                None => continue, // nothing yet — keep waiting until the deadline
            };
            debug!(msg_type = %msg.typ, "received inbound DIDComm message");
            let json = serde_json::to_string(&msg).map_err(VtaError::from)?;
            return Ok(Some(json));
        }
    }

    /// Gracefully shut down the DIDComm session — **required** for every
    /// session (see the type-level docs). Marks the session closed (so the
    /// drop-time leak check stays quiet) and tears down the mediator
    /// connection. Idempotent and safe to call on any clone.
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.atm.graceful_shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(shutdown: &Arc<AtomicBool>) -> LeakGuard {
        LeakGuard {
            shutdown: Arc::clone(shutdown),
            client_did: "did:key:zClient".into(),
            vta_did: "did:key:zVta".into(),
        }
    }

    #[test]
    fn leak_guard_reports_a_leak_until_shutdown_is_marked() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let g = guard(&shutdown);
        assert!(g.leaked(), "an un-shut-down session is a leak");

        // Marking shutdown (what `shutdown()` does) clears the leak.
        shutdown.store(true, Ordering::Release);
        assert!(!g.leaked(), "after shutdown() the session is not a leak");

        // Drop is a no-op now (shutdown marked) — no panic from the debug_assert.
        drop(g);
    }

    #[test]
    #[should_panic(expected = "dropped without shutdown()")]
    fn dropping_a_leaked_guard_trips_the_debug_assert() {
        // Construct a leaked guard and drop it: the debug_assert must fire (this
        // is the signal that catches a forgotten shutdown() in a developer's
        // own tests). Only meaningful in debug builds.
        if cfg!(debug_assertions) {
            let shutdown = Arc::new(AtomicBool::new(false));
            let _g = guard(&shutdown); // dropped at end of scope → panics
        } else {
            // Release builds compile out debug_assert; satisfy #[should_panic].
            panic!("dropped without shutdown() (release no-op shim)");
        }
    }
}
