use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use affinidi_messaging_core::{Inbound, MessageTransport};
use affinidi_messaging_delivery::{Delivery, InMemoryOutboxStore, MessagingService, OutboxStore};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
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
    /// The reliable-messaging delivery layer over the mediator socket. Its
    /// single inbound dispatcher demuxes replies by `thid` to [`request`]
    /// waiters and hands unsolicited messages to [`subscribe`], deleting each
    /// message from the mediator exactly once — this is what fixes the F5
    /// steal-and-destroy bug the old raw `live_stream_next(auto_delete=true)`
    /// path had when concurrent `send_and_wait`s shared one session.
    ///
    /// [`request`]: affinidi_messaging_delivery::MessagingService::request
    /// [`subscribe`]: affinidi_messaging_delivery::MessagingService::subscribe
    service: Arc<MessagingService>,
    /// Kept solely to `pack_encrypted` outbound messages (the delivery layer
    /// takes already-packed bytes) and to seal/open vault JWEs.
    atm: Arc<ATM>,
    /// The one persistent [`subscribe`] stream feeding [`receive_next`]. Each
    /// subscriber is independent + buffered, so this must be created once (in
    /// [`connect_with_secrets`]) and shared across clones — a fresh `subscribe()`
    /// per `receive_next` call would only see messages that arrive after it.
    ///
    /// [`subscribe`]: affinidi_messaging_delivery::MessagingService::subscribe
    /// [`receive_next`]: Self::receive_next
    /// [`connect_with_secrets`]: Self::connect_with_secrets
    subscriber: Arc<tokio::sync::Mutex<BoxStream<'static, Inbound>>>,
    /// The TSP leg riding this same session — see [`TspLeg`]. Always built (it
    /// costs one extra `subscribe()` receiver) so a `VtaClient` can turn TSP on
    /// for the Trust-Task surface without reconnecting.
    #[cfg(feature = "tsp")]
    tsp: Arc<TspLeg>,
    /// The mediator this session is connected to. The TSP leg's route is
    /// `[mediator_did, recipient]`, and a `VtaClient` compares it against the
    /// VTA's advertised `#tsp` endpoint to decide whether TSP can ride this
    /// socket or needs its own.
    pub(crate) mediator_did: String,
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

/// The **TSP leg** of a [`DIDCommSession`] — Trust-Task traffic over TSP on the
/// session's *existing* mediator connection.
///
/// # Why this lives on the DIDComm session
///
/// The mediator permits **one websocket per DID**. A consumer holding a DIDComm
/// session cannot also open a [`TspSession`](crate::session::TspSession) on the
/// same DID against the same mediator — the second socket is rejected with
/// `duplicate-channel` and the two reconnect loops duel. On the reference
/// deployment `#tsp` and `#vta-didcomm` resolve to the *same* mediator, so that
/// is the normal case, not an edge case (#803).
///
/// It does not need a second socket, because neither half of TSP needs one here:
///
/// - **Send** is an HTTP `POST /inbound` to the mediator
///   (`TspOps::send_raw`) — no socket at all.
/// - **Receive** already arrives on the DIDComm socket. The delivery layer's
///   `DidCommTransport` polls `live_stream_next_frame`, which yields **both**
///   protocols off the one pickup socket and tags each `Inbound` with
///   `message.protocol`. A TSP frame carries no DIDComm `thid`, so
///   `MessagingService` routes it to `subscribe()`.
///
/// This mirrors what the VTA itself already does on the server side: it deleted
/// its standalone TSP websocket for exactly this reason and now demuxes TSP off
/// its single delivery-layer socket (`vta-service/src/messaging/service.rs`).
///
/// The leg takes its **own** `subscribe()` receiver. Subscribers are a
/// broadcast, so each one sees every unsolicited frame and ignores what isn't
/// its protocol — the TSP pump cannot eat a DIDComm push, and
/// [`receive_next`](DIDCommSession::receive_next) cannot eat a TSP reply.
#[cfg(feature = "tsp")]
struct TspLeg {
    /// Kept to reach `atm.tsp()` for the outbound seal + route.
    atm: Arc<ATM>,
    /// The profile the TSP keys and mediator endpoint are read from — the same
    /// one the DIDComm transport is bound to.
    profile: Arc<ATMProfile>,
    /// In-flight `request_tsp` waiters + the parking lot for pushes. Shared
    /// implementation with [`TspSession`](crate::session::TspSession).
    demux: crate::tsp_demux::TspDemux,
    /// This leg's own inbound stream. Behind a mutex so whichever task holds it
    /// pumps on behalf of every waiter (leader/followers).
    stream: tokio::sync::Mutex<BoxStream<'static, Inbound>>,
}

/// What one turn at the TSP leg's inbound stream produced.
#[cfg(feature = "tsp")]
enum TspPump {
    /// A frame arrived and went to the request that was waiting for it.
    Delivered,
    /// A frame arrived that no in-flight request wanted.
    Uncorrelated(String),
    /// The slice elapsed with no TSP frame.
    Idle,
}

/// How long one turn at the TSP leg's stream lasts before the holder must
/// release it, bounding lock hand-off latency between concurrent requests.
/// Mirrors `session::PUMP_SLICE`.
#[cfg(feature = "tsp")]
const TSP_PUMP_SLICE: Duration = Duration::from_millis(250);

impl DIDCommSession {
    /// The session's local DID — the one used as the authcrypt
    /// sender on outbound messages. Surfaced so SDK helpers can
    /// pre-check sender == expected DID before sending (the VTA's
    /// `provision-integration` handler enforces sender == VP
    /// holder, for instance).
    pub fn client_did(&self) -> &str {
        &self.client_did
    }

    /// The mediator this session's websocket is connected to.
    ///
    /// Load-bearing for transport selection, not just diagnostics: because the
    /// mediator permits **one websocket per DID**, whether TSP can ride this
    /// session or needs its own connection is decided by comparing this against
    /// the VTA's advertised `#tsp` endpoint. See
    /// [`VtaClient::enable_tsp_trust_tasks`](crate::client::VtaClient::enable_tsp_trust_tasks).
    pub fn mediator_did(&self) -> &str {
        &self.mediator_did
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
        // Decode private key and build DIDComm secrets for a `did:key`
        // (Ed25519 signing + X25519 key-agreement derived from it).
        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        // Delegate to the secrets-driven path (signing first, then KA).
        Self::connect_with_secrets(
            client_did,
            vec![secrets.signing, secrets.key_agreement],
            vta_did,
            mediator_did,
        )
        .await
    }

    /// Connect to a VTA via DIDComm using **pre-built** DIDComm secrets.
    ///
    /// Same transport behaviour as [`connect`](Self::connect) — a persistent,
    /// auto-reconnecting WebSocket to the mediator — but the caller supplies
    /// the [`Secret`](affinidi_tdk::secrets_resolver::secrets::Secret)s rather
    /// than deriving them from a `did:key` seed. This is the path for hosted
    /// DIDs (`did:webvh`) whose signing (`#key-0` Ed25519) and key-agreement
    /// (`#key-1` X25519) keys are *independent* and exported as a
    /// [`DidSecretsBundle`](crate::did_secrets::DidSecretsBundle) — build the
    /// secrets with [`crate::did_key::secrets_from_bundle`] and pass them here.
    ///
    /// Secrets are inserted into the resolver in the order given; pass signing
    /// first by convention. Every secret's `id` MUST be a verification-method
    /// id of `client_did` (`{did}#...`) so the mediator/peer can match inbound
    /// JWE recipients against it.
    ///
    /// The same [`shutdown`](Self::shutdown) contract applies — see
    /// [`connect`](Self::connect).
    pub async fn connect_with_secrets(
        client_did: &str,
        secrets: Vec<affinidi_tdk::secrets_resolver::secrets::Secret>,
        vta_did: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create TDK shared state and insert secrets
        let tdk = TDKSharedState::new(TDKConfig::builder().build()?).await?;
        for secret in secrets {
            tdk.secrets_resolver().insert(secret).await;
        }

        // Build ATM — inbound is driven by the delivery layer's DidCommTransport,
        // not by direct ATM polling (see the `MessagingService` wiring below).
        let atm_config = ATMConfig::builder().build()?;
        let atm = Arc::new(ATM::new(atm_config, Arc::new(tdk)).await?);

        // Past this point we own live background tasks: the ATM's deletion
        // handler, and shortly a websocket transport that reconnects on its own
        // timer. Dropping the handles does NOT stop them. An abandoned transport
        // keeps holding — and fighting other sessions for — the mediator's
        // one-socket-per-DID slot for `client_did`, for the life of the process.
        //
        // So every fallible step runs inside `finish_connect`, and a failure
        // tears the ATM down here. One place to get right, rather than one per
        // `?` (a timeout arm that forgot this is exactly how a service that
        // reconnects on a schedule accumulates duelling ghost sockets).
        // `map_err` to a `String` before the match: the boxed error is not
        // `Send`, so holding it across the `graceful_shutdown().await` below
        // would make this whole future non-`Send` and break callers that
        // `tokio::spawn` a connect.
        let outcome = Self::finish_connect(&atm, client_did, vta_did, mediator_did)
            .await
            .map_err(|e| e.to_string());

        match outcome {
            Ok(session) => Ok(session),
            Err(msg) => {
                atm.graceful_shutdown().await;
                Err(msg.into())
            }
        }
    }

    /// Fallible tail of [`connect_with_secrets`]: everything that needs a live
    /// ATM. Split out so a single error path can shut that ATM down — see the
    /// call site.
    async fn finish_connect(
        atm: &Arc<ATM>,
        client_did: &str,
        vta_did: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create profile with mediator
        let profile = Arc::new(
            ATMProfile::new(
                atm,
                None,
                client_did.to_string(),
                Some(mediator_did.to_string()),
            )
            .await?,
        );

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

        // Set this client's ACL on the mediator to accept all message types.
        // `set_client_acl_on_connection` is itself fire-and-forget (it spawns a
        // background task and returns immediately), so no extra spawn here — the
        // connect path is not blocked on the mediator round-trip. Only compiled-in
        // when the `acl-setup` feature is enabled (requires `session` +
        // `trust-tasks-rs`). PNM enables `acl-setup`; SDK consumers that omit it
        // are unaffected.
        #[cfg(feature = "acl-setup")]
        crate::acl_setup::set_client_acl_on_connection(
            atm,
            client_did,
            mediator_did,
            "didcomm-session",
            "pnm",
        )
        .await;

        // Build the reliable-messaging delivery layer over the mediator
        // websocket, mirroring `vta-service`/`vtc-service`'s `build_messaging`:
        // wrap the (now websocket-enabled) ATM + profile in a `DidCommTransport`,
        // back an ephemeral in-memory outbox (the client is short-lived — no
        // durability needed), and start the merged inbound dispatcher via
        // `MessagingService::new`. The dispatcher is what demuxes replies to
        // `request` waiters and unsolicited pushes to `subscribe`, deleting each
        // message from the mediator exactly once (the F5 fix).
        let transport: Arc<dyn MessageTransport> = Arc::new(
            DidCommTransport::new((**atm).clone(), profile.clone())
                .await
                .map_err(|e| format!("bind DidComm transport: {e}"))?,
        );
        let outbox: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
        let service = Arc::new(MessagingService::new(transport, outbox));
        // ONE persistent subscriber for `receive_next` — a per-call `subscribe()`
        // would miss anything delivered before it started.
        let subscriber = Arc::new(tokio::sync::Mutex::new(service.subscribe()));

        // The TSP leg rides this same socket — see `TspLeg`. Built here rather
        // than on demand so enabling TSP for the Trust-Task surface later never
        // has to reconnect (and so it can never be tempted to open a second
        // socket for this DID). Its cost is one more broadcast receiver.
        #[cfg(feature = "tsp")]
        let tsp = Arc::new(TspLeg {
            atm: Arc::clone(atm),
            profile: Arc::clone(&profile),
            demux: crate::tsp_demux::TspDemux::new(),
            stream: tokio::sync::Mutex::new(service.subscribe()),
        });

        debug!("DIDComm session connected via mediator {mediator_did} (delivery-layer mode)");

        let shutdown = Arc::new(AtomicBool::new(false));
        let leak_guard = Arc::new(LeakGuard {
            shutdown: Arc::clone(&shutdown),
            client_did: client_did.to_string(),
            vta_did: vta_did.to_string(),
        });
        Ok(Self {
            service,
            atm: Arc::clone(atm),
            subscriber,
            #[cfg(feature = "tsp")]
            tsp,
            mediator_did: mediator_did.to_string(),
            client_did: client_did.to_string(),
            vta_did: vta_did.to_string(),
            shutdown,
            _leak_guard: leak_guard,
        })
    }

    /// Seal a cleartext JSON value as a `didcomm-authcrypt` JWE addressed to
    /// the VTA — the `sealedSecret` shape `vault/upsert/0.1` expects.
    ///
    /// `body` is the cleartext `VaultSecret` document. The VTA unpacks the JWE,
    /// cross-checks the authcrypt sender DID against the authenticated caller,
    /// and deserialises the body as a `VaultSecret`
    /// (`operations::vault::upsert::unseal_secret`). Authcrypt with the session's
    /// own keys, so the sender is provably this client's DID. The message `type`
    /// is informational — the VTA reads only `from` + `body`.
    pub(crate) async fn seal_to_vta(&self, body: serde_json::Value) -> Result<String, VtaError> {
        const VAULT_SECRET_TYPE: &str =
            "https://trusttasks.org/spec/vault/_shared/0.1/vault-secret";
        let msg_id = uuid::Uuid::new_v4().to_string();
        let msg = Message::build(msg_id, VAULT_SECRET_TYPE.to_string(), body)
            .from(self.client_did.clone())
            .to(self.vta_did.clone())
            .finalize();
        let (packed, _) = self
            .atm
            .pack_encrypted(
                &msg,
                &self.vta_did,
                Some(&self.client_did),
                Some(&self.client_did),
            )
            .await
            .map_err(|e| VtaError::DidcommTransport(format!("failed to seal vault secret: {e}")))?;
        Ok(packed)
    }

    /// Open a `didcomm-authcrypt` JWE the VTA sealed to this client (the
    /// `sealedSecret` / `sealedSessionBlob` returned by `vault/release` and
    /// `vault/proxy-login`), recovering the cleartext body.
    pub(crate) async fn open_from_vta(&self, jwe: &str) -> Result<serde_json::Value, VtaError> {
        let (msg, _meta) = self.atm.unpack(jwe).await.map_err(|e| {
            VtaError::DidcommTransport(format!("failed to open sealed secret: {e}"))
        })?;
        Ok(msg.body)
    }

    /// Pack `body` as an authcrypt DIDComm message of `msg_type` from this
    /// session to `recipient_did` and return the packed JWE string.
    ///
    /// Pack-only: the actual send/forward is done by the delivery layer
    /// ([`MessagingService::send`] / [`MessagingService::request`]), whose
    /// [`DidCommTransport`] wraps the message in a `routing/2.0/forward`
    /// envelope through the mediator internally — so there is no
    /// `forward_and_send_message` call here anymore. Strict mediators
    /// (`local_direct_delivery_allowed: false`) still get a forward-wrapped
    /// message because the transport always routes via the mediator.
    ///
    /// Shared by [`send_and_wait`](Self::send_and_wait) (which then awaits the
    /// reply the dispatcher demuxes to it by `thid`) and
    /// [`send_one_way`](Self::send_one_way) (which fires and forgets).
    ///
    /// [`MessagingService::send`]: affinidi_messaging_delivery::MessagingService::send
    /// [`MessagingService::request`]: affinidi_messaging_delivery::MessagingService::request
    async fn pack_message(
        &self,
        recipient_did: &str,
        msg_id: &str,
        msg_type: &str,
        body: serde_json::Value,
    ) -> Result<String, VtaError> {
        let msg = Message::build(msg_id.to_string(), msg_type.to_string(), body)
            .from(self.client_did.clone())
            .to(recipient_did.to_string())
            .finalize();

        // Pack encrypted (signed + encrypted to recipient)
        let (packed, _) = self
            .atm
            .pack_encrypted(
                &msg,
                recipient_did,
                Some(&self.client_did),
                Some(&self.client_did),
            )
            .await
            .map_err(|e| VtaError::DidcommTransport(format!("failed to pack message: {e}")))?;

        debug!(msg_type, msg_id, recipient_did, "packed DIDComm message");
        Ok(packed)
    }

    /// Send a one-way (fire-and-forget) DIDComm message to `recipient_did` and
    /// return as soon as the mediator accepts it — **no** response is awaited.
    ///
    /// This is the unsolicited-send counterpart to
    /// [`receive_next`](Self::receive_next): the message is authcrypt-packed
    /// with this session's own keys (so the recipient unpacks a
    /// cryptographically-authenticated sender DID) and forwarded via the
    /// mediator, exactly as [`send_and_wait`](Self::send_and_wait) does, minus
    /// the response wait and minus the trust-task envelope. Because it never
    /// touches the inbound live stream it is safe to call concurrently with a
    /// `receive_next` loop (e.g. an async peer-to-peer data plane). See
    /// issue #502.
    pub async fn send_one_way(
        &self,
        recipient_did: &str,
        msg_type: &str,
        body: serde_json::Value,
    ) -> Result<(), VtaError> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        let packed = self
            .pack_message(recipient_did, &msg_id, msg_type, body)
            .await?;
        // `BestEffort`: one truthful hop send — `Err` if the frame wasn't
        // transmitted (no silent `Ok` for a dropped frame, per R1.1).
        self.service
            .send(recipient_did, packed.into_bytes(), Delivery::BestEffort)
            .await
            .map_err(|e| VtaError::DidcommTransport(format!("failed to send message: {e}")))?;
        Ok(())
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
        // Pack the message; the delivery layer sends it (forward-wrapped via the
        // mediator) and awaits the reply the dispatcher demuxes to THIS waiter by
        // `thid == msg_id`. Concurrent `send_and_wait`s each register their own
        // waiter, so a peer request's reply can no longer be stolen (F5 fix).
        let packed = self
            .pack_message(&self.vta_did, &msg_id, msg_type, body)
            .await?;

        let received = self
            .service
            .request(
                &self.vta_did,
                packed.into_bytes(),
                &msg_id,
                Duration::from_secs(timeout_secs),
            )
            .await
            .map_err(|e| {
                // Preserve the exact timeout message callers/tests match on today.
                if e.to_string().contains("timed out") {
                    VtaError::DidcommTransport("timeout waiting for DIDComm response".into())
                } else {
                    VtaError::DidcommTransport(format!("message pickup error: {e}"))
                }
            })?;

        // `payload` is the full plaintext DIDComm `Message` JSON.
        let response_msg: Message =
            serde_json::from_slice(&received.payload).map_err(VtaError::from)?;

        debug!(response_type = %response_msg.typ, "received DIDComm response");

        // Check for problem report — map the `e.p.msg.*` code to the
        // matching VtaError variant so callers can `match` on the same
        // error shapes they get from REST (see `VtaError::from_http`).
        if response_msg.typ == PROBLEM_REPORT_TYPE || response_msg.typ.contains("problem-report") {
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
        serde_json::from_value(response_msg.body).map_err(VtaError::from)
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
        // Pull from the ONE persistent subscriber. This no longer competes with
        // `send_and_wait`: the dispatcher already routed any thread-correlated
        // reply to its `request` waiter, so this stream carries only unsolicited
        // inbound. The lock serialises concurrent `receive_next` calls on the
        // same session (each message goes to exactly one caller).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let mut stream = self.subscriber.lock().await;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(inbound)) => {
                    // The mediator multiplexes DIDComm and TSP onto one socket, so
                    // this stream carries both. A TSP frame's payload is a bare
                    // Trust-Task document, NOT a DIDComm `Message` — parsing it as
                    // one is a hard error, which would turn an inbound TSP frame
                    // into a failure of the DIDComm inbox that received it. Skip it
                    // here; the TSP leg has its own subscriber and its own copy of
                    // this frame (see `TspLeg`), so nothing is lost.
                    #[cfg(feature = "tsp")]
                    if inbound.message.protocol == affinidi_messaging_core::Protocol::TSP {
                        debug!(
                            "skipping an inbound TSP frame on the DIDComm inbox (the TSP leg has it)"
                        );
                        continue;
                    }
                    // `payload` is the full plaintext DIDComm `Message` JSON;
                    // re-serialise it to preserve the `{ id, type, body, from, … }`
                    // shape callers (`InboundMessage::parse`) expect.
                    let msg: Message =
                        serde_json::from_slice(&inbound.message.payload).map_err(VtaError::from)?;
                    debug!(msg_type = %msg.typ, "received inbound DIDComm message");
                    let json = serde_json::to_string(&msg).map_err(VtaError::from)?;
                    return Ok(Some(json));
                }
                // Stream ended — nothing more will EVER arrive on this session.
                //
                // Distinguish the two ways that happens, because they need opposite
                // reactions from the caller:
                //   * we called `shutdown()` — expected teardown, report idle;
                //   * anything else (mediator dropped us, delivery layer died) — the
                //     session is dead and must be rebuilt.
                //
                // Reporting the second as `Ok(None)` made a dead session look like a
                // quiet one: a polling loop would treat "stream ended" as "nothing
                // yet", call again, get the same answer instantly, and spin at full
                // tilt forever without reconnecting. `Err` is what makes the
                // supervisor reconnect instead.
                Ok(None) => {
                    return if self.shutdown.load(Ordering::Acquire) {
                        Ok(None)
                    } else {
                        Err(VtaError::DidcommTransport(
                            "mediator inbound stream ended — session is no longer live".into(),
                        ))
                    };
                }
                // Poll window elapsed with nothing — the ordinary idle case.
                Err(_) => return Ok(None),
            }
        }
    }

    /// Gracefully shut down the DIDComm session — **required** for every
    /// session (see the type-level docs). Marks the session closed (so the
    /// drop-time leak check stays quiet) and tears down the mediator
    /// connection. Idempotent and safe to call on any clone.
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        // Drop every TSP waiter first so an in-flight `request_tsp` fails fast
        // with "session shut down" rather than blocking until its own deadline
        // on a connection that is about to disappear.
        #[cfg(feature = "tsp")]
        self.tsp.demux.clear().await;
        self.atm.graceful_shutdown().await;
    }
}

// ── TSP leg ─────────────────────────────────────────────────────────
//
// Trust-Task traffic over TSP on this session's existing mediator connection.
// See `TspLeg` for why it is here and not in a session of its own.

#[cfg(feature = "tsp")]
impl DIDCommSession {
    /// Send an already-built Trust-Task document to `recipient_did` over TSP,
    /// routed through this session's mediator. Fire-and-forget: any reply
    /// arrives on [`receive_next_tsp`](Self::receive_next_tsp) (or is
    /// correlated by [`request_tsp`](Self::request_tsp) if one is waiting).
    ///
    /// `body` is the serialized document itself — TSP carries the Trust-Task
    /// bytes directly, with no DIDComm envelope around them (the VTA's
    /// `tsp_inbound::dispatch_one` hands the payload straight to
    /// `dispatch_trust_task_core`).
    ///
    /// **Opens no socket.** The send is an HTTP `POST /inbound` to the mediator,
    /// so it never touches the websocket and is safe to call while a
    /// `receive_next` / `receive_next_tsp` is blocked.
    ///
    /// The sender is proven by TSP itself, so the VTA derives authorization from
    /// the sealed `sender_vid` (intrinsic-sender auth) — no bearer token and no
    /// holder proof in the document.
    pub async fn send_tsp_document(
        &self,
        recipient_did: &str,
        body: &[u8],
    ) -> Result<(), VtaError> {
        self.tsp
            .atm
            .tsp()
            .send_routed(
                &self.tsp.profile,
                &[self.mediator_did.clone(), recipient_did.to_string()],
                body,
            )
            .await
            .map_err(|e| VtaError::TspTransport(format!("TSP send failed: {e}")))
    }

    /// Send `document` to `recipient_did` over TSP and wait for **its** reply.
    ///
    /// The TSP counterpart of [`send_and_wait`](Self::send_and_wait), with the
    /// same properties as [`TspSession::request`](crate::session::TspSession::request):
    ///
    /// - **Correlated, never "first frame that parses".** Replies are matched by
    ///   `crate::tsp_demux::correlates` — `threadId`, falling back to an echoed
    ///   `nonce`. The mediator inbox is durable and flushes on connect, so an
    ///   uncorrelated read can hand back a reply from a *previous process run*.
    /// - **Concurrent.** Several requests may be in flight; whichever holds the
    ///   stream pumps for all of them.
    /// - **Pushes survive.** A frame matching no in-flight request is parked for
    ///   [`receive_next_tsp`](Self::receive_next_tsp), not discarded.
    /// - **Finite.** Every wait is bounded by `timeout` (R1.2).
    ///
    /// Errors are `String`-flattened internally on purpose: a `Box<dyn Error>`
    /// is not `Send`, and one held across an await would make this future — and
    /// every caller of it, up to `VtaClient::dispatch_trust_task` — `!Send`.
    pub async fn request_tsp(
        &self,
        recipient_did: &str,
        document: &[u8],
        timeout: Duration,
    ) -> Result<String, VtaError> {
        let (request_id, nonce) =
            crate::tsp_demux::TspDemux::request_keys(document).map_err(VtaError::TspTransport)?;
        let mut rx = self.tsp.demux.register(request_id.clone(), nonce).await;

        // Registered *before* sending: a reply can land while the send is still
        // returning, and a waiter registered afterwards would miss it.
        let sent = self.send_tsp_document(recipient_did, document).await;
        if sent.is_err() {
            self.tsp.demux.deregister(&request_id).await;
        }
        sent?;

        let deadline = tokio::time::Instant::now() + timeout;
        let outcome = self.await_tsp_reply(&request_id, &mut rx, deadline).await;
        // Always deregister — a timed-out or failed request must not leave a
        // waiter behind for the pump to deliver into.
        self.tsp.demux.deregister(&request_id).await;
        outcome.map_err(VtaError::TspTransport)
    }

    /// Wait up to `timeout_secs` for the next **unsolicited** inbound TSP
    /// document — a VTA-pushed `task-consent/request` and the like — returning
    /// the unpacked Trust-Task document as a JSON string.
    ///
    /// The TSP counterpart of [`receive_next`](Self::receive_next). Same three
    /// outcomes, and the same reason they are distinct: `Ok(Some(doc))` is an
    /// application message, `Ok(None)` is idle (poll again), and `Err(_)` means
    /// the connection is gone (reconnect — polling again cannot help).
    pub async fn receive_next_tsp(&self, timeout_secs: u64) -> Result<Option<String>, VtaError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            // A frame an in-flight `request_tsp` read but did not want is ours.
            // Drain that before touching the stream, or a push that already
            // arrived would sit unseen behind a fresh read.
            if let Some(doc) = self.tsp.demux.take_parked().await {
                return Ok(Some(doc));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            let mut guard = self.tsp.stream.lock().await;
            // Bounded so the lock is released periodically even while idle —
            // otherwise a long-polling receive would hold it for its whole
            // budget and stall every concurrent `request_tsp`.
            let slice = TSP_PUMP_SLICE.min(remaining);
            let outcome = self
                .tsp_pump_once(&mut guard, slice)
                .await
                .map_err(VtaError::TspTransport)?;
            match outcome {
                // Not addressed to any in-flight request → it is a push, and
                // pushes are what this method is for.
                TspPump::Uncorrelated(doc) => return Ok(Some(doc)),
                TspPump::Delivered | TspPump::Idle => {
                    drop(guard);
                    continue;
                }
            }
        }
    }

    /// Wait for `request_id`'s reply, taking a turn at pumping the stream
    /// whenever it is free.
    ///
    /// Leader/followers, exactly as in
    /// [`TspSession::await_reply`](crate::session::TspSession): whoever holds
    /// the stream reads and demultiplexes for everyone; the rest park on their
    /// oneshot. Contending for the lock in the same `select!` as the oneshot is
    /// what lets a follower take over the moment the leader finishes.
    async fn await_tsp_reply(
        &self,
        request_id: &str,
        rx: &mut tokio::sync::oneshot::Receiver<String>,
        deadline: tokio::time::Instant,
    ) -> Result<String, String> {
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "timed out waiting for the TSP reply to request '{request_id}'"
                ));
            }

            tokio::select! {
                biased;

                // Someone else's pump already delivered our reply.
                delivered = &mut *rx => {
                    return delivered.map_err(|_| {
                        "TSP session shut down while waiting for a reply".to_string()
                    });
                }

                // We are the leader for as long as we hold this.
                mut guard = self.tsp.stream.lock() => {
                    let slice = TSP_PUMP_SLICE.min(remaining);
                    // Bound before the `match`: a scrutinee temporary lives for
                    // the whole match body, which contains an `.await`.
                    let outcome = self.tsp_pump_once(&mut guard, slice).await?;
                    match outcome {
                        TspPump::Uncorrelated(doc) => {
                            // Not ours and not any other waiter's — park it for
                            // the push consumer instead of dropping it.
                            self.tsp.demux.park(doc).await;
                        }
                        TspPump::Delivered | TspPump::Idle => {}
                    }
                    // Release before looping so a follower can take a turn.
                    drop(guard);
                }

                () = tokio::time::sleep(remaining) => {
                    return Err(format!(
                        "timed out waiting for the TSP reply to request '{request_id}'"
                    ));
                }
            }
        }
    }

    /// Read at most one TSP frame off the leg's stream within `slice` and route
    /// it: to the waiter it correlates with, or back to the caller as
    /// [`TspPump::Uncorrelated`].
    ///
    /// DIDComm frames on this stream are **skipped, not consumed from anyone** —
    /// this is the leg's own broadcast receiver, so
    /// [`receive_next`](Self::receive_next) still has its own copy of every one
    /// of them.
    ///
    /// `String` errors for the same `Send` reason as
    /// [`request_tsp`](Self::request_tsp).
    async fn tsp_pump_once(
        &self,
        stream: &mut BoxStream<'static, Inbound>,
        slice: Duration,
    ) -> Result<TspPump, String> {
        let until = tokio::time::Instant::now() + slice;
        loop {
            let remaining = until.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(TspPump::Idle);
            }
            let inbound = match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(inbound)) => inbound,
                // Stream ended is an ERROR, not "nothing arrived" — asking again
                // can never produce anything. Same reasoning as `receive_next`:
                // conflating them makes a dead session look like a quiet one and
                // a polling loop spins forever instead of reconnecting.
                Ok(None) => {
                    return Err(if self.shutdown.load(Ordering::Acquire) {
                        "TSP leg closed: the session was shut down".to_string()
                    } else {
                        "mediator inbound stream ended — session is no longer live".to_string()
                    });
                }
                Err(_) => return Ok(TspPump::Idle),
            };

            if inbound.message.protocol != affinidi_messaging_core::Protocol::TSP {
                continue; // a DIDComm frame — `receive_next`'s business, not ours
            }
            let json = String::from_utf8(inbound.message.payload)
                .map_err(|e| format!("TSP payload was not UTF-8: {e}"))?;

            // One correlation rule for every TSP session — see `tsp_demux`.
            return Ok(match self.tsp.demux.route(json).await {
                crate::tsp_demux::Routed::Delivered => TspPump::Delivered,
                crate::tsp_demux::Routed::Uncorrelated(doc) => TspPump::Uncorrelated(doc),
            });
        }
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

/// Every TSP-leg future must be `Send`, for the same reason
/// `session::tsp_send_assertions` exists: `VtaClient::dispatch_trust_task`
/// awaits `request_tsp`, and `vta-mcp` puts that future behind `#[tool]`, which
/// demands `Send`. One `Box<dyn Error>` (not `Send`) held across an `.await`
/// inside the leg is enough to break the whole chain — and only once feature
/// unification turns `tsp` on for a workspace build, a long way from the edit
/// that caused it.
///
/// A compile-time check: if these stop being `Send`, this module fails to build.
#[cfg(all(test, feature = "tsp"))]
mod tsp_leg_send_assertions {
    use std::time::Duration;

    fn assert_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn tsp_leg_futures_are_send(s: &super::DIDCommSession) {
        assert_send(s.request_tsp("did:vta", b"{}", Duration::from_secs(1)));
        assert_send(s.receive_next_tsp(1));
        assert_send(s.send_tsp_document("did:vta", b"{}"));
        assert_send(s.receive_next(1));
        assert_send(s.shutdown());
    }
}
