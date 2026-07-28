//! Delivery-layer construction + protocol-routed inbound loop (D2 P2a).
//!
//! Mirrors `vtc-service::messaging`: build an ATM + bounded-websocket
//! `ATMProfile` for the VTA's DID against the configured mediator, wrap it in a
//! [`DidCommTransport`], back an outbox with [`VtiOutboxStore`], and drive
//! [`MessagingService`]. Inbound is protocol-routed off
//! [`MessagingService::subscribe`]: DIDComm frames go to
//! [`super::router::dispatch`] (after the `#620` verified-sender-or-none rule
//! stamps `Message::from`); TSP frames go to
//! [`super::tsp_inbound::dispatch_one`] and their reply is sealed + routed back
//! over the same mediator socket.
//!
//! P2a uses [`MessagingService::new`] (consume-only receipts) — no receipt
//! *emit* yet (that lands with the first `Guaranteed` VTA pushes in P2b); the
//! consume half is always active, so the VTA still settles its own sends.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_messaging_core::{Inbound, MessageTransport, Protocol, ReceivedMessage};
use affinidi_messaging_delivery::{Delivery, MessagingService, OutboxStore};
use affinidi_messaging_didcomm::Message;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use vti_common::outbox_store::VtiOutboxStore;

use crate::messaging::router::{self, VtaState};
use crate::messaging::shim::{DIDCommResponse, ProblemReport, ServiceProblemReport};
use crate::server::AppState;
use crate::store::KeyspaceHandle;

/// The live delivery-layer wiring for the VTA's mediator socket, returned by
/// [`build_messaging`]. The `service` is published into the outbound bridge and
/// drives the inbound loop; `atm` + `profile` pack/seal replies (DIDComm via
/// `pack_encrypted`, TSP via `tsp().send_routed`).
pub struct VtaMessaging {
    pub service: Arc<MessagingService>,
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
}

/// Build the delivery-layer [`MessagingService`] over a [`DidCommTransport`]
/// bound to the VTA's single mediator websocket.
///
/// Mirrors `vtc-service::messaging::build_messaging`: a fresh TDK seeded with
/// the VTA's secrets (and the app's DID resolver, so the listener sees the same
/// seeded self-DID cache entry the REST path does), an ATM, a profile against
/// the mediator, then a **bounded** `profile_enable_websocket` (the connect can
/// hang) before the transport is bound. The `outbox` keyspace backs
/// `Guaranteed` sends durably (unused by P2a's `BestEffort`-only sends, but
/// `MessagingService::new` requires a store).
pub async fn build_messaging(
    secrets: Vec<Secret>,
    vta_did: &str,
    mediator_did: &str,
    outbox_ks: KeyspaceHandle,
    did_resolver: Option<&DIDCacheClient>,
    resolver_url: Option<&str>,
) -> Result<VtaMessaging, String> {
    // Reuse the app's initialized resolver when available so the listener sees
    // the same seeded self-DID cache entry; else fall back to resolver-url mode.
    let mut builder = TDKConfig::builder().with_load_environment(false);
    if let Some(dr) = did_resolver {
        builder = builder.with_did_resolver(dr.clone());
    } else if let Some(url) = resolver_url {
        let resolver_config = DIDCacheConfigBuilder::default()
            .with_network_mode(url)
            .build();
        builder = builder.with_did_resolver_config(resolver_config);
    }
    let tdk_config = builder
        .build()
        .map_err(|e| format!("build TDK config: {e}"))?;

    let tdk = TDKSharedState::new(tdk_config)
        .await
        .map_err(|e| format!("create TDK shared state: {e}"))?;
    for secret in secrets {
        tdk.secrets_resolver().insert(secret).await;
    }

    let atm = ATM::new(
        ATMConfig::builder()
            .build()
            .map_err(|e| format!("build ATM config: {e}"))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| format!("create ATM: {e}"))?;

    let profile = ATMProfile::new(
        &atm,
        None,
        vta_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await
    .map_err(|e| format!("create ATM profile: {e}"))?;

    // Register with the ATM (`live_stream: false` — the websocket is enabled
    // explicitly, bounded, just below). The VTA's listener lives for the whole
    // process, so this is not about reclaiming anything today; it is what makes
    // stopping the socket *possible at all*. `ATM::graceful_shutdown` stops
    // websockets by iterating the profile map, so an unregistered profile's
    // transport survives every shutdown path there is (vta-sdk #830). A listener
    // whose socket cannot be stopped short of `exit()` is a trap for the next
    // person who adds a shutdown path here.
    let profile = atm
        .profile_add(&profile, false)
        .await
        .map_err(|e| format!("register ATM profile: {e}"))?;

    // Bounded — a `did:webvh` mediator websocket connect can hang.
    match tokio::time::timeout(
        Duration::from_secs(30),
        atm.profile_enable_websocket(&profile),
    )
    .await
    {
        Ok(res) => res.map_err(|e| format!("enable websocket: {e}"))?,
        Err(_) => {
            return Err(
                "timeout enabling websocket to mediator after 30s — mediator may be unreachable"
                    .to_string(),
            );
        }
    }

    let atm = Arc::new(atm);
    let transport: Arc<dyn MessageTransport> = Arc::new(
        DidCommTransport::new((*atm).clone(), profile.clone())
            .await
            .map_err(|e| format!("bind DidComm transport: {e}"))?,
    );
    let outbox: Arc<dyn OutboxStore> = Arc::new(VtiOutboxStore::new(outbox_ks));
    // P2a uses `new` (not `with_receipts`) — no layer-receipt *emit* yet (P2b);
    // the consume half is always active, so the VTA settles its own sends.
    // Clone transport + outbox before `new` consumes them: the background loops
    // need their own handles.
    let service = Arc::new(MessagingService::new(transport.clone(), outbox.clone()));
    // Durable outbox: drain sends due entries + retries; outbox-drain confirms
    // Delivered on recipient pickup; confirmation sweep settles expired entries.
    // Dormant in P2a (no Guaranteed sends yet) but wired for P2b + restart
    // resilience.
    tokio::spawn(affinidi_messaging_delivery::drain_loop(
        outbox.clone(),
        service.primary_handle(),
        Duration::from_secs(2),
    ));
    tokio::spawn(affinidi_messaging_delivery::outbox_drain_loop(
        service.primary_handle(),
        outbox.clone(),
        Duration::from_secs(10),
    ));
    tokio::spawn(affinidi_messaging_delivery::confirmation_loop(
        outbox.clone(),
        Duration::from_secs(30),
    ));

    Ok(VtaMessaging {
        service,
        atm,
        profile,
    })
}

/// Drive inbound dispatch off [`MessagingService::subscribe`] until shutdown.
///
/// For each inbound: DIDComm → rehydrate the plaintext [`Message`], stamp the
/// **cryptographically-authenticated** sender onto `from` (`#620`), enforce the
/// framework `MessagePolicy` equivalent (encrypted AND authenticated
/// non-anonymous sender, for every type), dispatch, and pack + `send` any reply
/// authcrypt to the sender. TSP →
/// [`super::tsp_inbound::dispatch_one`], sealing + routing the reply back over
/// the same mediator socket.
pub async fn run_inbound_loop(
    messaging: Arc<VtaMessaging>,
    app_state: AppState,
    vta_did: String,
    mediator_did: String,
    shutdown: CancellationToken,
) {
    let vta_state = Arc::new(VtaState::from(&app_state));
    let mut stream = messaging.service.subscribe();
    info!("VTA messaging connected to mediator — inbound messages will be processed");

    // Handlers run concurrently, bounded by a semaphore.
    //
    // This loop used to `await` `handle_inbound` inline, so the VTA processed
    // exactly one inbound frame at a time — across BOTH protocols, since one
    // mediator websocket carries DIDComm and TSP together (one socket per DID).
    // A single slow handler therefore stalled every other caller's traffic, and
    // a hanging one wedged inbound messaging entirely.
    //
    // Spawning is safe because the dispatch spine is already concurrent: the
    // REST route runs `dispatch_trust_task_core` under axum with no such
    // serialisation, so handlers cannot have been relying on it.
    //
    // Bounded rather than unbounded: an unbounded spawn turns a burst (or a
    // hostile sender) into unbounded task and memory growth. At the cap, the
    // loop waits for a permit — degrading to the old serialised behaviour under
    // extreme load instead of falling over.
    const MAX_INFLIGHT_INBOUND: usize = 32;
    let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_INBOUND));

    loop {
        tokio::select! {
            maybe = stream.next() => {
                let Some(inbound) = maybe else {
                    warn!("VTA inbound stream ended — messaging dispatcher stopping");
                    break;
                };

                // Acquire before spawning so the cap actually bounds in-flight
                // work; the permit is released when the handler task ends.
                let permit = match Arc::clone(&inflight).acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("inbound concurrency semaphore closed — stopping");
                        break;
                    }
                };

                let messaging = Arc::clone(&messaging);
                let app_state = app_state.clone();
                let vta_state = Arc::clone(&vta_state);
                let vta_did = vta_did.clone();
                let mediator_did = mediator_did.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_inbound(
                        inbound,
                        &messaging,
                        &app_state,
                        &vta_state,
                        &vta_did,
                        &mediator_did,
                    )
                    .await;
                });
            }
            _ = shutdown.cancelled() => {
                info!("VTA messaging stopping (shutdown signalled)");
                break;
            }
        }
    }
    info!("VTA messaging stopped");
}

/// Route one inbound frame by protocol. `mediator_did` (and `messaging.profile`)
/// are used only by the `tsp`-gated arm.
async fn handle_inbound(
    inbound: Inbound,
    messaging: &Arc<VtaMessaging>,
    app_state: &AppState,
    vta_state: &Arc<VtaState>,
    vta_did: &str,
    mediator_did: &str,
) {
    match inbound.message.protocol {
        Protocol::DIDComm => {
            let _ = mediator_did;
            handle_didcomm(inbound, messaging, app_state, vta_state, vta_did).await;
        }
        #[cfg(feature = "tsp")]
        Protocol::TSP => {
            handle_tsp(inbound, messaging, app_state, mediator_did).await;
        }
        #[cfg(not(feature = "tsp"))]
        Protocol::TSP => {
            let _ = mediator_did;
            warn!("received an inbound TSP frame but the `tsp` feature is disabled — dropping");
        }
    }
}

/// Outcome of the framework `MessagePolicy` gate for one inbound DIDComm frame,
/// factored out of [`handle_didcomm`] so the policy is unit-testable without a
/// live mediator socket. See [`inbound_gate`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum InboundGate {
    /// The frame was not encrypted — reply `bad_request` ("must be encrypted").
    NotEncrypted,
    /// Encrypted, but the sender is anonymous or not cryptographically
    /// verified — reply `unauthorized`. This is the branch that stops a
    /// plaintext/forged sender from reaching a handler.
    Unauthenticated,
    /// Encrypted with a cryptographically-verified, non-anonymous sender —
    /// dispatch to the handler as this DID.
    Authenticated(String),
}

impl InboundGate {
    /// The dispatchable sender DID, or `None` for a rejected frame.
    fn authenticated_sender(&self) -> Option<&str> {
        match self {
            InboundGate::Authenticated(did) => Some(did.as_str()),
            _ => None,
        }
    }
}

/// Apply the framework `MessagePolicy` that gated EVERY route before dispatch:
/// `require_encrypted(true)` + `require_authenticated(true)` +
/// `allow_anonymous_sender(false)` (framework `middleware/policy.rs::check`).
///
/// Reads the transport-reported flags off the inbound [`ReceivedMessage`]:
/// `message.encrypted`, `message.sender`, and `message.verified` (whether the
/// transport *cryptographically authenticated* the sender). The only
/// dispatchable frame is an encrypted one whose sender is both present and
/// verified — so a plaintext frame (`encrypted == false`), an anonymous read
/// (`sender == None`), or an unverified/forged sender (`verified == false`)
/// is refused. Applied for ALL message types — not per-handler — so a handler
/// that doesn't itself call `auth_from_message` (discovery, TEE status/
/// attestation) still cannot be reached by an unauthenticated or anonymous
/// sender, exactly as the removed middleware layer guaranteed. There is NO
/// discovery exemption: the old policy layer required authcrypt for discovery
/// too, so requiring it here is behaviour-preserving.
fn inbound_gate(message: &ReceivedMessage) -> InboundGate {
    if !message.encrypted {
        return InboundGate::NotEncrypted;
    }
    match message.sender.as_deref() {
        // `Some` iff the sender is cryptographically authenticated;
        // absence collapses the framework's NotAuthenticated / AnonymousSender
        // / MissingSenderDid violations into one branch.
        Some(did) if message.verified => InboundGate::Authenticated(did.to_string()),
        _ => InboundGate::Unauthenticated,
    }
}

/// DIDComm inbound: rehydrate, stamp the verified sender, gate encryption,
/// dispatch, pack + send the reply.
async fn handle_didcomm(
    inbound: Inbound,
    messaging: &Arc<VtaMessaging>,
    app_state: &AppState,
    vta_state: &Arc<VtaState>,
    vta_did: &str,
) {
    let mut msg: Message = match serde_json::from_slice(&inbound.message.payload) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "failed to parse inbound DIDComm message — dropping");
            return;
        }
    };

    // #620: the ONLY trusted sender is the cryptographically-authenticated one
    // (`sender` filtered by `verified`, applied inside [`inbound_gate`]).
    // Capture the plaintext `from` first — solely as a best-effort *reply
    // address* for anoncrypt public reads (never for auth) — then overwrite
    // `from` so every handler's `auth_from_message` / `ctx.sender_did` sees
    // only the proven sender (or `None`, which those reject).
    let plaintext_from = msg.from.clone();
    let gate = inbound_gate(&inbound.message);
    let auth_sender = gate.authenticated_sender().map(str::to_string);
    msg.from = auth_sender.clone();

    // The reply target: the authenticated sender when present, else the
    // plaintext `from` (a public read may arrive anoncrypt).
    let reply_to = auth_sender.clone().or(plaintext_from);
    let msg_id = msg.id.clone();
    let message_type = msg.typ.clone();
    let start = std::time::Instant::now();

    // Faithful in-loop translation of the framework `MessagePolicy` — see
    // [`inbound_gate`] for the full rationale (enforced for ALL message types,
    // no discovery exemption).
    let reply = match &gate {
        InboundGate::NotEncrypted => Some(DIDCommResponse::problem_report(
            ProblemReport::bad_request("DIDComm message must be encrypted"),
        )),
        InboundGate::Unauthenticated => Some(DIDCommResponse::problem_report(
            ProblemReport::unauthorized(
                "DIDComm message must be authenticated (authcrypt) with a non-anonymous sender",
            ),
        )),
        InboundGate::Authenticated(_) => {
            let ctx = crate::messaging::shim::HandlerContext {
                sender_did: auth_sender.clone(),
            };
            router::dispatch(msg, ctx, vta_state.clone(), app_state.clone()).await
        }
    };

    info!(
        target: "didcomm_server::request",
        message_type = %message_type,
        sender = %auth_sender.as_deref().unwrap_or("<anon>"),
        status = if reply.is_some() { "ok(response)" } else { "ok(empty)" },
        latency = ?start.elapsed(),
        "Request processed"
    );

    let Some(reply) = reply else {
        return;
    };
    let Some(to) = reply_to else {
        warn!(
            reply_type = %reply.type_,
            "computed a DIDComm reply but the inbound message had no sender/from to reply to — dropping"
        );
        return;
    };

    let reply_id = uuid::Uuid::new_v4().to_string();
    let thid = reply.thid.unwrap_or(msg_id);
    let reply_msg = Message::build(reply_id, reply.type_, reply.body)
        .from(vta_did.to_string())
        .to(to.clone())
        .thid(thid)
        .finalize();
    match messaging
        .atm
        .pack_encrypted(&reply_msg, &to, Some(vta_did), Some(vta_did))
        .await
    {
        Ok((packed, _)) => {
            if let Err(e) = messaging
                .service
                .send(&to, packed.into_bytes(), Delivery::BestEffort)
                .await
            {
                warn!(recipient = %to, error = %e, "failed to send DIDComm reply");
            }
        }
        Err(e) => warn!(recipient = %to, error = %e, "failed to pack DIDComm reply"),
    }
}

/// TSP inbound: dispatch on the shared Trust-Task spine and seal + route the
/// reply back to the proven sender VID over the same mediator socket
/// (`send_routed([mediator_did, sender_vid])`), mirroring the framework's
/// `TspResponse` handling.
#[cfg(feature = "tsp")]
async fn handle_tsp(
    inbound: Inbound,
    messaging: &Arc<VtaMessaging>,
    app_state: &AppState,
    mediator_did: &str,
) {
    let Some(sender_vid) = inbound.message.sender.clone() else {
        warn!("inbound TSP frame has no authenticated sender VID — dropping");
        return;
    };
    let reply = crate::messaging::tsp_inbound::dispatch_one(
        app_state,
        &inbound.message.payload,
        &sender_vid,
    )
    .await;
    if reply.is_empty() {
        return;
    }
    let route = vec![mediator_did.to_string(), sender_vid.clone()];
    if let Err(e) = messaging
        .atm
        .tsp()
        .send_routed(&messaging.profile, &route, &reply)
        .await
    {
        warn!(recipient = %sender_vid, error = %e, "failed to send TSP reply");
    }
}

#[cfg(test)]
mod tests {
    use super::{InboundGate, inbound_gate};
    use affinidi_messaging_core::{Protocol, ReceivedMessage};

    const SENDER: &str = "did:key:z6MkSenderUnderTest";

    /// A minimal inbound [`ReceivedMessage`] carrying the three flags the gate
    /// reads; the rest are fixed filler (the gate ignores them).
    fn received(encrypted: bool, sender: Option<&str>, verified: bool) -> ReceivedMessage {
        ReceivedMessage {
            id: "urn:uuid:test".to_string(),
            sender: sender.map(str::to_string),
            recipient: "did:key:z6MkRecipient".to_string(),
            payload: Vec::new(),
            protocol: Protocol::DIDComm,
            verified,
            encrypted,
        }
    }

    /// The happy path: an encrypted frame from a verified, non-anonymous
    /// sender is dispatched as that DID.
    #[test]
    fn encrypted_and_verified_sender_is_authenticated() {
        assert_eq!(
            inbound_gate(&received(true, Some(SENDER), true)),
            InboundGate::Authenticated(SENDER.to_string()),
        );
    }

    /// Core case: an encrypted frame whose sender is present but
    /// NOT cryptographically verified (a forged / plaintext-authenticated
    /// `from`) must be refused — never dispatched as that DID.
    #[test]
    fn unverified_sender_is_rejected() {
        assert_eq!(
            inbound_gate(&received(true, Some(SENDER), false)),
            InboundGate::Unauthenticated,
        );
        // And it must NOT leak the forged DID as a dispatchable sender.
        assert_eq!(
            inbound_gate(&received(true, Some(SENDER), false)).authenticated_sender(),
            None,
        );
    }

    /// An anonymous read (anoncrypt: encrypted, no sender) is refused — no
    /// handler runs for an unauthenticated caller, matching the framework's
    /// `allow_anonymous_sender(false)`.
    #[test]
    fn anonymous_encrypted_sender_is_rejected() {
        assert_eq!(
            inbound_gate(&received(true, None, false)),
            InboundGate::Unauthenticated,
        );
        // Even a "verified" flag with no sender DID can't authenticate.
        assert_eq!(
            inbound_gate(&received(true, None, true)),
            InboundGate::Unauthenticated,
        );
    }

    /// A plaintext frame (the exact forged-sender exploit shape: forged `from`,
    /// no encryption) is refused at the encryption gate, before the sender is
    /// even considered.
    #[test]
    fn plaintext_frame_is_rejected() {
        assert_eq!(
            inbound_gate(&received(false, Some(SENDER), false)),
            InboundGate::NotEncrypted,
        );
        // Not-encrypted dominates: even a "verified" plaintext sender is
        // refused (an unreachable flag combo in practice, but the gate must
        // never dispatch an unencrypted frame).
        assert_eq!(
            inbound_gate(&received(false, Some(SENDER), true)),
            InboundGate::NotEncrypted,
        );
        assert_eq!(
            inbound_gate(&received(false, Some(SENDER), true)).authenticated_sender(),
            None,
        );
    }
}
