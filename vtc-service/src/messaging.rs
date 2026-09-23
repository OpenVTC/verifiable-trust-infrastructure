use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_core::{Inbound, InboundKind, MessageTransport, Protocol};
use affinidi_messaging_delivery::{Delivery, MessagingService, OutboxStore};
use affinidi_messaging_didcomm::Message;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use futures_util::StreamExt;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use serde_json::json;
use vti_common::outbox_store::VtiOutboxStore;

use vta_sdk::protocols::credential_exchange::PRESENT as CREDENTIAL_PRESENT_TYPE;
use vta_sdk::protocols::credential_exchange::REQUEST as CREDENTIAL_REQUEST_TYPE;
use vta_sdk::protocols::credential_exchange::{
    ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody, PresentBody, RequestBody,
};
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, JoinRequestSubmitReceiptBody,
};
use vta_sdk::protocols::{PROBLEM_REPORT_TYPE, problem_report_codes as codes};

use crate::config::AppConfig;
use crate::join::JoinTransport;
use crate::members::Disposition;
use crate::server::AppState;
use crate::store::KeyspaceHandle;
use crate::trust_tasks::{JoinAuthCtx, TrustTaskOutcome, dispatch_trust_task_core};

/// DIDComm message types handled locally by the dispatcher rather than routed
/// to a protocol handler. These used to come from the
/// `affinidi-messaging-didcomm-service` framework; with that framework removed
/// (the delivery-layer cut-over, D2 P1a) we re-declare the two we act on.
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PONG_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
/// The high-frequency message-pickup status heartbeat. Dispatched as a no-op
/// (was the framework's `ignore_handler`) and never logged.
const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// The VTC's live messaging handle, published into
/// [`AppState::didcomm`](crate::server::AppState) once the listener starts.
///
/// Holds the delivery-layer [`MessagingService`] (the one inbound/outbound
/// chokepoint over the VTC's single mediator websocket), the [`ATM`] used to
/// authcrypt-pack outbound replies, and the VTC's own DID (the pack sender).
/// Every outbound `AppState::send_to_member` reads this so it reuses the one
/// connection — the mediator permits only one websocket per DID.
pub struct VtcMessaging {
    pub service: Arc<MessagingService>,
    pub atm: Arc<ATM>,
    pub vtc_did: String,
    /// The ATM profile the mediator socket is bound to.
    ///
    /// Kept because a TSP reply is sealed and routed through the profile
    /// (`atm.tsp().send_routed(&profile, …)`), where a DIDComm reply goes through
    /// the delivery layer's `send`. Same socket either way — the mediator permits
    /// one per DID.
    pub profile: Arc<ATMProfile>,
    /// The mediator this socket is bound to.
    ///
    /// A TSP send is `send_routed(&profile, &[mediator, recipient], …)`, so an
    /// outbound TSP caller that is not answering an inbound frame (which
    /// carries the mediator with it) needs the first hop from somewhere. Kept
    /// here rather than re-read from config so the routed hop is always the
    /// mediator the socket is actually on.
    pub mediator_did: String,
}

/// The VTC's signing + key-agreement verification-method ids, read from its
/// **own DID document** rather than assumed.
///
/// The VTC mints itself a `did:webvh` whose keys land at `#key-0` (signing)
/// and `#key-1` (key agreement) — `status.rs` assigns exactly those ids. But
/// that numbering is a property of *that minting path*, not of DIDs in
/// general: a `did:peer`, for instance, numbers from `#key-1` (Ed25519) and
/// `#key-2` (X25519). Hardcoding `#key-0`/`#key-1` meant a VTC on any other
/// method failed the secret lookup in [`run_didcomm_service`] and silently
/// ran with **messaging disabled** — an easy trap, since the only symptom is
/// a single warn line and outbound `send_to_member` failing forever after.
///
/// Resolution order: the document's first `authentication` relationship (then
/// any bare `verificationMethod`) for signing, and its first `keyAgreement`
/// for key agreement. The historical `#key-0`/`#key-1` convention remains the
/// fallback when no resolver is configured or the DID can't be resolved, so
/// the production `did:webvh` path is unchanged either way — a `did:webvh`
/// document lists those exact ids, so resolution returns them anyway.
async fn vtc_key_ids(
    did_resolver: Option<&DIDCacheClient>,
    vtc_did: &str,
) -> (String, Option<String>) {
    let conventional = || (format!("{vtc_did}#key-0"), Some(format!("{vtc_did}#key-1")));

    let Some(resolver) = did_resolver else {
        return conventional();
    };
    let resolved = match resolver.resolve(vtc_did).await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                %vtc_did,
                error = %e,
                "could not resolve the VTC DID for its key ids — falling back to #key-0/#key-1",
            );
            return conventional();
        }
    };

    // A relationship id may be a bare fragment (`"#key-1"`) rather than an
    // absolute DID URL; the secrets resolver is keyed by the absolute id, so
    // re-attach the DID before looking it up.
    let absolutize = |id: &str| -> String {
        match id.strip_prefix('#') {
            Some(fragment) => format!("{vtc_did}#{fragment}"),
            None => id.to_string(),
        }
    };

    let doc = &resolved.doc;
    let signing = doc
        .authentication
        .first()
        .map(|vr| vr.get_id())
        .or_else(|| doc.verification_method.first().map(|vm| vm.id.as_str()))
        .map(&absolutize);
    let ka = doc.key_agreement.first().map(|vr| absolutize(vr.get_id()));

    match signing {
        Some(signing) => (signing, ka),
        // A document with no usable verification method at all — keep the old
        // behaviour so the failure surfaces as the existing "signing secret
        // not found" warn rather than some new path.
        None => conventional(),
    }
}

/// Build the delivery-layer [`MessagingService`] over a `DidCommTransport`
/// bound to the VTC's single mediator websocket.
///
/// Mirrors `vta-sdk::didcomm_session::connect_with_secrets`: a fresh TDK with
/// the VTC's secrets, an ATM, a profile against the mediator, then a
/// **bounded** `profile_enable_websocket` (the connect can hang) before the
/// transport is bound (`DidCommTransport::new` requires the websocket first).
/// The `outbox` keyspace backs `Guaranteed` sends durably (unused by P1a's
/// `BestEffort`-only sends, but `MessagingService::new` requires a store).
async fn build_messaging(
    secrets: Vec<Secret>,
    vtc_did: &str,
    mediator_did: &str,
    outbox_ks: KeyspaceHandle,
    tsp_relationships_ks: KeyspaceHandle,
) -> Result<(Arc<MessagingService>, Arc<ATM>, Arc<ATMProfile>), String> {
    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .build()
            .map_err(|e| format!("build TDK config: {e}"))?,
    )
    .await
    .map_err(|e| format!("create TDK shared state: {e}"))?;
    for secret in secrets {
        tdk.secrets_resolver().insert(secret).await;
    }

    // Persist TSP relationship state in the `tsp_relationships` keyspace so it
    // survives a restart. Without it a restarted VTC forgets every peer and — by
    // Rev 3 §7.2.2 — silently drops their traffic (and its own replies) until
    // each re-handshakes. Only the `tsp` build has a relationship store to
    // configure; the shared adapter lives in `vti_common::relationship_store`.
    let atm_config_builder = ATMConfig::builder();
    #[cfg(feature = "tsp")]
    let atm_config_builder = atm_config_builder.with_relationship_store(
        vti_common::relationship_store::build_relationship_store(tsp_relationships_ks.clone()),
    );
    #[cfg(not(feature = "tsp"))]
    let _ = &tsp_relationships_ks; // consumed only by the `tsp` build above

    let atm = ATM::new(
        atm_config_builder
            .build()
            .map_err(|e| format!("build ATM config: {e}"))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| format!("create ATM: {e}"))?;

    let profile = ATMProfile::new(
        &atm,
        None,
        vtc_did.to_string(),
        Some(mediator_did.to_string()),
    )
    .await
    .map_err(|e| format!("create ATM profile: {e}"))?;

    // Register with the ATM (`live_stream: false` — the websocket is enabled
    // explicitly, bounded, just below). Mirrors `vta-service`'s
    // `build_messaging`: the listener lives for the whole process, so this is
    // not about reclaiming anything today, but `ATM::graceful_shutdown` stops
    // websockets by iterating the profile map — an unregistered profile's
    // transport survives every shutdown path there is (vta-sdk #830).
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
    // P1a uses `new` (not `with_receipts`) — no layer-receipt emission yet.
    // Clone transport + outbox before `new` consumes them: the background
    // loops need their own handles.
    let service = Arc::new(MessagingService::new(transport.clone(), outbox.clone()));
    // Durable outbox: drain sends due entries + retries; outbox-drain confirms
    // Delivered on recipient pickup; confirmation sweep settles expired entries.
    tokio::spawn(affinidi_messaging_delivery::drain_loop(
        outbox.clone(),
        transport.clone(),
        std::time::Duration::from_secs(2),
    ));
    tokio::spawn(affinidi_messaging_delivery::outbox_drain_loop(
        transport.clone(),
        outbox.clone(),
        std::time::Duration::from_secs(10),
    ));
    tokio::spawn(affinidi_messaging_delivery::confirmation_loop(
        outbox.clone(),
        std::time::Duration::from_secs(30),
    ));
    Ok((service, atm, profile))
}

/// Start the VTC messaging listener and block until shutdown.
///
/// Owns the VTC's single mediator websocket via the delivery-layer
/// [`MessagingService`] and drives inbound dispatch off
/// [`MessagingService::subscribe`]. Replies are packed authcrypt (the VTC's
/// keys) and sent `BestEffort` back to the request's sender.
///
/// `state` carries the keyspaces + audit writer the handlers write into (the
/// same shared `AppState` the REST surface holds) and the `didcomm` slot every
/// outbound `AppState::send_to_member` reads once this publishes it.
pub async fn run_didcomm_service(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vtc_did: &str,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mediator_did = match &config.messaging {
        Some(m) => m.mediator_did.clone(),
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Does the document we publish match what this binary serves? Checked
    // against the DID as *resolved*, not against the local mirror: a service
    // entry can be published long after the VTC last wrote its own copy (the
    // reference deployment's `#tsp` arrived at log version 3), so the resolved
    // document is the only view that reflects what clients actually read.
    //
    // Reported here rather than left to the per-frame arm below because by the
    // time a frame arrives it is already too late to say anything useful — a
    // TSP frame in a non-`tsp` build never reaches this loop at all. It dies in
    // the messaging SDK's websocket transport, which classifies TSP only under
    // its own `tsp` feature and otherwise hands the CESR bytes to the DIDComm
    // unpacker, where they surface as `Cannot parse message as JSON` (CESR
    // starts with `-`, which serde_json reads as a number). That is the whole
    // reason this check exists at startup: it is the last layer that still
    // knows what the failure means.
    match crate::transport_capability::resolved_capabilities(state.did_resolver.as_ref(), vtc_did)
        .await
    {
        Some(caps) => {
            use crate::transport_capability::{MessagingVerdict, Severity};

            // Every observation, at its own severity, from the one function
            // `vtc status` also renders — so an operator who runs `vtc status`
            // to explain a boot message is told the same story, not a second
            // one.
            //
            // `code` rides along as a structured field so a log pipeline can
            // alert on the finding rather than on a substring of prose that
            // exists to be reworded.
            for finding in crate::transport_capability::findings_for_build(&caps) {
                let code = format!("{:?}", finding.code);
                match finding.severity {
                    Severity::Error => error!(finding = %code, "{}", finding.message),
                    Severity::Warn => warn!(finding = %code, "{}", finding.message),
                    Severity::Info => info!(finding = %code, "{}", finding.message),
                }
            }

            match crate::transport_capability::classify_for_messaging(&caps) {
                MessagingVerdict::Ok => {}
                MessagingVerdict::Degraded(_) => {
                    warn!(
                        "starting messaging anyway — at least one advertised transport is \
                         servable, but clients preferring the transports above will be silently \
                         dropped"
                    );
                }
                MessagingVerdict::Unreachable(_) => {
                    // Not starting is the honest outcome: every transport this VTC
                    // advertises is one it cannot answer on, so connecting to the
                    // mediator would buy nothing but a socket that drops frames.
                    error!(
                        "no advertised messaging transport is servable by this build — messaging \
                         disabled. The VTC will keep serving REST; fix the build or the DID \
                         document above to restore messaging."
                    );
                    let _ = shutdown_rx.changed().await;
                    return;
                }
            }
        }
        None => {
            // No resolver, or resolution failed. Unknown is not bad — don't
            // turn a resolver blip into a messaging outage.
            debug!(
                %vtc_did,
                "could not resolve the VTC DID to check advertised transports against this \
                 build — continuing"
            );
        }
    }

    // Collect secrets for the profile, keyed by the verification-method ids
    // the VTC's own DID document actually declares (see `vtc_key_ids`).
    let (signing_id, ka_id) = vtc_key_ids(state.did_resolver.as_ref(), vtc_did).await;
    let mut secrets = Vec::new();
    if let Some(s) = secrets_resolver.get_secret(&signing_id).await {
        secrets.push(s);
    } else {
        warn!(%signing_id, "VTC signing secret not found — messaging disabled");
        let _ = shutdown_rx.changed().await;
        return;
    }
    if let Some(ka_id) = ka_id.as_deref()
        && let Some(s) = secrets_resolver.get_secret(ka_id).await
    {
        secrets.push(s);
    }

    info!(
        vtc_did = %vtc_did,
        mediator = %mediator_did,
        "starting VTC messaging listener"
    );

    let (service, atm, profile) = match build_messaging(
        secrets,
        vtc_did,
        &mediator_did,
        state.outbox_ks.clone(),
        state.tsp_relationships_ks.clone(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("failed to start VTC messaging: {e}");
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    // Boot-enumerate the durable TSP relationships (D9) and sweep idle ones
    // (D6). Spawned once, here — not in `build_messaging` — so it does not
    // depend on the mediator socket and cannot leak a task per reconnect.
    #[cfg(feature = "tsp")]
    tokio::spawn(vti_common::relationship_store::maintenance_loop(
        vti_common::relationship_store::build_relationship_store(
            state.tsp_relationships_ks.clone(),
        ),
    ));

    // Publish the handle so any VTC component can send to a member over this
    // one connection (`AppState::send_to_member`). Set-once; it persists across
    // reconnects (the transport reconnects internally).
    let messaging = Arc::new(VtcMessaging {
        service: service.clone(),
        atm: atm.clone(),
        vtc_did: vtc_did.to_string(),
        profile: profile.clone(),
        mediator_did: mediator_did.clone(),
    });
    #[cfg(feature = "tsp")]
    let tsp_messaging = messaging.clone();
    if state.didcomm.set(messaging).is_err() {
        warn!("VTC messaging handle was already published — outbound sends use the existing one");
    }

    info!("VTC messaging connected to mediator — inbound messages will be processed");

    let vtc_did_owned = vtc_did.to_string();
    let mut stream = service.subscribe();

    loop {
        tokio::select! {
            maybe = stream.next() => {
                let Some(inbound) = maybe else {
                    warn!("VTC inbound stream ended — messaging dispatcher stopping");
                    break;
                };
                // The reply goes to whoever reached us: the authenticated sender
                // when present, else the plaintext `from` (the manifest public
                // read may arrive anoncrypt). Captured before `inbound` moves
                // into `dispatch`. NOTE: we do NOT ack — `MessagingService`'s
                // own dispatcher acks after handing the message to `subscribe`.
                // TSP frames arrive off the SAME mediator socket (the transport
                // tags which via `message.protocol`) and carry Trust-Task bytes
                // rather than a DIDComm plaintext, so they take their own path:
                // the DIDComm branch below would fail to parse the payload and
                // drop the frame silently, which is what happened before this.
                match inbound.message.protocol {
                    Protocol::DIDComm => {}
                    #[cfg(feature = "tsp")]
                    Protocol::TSP => {
                        handle_tsp(inbound, &tsp_messaging, &state, &mediator_did).await;
                        continue;
                    }
                    #[cfg(not(feature = "tsp"))]
                    Protocol::TSP => {
                        warn!(
                            "received an inbound TSP frame but the `tsp` feature is disabled — \
                             dropping"
                        );
                        continue;
                    }
                    // DIDComm v1 (Aries RFC 0019) shares no wire format,
                    // algorithms or identifier scheme with v2.1, so it must
                    // `continue` rather than fall through — the branch below
                    // would try to parse it as a v2.1 plaintext and drop it
                    // silently, which is the exact failure the note above
                    // describes for TSP.
                    Protocol::DIDCommV1 => {
                        warn!(
                            "received an inbound DIDComm v1 frame; this VTC speaks v2.1 only — \
                             dropping"
                        );
                        continue;
                    }
                    // `Protocol` is `#[non_exhaustive]` upstream. Drop rather
                    // than fall through, for the reason above, and never panic:
                    // this runs on every inbound frame, so an unknown protocol
                    // must not be a remotely triggerable crash.
                    other => {
                        warn!(
                            protocol = ?other,
                            "received an inbound frame in a protocol this VTC does not implement \
                             — dropping"
                        );
                        continue;
                    }
                }

                let reply_to = inbound.message.sender.clone().or_else(|| {
                    serde_json::from_slice::<Message>(&inbound.message.payload)
                        .ok()
                        .and_then(|m| m.from)
                });

                if let Some(reply) = dispatch(inbound, &state).await {
                    let Some(to) = reply_to else {
                        warn!(
                            reply_type = %reply.type_,
                            "computed a DIDComm reply but the inbound message had no sender/from \
                             to reply to — dropping"
                        );
                        continue;
                    };
                    let reply_id = uuid::Uuid::new_v4().to_string();
                    let reply_msg = Message::build(reply_id, reply.type_, reply.body)
                        .from(vtc_did_owned.clone())
                        .to(to.clone())
                        .thid(reply.thid)
                        .finalize();
                    match atm
                        .pack_encrypted(&reply_msg, &to, Some(&vtc_did_owned), Some(&vtc_did_owned))
                        .await
                    {
                        Ok((packed, _)) => {
                            if let Err(e) = service
                                .send(&to, packed.into_bytes(), Delivery::BestEffort)
                                .await
                            {
                                warn!(recipient = %to, error = %e, "failed to send DIDComm reply");
                            }
                        }
                        Err(e) => warn!(recipient = %to, error = %e, "failed to pack DIDComm reply"),
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("VTC messaging stopping (shutdown signalled)");
                break;
            }
        }
    }

    info!("VTC messaging stopped");
}

/// Answer one inbound TSP frame: dispatch its Trust Task on the shared spine and
/// seal the response back to the proven sender over the same socket.
///
/// Mirrors `vta-service`'s `messaging::tsp_inbound::dispatch_one` +
/// `service::handle_tsp`, deliberately: TSP, DIDComm and REST all feed
/// [`dispatch_trust_task_core`], so a caller gets byte-identical round-trip
/// semantics whichever transport it reached us on.
///
/// **One socket.** There is no TSP listener here. The delivery layer's
/// `DidCommTransport` owns the single mediator websocket and surfaces both
/// protocols off it — the mediator permits one per DID and evicts a second as
/// `duplicate-channel`, so opening one would flap the VTC.
///
/// **The sender is proven.** `inbound.message.sender` on a TSP frame is the VID
/// TSP's `unpack` cryptographically authenticated, exactly as DIDComm's authcrypt
/// sender is — so it is the caller identity `dispatch_trust_task_core` authorises
/// against, with no plaintext `from` to be spoofed. A frame without one is
/// dropped rather than treated as anonymous.
///
/// Receive-side only: answering over TSP is required (the caller is waiting on the
/// TSP correlation), but VTC-*initiated* sends to members stay DIDComm until the
/// Phase B flip (`docs/05-design-notes/tsp-enablement.md` §12, §14 Q4).
/// The proven caller for a TSP frame, or `None` if there is not one.
///
/// Factored out of [`handle_tsp`] so the authorization-relevant decision is
/// unit-testable without a live mediator socket — the same reason `vta-service`
/// factors out its `inbound_gate`.
///
/// A TSP frame's `sender` is the VID TSP's `unpack` authenticated, and `verified`
/// says whether that authentication actually happened. Requiring **both** is what
/// stops an unverified frame being dispatched as though its sender were proven;
/// `dispatch_trust_task_core` authorises on this value, so a wrong answer here is
/// an authorization bug, not a logging one.
///
/// Note there is no plaintext-`from` fallback, deliberately. The DIDComm path has
/// one for its two public-read handlers, which never authorize on it. TSP has no
/// such reader, so accepting an unproven identity here would only create a way in.
#[cfg(feature = "tsp")]
fn tsp_sender(message: &affinidi_messaging_core::ReceivedMessage) -> Option<String> {
    message.sender.clone().filter(|_| message.verified)
}

/// Is this inbound TSP payload a **reply** to a task we sent, rather than a
/// request addressed to us?
///
/// Accepts both wire shapes deliberately. The published `trust-tasks-tsp`
/// binding — which the trust registry, `vta-service` and (since the SDK's
/// `tsp_binding` cutover) every client in this workspace implement — wraps a
/// document in `{"type": ".../binding/tsp/0.1/envelope", "document": …}`. The
/// bare shape is what this workspace used to send, and a peer may still be on
/// it. Being liberal here costs nothing: the two shapes are unambiguous, and
/// the alternative is a peer's replies silently falling through to the request
/// dispatcher.
///
/// Returns `Some` only for a `#response` or `trust-task-error` carrying a
/// `threadId` — a request never qualifies, so no inbound work is diverted.
#[cfg(feature = "tsp")]
fn tsp_reply_document(payload: &[u8]) -> Option<trust_tasks_rs::TrustTask<serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let inner = match value.get("document") {
        Some(document) => document.clone(),
        None => value,
    };
    let doc: trust_tasks_rs::TrustTask<serde_json::Value> = serde_json::from_value(inner).ok()?;
    doc.thread_id.as_ref()?;
    let is_reply = doc.type_uri.is_response() || doc.type_uri.slug() == "trust-task-error";
    is_reply.then_some(doc)
}

#[cfg(feature = "tsp")]
async fn handle_tsp(
    inbound: Inbound,
    messaging: &Arc<VtcMessaging>,
    state: &AppState,
    mediator_did: &str,
) {
    let Some(sender_vid) = tsp_sender(&inbound.message) else {
        warn!("inbound TSP frame has no cryptographically-verified sender VID — dropping");
        return;
    };

    // A relationship request is not traffic: it carries no envelope, and the
    // transport has already RECORDED it (which is what admits the application
    // messages that follow, Rev 3 §7.2.2). What is left is the answer, and that
    // is this VTC's — it must not reach the Trust-Task spine, which would answer
    // a valid control message with "this is not a Trust Task".
    if let InboundKind::RelationshipControl {
        request,
        thread_digest,
        reply_expected,
        ..
    } = inbound.kind
    {
        handle_tsp_control(
            &messaging.atm,
            &messaging.profile,
            &sender_vid,
            request,
            thread_digest,
            reply_expected,
        )
        .await;
        return;
    }

    // A reply to a task *we* sent (a trust-registry record write, say) arrives
    // on this socket like any other frame. Complete its waiter instead of
    // dispatching it: the spine would answer a `#response` with an
    // unsupported-type error, and the caller — which is waiting on a
    // correlated reply, not on a send `Ok` — would time out and retry forever.
    //
    // The DIDComm arm gets this from its envelope branch in `dispatch`; TSP has
    // no message type to switch on, so the check is here. `tsp_reply_document`
    // reads through the binding envelope as well as around it, so this runs
    // before the envelope comes off.
    if let Some(doc) = tsp_reply_document(&inbound.message.payload) {
        let thread_id = doc.thread_id.clone().unwrap_or_default();
        if !state.pending_replies.complete(doc) {
            debug!(%thread_id, sender = %sender_vid, "TSP reply had no waiter — dropping");
        }
        return;
    }

    // Carriage off before dispatch: the spine parses a Trust-Task document and
    // an envelope is not one, so a wrapped frame reaching it is a
    // `malformedRequest` for a request that was perfectly well formed.
    //
    // Liberal, unlike `vta-service`, and for a reason that is about *this*
    // service: the VTC answers peers it does not ship with — the trust registry,
    // an operator's own client — and the two shapes are unambiguous, so refusing
    // the older one buys nothing. What the carriage decides here is the reply's
    // (see below), which is the part a peer cannot shrug off.
    let wrapped = vta_sdk::tsp_binding::open_envelope(&inbound.message.payload);
    let document = match &wrapped {
        Ok(document) => document.as_slice(),
        Err(_) => inbound.message.payload.as_slice(),
    };

    let ctx = JoinAuthCtx {
        transport: JoinTransport::Tsp,
        sender_did: Some(sender_vid.clone()),
        // A transport proves a *sender*; it never checks the document's
        // proof. The spine fills this in where the specification
        // requires one.
        verified_signer: None,
    };
    let outcome = dispatch_trust_task_core(state, &ctx, document).await;

    // The spine returns the self-describing framework document (its own `type` +
    // status code), so an unauthorised caller gets a Trust-Task error envelope
    // rather than silence — the VID is proven, so there is no enumeration
    // exposure, and a conformant client only understands envelopes.
    // No DIDComm envelope — TSP has a binding of its own — and the reply goes
    // back in **the carriage the request arrived in**. Always-wrap would be
    // wrong here precisely because the accept above is liberal: a peer still
    // sending bare would get an envelope it cannot open, and a reply that cannot
    // be read is indistinguishable from a request that was never answered. The
    // DIDComm path re-parses `body` only because it must lift `type` into a
    // DIDComm envelope.
    if outcome.body.is_empty() {
        return;
    }
    let reply = if wrapped.is_ok() {
        vta_sdk::tsp_binding::wrap_envelope(&outcome.body)
    } else {
        outcome.body
    };

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

/// What to do about one inbound TSP relationship request.
#[cfg(feature = "tsp")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ControlDecision {
    /// Send an accept. The transport has already recorded the relationship;
    /// this completes it.
    Accept,
    /// Send a cancellation, carrying why. Named for the wire action rather than
    /// the intent, because it serves **answering** a peer's cancellation of a
    /// mutual relationship (§7.3), not refusing anything.
    ///
    /// Since affinidi-messaging-sdk 0.27.1 the transport sends that answer
    /// itself, so this fires only when its send failed and the answer is still
    /// owed — and goes out through `answer_cancellation`, because the
    /// relationship is already forgotten (Keyring VTI-38).
    Cancel(&'static str),
    /// Record only — no reply is due.
    Nothing,
}

/// Decide how to answer an inbound TSP relationship request — a pure function,
/// tested without a socket, mirroring `vta-service`'s. It performs **no ACL
/// check**: the ACL gate lives at the Trust Task layer.
#[cfg(feature = "tsp")]
fn decide_control(
    request: affinidi_messaging_core::RelationshipRequest,
    reply_expected: bool,
) -> ControlDecision {
    use affinidi_messaging_core::RelationshipRequest;
    match request {
        // §7.2.5: an invite may introduce a VID, whose signature the transport
        // verified before this was reached. Not gated here — the introduced VID
        // gains a relationship and no authority, and its own tasks meet the same
        // ACL at the Trust Task layer.
        RelationshipRequest::Invite => ControlDecision::Accept,
        // The peer accepted an invite this VTC sent. The transport recorded the
        // state change; answering an accept would start a loop.
        RelationshipRequest::Accept => ControlDecision::Nothing,
        // §7.3: a cancellation for a relationship held in both directions is
        // answered with one of our own before forgetting it. The transport
        // (affinidi-messaging-sdk 0.27.1+) sends that answer itself;
        // `reply_expected` means "the answer is still owed" — true only when
        // the transport's own send failed. So this retries a failed answer and
        // never sends a second one. The transport's reading, not re-derived here.
        RelationshipRequest::Cancel => {
            if reply_expected {
                ControlDecision::Cancel("the peer cancelled a mutual relationship (§7.3)")
            } else {
                ControlDecision::Nothing
            }
        }
        // `RelationshipRequest` is `#[non_exhaustive]`: a request type this build
        // does not know is one upstream minor release away. Record and say
        // nothing rather than guess — the transport has already recorded whatever
        // state change the message implied.
        _ => ControlDecision::Nothing,
    }
}

/// Answer one inbound TSP relationship request (§7.2), or decline to.
///
/// Nothing here can fail the listener: a reply that cannot be sent is logged and
/// dropped, because the alternative is a VTC that stops receiving because one
/// peer became unreachable mid-answer. The relationship is already recorded, so
/// traffic still flows even when the answer does not land.
#[cfg(feature = "tsp")]
async fn handle_tsp_control(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    sender_vid: &str,
    request: affinidi_messaging_core::RelationshipRequest,
    thread_digest: [u8; 32],
    reply_expected: bool,
) {
    match decide_control(request, reply_expected) {
        ControlDecision::Accept => {
            match atm
                .tsp()
                .accept_relationship(profile, sender_vid, thread_digest)
                .await
            {
                Ok(state) => info!(
                    sender = %sender_vid, ?request, ?state,
                    "accepted an inbound TSP relationship request",
                ),
                Err(e) => warn!(
                    sender = %sender_vid, error = %e,
                    "could not send a TSP relationship accept; the relationship stays recorded, \
                     so traffic still flows, but the peer sees no answer",
                ),
            }
        }
        // Reached only when the transport's own §7.3 answer failed to send.
        // The relationship is already forgotten, so this must be
        // `answer_cancellation` (no state machine); `cancel_relationship`
        // refuses `SendCancel` out of `None`, which is how the peer went
        // unanswered before (Keyring VTI-38). For a cancellation,
        // `thread_digest` is the relationship digest the peer named.
        ControlDecision::Cancel(why) => {
            match atm
                .tsp()
                .answer_cancellation(profile, sender_vid, thread_digest)
                .await
            {
                Ok(_) => info!(
                    sender = %sender_vid, ?request, reason = %why,
                    "answered an inbound TSP relationship cancellation (§7.3) after the \
                     transport's own answer failed",
                ),
                Err(e) => warn!(
                    sender = %sender_vid, reason = %why, error = %e,
                    "could not send the §7.3 answer to a TSP relationship cancellation; \
                     the relationship is forgotten on this side, but the peer sees no answer",
                ),
            }
        }
        ControlDecision::Nothing => info!(
            sender = %sender_vid, ?request,
            "recorded an inbound TSP relationship request; no answer is due",
        ),
    }
}

#[cfg(all(test, feature = "tsp"))]
mod tsp_control_tests {
    use super::{ControlDecision, decide_control};
    use affinidi_messaging_core::RelationshipRequest;

    #[test]
    fn an_invite_is_accepted() {
        assert_eq!(
            decide_control(RelationshipRequest::Invite, false),
            ControlDecision::Accept
        );
        // `reply_expected` does not change the answer to an invite.
        assert_eq!(
            decide_control(RelationshipRequest::Invite, true),
            ControlDecision::Accept
        );
    }

    #[test]
    fn an_accept_is_recorded_only() {
        assert_eq!(
            decide_control(RelationshipRequest::Accept, true),
            ControlDecision::Nothing
        );
    }

    /// `reply_expected` means "the answer is still owed" (affinidi-messaging-sdk
    /// 0.27.1): the transport answers a mutual cancellation itself, so `false`
    /// also covers "already answered", and answering then would send twice.
    #[test]
    fn a_cancel_is_answered_only_when_the_answer_is_still_owed() {
        assert!(matches!(
            decide_control(RelationshipRequest::Cancel, true),
            ControlDecision::Cancel(_)
        ));
        assert_eq!(
            decide_control(RelationshipRequest::Cancel, false),
            ControlDecision::Nothing
        );
    }
}

/// A reply the dispatcher packs + sends back to the request's sender, threaded
/// to the request. Replaces the old framework's `DIDCommResponse`.
struct Reply {
    type_: String,
    body: serde_json::Value,
    thid: String,
}

/// Route one inbound message to its handler + emit the per-request log line.
///
/// Rehydrates the plaintext DIDComm [`Message`] from the neutral payload (the
/// full DIDComm plaintext — `typ`/`from`/`body`/`id` recoverable), computes the
/// **cryptographically-authenticated** sender, and dispatches on `msg.typ`.
///
/// The authenticated sender is `inbound.message.sender` filtered by `verified`:
/// SDK 0.18.56's `DidCommTransport` sets `sender` to the DID of the key that
/// actually authcrypted the envelope (or `None` for anonymous / spoofed
/// `from`), so the anti-spoof guarantee the old local `authenticated_sender_did`
/// enforced now lives in the transport. Handlers that need a proven caller use
/// this; the two public-read handlers (manifest, credential request/present)
/// use the plaintext `msg.from` and never authorize on it.
async fn dispatch(inbound: Inbound, state: &AppState) -> Option<Reply> {
    let msg: Message = serde_json::from_slice(&inbound.message.payload).ok()?;

    // Message-pickup status heartbeat: dispatch silently (was `ignore_handler`)
    // — no handler, no log line.
    if msg.typ == MESSAGE_PICKUP_STATUS_TYPE {
        return None;
    }

    // A Trust Task in the DIDComm **binding envelope** is one of two things,
    // and the type cannot tell them apart because both carry it: a *reply* to
    // something this service sent, or a *request* addressed to it.
    //
    // The waiter decides. `complete` returns `true` only when a registered
    // waiter took the document — i.e. it answers a request of ours — so a
    // capability write reply (git-trust/*, governance/capability/*) is
    // absorbed here and answered with nothing. Anything else falls through to
    // routing as an ordinary inbound request.
    //
    // Until now the fall-through did not exist: the arm returned `None`
    // unconditionally, so **every enveloped request over DIDComm was silently
    // dropped** — accepted by the transport, matched against no waiter, and
    // discarded without a reply. A conformant peer that speaks the binding
    // (which is what `trust-tasks-didcomm` produces) could not reach this
    // service over DIDComm at all.
    if msg.typ == vti_common::capability_client::TRUST_TASK_ENVELOPE_TYPE
        && let Some((_thid, doc)) =
            vti_common::capability_client::parse_envelope_document(&msg.body)
        && state.pending_replies.complete(doc)
    {
        return None;
    }

    let auth_sender = inbound
        .message
        .sender
        .clone()
        .filter(|_| inbound.message.verified);

    // Per-request observability (folds the old `log_request_middleware`): every
    // inbound message that is dispatched logs type / sender / outcome / latency
    // at `info!`, except the pickup-status heartbeat handled above.
    let start = std::time::Instant::now();
    let message_type = msg.typ.clone();
    let sender_log = auth_sender
        .clone()
        .or_else(|| msg.from.clone())
        .unwrap_or_else(|| "<anon>".to_string());

    let reply = route(&msg, auth_sender, state).await;

    info!(
        target: "didcomm_server::request",
        message_type = %message_type,
        sender = %sender_log,
        status = if reply.is_some() { "ok(response)" } else { "ok(empty)" },
        latency = ?start.elapsed(),
        "Request processed"
    );
    reply
}

/// The type-routed dispatch (was the framework `Router`). The `_` arm is the
/// old fallback: a problem-report is logged and never replied to (a reply would
/// loop); any other unsupported type gets a threaded BAD_REQUEST problem-report.
async fn route(msg: &Message, auth_sender: Option<String>, state: &AppState) -> Option<Reply> {
    match msg.typ.as_str() {
        TRUST_PING_TYPE => trust_ping_reply(msg, auth_sender.as_deref()),
        // The binding envelope: carriage, not a verb. The document inside names
        // the task, and the spine routes on that — so this one arm reaches
        // **every** dispatched URI. A verb is reachable because it is
        // dispatched, not because someone remembered to write it down twice.
        vti_common::capability_client::TRUST_TASK_ENVELOPE_TYPE => {
            envelope_task_handler(msg, auth_sender, state).await
        }
        // There are no task-typed arms. The binding (`bindings/didcomm/0.2`
        // §2–§5) makes the envelope the **only** DIDComm carriage for a Trust
        // Task and requires a consumer to refuse any other type at the DIDComm
        // layer — so a document whose DIDComm `type` is its own task URI falls
        // to `unhandled_message`, which says where it should have been carried
        // (Keyring VTI-42). Twelve such arms lived here; two of them
        // (`members/self-remove`, `members/vmc`) parsed bespoke bodies and
        // skipped the spine's freshness, recipient and proof checks entirely.
        CREDENTIAL_REQUEST_TYPE => credential_request_handler(msg, state).await,
        CREDENTIAL_PRESENT_TYPE => credential_present_handler(msg, state).await,
        _ => unhandled_message(msg),
    }
}

/// Local trust-ping responder (was the framework `trust_ping_handler`). Replies
/// a `trust-ping/2.0/ping-response` on the ping's thread unless the ping didn't
/// request a response or has no (authenticated) sender to reply to.
fn trust_ping_reply(msg: &Message, auth_sender: Option<&str>) -> Option<Reply> {
    #[derive(serde::Deserialize)]
    struct PingBody {
        #[serde(default = "default_true")]
        response_requested: bool,
    }
    fn default_true() -> bool {
        true
    }

    let body: PingBody = serde_json::from_value(msg.body.clone()).unwrap_or(PingBody {
        response_requested: true,
    });
    if !body.response_requested {
        return None;
    }
    // Only pong an authenticated ping (no reply to a spoofed/anonymous sender).
    auth_sender?;
    Some(Reply {
        type_: TRUST_PONG_TYPE.to_string(),
        body: serde_json::Value::Null,
        thid: msg.id.clone(),
    })
}

/// Build a threaded problem-report reply so a sender gets a typed code +
/// comment instead of a silent internal error (which often yields no reply).
fn problem_report(thid: String, code: &str, comment: impl Into<String>) -> Reply {
    Reply {
        type_: PROBLEM_REPORT_TYPE.to_string(),
        body: problem_report_body(code, comment),
        thid,
    }
}

/// The problem-report body shape — `{code, comment}`, matching
/// [`vta_sdk::protocols::extract_problem_report`] on the receiving side.
fn problem_report_body(code: &str, comment: impl Into<String>) -> serde_json::Value {
    json!({ "code": code, "comment": comment.into() })
}

/// Pull the human-facing detail out of an inbound DIDComm v2 problem-report
/// body — `code`, `comment` (which may carry `{1}`/`{2}` placeholders), and the
/// `args` that fill them — as display strings for logging the *cause* a peer
/// reported. Missing fields read as `<none>` so the log is explicit about what
/// the peer omitted rather than silently blank.
fn problem_report_details(body: &serde_json::Value) -> (String, String, String) {
    let field = |k: &str| {
        body.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string()
    };
    let args = match body.get("args").and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => "<none>".to_string(),
    };
    (field("code"), field("comment"), args)
}

/// Fallback for an inbound DIDComm message whose `type` matches no handler.
///
/// An unexpected/unsupported message type — e.g. a protocol-version drift
/// between the client and this VTC — is logged at `warn!` (visible at the
/// default level) with the type + sender, and (for a genuine unsupported
/// request) returns a threaded problem-report so the sender isn't left hanging.
///
/// **Never reply to a problem-report.** Replying to one with our own
/// (unsupported-type) problem-report makes the peer reply to *that*, and so on —
/// an unbounded problem-report ping-pong (observed against the mediator). A
/// problem-report is a terminal notification: log it and stop. Mirrors the VTA's
/// `handle_unknown` (`vta-service` `messaging::handlers`).
fn unhandled_message(message: &Message) -> Option<Reply> {
    if message.typ.contains("problem-report") {
        let (code, comment, args) = problem_report_details(&message.body);
        warn!(
            from = message.from.as_deref().unwrap_or("<anon>"),
            thid = message.thid.as_deref().unwrap_or("<none>"),
            code = %code,
            comment = %comment,
            args = %args,
            // The full body too: we don't always know which fields a peer's
            // problem-report carries, so log the raw JSON so the *cause* is never
            // lost to a field-name mismatch.
            body = %message.body,
            id = %message.id,
            "received unhandled problem-report — not replying (a reply would loop)"
        );
        return None;
    }
    // A Trust Task typed as itself rather than carried in the binding
    // envelope. The binding (`bindings/didcomm/0.2` §2, §4) says this is
    // refused at the DIDComm layer and never enters the framework pipeline —
    // so no `trust-task-error` — but "unsupported message type" alone reads as
    // "this service does not implement the task", which is false: it is served,
    // just not in this carriage (Keyring VTI-42). Name the carriage it needs.
    if let Some(comment) = trust_task_needs_envelope(&message.typ) {
        warn!(
            message_type = %message.typ,
            from = message.from.as_deref().unwrap_or("<anon>"),
            id = %message.id,
            "Trust Task arrived typed as its task URI, not in the DIDComm binding envelope — refused"
        );
        return Some(problem_report(
            message.id.clone(),
            codes::BAD_REQUEST,
            comment,
        ));
    }
    warn!(
        message_type = %message.typ,
        from = message.from.as_deref().unwrap_or("<anon>"),
        id = %message.id,
        "inbound DIDComm message has no matching handler — dropping (unsupported message type)"
    );
    Some(problem_report(
        message.id.clone(),
        codes::BAD_REQUEST,
        format!("unsupported message type: {}", message.typ),
    ))
}

/// The problem-report comment for a DIDComm message whose `type` is a Trust
/// Task URI, or `None` when it is not one.
///
/// Keyed on the published-spec prefix, not on the dispatcher's list: the
/// refusal is about the *carriage*, which is wrong for every Trust Task URI
/// whether or not this service serves it — enveloped, an unserved task gets
/// the spine's own `trust-task-error`, which is the better answer.
pub(crate) fn trust_task_needs_envelope(typ: &str) -> Option<String> {
    typ.starts_with(TRUST_TASK_SPEC_PREFIX).then(|| {
        format!(
            "unsupported message type: {typ} — Trust Tasks must be carried in the DIDComm \
             binding envelope `{}` with the task document as the body",
            vti_common::capability_client::TRUST_TASK_ENVELOPE_TYPE
        )
    })
}

/// Every published Trust Task type URI starts with this.
const TRUST_TASK_SPEC_PREFIX: &str = "https://trusttasks.org/spec/";

/// Render a [`TrustTaskOutcome`] as a DIDComm reply: the response document
/// (self-describing — carries its own `type`, either a `#response` or a
/// `trust-task-error`) threaded to the request id.
///
/// # The reply's DIDComm `type` is still the document's
///
/// Binding §5 (`responded`/`errored`) carries a reply in the envelope type
/// too, and the VTA already does. This does not, yet, and deliberately: the
/// OpenVTC client's inbound dispatch keys VTC replies on the DIDComm `type`
/// being the response document's own (`…/submit/0.1#response`, the vetting
/// responses — `vetting::wire::open` requires `document.type == message.typ`),
/// so switching here would silently drop its join verdicts. Changing this
/// wants that consumer to read the envelope first; tracked with Keyring
/// VTI-42.
fn tt_didcomm_reply(outcome: TrustTaskOutcome, thid: String) -> Option<Reply> {
    let doc: serde_json::Value = match serde_json::from_slice(&outcome.body) {
        Ok(d) => d,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("reply document parse: {e}"),
            ));
        }
    };
    // A reply document with no `type` at all is malformed; label it as the
    // framework error document it will be treated as. Through the shared helper
    // rather than a literal — this crate must name exactly one version of that
    // URI, and the census test enforces it (`trust_task_manifest`'s
    // `UNPUBLISHED_CANONICAL_OK` pins the family at one URI, so a second
    // spelling here fails the build even though nothing on the wire changed).
    let typ = doc
        .get("type")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| crate::trust_tasks::framework_error_type_uri().to_string());
    Some(Reply {
        type_: typ,
        body: doc,
        thid,
    })
}

/// Serialise an inbound DIDComm message body (the Trust Task document) to the
/// bytes the dispatcher parses.
fn inbound_doc_bytes(message: &Message) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&message.body).map_err(|e| format!("serialise inbound document: {e}"))
}

/// Pull the framework reject `code` + human-readable `message` out of a
/// serialised `trust-task-error` document, for logging. The *reason* a Trust
/// Task was refused lives in the error document's `payload` (not the HTTP
/// status), so surfacing it at the dispatch boundary is what makes a refusal
/// diagnosable. #539 made join refusals loud; #541 moved the reason into the
/// document body without teaching the log to read it back out — this restores
/// that visibility, now for every task the envelope carries. Returns `("<unparseable>", None)` if the bytes aren't a
/// recognisable error document.
fn error_doc_summary(body: &[u8]) -> (String, Option<String>) {
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(body) else {
        return ("<unparseable error document>".to_string(), None);
    };
    let code = doc
        .pointer("/payload/code")
        .and_then(|c| c.as_str())
        .unwrap_or("<unknown>")
        .to_string();
    let message = doc
        .pointer("/payload/message")
        .and_then(|m| m.as_str())
        .map(str::to_string);
    (code, message)
}

/// Any Trust Task carried in the DIDComm binding envelope.
///
/// The transport-neutral path: open carriage, name the proven sender, hand the
/// bytes to the spine, re-wrap the reply. It is the DIDComm twin of
/// [`handle_tsp`], and between them they are the whole of what a binding
/// adapter should be. It is also the **only** DIDComm path to the spine: the
/// per-verb, task-typed arms that predated it are retired (Keyring VTI-42).
///
/// # Only the *authenticated* sender
///
/// `auth_sender` is the authcrypt-proven DID; the plaintext `msg.from` is not
/// consulted. The retired manifest arm did consult it, for a public read — but
/// a *generic* arm cannot make that judgement per task, and defaulting to the
/// unproven value would hand every authenticated verb a spoofable caller. So
/// the context carries `None` when nothing was proven, and authorization fails
/// closed inside the handler that cares. A public read is unaffected: it never
/// looks.
async fn envelope_task_handler(
    msg: &Message,
    auth_sender: Option<String>,
    state: &AppState,
) -> Option<Reply> {
    let thid = msg.id.clone();
    let body = match inbound_doc_bytes(msg) {
        Ok(b) => b,
        Err(e) => return Some(problem_report(thid, codes::INTERNAL, e)),
    };
    let ctx = JoinAuthCtx {
        transport: JoinTransport::DIDComm,
        sender_did: auth_sender,
        // A transport proves a *sender*; it never checks the document's
        // proof. The spine fills this in where the specification
        // requires one.
        verified_signer: None,
    };
    let outcome = dispatch_trust_task_core(state, &ctx, &body).await;
    // A refusal answers with a `trust-task-error` and changes nothing, so
    // without this line it looks like the request "went nowhere" (#539). The
    // reason is in the error document's payload, not the status (#541).
    if !outcome.status.is_success() {
        let (code, reason) = error_doc_summary(&outcome.body);
        warn!(
            task = msg.body.get("type").and_then(|t| t.as_str()).unwrap_or("<none>"),
            thid = %thid,
            status = outcome.status.as_u16(),
            code = %code,
            reason = reason.as_deref().unwrap_or("<none>"),
            "enveloped Trust Task refused — trust-task-error returned"
        );
    }
    tt_didcomm_reply(outcome, thid)
}

/// `credential-exchange/request/1.0` over DIDComm (Phase 3, task 3.2 wire).
///
/// The holder redeems a pre-authorized offer: the body carries an OID4VCI
/// credential request with a key-binding proof. [`credentials::redeem`] looks
/// up the pending issuance by the proof `nonce` (the pre-authorized code),
/// verifies the proof binds the intended subject, and returns the credential —
/// which we wrap in a `credential-exchange/issue` reply (the same shape the VTA
/// holder-receive handler consumes). Single-use: the offer is consumed on
/// success only.
///
/// The DIDComm `from` (authcrypt sender) authenticates the *relayer*; the
/// **inner key-binding proof** authenticates the *holder*, and the credential
/// is released only to the proven subject — so a relayer ≠ holder is safe (it
/// can't satisfy the proof), mirroring the provision-integration onion.
async fn credential_request_handler(msg: &Message, state: &AppState) -> Option<Reply> {
    let thid = msg.id.clone();
    let body: RequestBody = match serde_json::from_value(msg.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("malformed credential request: {e}"),
            ));
        }
    };

    let response = match crate::credentials::redeem(
        &state.join_requests_ks,
        &body.credential_request,
        chrono::Utc::now(),
        &crate::credentials::vm_resolver::DidVmResolver::new(state.did_resolver.clone()),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("credential issuance: {e}"),
            ));
        }
    };

    let issue = IssueBody {
        credential_response: Some(response),
        sealed: None,
    };
    let issue_body = match serde_json::to_value(&issue) {
        Ok(v) => v,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("issue serialise: {e}"),
            ));
        }
    };
    Some(Reply {
        type_: CREDENTIAL_ISSUE_TYPE.to_string(),
        body: issue_body,
        thid,
    })
}

/// `credential-exchange/present/1.0` over DIDComm (close-the-join-loop, part 3).
///
/// The holder answers the VTC's DCQL query with an OID4VP `vp_token`. The present
/// replies on the query's thread (`thid`); the VTC consumes the **single-use
/// presentation challenge** keyed by that thread
/// ([`crate::credentials::present_challenge`]) to recover the expected nonce +
/// audience (freshness / replay), cryptographically verifies the `vp_token`, runs
/// the join decision, and — on `allow` — admits the proven holder and issues the
/// MembershipCredential. Replies with a join receipt (request id + status).
///
/// The DIDComm `from` (authcrypt sender) authenticates the *relayer*; the
/// **holder kb-jwt** inside the `vp_token` authenticates the *holder* and binds
/// the verifier's nonce + audience — so a relayer ≠ holder is safe (it cannot
/// forge the kb-jwt), mirroring the request-handler onion.
async fn credential_present_handler(msg: &Message, state: &AppState) -> Option<Reply> {
    // The reply threads to the present's own id (not the query thread).
    let thid = msg.id.clone();
    let body: PresentBody = match serde_json::from_value(msg.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("malformed present body: {e}"),
            ));
        }
    };

    // The present replies on the query's thread; the challenge is keyed by it.
    let thread_id = match msg.thid.clone() {
        Some(t) => t,
        None => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                "present carries no thread id (thid) to correlate its challenge",
            ));
        }
    };

    let now = chrono::Utc::now();
    let challenge = match crate::credentials::present_challenge::consume(
        &state.join_requests_ks,
        &thread_id,
        now,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("present challenge: {e}"),
            ));
        }
    };

    let outcome = match crate::routes::join_requests::present::present_and_decide_join(
        state,
        &body.vp_token,
        &challenge.aud,
        &challenge.nonce,
        // The same thread the challenge was keyed by: the exchange every
        // presented credential's `taskContext` is resolved against.
        &thread_id,
        JoinTransport::DIDComm,
        now,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("present decision: {e}"),
            ));
        }
    };

    // On auto-admit, deliver the issued MembershipCredential (+ role VEC) to the
    // proven holder's wallet over DIDComm — the holder only gets a receipt on the
    // reply thread, so without this the credential it just earned would never
    // reach it. Best-effort: the credential is already issued + persisted, so a
    // delivery failure is logged (the holder/admin can re-fetch), not fatal.
    if let Some(admit) = outcome.admit.as_deref() {
        let holder_did = outcome.request.applicant_did.clone();
        if let Err(e) =
            crate::credentials::delivery::deliver_membership_credentials(state, &holder_did, admit)
                .await
        {
            warn!(holder = %holder_did, request = %outcome.request.id, error = %e, "membership-credential delivery failed; credential is issued and can be re-delivered");
        } else {
            info!(holder = %holder_did, request = %outcome.request.id, "queued membership credentials for guaranteed delivery to holder");
        }
    }

    let status = serde_json::to_value(outcome.request.status)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let receipt = JoinRequestSubmitReceiptBody {
        request_id: outcome.request.id,
        status,
    };
    let receipt_body = match serde_json::to_value(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return Some(problem_report(
                thid,
                codes::INTERNAL,
                format!("receipt serialise: {e}"),
            ));
        }
    };
    Some(Reply {
        type_: JOIN_REQUEST_SUBMIT_RECEIPT_TYPE.to_string(),
        body: receipt_body,
        thid,
    })
}

pub(crate) fn parse_disposition(s: &str) -> Result<Disposition, String> {
    match s.to_ascii_lowercase().as_str() {
        "purge" => Ok(Disposition::Purge),
        "tombstone" => Ok(Disposition::Tombstone),
        "historical" => Ok(Disposition::Historical),
        "policydefault" => Ok(Disposition::PolicyDefault),
        other => Err(format!(
            "unknown disposition '{other}' (expected purge|tombstone|historical|policydefault)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A `#response` must be recognised as a reply in **both** TSP wire
    /// shapes: bare (what this workspace sends) and wrapped in the
    /// `trust-tasks-tsp` binding envelope (what the trust registry sends).
    /// Miss either and the reply falls through to the request dispatcher,
    /// which answers it with an unsupported-type error while the caller waits
    /// out its whole timeout.
    #[cfg(feature = "tsp")]
    #[test]
    fn a_tsp_reply_is_recognised_bare_and_enveloped() {
        let doc = json!({
            "id": "urn:uuid:reply",
            "type": "https://trusttasks.org/spec/registry/record/put/0.1#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "threadId": "urn:uuid:request",
            "payload": { "ok": true, "created": true },
        });
        let bare = serde_json::to_vec(&doc).unwrap();
        assert_eq!(
            tsp_reply_document(&bare).and_then(|d| d.thread_id),
            Some("urn:uuid:request".to_string()),
        );

        let enveloped = serde_json::to_vec(&json!({
            "type": "https://trusttasks.org/binding/tsp/0.1/envelope",
            "document": doc,
        }))
        .unwrap();
        assert_eq!(
            tsp_reply_document(&enveloped).and_then(|d| d.thread_id),
            Some("urn:uuid:request".to_string()),
        );
    }

    /// The demux must divert replies and nothing else. A request — no
    /// `threadId`, not a `#response` — has to reach the dispatcher, or every
    /// inbound TSP Trust Task is silently dropped.
    #[cfg(feature = "tsp")]
    #[test]
    fn an_inbound_request_is_not_mistaken_for_a_reply() {
        // A published request URI, deliberately: binding a `trusttasks.org/spec/`
        // literal asserts the registry serves that task, and the canonical-task
        // census checks every one of them — including the ones in tests.
        let request = serde_json::to_vec(&json!({
            "id": "urn:uuid:req",
            "type": "https://trusttasks.org/spec/registry/record/query/0.1",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": {},
        }))
        .unwrap();
        assert!(tsp_reply_document(&request).is_none());

        // A `#response` without a thread to correlate on is not actionable
        // either — completing a waiter needs the thread id.
        let unthreaded = serde_json::to_vec(&json!({
            "id": "urn:uuid:resp",
            "type": "https://trusttasks.org/spec/registry/record/put/0.1#response",
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "ok": true },
        }))
        .unwrap();
        assert!(tsp_reply_document(&unthreaded).is_none());
    }

    /// A `trust-task-error` is how the registry says "permission denied", and
    /// it is a reply like any other: the waiter must be completed so the caller
    /// classifies it, rather than left to time out as though nothing answered.
    #[cfg(feature = "tsp")]
    #[test]
    fn an_error_document_counts_as_a_reply() {
        // Version taken from the emitter, not named here — see `error_doc` in
        // `registry::messaging`. `tests/registry_didcomm.rs` covers acceptance
        // of an older error document on purpose.
        let error = serde_json::to_vec(&json!({
            "id": "urn:uuid:err",
            "type": crate::trust_tasks::helpers::framework_error_type_uri().to_string(),
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "threadId": "urn:uuid:request",
            "payload": { "code": "permissionDenied" },
        }))
        .unwrap();
        assert!(tsp_reply_document(&error).is_some());
    }

    #[test]
    fn problem_report_details_extracts_code_comment_and_args() {
        let (code, comment, args) = problem_report_details(&json!({
            "code": "e.p.xfer.cant-use-endpoint",
            "comment": "Unable to use the {1} endpoint for {2}.",
            "args": ["https://x.example/finance", "did:example:1234"],
        }));
        assert_eq!(code, "e.p.xfer.cant-use-endpoint");
        assert_eq!(comment, "Unable to use the {1} endpoint for {2}.");
        assert_eq!(args, "https://x.example/finance, did:example:1234");
    }

    #[test]
    fn problem_report_details_marks_missing_fields() {
        let (code, comment, args) = problem_report_details(&json!({}));
        assert_eq!(code, "<none>");
        assert_eq!(comment, "<none>");
        assert_eq!(args, "<none>");
    }

    #[test]
    fn problem_report_body_is_code_and_comment() {
        // The body shape must match `vta_sdk::protocols::extract_problem_report`.
        let body = problem_report_body(codes::BAD_REQUEST, "malformed body");
        let (code, comment) = vta_sdk::protocols::extract_problem_report(&body);
        assert_eq!(code, codes::BAD_REQUEST);
        assert_eq!(comment, "malformed body");
    }
}

/// The TSP receive-side authorization gate.
///
/// `dispatch_trust_task_core` authorises on whatever [`tsp_sender`] returns, so a
/// wrong answer here is an authorization bug. These pin both directions without a
/// mediator socket.
#[cfg(all(test, feature = "tsp"))]
mod tsp_sender_tests {
    use super::tsp_sender;
    use affinidi_messaging_core::{Protocol, ReceivedMessage};

    const SENDER: &str = "did:key:z6MkTspSenderUnderTest";

    fn frame(sender: Option<&str>, verified: bool) -> ReceivedMessage {
        ReceivedMessage {
            id: "urn:uuid:test".to_string(),
            sender: sender.map(str::to_string),
            recipient: "did:key:z6MkVtcUnderTest".to_string(),
            payload: b"{}".to_vec(),
            protocol: Protocol::TSP,
            verified,
            encrypted: true,
        }
    }

    #[test]
    fn a_verified_sender_is_the_proven_caller() {
        assert_eq!(
            tsp_sender(&frame(Some(SENDER), true)).as_deref(),
            Some(SENDER)
        );
    }

    /// The one that matters: a sender the TSP stack did **not** authenticate must
    /// not reach the spine as a proven caller. Accepting it would authorize a
    /// forged identity.
    #[test]
    fn an_unverified_sender_is_refused() {
        assert_eq!(tsp_sender(&frame(Some(SENDER), false)), None);
    }

    /// No sender at all — an anonymous frame. TSP has no public-read handler, so
    /// there is nothing this could legitimately be.
    #[test]
    fn an_anonymous_frame_is_refused() {
        assert_eq!(tsp_sender(&frame(None, true)), None);
        assert_eq!(tsp_sender(&frame(None, false)), None);
    }
}
