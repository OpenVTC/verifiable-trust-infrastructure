//! A host service's mediator session, and its supervisor: how an identity a VTA
//! provisioned for a host service (a witness, a ballot box) is reached over TSP
//! and DIDComm.
//!
//! The service supplies a [`Responder`] — one inbound Trust Task document from
//! a transport-proven sender in, at most one signed reply out — and this module
//! owns everything else: the socket, the reconnect loop, the TSP relationship
//! answers, the binding envelopes and the acks.
//!
//! # One socket per DID, both protocols on it
//!
//! A mediator permits one websocket per DID and evicts a second as
//! `duplicate-channel`, so each identity holds exactly one: its own ATM, its
//! own profile, its own `DidCommTransport`, whose inbound stream surfaces
//! DIDComm and TSP frames off that one socket, tagged by protocol. TSP send is
//! routed through the same profile. Nothing here opens a second socket.
//!
//! One ATM per identity rather than one shared, for isolation: an identity's
//! ATM holds only that identity's secrets, so nothing can pack or seal as
//! another identity, and tearing one session down cannot touch another's.
//! A service holding several identities (the witness holds up to ten) runs one
//! [`supervise`] per identity.
//!
//! # The supervisor (CLAUDE.md *Mediator connection*)
//!
//! [`supervise`] owns an identity's whole connection lifecycle: gate → connect
//! → serve → reconnect.
//!
//! - **Gate.** The mediator authenticates the identity by resolving its DID,
//!   so a connect is not attempted until that DID resolves over the network —
//!   through the configured resolver, never an HTTP probe of the log URL.
//!   `did:key` is not gated. A success is trusted for
//!   [`SELF_RESOLUTION_FRESH_FOR`], the resolver cache's own document TTL.
//! - **Connect with retry**: capped exponential backoff with full jitter
//!   ([`CONNECT_RETRY_BASE`] … [`CONNECT_RETRY_CAP`]), self-resolution
//!   re-confirmed before every attempt.
//! - **Teardown.** Every error path after the ATM exists ends in
//!   `ATM::graceful_shutdown`: the ATM has no `Drop`, and an abandoned socket
//!   keeps reconnecting while holding the mediator's one slot for this DID.
//! - **[`MIN_HEALTHY_SESSION`].** A session must last that long before it
//!   resets the backoff, so a flapping mediator is not retried at full rate.
//! - **Shutdown** is checked at every await that can wait: the gate, the
//!   connect, the backoff sleep, the serve loop. Nothing here runs on `run`'s
//!   startup path, so the process reaches its signal wait at once.
//!
//! The VTA's supervisor (`vta-service` `server::MessagingConnect`) and the
//! VTC's connect loop do the same; their code is bound to their own config
//! and state types. This module is the host services' one copy.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_messaging_core::{
    Inbound, InboundKind, MessageTransport, Protocol, RelationshipRequest,
};
use affinidi_messaging_sdk::DidCommTransport;
use affinidi_secrets_resolver::SecretsResolver as _;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use futures_util::StreamExt as _;
use rand::RngExt as _;
use serde_json::Value;
use tokio::sync::{Semaphore, watch};
use tracing::{debug, info, warn};
use trust_tasks_didcomm::ENVELOPE_TYPE;

use crate::inbox::{Escalation, InboxWatch, ReconnectGovernor};
use crate::sender_order::{FrameOrder, SenderOrder};

/// What a host service does with one inbound Trust Task document.
///
/// Called only with a sender the transport proved; the document is the bytes
/// the binding envelope carried, exactly as received. The answer is the signed
/// reply to send back to that sender, or `None` to send nothing (a reply, an
/// error, bytes that are not a document). An implementation signs its own
/// replies: this module never does, and sends nothing unsigned.
#[async_trait::async_trait]
pub trait Responder: Send + Sync + 'static {
    /// The identity's operator-facing name, for logs.
    fn name(&self) -> &str;
    /// The identity's DID: the one its socket is held for and its replies are from.
    fn did(&self) -> &str;
    /// Answer `document` from `sender`.
    async fn answer(&self, sender: &str, document: &[u8]) -> Option<Value>;
}

/// First wait between failed connects.
pub const CONNECT_RETRY_BASE: Duration = Duration::from_secs(2);
/// Longest wait between failed connects.
pub const CONNECT_RETRY_CAP: Duration = Duration::from_secs(60);
/// A session must last this long to count as healthy and reset the backoff.
pub const MIN_HEALTHY_SESSION: Duration = Duration::from_secs(60);
/// How long a successful self-resolution is trusted.
pub const SELF_RESOLUTION_FRESH_FOR: Duration = Duration::from_secs(300);
/// Bound on enabling the websocket, which can hang against a `did:webvh` mediator.
const WEBSOCKET_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Inbound frames handled at once, per identity.
const MAX_INFLIGHT_INBOUND: usize = 16;

/// What every identity's session shares.
pub struct Shared {
    /// One DID-document cache for the process, used by every ATM (and, in the
    /// service, every proof check), so a rotation followed in one place is
    /// followed in all.
    pub did_resolver: DIDCacheClient,
    /// The resolver sidecar self-resolution goes through, when configured.
    pub resolver_url: Option<String>,
}

/// One identity, ready to connect: who answers for it, where it is reached,
/// and its keys.
pub struct IdentitySession {
    identity: Arc<dyn Responder>,
    mediator_did: String,
    secrets: Vec<Secret>,
}

/// Hand-written: `secrets` holds private keys.
impl std::fmt::Debug for IdentitySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentitySession")
            .field("identity", &self.identity.did())
            .field("mediator_did", &self.mediator_did)
            .field(
                "secrets",
                &format_args!("<{} redacted>", self.secrets.len()),
            )
            .finish()
    }
}

impl IdentitySession {
    /// An identity's session, before it connects.
    pub fn new(identity: Arc<dyn Responder>, mediator_did: String, secrets: Vec<Secret>) -> Self {
        Self {
            identity,
            mediator_did,
            secrets,
        }
    }
}

/// A connected session: the ATM, the registered profile, and the transport
/// bound to the profile's one socket.
struct Live {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    transport: Arc<DidCommTransport>,
}

/// Why a session ended.
enum SessionEnd {
    /// The process is stopping.
    Shutdown,
    /// The session was lost; the supervisor builds another.
    Lost(String),
}

/// Keep `session` connected and served until `shutdown` turns true.
pub async fn supervise(
    session: IdentitySession,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let name = session.identity.name().to_string();
    let did = session.identity.did().to_string();
    let mut probe = SelfResolution::new(&did, shared.resolver_url.as_deref());
    // Kept across sessions: a fresh session is not a reason to reconnect sooner.
    let governor = Arc::new(ReconnectGovernor::new(Escalation::EndSession));
    let mut attempt: u32 = 0;

    loop {
        if stopping(&shutdown) {
            return;
        }

        // Gate: the mediator resolves this DID to authenticate it.
        let Some(resolvable) = until_shutdown(&mut shutdown, probe.is_resolvable()).await else {
            return;
        };
        let failure = if !resolvable {
            "its own DID does not resolve over the network yet (the mediator authenticates it \
             by resolving it)"
                .to_string()
        } else {
            match until_shutdown(&mut shutdown, connect(&session, &shared)).await {
                None => return,
                Some(Err(e)) => e,
                Some(Ok(live)) => {
                    let live = Arc::new(live);
                    info!(
                        identity = %name,
                        did = %did,
                        mediator = %session.mediator_did,
                        "host identity connected to its mediator — serving Trust Tasks over TSP \
                         and DIDComm"
                    );
                    let started = tokio::time::Instant::now();
                    let end = serve(&live, &session, &governor, &mut shutdown).await;
                    // Always: the ATM has no `Drop`, and an abandoned socket
                    // keeps this DID's one slot at the mediator.
                    live.atm.graceful_shutdown().await;
                    match end {
                        SessionEnd::Shutdown => return,
                        SessionEnd::Lost(why) => {
                            if started.elapsed() >= MIN_HEALTHY_SESSION {
                                attempt = 0;
                            }
                            why
                        }
                    }
                }
            }
        };

        let wait = connect_backoff(attempt);
        warn!(
            identity = %name,
            attempt = attempt + 1,
            retry_in_secs = wait.as_secs_f64(),
            "host identity is not connected: {failure}; retrying"
        );
        if until_shutdown(&mut shutdown, tokio::time::sleep(wait))
            .await
            .is_none()
        {
            return;
        }
        attempt = attempt.saturating_add(1);
    }
}

fn stopping(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

/// Run `fut`, or return `None` as soon as shutdown is signalled (or its
/// sender is gone).
async fn until_shutdown<F: std::future::Future>(
    shutdown: &mut watch::Receiver<bool>,
    fut: F,
) -> Option<F::Output> {
    if stopping(shutdown) {
        return None;
    }
    tokio::pin!(fut);
    loop {
        tokio::select! {
            out = &mut fut => return Some(out),
            changed = shutdown.changed() => {
                if changed.is_err() || stopping(shutdown) {
                    return None;
                }
            }
        }
    }
}

/// Build an identity's ATM, register its profile, and bind the transport to
/// its one socket. Every failure after the ATM exists tears it down.
async fn connect(session: &IdentitySession, shared: &Shared) -> Result<Live, String> {
    let tdk_config = TDKConfig::builder()
        .with_did_resolver(shared.did_resolver.clone())
        .build()
        .map_err(|e| format!("build TDK config: {e}"))?;
    let tdk = TDKSharedState::new(tdk_config)
        .await
        .map_err(|e| format!("create TDK shared state: {e}"))?;
    for secret in &session.secrets {
        tdk.secrets_resolver().insert(secret.clone()).await;
    }

    // Frames this identity cannot unpack are deleted by the messaging SDK, the
    // one owner of that decision; left alone, one would be redelivered on
    // every reconnect forever.
    let atm_config = ATMConfig::builder()
        .with_delete_unprocessable(true)
        .build()
        .map_err(|e| format!("build ATM config: {e}"))?;
    let atm = Arc::new(
        ATM::new(atm_config, Arc::new(tdk))
            .await
            .map_err(|e| format!("create ATM: {e}"))?,
    );

    match bind(&atm, session).await {
        Ok((profile, transport)) => Ok(Live {
            atm,
            profile,
            transport: Arc::new(transport),
        }),
        Err(e) => {
            atm.graceful_shutdown().await;
            Err(e)
        }
    }
}

/// The fallible steps that leave a profile or a socket behind.
async fn bind(
    atm: &Arc<ATM>,
    session: &IdentitySession,
) -> Result<(Arc<ATMProfile>, DidCommTransport), String> {
    let profile = ATMProfile::new(
        atm,
        None,
        session.identity.did().to_string(),
        Some(session.mediator_did.clone()),
    )
    .await
    .map_err(|e| format!("create ATM profile: {e}"))?;
    // Registered with the ATM, so `graceful_shutdown` (which walks the
    // ATM's profiles) can stop its socket.
    let profile = atm
        .profile_add(&profile, false)
        .await
        .map_err(|e| format!("register ATM profile: {e}"))?;
    match tokio::time::timeout(
        WEBSOCKET_CONNECT_TIMEOUT,
        atm.profile_enable_websocket(&profile),
    )
    .await
    {
        Ok(res) => res.map_err(|e| format!("enable websocket: {e}"))?,
        Err(_) => {
            return Err(format!(
                "timed out enabling the websocket to {} after {}s",
                session.mediator_did,
                WEBSOCKET_CONNECT_TIMEOUT.as_secs()
            ));
        }
    }
    let transport = DidCommTransport::new((**atm).clone(), profile.clone())
        .await
        .map_err(|e| format!("bind the transport: {e}"))?;
    Ok((profile, transport))
}

/// Serve one connected session until it is lost or the process stops.
async fn serve(
    live: &Arc<Live>,
    session: &IdentitySession,
    governor: &Arc<ReconnectGovernor>,
    shutdown: &mut watch::Receiver<bool>,
) -> SessionEnd {
    let mut inbound = live.transport.inbound();
    // Collect what live delivery missed, and end the session when the
    // receive leg stops delivering and a reconnect has not helped (VTI-50).
    let mut watch_task = tokio::spawn(crate::inbox::run_inbox_watch(
        live.atm.clone(),
        live.profile.clone(),
        Some(live.transport.connection_state()),
        InboxWatch::new(),
        governor.clone(),
    ));
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_INBOUND));
    let sender_order = SenderOrder::new();

    let end = loop {
        tokio::select! {
            frame = inbound.next() => {
                let Some(frame) = frame else {
                    break SessionEnd::Lost("the inbound stream ended".to_string());
                };
                let Ok(permit) = inflight.clone().acquire_owned().await else {
                    break SessionEnd::Lost("the inbound limiter closed".to_string());
                };
                let ticket = sender_order.admit(frame.message.sender.as_deref(), frame_order(&frame));
                let live = live.clone();
                let identity = session.identity.clone();
                let mediator_did = session.mediator_did.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    ticket.ready().await;
                    let _ticket = ticket;
                    handle_frame(frame, &live, &*identity, &mediator_did).await;
                });
            }
            exit = &mut watch_task => {
                break SessionEnd::Lost(format!(
                    "the mediator inbox watch ended the session ({exit:?})"
                ));
            }
            changed = shutdown.changed() => {
                if changed.is_err() || stopping(shutdown) {
                    break SessionEnd::Shutdown;
                }
            }
        }
    };
    watch_task.abort();
    end
}

/// A TSP relationship-control frame is a barrier for that sender's later
/// frames; other TSP traffic follows it; DIDComm frames are unordered.
fn frame_order(frame: &Inbound) -> FrameOrder {
    match frame.message.protocol {
        Protocol::TSP if frame.is_relationship_control() => FrameOrder::Barrier,
        Protocol::TSP => FrameOrder::Follower,
        _ => FrameOrder::Unordered,
    }
}

/// Handle one inbound frame, then acknowledge it.
///
/// Every way out reaches the ack: an unacked frame is not dropped — the
/// mediator re-pushes it on every reconnect — and nothing here is a reason to
/// keep one. The ack comes after any reply is away, never before.
async fn handle_frame(frame: Inbound, live: &Live, identity: &dyn Responder, mediator_did: &str) {
    handle(&frame, live, identity, mediator_did).await;
    if let Err(e) = live.transport.ack(frame.ack.clone()).await {
        debug!(identity = %identity.name(), error = %e, "could not ack an inbound frame");
    }
}

async fn handle(frame: &Inbound, live: &Live, identity: &dyn Responder, mediator_did: &str) {
    // The transport proved the sender, or there is nobody to answer.
    let Some(sender) = frame
        .message
        .sender
        .clone()
        .filter(|_| frame.message.verified)
    else {
        debug!(identity = %identity.name(), "inbound frame has no verified sender — dropped");
        return;
    };

    if let InboundKind::RelationshipControl {
        request,
        thread_digest,
        reply_expected,
        ..
    } = &frame.kind
    {
        answer_relationship(
            live,
            identity,
            &sender,
            *request,
            *thread_digest,
            *reply_expected,
        )
        .await;
        return;
    }

    match frame.message.protocol {
        Protocol::TSP => {
            handle_tsp(frame, live, identity, mediator_did, &sender).await;
        }
        Protocol::DIDComm => handle_didcomm(frame, live, identity, &sender).await,
        other => debug!(
            identity = %identity.name(),
            protocol = ?other,
            "inbound frame in a protocol this service does not speak — dropped"
        ),
    }
}

/// Answer a TSP relationship request. No authorization here: a host service's
/// identity is public, and a relationship confers no authority — every
/// document still meets the responder's checks.
async fn answer_relationship(
    live: &Live,
    identity: &dyn Responder,
    sender: &str,
    request: RelationshipRequest,
    thread_digest: [u8; 32],
    reply_expected: bool,
) {
    match request {
        RelationshipRequest::Invite => {
            match live
                .atm
                .tsp()
                .accept_relationship(&live.profile, sender, thread_digest)
                .await
            {
                Ok(_) => info!(
                    identity = %identity.name(), %sender,
                    "accepted a TSP relationship request"
                ),
                Err(e) => warn!(
                    identity = %identity.name(), %sender, error = %e,
                    "could not send a TSP relationship accept; the relationship stays recorded"
                ),
            }
        }
        // The transport sends the §7.3 answer itself; `reply_expected` means
        // its send failed and the answer is still owed.
        RelationshipRequest::Cancel if reply_expected => {
            if let Err(e) = live
                .atm
                .tsp()
                .answer_cancellation(&live.profile, sender, thread_digest)
                .await
            {
                warn!(
                    identity = %identity.name(), %sender, error = %e,
                    "could not answer a TSP relationship cancellation"
                );
            }
        }
        _ => debug!(
            identity = %identity.name(), %sender, ?request,
            "recorded a TSP relationship message; no answer is due"
        ),
    }
}

/// A TSP frame: open the binding envelope, dispatch, and answer in the
/// carriage the request came in — a peer still sending the bare document
/// could not open an envelope.
async fn handle_tsp(
    frame: &Inbound,
    live: &Live,
    identity: &dyn Responder,
    mediator_did: &str,
    sender: &str,
) {
    let payload = &frame.message.payload;
    let wrapped = vta_sdk::tsp_binding::open_envelope(payload);
    let document = match &wrapped {
        Ok(document) => document.as_slice(),
        Err(_) => payload.as_slice(),
    };
    let Some(reply) = identity.answer(sender, document).await else {
        debug!(identity = %identity.name(), %sender, "TSP frame dropped unanswered");
        return;
    };
    let Ok(bytes) = serde_json::to_vec(&reply) else {
        return;
    };
    let bytes = if wrapped.is_ok() {
        vta_sdk::tsp_binding::wrap_envelope(&bytes)
    } else {
        bytes
    };
    // Routed to the sender's own mediator when it is not ours. `Ok` means the
    // mediator accepted it, not that the peer has it.
    if let Err(e) =
        crate::tsp_route::send_reply(&live.atm, &live.profile, mediator_did, sender, &bytes).await
    {
        warn!(identity = %identity.name(), %sender, error = %e, "could not send a TSP reply");
    }
}

/// A DIDComm frame: only a Trust-Task binding envelope is a request. A
/// problem report, a ping or a pickup status is not answered.
async fn handle_didcomm(frame: &Inbound, live: &Live, identity: &dyn Responder, sender: &str) {
    let Some((thread, document)) = didcomm_request(&frame.message.payload) else {
        debug!(identity = %identity.name(), %sender, "DIDComm message is not a Trust-Task envelope — not answered");
        return;
    };
    let Some(reply) = identity.answer(sender, &document).await else {
        debug!(identity = %identity.name(), %sender, "DIDComm request dropped unanswered");
        return;
    };
    let message = Message::build(
        uuid::Uuid::new_v4().to_string(),
        ENVELOPE_TYPE.to_string(),
        reply,
    )
    .from(identity.did().to_string())
    .to(sender.to_string())
    .thid(thread)
    .finalize();
    let packed = match live
        .atm
        .pack_encrypted(&message, sender, Some(identity.did()), Some(identity.did()))
        .await
    {
        Ok((packed, _)) => packed,
        Err(e) => {
            warn!(identity = %identity.name(), %sender, error = %e, "could not pack a DIDComm reply");
            return;
        }
    };
    // `Ok` is "handed to the mediator", not "delivered" (R1.1).
    match live.transport.send(sender, packed.into_bytes()).await {
        Ok(_) => {
            debug!(identity = %identity.name(), %sender, "DIDComm reply handed to the mediator")
        }
        Err(e) => {
            warn!(identity = %identity.name(), %sender, error = %e, "could not send a DIDComm reply")
        }
    }
}

/// The document a DIDComm binding envelope carries, and the thread to answer
/// on (the envelope's own `id`, which is what a DIDComm caller correlates on).
/// `None` for anything that is not a Trust-Task envelope.
pub fn didcomm_request(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    let message: serde_json::Value = serde_json::from_slice(payload).ok()?;
    if message.get("type")?.as_str()? != ENVELOPE_TYPE {
        return None;
    }
    let thread = message.get("id")?.as_str()?.to_string();
    let document = serde_json::to_vec(message.get("body")?).ok()?;
    Some((thread, document))
}

/// Full jitter over `min(cap, base · 2^attempt)`.
fn connect_backoff(attempt: u32) -> Duration {
    let ceiling = connect_backoff_ceiling(attempt);
    let max_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(rand::rng().random_range(0..=max_ms))
}

/// `min(cap, base · 2^attempt)`, saturating.
fn connect_backoff_ceiling(attempt: u32) -> Duration {
    let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
    CONNECT_RETRY_BASE
        .saturating_mul(factor)
        .min(CONNECT_RETRY_CAP)
}

/// "Does this identity's own DID resolve over the network right now?",
/// asked at most once per [`SELF_RESOLUTION_FRESH_FOR`] while it keeps
/// succeeding. Each real check resolves through a throwaway resolver, so no
/// cached copy can answer for the network.
struct SelfResolution {
    did: String,
    resolver_url: Option<String>,
    last_confirmed: Option<tokio::time::Instant>,
}

impl SelfResolution {
    fn new(did: &str, resolver_url: Option<&str>) -> Self {
        Self {
            did: did.to_string(),
            resolver_url: resolver_url.map(str::to_string),
            last_confirmed: None,
        }
    }

    async fn is_resolvable(&mut self) -> bool {
        if !needs_network_probe(&self.did) {
            return true;
        }
        let now = tokio::time::Instant::now();
        if self
            .last_confirmed
            .is_some_and(|at| now.saturating_duration_since(at) < SELF_RESOLUTION_FRESH_FOR)
        {
            return true;
        }
        let ok = resolves_now(&self.did, self.resolver_url.as_deref()).await;
        self.last_confirmed = ok.then_some(now);
        ok
    }
}

/// Only methods resolved over the network are gated: did:web, did:webvh, and a
/// did:scid:vh:1, whose log is a did:webvh log.
fn needs_network_probe(did: &str) -> bool {
    vta_sdk::did_scid::is_network_resolved(did)
}

async fn resolves_now(did: &str, resolver_url: Option<&str>) -> bool {
    let mut builder =
        DIDCacheConfigBuilder::default().with_host_policy(vta_sdk::resolver::webvh_host_policy());
    if let Some(url) = resolver_url {
        builder = builder.with_network_mode(url);
    }
    let resolver = match DIDCacheClient::new(builder.build()).await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "could not build a resolver for the self-resolution check");
            return false;
        }
    };
    let resolved = resolver.resolve(did).await;
    // Must stop before dropping: in network mode the client holds a
    // reconnecting websocket task that a drop would abandon.
    resolver.stop();
    match resolved {
        Ok(_) => true,
        Err(e) => {
            debug!(%did, error = %e, "own DID does not resolve yet");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_backoff_grows_to_its_cap_and_never_past_it() {
        assert_eq!(connect_backoff_ceiling(0), CONNECT_RETRY_BASE);
        assert_eq!(connect_backoff_ceiling(1), CONNECT_RETRY_BASE * 2);
        assert_eq!(connect_backoff_ceiling(5), CONNECT_RETRY_CAP);
        assert_eq!(connect_backoff_ceiling(u32::MAX), CONNECT_RETRY_CAP);
        for attempt in [0, 3, 40] {
            assert!(connect_backoff(attempt) <= connect_backoff_ceiling(attempt));
        }
    }

    #[test]
    fn only_network_resolved_methods_are_gated() {
        assert!(needs_network_probe("did:webvh:QmScid:example.com:w"));
        assert!(needs_network_probe("did:web:example.com"));
        assert!(!needs_network_probe("did:key:z6MkExample"));
        assert!(!needs_network_probe("did:peer:2zExample"));
    }

    #[test]
    fn a_didcomm_envelope_threads_on_its_own_id() {
        let document = json!({ "id": "urn:uuid:doc", "type": "https://trusttasks.org/spec/x/0.1" });
        let payload = serde_json::to_vec(&json!({
            "id": "urn:uuid:envelope",
            "type": ENVELOPE_TYPE,
            "body": document,
        }))
        .unwrap();
        let (thread, body) = didcomm_request(&payload).expect("an envelope");
        assert_eq!(thread, "urn:uuid:envelope");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            document
        );
    }

    #[test]
    fn a_didcomm_message_that_is_not_an_envelope_is_not_a_request() {
        for typ in [
            "https://didcomm.org/report-problem/2.0/problem-report",
            "https://didcomm.org/trust-ping/2.0/ping",
            "https://trusttasks.org/spec/trust-task-discovery/0.3",
        ] {
            let payload =
                serde_json::to_vec(&json!({ "id": "urn:uuid:x", "type": typ, "body": {} }))
                    .unwrap();
            assert!(didcomm_request(&payload).is_none(), "{typ}");
        }
        assert!(didcomm_request(b"not json").is_none());
    }

    #[tokio::test]
    async fn a_did_key_identity_is_never_gated() {
        let mut probe = SelfResolution::new("did:key:z6MkExample", None);
        assert!(probe.is_resolvable().await);
    }

    #[tokio::test]
    async fn shutdown_interrupts_a_wait() {
        let (tx, mut rx) = watch::channel(false);
        let waiting = tokio::spawn(async move {
            until_shutdown(&mut rx, tokio::time::sleep(Duration::from_secs(3600))).await
        });
        tx.send(true).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("shutdown must not wait out the sleep")
            .unwrap();
        assert!(out.is_none());
    }
}
