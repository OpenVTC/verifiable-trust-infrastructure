//! The **collector**: the connections the VTA holds for the principal's persona
//! DIDs (VTI-NTF-080 – 093). Who collects for which identifier is decided in
//! [`crate::operations::collection`]; this module only acts on it.
//!
//! # Shape
//!
//! One supervisor ([`run`]) reconciles the connections it holds with the plan
//! every [`RECONCILE_INTERVAL`] and whenever a claim, a release or the setting
//! asks it to. For each identifier the plan gives the VTA it opens **one**
//! session: its own TDK and ATM, holding only that identifier's keys, one
//! profile, one websocket at the mediator the identifier's document names, and
//! the delivery layer over it, which carries DIDComm and TSP on that one socket.
//!
//! - **One socket per DID.** [`CollectionControl::insert`] refuses a second
//!   session for an identifier; a session is opened only under the identifier's
//!   lock after re-reading its claim, and closed (`graceful_shutdown`, which
//!   stops the websocket) before a grant is answered. The VTA's own DID is
//!   never a candidate and is refused here again.
//! - **No connection for several contexts** (VTI-NTF-089): a session holds one
//!   identifier, so it serves one context. What the connections of different
//!   contexts reveal in common to the mediator is the network address of this
//!   node, and when they were opened — `docs/02-vta/collection.md`.
//! - **Inside the boundary** (VTI-NTF-089): the keys are loaded under internal
//!   authority in this process — inside the enclave, for a TEE VTA — and never
//!   leave it; what the host carries is what the mediator sees.
//! - **Eviction** (VTI-NTF-085): the transport backs off on a connection that
//!   dies young (`affinidi-messaging-sdk`'s escalating reconnect). The session
//!   counts such closures, and after [`CONFLICT_BOUND`] within
//!   [`CONFLICT_WINDOW`] it stops, records the conflict, and audits it.
//! - **Rotation, mediator change** (VTI-NTF-090): a session is rebuilt when the
//!   identifier's methods or mediator change; the claim is untouched. The VTA
//!   does not keep collecting at a mediator the document no longer names
//!   (a SHOULD it does not meet yet; see the docs).
//!
//! [`CollectionControl::insert`]: crate::operations::collection::CollectionControl::insert

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_core::{ConnState, Inbound, MessageTransport, Protocol};
use affinidi_messaging_delivery::{Delivery, InMemoryOutboxStore, MessagingService};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::{ATM, DidCommTransport};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use vta_sdk::notifications::identity;

use crate::operations::collection::{
    self as engine, Assignment, Candidate, CollectingSession, ConflictRecord,
};
use crate::server::AppState;
use crate::trust_tasks::collection::{CollectedIdentity, answer_collected};

/// How often the supervisor reconciles without being asked.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
/// A connection closed sooner than this after it opened counts towards a
/// conflict.
pub const STABLE_CONNECTION: Duration = Duration::from_secs(30);
/// The bound VTI-NTF-085 requires the VTA to state: after this many
/// short-lived connections within [`CONFLICT_WINDOW`], it stops.
pub const CONFLICT_BOUND: usize = 5;
/// The window [`CONFLICT_BOUND`] is counted over.
pub const CONFLICT_WINDOW: Duration = Duration::from_secs(15 * 60);
/// How long a session's websocket may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Collected documents handled at once, per identifier.
const MAX_INFLIGHT: usize = 8;
/// The longest the supervisor waits before retrying an identifier whose
/// session would not open.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(600);

/// DIDComm trust ping, which a recipient answers as its transport's
/// specification requires (VTI-NTF-087's last sentence).
const TRUST_PING: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PING_RESPONSE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

/// One identifier's session. See the module docs.
pub struct PersonaSession {
    atm: Arc<ATM>,
    cancel: CancellationToken,
    fingerprint: String,
}

impl CollectingSession for PersonaSession {
    fn close(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.cancel.cancel();
            // What actually stops the websocket: `graceful_shutdown` walks the
            // profile map and stops each transport. Dropping the ATM would
            // abandon the socket, which keeps reconnecting and holding the
            // mediator's one slot for the DID.
            self.atm.graceful_shutdown().await;
        })
    }

    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Run the collector until `shutdown`, then close every connection it holds.
pub async fn run(state: AppState, shutdown: CancellationToken) {
    if let Err(e) = engine::record_setting(&state).await {
        warn!(error = %e, "could not record the collection setting");
    }
    info!(
        enabled = state.collection.enabled(),
        "collector started (VTI-NTF-080 – 093)"
    );
    let mut retry: HashMap<String, (Instant, u32)> = HashMap::new();
    loop {
        if let Err(e) = reconcile(&state, &shutdown, &mut retry).await {
            warn!(error = %e, "collection pass failed; trying again on the next");
        }
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = state.collection.kicked() => {}
            _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
        }
    }
    state.collection.stop_all().await;
    info!("collector stopped; every collection connection is closed");
}

fn own_did(state_vta_did: Option<&str>, cand: &Candidate) -> bool {
    state_vta_did.is_some_and(|own| {
        let own = identity(own);
        own == identity(&cand.identifier) || own == identity(&cand.log_did)
    })
}

/// One pass: close what the plan no longer gives the VTA, open what it does.
async fn reconcile(
    state: &AppState,
    shutdown: &CancellationToken,
    retry: &mut HashMap<String, (Instant, u32)>,
) -> Result<(), vti_common::error::AppError> {
    let now = chrono::Utc::now();
    let plan = engine::current_plan(state, now).await?;
    let candidates: Vec<Candidate> = plan.iter().map(|(c, _)| c.clone()).collect();
    if let Err(e) = engine::sweep(state, &candidates, now).await {
        warn!(error = %e, "collection sweep failed");
    }
    let vta_did = state.config.read().await.vta_did.clone();
    let desired: HashMap<String, &Candidate> = plan
        .iter()
        .filter(|(c, a)| {
            matches!(a, Assignment::Vta { open_now: true }) && !own_did(vta_did.as_deref(), c)
        })
        .map(|(c, _)| (identity(&c.log_did), c))
        .collect();

    // Close what is no longer ours, or whose identifier changed under it.
    for held in state.collection.collecting() {
        let stale = match desired.get(&held) {
            None => true,
            Some(c) => {
                state.collection.session_fingerprint(&held).as_deref()
                    != Some(c.fingerprint().as_str())
            }
        };
        if stale {
            let _guard = state.collection.lock_identifier(&held).await;
            state.collection.stop(&held).await;
            debug!(identifier = %held, "collection connection closed");
        }
    }
    retry.retain(|k, _| desired.contains_key(k));

    for (key, cand) in desired {
        if shutdown.is_cancelled() {
            break;
        }
        if state.collection.is_collecting(&key) {
            continue;
        }
        if retry.get(&key).is_some_and(|(at, _)| Instant::now() < *at) {
            continue;
        }
        let _guard = state.collection.lock_identifier(&key).await;
        // Re-read under the lock: a grant that landed since the plan was made
        // must win (VTI-NTF-081).
        if !may_open(state, cand).await? {
            continue;
        }
        match open_session(state, cand).await {
            Ok(session) => {
                let session: Arc<dyn CollectingSession> = session;
                if state.collection.insert(&key, Arc::clone(&session)).is_err() {
                    // Unreachable under the lock; closed rather than kept.
                    session.close().await;
                    continue;
                }
                retry.remove(&key);
                info!(identifier = %cand.identifier, mediator = %cand.mediator_did,
                    "collecting for a persona");
            }
            Err(e) => {
                let failures = retry.get(&key).map_or(0, |(_, n)| *n) + 1;
                let delay = RECONCILE_INTERVAL
                    .saturating_mul(1 << failures.min(5))
                    .min(MAX_RETRY_DELAY);
                retry.insert(key, (Instant::now() + delay, failures));
                warn!(identifier = %cand.identifier, error = %e, retry_in = ?delay,
                    "could not open a collection connection");
            }
        }
    }
    Ok(())
}

/// Whether the VTA may open its connection for `cand` now, read under the
/// identifier's lock.
async fn may_open(state: &AppState, cand: &Candidate) -> Result<bool, vti_common::error::AppError> {
    if !state.collection.enabled() {
        return Ok(false);
    }
    let skew =
        chrono::Duration::seconds(state.config.read().await.collection.clock_skew_secs as i64);
    let now = chrono::Utc::now();
    if engine::get_claim(&state.collection_ks, &cand.context_id, &cand.log_did)
        .await?
        .is_some_and(|c| c.keeps_vta_off(now, skew))
    {
        return Ok(false);
    }
    Ok(
        engine::get_conflict(&state.collection_ks, &cand.context_id, &cand.log_did)
            .await?
            .is_none(),
    )
}

/// Open `cand`'s session. Every error after the ATM holds a profile tears it
/// down, so a failed attempt leaves no socket behind.
async fn open_session(state: &AppState, cand: &Candidate) -> Result<Arc<PersonaSession>, String> {
    let (secrets, signing_id) = engine::collection_secrets(state, cand)
        .await
        .map_err(|e| format!("load the identifier's keys: {e}"))?;
    if secrets.is_empty() {
        return Err("this VTA holds none of the identifier's keys".into());
    }
    let signing_fragment = signing_id
        .as_deref()
        .and_then(|id| id.split_once('#').map(|(_, f)| f.to_string()))
        .ok_or("the identifier publishes no signing key this VTA holds")?;
    let signing: Vec<_> = secrets
        .iter()
        .filter(|s| {
            s.id.split_once('#')
                .is_some_and(|(_, f)| f == signing_fragment)
        })
        .map(|s| s.secret.clone())
        .collect();

    let resolver = state
        .did_resolver
        .as_ref()
        .ok_or("no DID resolver is configured")?;
    let tdk_config = TDKConfig::builder()
        .with_load_environment(false)
        .with_did_resolver(resolver.clone())
        .build()
        .map_err(|e| format!("build TDK config: {e}"))?;
    let tdk = TDKSharedState::new(tdk_config)
        .await
        .map_err(|e| format!("create TDK state: {e}"))?;
    for s in secrets {
        tdk.secrets_resolver().insert(s.secret).await;
    }
    let atm_config = ATMConfig::builder().with_delete_unprocessable(true);
    #[cfg(feature = "tsp")]
    let atm_config = {
        let ks = state
            .store
            .keyspace(crate::keyspaces::RELATIONSHIPS)
            .map_err(|e| format!("open the relationships keyspace: {e}"))?;
        let ks = match state.storage_encryption_key {
            Some(key) => ks.with_encryption(key),
            None => ks,
        };
        atm_config.with_relationship_store(Arc::new(
            affinidi_messaging_sdk::PersistentRelationshipStore::new(
                crate::messaging::tsp_relationship_store::KeyspaceRelationshipKv::new(ks),
            ),
        ))
    };
    let atm = Arc::new(
        ATM::new(
            atm_config
                .build()
                .map_err(|e| format!("build ATM config: {e}"))?,
            Arc::new(tdk),
        )
        .await
        .map_err(|e| format!("create ATM: {e}"))?,
    );
    let profile = ATMProfile::new(
        &atm,
        None,
        cand.identifier.clone(),
        Some(cand.mediator_did.clone()),
    )
    .await
    .map_err(|e| format!("create profile: {e}"))?;
    let profile = match atm.profile_add(&profile, false).await {
        Ok(p) => p,
        Err(e) => {
            atm.graceful_shutdown().await;
            return Err(format!("register profile: {e}"));
        }
    };
    let transport = match connect(&atm, &profile).await {
        Ok(t) => t,
        Err(e) => {
            atm.graceful_shutdown().await;
            return Err(e);
        }
    };
    #[cfg(feature = "tsp")]
    let tsp = crate::messaging::tsp_transport::TspTransport::new((*atm).clone(), profile.clone());
    let service = Arc::new(MessagingService::new(
        transport.clone(),
        Arc::new(InMemoryOutboxStore::new()),
    ));

    let cancel = CancellationToken::new();
    let me = Arc::new(CollectedIdentity {
        context_id: cand.context_id.clone(),
        identifier: cand.identifier.clone(),
        log_did: cand.log_did.clone(),
        signing,
    });
    let ctx = Arc::new(SessionCtx {
        state: state.clone(),
        me,
        atm: Arc::clone(&atm),
        profile,
        service,
        #[cfg(feature = "tsp")]
        tsp,
    });
    tokio::spawn(inbound_loop(Arc::clone(&ctx), cancel.clone()));
    tokio::spawn(watch_for_conflict(
        state.clone(),
        cand.clone(),
        transport.connection_state(),
        cancel.clone(),
    ));
    Ok(Arc::new(PersonaSession {
        atm,
        cancel,
        fingerprint: cand.fingerprint(),
    }))
}

async fn connect(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
) -> Result<Arc<dyn MessageTransport>, String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, atm.profile_enable_websocket(profile)).await {
        Ok(res) => res.map_err(|e| format!("enable websocket: {e}"))?,
        Err(_) => return Err("timed out opening the mediator websocket".into()),
    }
    Ok(Arc::new(
        DidCommTransport::new((**atm).clone(), profile.clone())
            .await
            .map_err(|e| format!("bind transport: {e}"))?,
    ))
}

/// Everything a collected frame is handled with.
struct SessionCtx {
    state: AppState,
    me: Arc<CollectedIdentity>,
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    service: Arc<MessagingService>,
    #[cfg(feature = "tsp")]
    tsp: Option<crate::messaging::tsp_transport::TspTransport>,
}

async fn inbound_loop(ctx: Arc<SessionCtx>, cancel: CancellationToken) {
    let mut stream = ctx.service.subscribe();
    let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            next = stream.next() => {
                let Some(inbound) = next else { break };
                let Ok(permit) = Arc::clone(&inflight).acquire_owned().await else { break };
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    let _permit = permit;
                    handle(&ctx, inbound).await;
                });
            }
        }
    }
}

async fn handle(ctx: &SessionCtx, inbound: Inbound) {
    match inbound.message.protocol {
        Protocol::DIDComm => handle_didcomm(ctx, inbound).await,
        #[cfg(feature = "tsp")]
        Protocol::TSP => handle_tsp(ctx, inbound).await,
        other => debug!(protocol = ?other, identifier = %ctx.me.identifier,
            "a collected frame in a protocol this VTA does not take for a persona — dropped"),
    }
}

async fn handle_didcomm(ctx: &SessionCtx, inbound: Inbound) {
    use affinidi_messaging_didcomm::Message;
    let msg: Message = match serde_json::from_slice(&inbound.message.payload) {
        Ok(m) => m,
        Err(e) => {
            debug!(error = %e, "a collected DIDComm frame did not parse — dropped");
            return;
        }
    };
    // Only an encrypted frame from a proven sender is answered: an answer to
    // anyone else would go nowhere it could be checked.
    let sender = match inbound.message.sender.as_deref() {
        Some(s) if inbound.message.encrypted && inbound.message.verified => s.to_string(),
        _ => {
            debug!(identifier = %ctx.me.identifier, "a collected DIDComm frame without a proven sender — dropped");
            return;
        }
    };
    let (typ, body) = if msg.typ == trust_tasks_didcomm::ENVELOPE_TYPE {
        let doc = serde_json::to_vec(&msg.body).unwrap_or_default();
        let Some(reply) = answer_collected(&ctx.state, &ctx.me, &sender, &doc).await else {
            return;
        };
        let Ok(reply) = serde_json::from_slice::<serde_json::Value>(&reply) else {
            return;
        };
        (trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), reply)
    } else if msg.typ == TRUST_PING {
        if msg.body["response_requested"].as_bool() == Some(false) {
            return;
        }
        (TRUST_PING_RESPONSE.to_string(), serde_json::json!({}))
    } else {
        debug!(identifier = %ctx.me.identifier, typ = %msg.typ,
            "a collected DIDComm message that carries no operation — dropped");
        return;
    };
    let me = ctx.me.identifier.as_str();
    let reply = Message::build(format!("urn:uuid:{}", uuid::Uuid::new_v4()), typ, body)
        .from(me.to_string())
        .to(sender.clone())
        .thid(msg.id.clone())
        .finalize();
    match ctx
        .atm
        .pack_encrypted(&reply, &sender, Some(me), Some(me))
        .await
    {
        Ok((packed, _)) => {
            if let Err(e) = ctx
                .service
                .send(&sender, packed.into_bytes(), Delivery::BestEffort)
                .await
            {
                warn!(identifier = %me, recipient = %sender, error = %e,
                    "could not send an answer as a collected identifier");
            }
        }
        Err(e) => {
            warn!(identifier = %me, error = %e, "could not pack an answer as a collected identifier")
        }
    }
}

#[cfg(feature = "tsp")]
async fn handle_tsp(ctx: &SessionCtx, inbound: Inbound) {
    use crate::messaging::tsp_inbound::{ControlDecision, decide_control};
    let Some(sender) = inbound.message.sender.clone() else {
        return;
    };
    if let affinidi_messaging_core::InboundKind::RelationshipControl {
        request,
        thread_digest,
        reply_expected,
        ..
    } = &inbound.kind
    {
        // The transport's own exchange, answered as its specification
        // requires of a recipient — as the persona.
        let tsp = ctx.atm.tsp();
        let result = match decide_control(*request, *reply_expected) {
            ControlDecision::Accept => tsp
                .accept_relationship(&ctx.profile, &sender, *thread_digest)
                .await
                .map(|_| ()),
            ControlDecision::Cancel(_) => tsp
                .answer_cancellation(&ctx.profile, &sender, *thread_digest)
                .await
                .map(|_| ()),
            ControlDecision::Nothing => Ok(()),
        };
        if let Err(e) = result {
            debug!(identifier = %ctx.me.identifier, error = %e, "a TSP relationship answer was not sent");
        }
        return;
    }
    let document = match vta_sdk::tsp_binding::open_envelope(&inbound.message.payload) {
        Ok(d) => d,
        Err(reason) => {
            debug!(identifier = %ctx.me.identifier, %reason, "a collected TSP frame is not a binding envelope — dropped");
            return;
        }
    };
    let Some(reply) = answer_collected(&ctx.state, &ctx.me, &sender, &document).await else {
        return;
    };
    let Some(tsp) = ctx.tsp.as_ref() else {
        return;
    };
    if let Err(e) = tsp
        .send_reply(&sender, &vta_sdk::tsp_binding::wrap_envelope(&reply))
        .await
    {
        warn!(identifier = %ctx.me.identifier, recipient = %sender, error = %e,
            "could not send a TSP answer as a collected identifier");
    }
}

/// VTI-NTF-085: count the connections that another one closed, and stop at the
/// bound.
async fn watch_for_conflict(
    state: AppState,
    cand: Candidate,
    mut conn: tokio::sync::watch::Receiver<ConnState>,
    cancel: CancellationToken,
) {
    let mut closures = ClosureCounter::default();
    let mut connected_at: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            changed = conn.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        let now = Instant::now();
        match *conn.borrow() {
            ConnState::Connected => connected_at = Some(now),
            ConnState::Disconnected => {
                let Some(since) = connected_at.take() else {
                    continue;
                };
                if now.duration_since(since) >= STABLE_CONNECTION {
                    continue;
                }
                warn!(identifier = %cand.identifier,
                    "a collection connection closed soon after it opened — another connection \
                     for this identifier may be collecting");
                if closures.record(now) {
                    break;
                }
            }
            _ => {}
        }
    }
    // At the bound: stop, record, audit. Spawned apart from the session's own
    // tasks, because stopping the session cancels them.
    tokio::spawn(async move {
        let _guard = state.collection.lock_identifier(&cand.log_did).await;
        let record = ConflictRecord {
            context_id: cand.context_id.clone(),
            log_did: cand.log_did.clone(),
            since: chrono::Utc::now(),
            closures: CONFLICT_BOUND as u32,
        };
        if let Err(e) = engine::record_conflict(&state.collection_ks, &record).await {
            warn!(error = %e, "could not record a collection conflict");
        }
        state.collection.stop(&cand.log_did).await;
        vta_audit::record_with_detail_best_effort(
            &state.audit_sink,
            "collection.conflict",
            "system:collector",
            Some(&cand.identifier),
            "failure",
            Some("collection"),
            Some(&cand.context_id),
            Some(&format!(
                "another connection closed this VTA's {CONFLICT_BOUND} times within {} minutes; \
                 stopped collecting until a client claims the identifier (VTI-NTF-085)",
                CONFLICT_WINDOW.as_secs() / 60
            )),
        )
        .await;
        warn!(identifier = %cand.identifier,
            "stopped collecting for a persona: another connection keeps closing the VTA's — \
             listed as `conflict` until a client claims it");
    });
}

/// Short-lived connections within [`CONFLICT_WINDOW`].
#[derive(Default)]
struct ClosureCounter {
    at: VecDeque<Instant>,
}

impl ClosureCounter {
    /// Record one; `true` once the bound is reached.
    fn record(&mut self, now: Instant) -> bool {
        self.at.push_back(now);
        while self
            .at
            .front()
            .is_some_and(|t| now.duration_since(*t) > CONFLICT_WINDOW)
        {
            self.at.pop_front();
        }
        self.at.len() >= CONFLICT_BOUND
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VTI-NTF-085: the bound is reached only by enough closures inside the
    /// window; older ones age out.
    #[test]
    fn vti_ntf_085_the_conflict_bound_counts_within_its_window() {
        let mut c = ClosureCounter::default();
        let t0 = Instant::now();
        for i in 0..CONFLICT_BOUND - 1 {
            assert!(!c.record(t0 + Duration::from_secs(i as u64)));
        }
        assert!(c.record(t0 + Duration::from_secs(10)));

        let mut c = ClosureCounter::default();
        for i in 0..CONFLICT_BOUND {
            let at = t0 + CONFLICT_WINDOW.saturating_mul(i as u32 + 1);
            assert!(!c.record(at), "spread past the window, never a conflict");
        }
    }
}
