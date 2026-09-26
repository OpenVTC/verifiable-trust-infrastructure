//! Pushing a signed Trust Task to a peer, over whichever transport the peer
//! speaks — TSP, then DIDComm, then REST — durably, with escalation.
//!
//! # Why
//!
//! The DID document is authoritative for which protocols a party speaks, and
//! the protocol used is the highest-preference one present in both parties'
//! documents, TSP over DIDComm over REST
//! (`docs/05-design-notes/tsp-enablement.md`). This module is that rule for
//! pushes a node originates — a removal notice, a consent request, a granted
//! notice — shared by every node type so each does not re-derive it. The node
//! supplies what is its own through a [`PushContext`]: where push records
//! live, its outbox, its resolver, and its messaging handle.
//!
//! # How
//!
//! [`push_trust_task`] takes a **signed** Trust Task document and a delivery
//! deadline, and:
//!
//! 1. **Selects** ([`plan`]): resolves the recipient's DID document and matches
//!    on service `type` — `TSPTransport`, `DIDCommMessaging`, and for REST only
//!    `TrustTaskHTTPS`, the one type that claims to accept Trust Task
//!    documents (HTTPS binding 0.2 §6.2). A recipient advertising none of them
//!    (a `did:key` wallet) is reached over DIDComm through the node's own
//!    mediator. One that advertises only transports this node does not speak
//!    is refused, never silently downgraded.
//! 2. **Records** the push in [`PushContext::records`] — which the node
//!    encrypts at rest under its storage key — with the document, the plan,
//!    and the deadline.
//! 3. **Queues** the first attempt on the delivery layer's durable outbox. A
//!    DIDComm attempt is packed and queued as ciphertext, as before. A TSP or
//!    REST attempt is queued as the push's **id only**, pinned to the
//!    [`TspPushTransport`] or [`RestPushTransport`], which loads the document
//!    from the encrypted record when it sends. So nothing in the outbox is
//!    readable at rest, whichever transport it is for, and a TSP relationship
//!    the peer lost is re-established on the next try.
//!
//! # Evidence and escalation (VTI-TRN-030, -040, -041, -042)
//!
//! A queued attempt is not a delivery. [`sweep`] watches each push:
//!
//! - **Delivered** by the outbox — the message was collected from the mediator
//!   (class 3, both DIDComm and TSP when the recipient is on this node's
//!   mediator) — records the push delivered and names the evidence.
//! - **Sent over REST** — the recipient's own server answered 2xx, a protocol
//!   reply (class 2) — confirms it the same way.
//! - **Failed or unconfirmed** at the attempt's window — no evidence — re-resolves
//!   the recipient and queues the next transport it offers. With none left, the
//!   push is marked failed and logged for the operator.
//!
//! Each attempt but the last gets at most [`ATTEMPT_WINDOW`]; the last gets
//! what remains of the deadline. The recipient may receive a document more than
//! once across transports; it deduplicates by the document `id`, which every
//! attempt carries unchanged (VTI-TRN-043).

#[cfg(feature = "tsp")]
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_core::{
    ConnState, Inbound, InboundAck, MessageTransport, MessagingError, SendReceipt, TransportKind,
};
use affinidi_messaging_delivery::MessagingService;
use affinidi_messaging_delivery::{Delivery, OutboxState};
use affinidi_tdk::messaging::ATM;
use chrono::Utc;
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use vta_sdk::protocol::matching::{
    DIDCOMM_SERVICE_TYPE, Protocol, ServiceCapabilities, TRUST_TASK_HTTPS_SERVICE_TYPE,
};

use crate::capability_client::TRUST_TASK_ENVELOPE_TYPE;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// What a node lends the push engine: the stores and handles that are its own.
#[derive(Clone, Copy)]
pub struct PushContext<'a> {
    /// Where push records live. Encrypt it at rest: a record holds the
    /// document until the push finishes.
    pub records: &'a KeyspaceHandle,
    /// The delivery layer's outbox keyspace, read for evidence.
    pub outbox: &'a KeyspaceHandle,
    /// Resolves the recipient's DID document. `None` treats every recipient
    /// as advertising nothing, so it is reached over DIDComm.
    pub resolver: Option<&'a DIDCacheClient>,
    /// The node's messaging, when it is running. Without it only REST can be
    /// attempted, and no attempt can be queued at all.
    pub messaging: Option<PushMessaging<'a>>,
    /// Whether this build and configuration can send over TSP.
    pub tsp: bool,
}

/// The node's running messaging.
#[derive(Clone, Copy)]
pub struct PushMessaging<'a> {
    /// The delivery layer every attempt is queued on.
    pub service: &'a MessagingService,
    /// Packs DIDComm attempts.
    pub atm: &'a ATM,
    /// The node's own DID, the sender of every push.
    pub own_did: &'a str,
}

/// The longest any attempt but the last waits for evidence before the push
/// moves to the next transport. Long enough for a device that checks in
/// hourly; short enough that a transport the recipient stopped reading does
/// not hold a removal notice for its whole thirty-day window.
pub const ATTEMPT_WINDOW: Duration = Duration::from_secs(60 * 60);

/// How long an attempt may be missing from the outbox before the sweep
/// concludes it was never queued. The record is written before the entry, so a
/// sweep landing between the two sees no entry — which means "not queued yet",
/// never "delivered" or "failed".
const ENQUEUE_GRACE: Duration = Duration::from_secs(30);

/// How long a finished push's record is kept, as the record of which evidence
/// its delivery rests on (VTI-TRN-041), before the sweep removes it.
const FINISHED_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Transport ids the TSP and REST transports are registered under.
/// Kept at their original values so attempts queued before the move to
/// `vti-common` still drain after an upgrade.
pub const TSP_TRANSPORT_ID: &str = "member-push-tsp";
pub const REST_TRANSPORT_ID: &str = "member-push-rest";

const RECORD_PREFIX: &str = "push:";

/// A push in flight or recently finished.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PushRecord {
    id: String,
    recipient: String,
    /// The signed Trust Task document, unchanged across attempts.
    document: Value,
    /// Transports still to try after the current one, in preference order.
    remaining: Vec<Protocol>,
    /// The transport of the attempt in flight.
    current: Protocol,
    /// The outbox key of the attempt in flight.
    attempt_key: String,
    attempt: u32,
    /// The recipient's TSP mediator, when it advertises one.
    #[serde(default)]
    peer_tsp_mediator: Option<String>,
    /// The recipient's Trust-Task HTTPS base, when it advertises one.
    #[serde(default)]
    rest_base: Option<String>,
    /// Overall deadline, epoch milliseconds.
    deadline_ms: u64,
    /// When the attempt in flight was queued, epoch milliseconds.
    #[serde(default)]
    queued_at_ms: u64,
    #[serde(default)]
    outcome: Option<PushOutcome>,
}

/// How a push ended.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PushOutcome {
    delivered: bool,
    via: Protocol,
    /// The class of evidence a delivery rests on (VTI-TRN-041): `collected`
    /// (transport evidence the recipient collected it) or `reply` (the
    /// recipient's own server acknowledged it). `none` for a failure.
    evidence: String,
    at_ms: u64,
}

fn record_key(id: &str) -> String {
    format!("{RECORD_PREFIX}{id}")
}

fn now_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

/// What the recipient's DID document says it can be reached over.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Reach {
    tsp_mediator: Option<String>,
    didcomm: bool,
    rest_base: Option<String>,
}

impl Reach {
    fn advertises_anything(&self) -> bool {
        self.tsp_mediator.is_some() || self.didcomm || self.rest_base.is_some()
    }

    fn from_document(doc: &Value) -> Self {
        let caps = ServiceCapabilities::from_did_document(doc);
        Reach {
            tsp_mediator: caps.tsp,
            didcomm: caps.didcomm.is_some(),
            rest_base: trust_task_https_base(doc),
        }
    }
}

/// The `TrustTaskHTTPS` service endpoint, if advertised. REST reaches a peer
/// only through this type: it is the one that claims to accept Trust Task
/// documents, and an application REST API advertised under another type never
/// agreed to (HTTPS binding 0.2 §6.2).
fn trust_task_https_base(doc: &Value) -> Option<String> {
    doc.get("service")?.as_array()?.iter().find_map(|svc| {
        let typed = match svc.get("type")? {
            Value::String(t) => t == TRUST_TASK_HTTPS_SERVICE_TYPE,
            Value::Array(ts) => ts
                .iter()
                .any(|t| t.as_str() == Some(TRUST_TASK_HTTPS_SERVICE_TYPE)),
            _ => false,
        };
        if !typed {
            return None;
        }
        match svc.get("serviceEndpoint")? {
            Value::String(uri) if !uri.is_empty() => Some(uri.clone()),
            Value::Object(o) => o.get("uri").and_then(Value::as_str).map(str::to_string),
            _ => None,
        }
    })
}

/// What this node can send over right now.
struct Ours {
    tsp: bool,
    didcomm: bool,
    rest: bool,
}

fn ours(ctx: &PushContext<'_>) -> Ours {
    let messaging_up = ctx.messaging.is_some();
    Ours {
        tsp: messaging_up && ctx.tsp,
        didcomm: messaging_up,
        rest: true,
    }
}

/// The transports to try, in order, for `recipient`: the ones both sides
/// speak, TSP > DIDComm > REST.
///
/// A recipient that advertises no transport at all — a `did:key` wallet — is
/// reached over DIDComm through the node's own mediator. One that advertises
/// transports this node cannot use is refused: never a silent downgrade past
/// what the peer said it speaks.
async fn plan(ctx: &PushContext<'_>, recipient: &str) -> Result<(Vec<Protocol>, Reach), AppError> {
    let reach = resolve_reach(ctx, recipient).await;
    let ours = ours(ctx);
    let mut plan = Vec::new();
    for p in Protocol::PREFERENCE_ORDER {
        let both = match p {
            Protocol::Tsp => ours.tsp && reach.tsp_mediator.is_some(),
            Protocol::Didcomm => ours.didcomm && reach.didcomm,
            Protocol::Rest => ours.rest && reach.rest_base.is_some(),
        };
        if both {
            plan.push(p);
        }
    }
    if plan.is_empty() && !reach.advertises_anything() && ours.didcomm {
        plan.push(Protocol::Didcomm);
    }
    if plan.is_empty() {
        return Err(AppError::Validation(format!(
            "no matching protocol for {recipient}: it advertises {} and this node can \
             send over {}",
            describe_reach(&reach),
            describe_ours(&ours)
        )));
    }
    Ok((plan, reach))
}

fn describe_reach(r: &Reach) -> String {
    let mut v = Vec::new();
    if r.tsp_mediator.is_some() {
        v.push("tsp");
    }
    if r.didcomm {
        v.push(DIDCOMM_SERVICE_TYPE);
    }
    if r.rest_base.is_some() {
        v.push(TRUST_TASK_HTTPS_SERVICE_TYPE);
    }
    if v.is_empty() {
        "nothing".into()
    } else {
        v.join(", ")
    }
}

fn describe_ours(o: &Ours) -> String {
    let mut v = Vec::new();
    if o.tsp {
        v.push("tsp");
    }
    if o.didcomm {
        v.push("didcomm");
    }
    if o.rest {
        v.push("rest");
    }
    v.join(", ")
}

/// Resolve the recipient's advertised transports. An unresolvable DID reads as
/// advertising nothing — the same as a `did:key` — so a push to it still goes
/// the way pushes always went, over the shared mediator. Bounded (VTI-TRN-050).
async fn resolve_reach(ctx: &PushContext<'_>, recipient: &str) -> Reach {
    let Some(resolver) = ctx.resolver else {
        return Reach::default();
    };
    match tokio::time::timeout(Duration::from_secs(15), resolver.resolve(recipient)).await {
        Ok(Ok(resolved)) => serde_json::to_value(&resolved.doc)
            .map(|doc| Reach::from_document(&doc))
            .unwrap_or_default(),
        Ok(Err(e)) => {
            debug!(recipient, error = %e, "could not resolve the push recipient; using the shared mediator");
            Reach::default()
        }
        Err(_) => {
            debug!(
                recipient,
                "resolving the push recipient timed out; using the shared mediator"
            );
            Reach::default()
        }
    }
}

/// Push a **signed** Trust Task document to `recipient`, over the best
/// transport both sides speak, durably, with escalation to the next transport
/// when an attempt produces no evidence of delivery.
///
/// `Ok` means the first attempt is durably queued (VTI-TRN-030) — not that it
/// was delivered. The outcome is recorded by [`sweep`].
pub async fn push_trust_task(
    ctx: &PushContext<'_>,
    recipient: &str,
    document: Value,
    deliver_by: Duration,
) -> Result<String, AppError> {
    let (plan, reach) = plan(ctx, recipient).await?;
    let id = uuid::Uuid::new_v4().to_string();
    let mut remaining = plan;
    let current = remaining.remove(0);
    let mut record = PushRecord {
        id: id.clone(),
        recipient: recipient.to_string(),
        document,
        remaining,
        current,
        attempt_key: String::new(),
        attempt: 0,
        peer_tsp_mediator: reach.tsp_mediator,
        rest_base: reach.rest_base,
        deadline_ms: now_ms().saturating_add(deliver_by.as_millis() as u64),
        queued_at_ms: 0,
        outcome: None,
    };
    // An attempt that cannot even be queued moves straight on; only when no
    // transport will take it is the push refused.
    loop {
        match queue_attempt(ctx, &mut record).await {
            Ok(()) => break,
            Err(e) if !record.remaining.is_empty() => {
                warn!(
                    recipient,
                    via = %record.current,
                    error = %e,
                    "could not queue a push on its preferred transport; trying the next"
                );
                record.current = record.remaining.remove(0);
                record.attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
    info!(recipient, via = %record.current, push = %id, "trust-task push queued");
    Ok(id)
}

/// How a push ended, once it has: `(delivered, via, evidence)`, where
/// `evidence` is the class the delivery rests on (VTI-TRN-041). `None` while
/// it is still in flight, or once its record has been swept.
pub async fn outcome(
    records: &KeyspaceHandle,
    id: &str,
) -> Result<Option<(bool, Protocol, String)>, AppError> {
    Ok(load_record(records, id)
        .await?
        .and_then(|r| r.outcome)
        .map(|o| (o.delivered, o.via, o.evidence)))
}

/// Queue the attempt `record.current`, and store the record.
async fn queue_attempt(ctx: &PushContext<'_>, record: &mut PushRecord) -> Result<(), AppError> {
    let messaging = ctx.messaging;
    let now = now_ms();
    let remaining_ms = record.deadline_ms.saturating_sub(now).max(1_000);
    // The last attempt gets whatever is left. Every other one gets its share
    // of it, capped at `ATTEMPT_WINDOW`, so a short deadline still leaves room
    // to escalate: a 15-minute consent request tries each of three transports
    // for five minutes, where taking the whole deadline first would never
    // reach the second.
    let window_ms = if record.remaining.is_empty() {
        remaining_ms
    } else {
        let share = remaining_ms / (record.remaining.len() as u64 + 1);
        share.min(ATTEMPT_WINDOW.as_millis() as u64).max(1_000)
    };
    let window = Duration::from_millis(window_ms);
    record.attempt_key = format!("{}:{}:{}", record.id, record.attempt, record.current);
    record.queued_at_ms = now;
    // The record is written before the attempt is queued, so a transport that
    // drains the entry at once finds what it has to send.
    store_record(ctx, record).await?;

    let delivery = Delivery::Guaranteed {
        idempotency_key: Some(record.attempt_key.clone()),
        ordering_key: None,
        deliver_by: window,
    };
    let messaging = messaging
        .ok_or_else(|| AppError::Internal("messaging not running — cannot push".into()))?;
    match record.current {
        Protocol::Didcomm => {
            let envelope = affinidi_tdk::didcomm::Message::build(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                TRUST_TASK_ENVELOPE_TYPE.to_string(),
                record.document.clone(),
            )
            .from(messaging.own_did.to_string())
            .to(record.recipient.clone())
            .finalize();
            let (packed, _) = messaging
                .atm
                .pack_encrypted(
                    &envelope,
                    &record.recipient,
                    Some(messaging.own_did),
                    Some(messaging.own_did),
                )
                .await
                .map_err(|e| {
                    AppError::Internal(format!("DIDComm pack for {} failed: {e}", record.recipient))
                })?;
            messaging
                .service
                .send(&record.recipient, packed.into_bytes(), delivery)
                .await
                .map_err(|e| AppError::Internal(format!("queue DIDComm push: {e}")))?;
        }
        Protocol::Tsp | Protocol::Rest => {
            let transport = if record.current == Protocol::Tsp {
                TSP_TRANSPORT_ID
            } else {
                REST_TRANSPORT_ID
            };
            // The id only: the transport reads the document from the encrypted
            // record at send time, so the outbox holds nothing readable.
            messaging
                .service
                .send_via(
                    transport,
                    &record.recipient,
                    record.id.clone().into_bytes(),
                    delivery,
                )
                .await
                .map_err(|e| AppError::Internal(format!("queue {} push: {e}", record.current)))?;
        }
    }
    Ok(())
}

async fn store_record(ctx: &PushContext<'_>, record: &PushRecord) -> Result<(), AppError> {
    ctx.records.insert(record_key(&record.id), record).await
}

async fn load_record(ks: &KeyspaceHandle, id: &str) -> Result<Option<PushRecord>, AppError> {
    ks.get(record_key(id)).await
}

/// One pass over every push: settle what has evidence, escalate what has none,
/// and drop finished records past their retention. The retention sweeper runs
/// it on a timer.
pub async fn sweep(ctx: &PushContext<'_>) -> Result<(), AppError> {
    use affinidi_messaging_delivery::OutboxStore as _;
    let Some(messaging) = ctx.messaging else {
        return Ok(());
    };
    let outbox = crate::outbox_store::VtiOutboxStore::new(ctx.outbox.clone());
    let now = now_ms();
    for (_, bytes) in ctx
        .records
        .prefix_iter_raw(RECORD_PREFIX.as_bytes().to_vec())
        .await?
    {
        let Ok(mut record) = serde_json::from_slice::<PushRecord>(&bytes) else {
            continue;
        };
        if let Some(outcome) = &record.outcome {
            if now.saturating_sub(outcome.at_ms) > FINISHED_RETENTION.as_millis() as u64 {
                ctx.records.remove(record_key(&record.id)).await?;
            }
            continue;
        }
        let entry = outbox
            .get(&record.attempt_key)
            .await
            .map_err(|e| AppError::Internal(format!("read push delivery state: {e}")))?;
        // An attempt still queued or sent at its own deadline has produced no
        // evidence in its window. Treated here, rather than after the delivery
        // layer's own settle pass, so escalation is not held for it.
        let expired = entry.as_ref().is_some_and(|e| now >= e.deliver_by_ms);
        let observed = entry.as_ref().is_some_and(|e| e.outbox_observed);
        let entry_state = entry.map(|e| e.state);
        match entry_state {
            Some(OutboxState::Delivered) => {
                finish(ctx, &mut record, true, "collected").await?;
            }
            // REST has no collection signal, and needs none: a 2xx is the
            // recipient's own server acknowledging the document.
            Some(OutboxState::Sent) if record.current == Protocol::Rest => {
                let _ = messaging.service.confirm(&record.attempt_key).await;
                finish(ctx, &mut record, true, "reply").await?;
            }
            Some(OutboxState::Queued | OutboxState::Sent) if !expired => {}
            // Not in the outbox. Just queued, and the entry is not written yet:
            // wait. Long past that: the enqueue never happened (the process
            // died between the record and the entry), so queue this same
            // attempt again rather than give up on a transport never tried.
            None if now.saturating_sub(record.queued_at_ms) < ENQUEUE_GRACE.as_millis() as u64 => {}
            None => {
                warn!(
                    push = %record.id,
                    attempt = %record.attempt_key,
                    "push attempt was never queued; queuing it again"
                );
                if let Err(e) = queue_attempt(ctx, &mut record).await {
                    warn!(push = %record.id, error = %e, "could not re-queue the push");
                    escalate(ctx, &mut record).await?;
                }
            }
            Some(OutboxState::Queued | OutboxState::Sent)
            | Some(OutboxState::Failed | OutboxState::Unconfirmed) => {
                // Why this attempt is being given up on — the one fact needed
                // to tell a lost message from a slow one afterwards.
                debug!(
                    push = %record.id,
                    attempt = %record.attempt_key,
                    state = ?entry_state,
                    expired,
                    observed,
                    "push attempt ended without delivery evidence"
                );
                escalate(ctx, &mut record).await?;
            }
            // A state this build does not know yet: wait rather than escalate,
            // which could send a second copy of something already delivered.
            Some(_) => {}
        }
    }
    Ok(())
}

/// No evidence inside the attempt's window: re-resolve the recipient and try
/// the next transport it offers (VTI-TRN-042). "A dead mediator is not a dead
/// peer", so the re-resolution comes first.
async fn escalate(ctx: &PushContext<'_>, record: &mut PushRecord) -> Result<(), AppError> {
    if now_ms() >= record.deadline_ms {
        return finish(ctx, record, false, "none").await;
    }
    // A recipient that now offers nothing we speak leaves nothing to escalate to.
    let (fresh, reach) = plan(ctx, &record.recipient).await.unwrap_or_default();
    record.peer_tsp_mediator = reach.tsp_mediator;
    record.rest_base = reach.rest_base;
    // What is left of the original plan, kept only where the recipient still
    // offers it, and never the transport that just failed to produce evidence.
    let tried = record.current;
    let next: Vec<Protocol> = record
        .remaining
        .iter()
        .copied()
        .filter(|p| *p != tried && fresh.contains(p))
        .collect();
    if next.is_empty() {
        return finish(ctx, record, false, "none").await;
    }
    warn!(
        recipient = %record.recipient,
        from = %tried,
        to = %next[0],
        "push produced no delivery evidence in its window; escalating"
    );
    record.remaining = next;
    record.current = record.remaining.remove(0);
    record.attempt += 1;
    if let Err(e) = queue_attempt(ctx, record).await {
        warn!(recipient = %record.recipient, error = %e, "could not queue the escalated push");
        return finish(ctx, record, false, "none").await;
    }
    Ok(())
}

async fn finish(
    ctx: &PushContext<'_>,
    record: &mut PushRecord,
    delivered: bool,
    evidence: &str,
) -> Result<(), AppError> {
    record.outcome = Some(PushOutcome {
        delivered,
        via: record.current,
        evidence: evidence.to_string(),
        at_ms: now_ms(),
    });
    if delivered {
        info!(
            recipient = %record.recipient,
            via = %record.current,
            evidence,
            "trust-task push delivered"
        );
    } else {
        // Surfaced to the operator: every transport the recipient offers has
        // been tried inside the deadline without evidence (VTI-TRN-042).
        warn!(
            recipient = %record.recipient,
            last_via = %record.current,
            "push could not be confirmed on any transport the recipient offers"
        );
    }
    store_record(ctx, record).await
}

// ─── transports ──────────────────────────────────────────────────────────

/// Loads the document a TSP/REST outbox entry names. The entry carries the
/// push id only.
async fn document_for(ks: &KeyspaceHandle, packed: &[u8]) -> Result<PushRecord, MessagingError> {
    let id = std::str::from_utf8(packed)
        .map_err(|_| MessagingError::Transport("push entry is not a push id".into()))?;
    load_record(ks, id)
        .await
        .map_err(|e| MessagingError::Transport(format!("read push record: {e}")))?
        .ok_or_else(|| MessagingError::Transport(format!("no push record {id}")))
}

/// Sends a push over TSP, sealed at send time from the encrypted push
/// record, and reports the collection-evidence id the mediator will list.
///
/// A recipient on this node's mediator is sealed and routed through it, and
/// the returned `hop_id` is the id the mediator lists the message under in
/// this node's outbox — `sha256` of the stored (base64url) form of the
/// inner message — so the delivery layer's existing outbox poll sees it
/// collected. A recipient on another mediator is sent nested, for metadata
/// privacy; no mediator reports collection for that, so it carries no
/// `hop_id` and settles by escalation.
#[cfg(feature = "tsp")]
pub struct TspPushTransport {
    /// The node's ATM.
    pub atm: Arc<affinidi_tdk::messaging::ATM>,
    /// The node's profile on its mediator.
    pub profile: Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    /// The node's mediator.
    pub mediator_did: String,
    /// Where push records live ([`PushContext::records`]).
    pub pushes: KeyspaceHandle,
    /// The DIDComm socket's state: TSP sends go to the same mediator, so it is
    /// reachable exactly when that socket is.
    pub conn: watch::Receiver<ConnState>,
}

#[cfg(feature = "tsp")]
#[async_trait::async_trait]
impl MessageTransport for TspPushTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tsp
    }

    async fn send(&self, dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
        use affinidi_tdk::messaging::protocols::tsp::{SendReadiness, invite_refusal_is_benign};

        let record = document_for(&self.pushes, &packed).await?;
        let doc = serde_json::to_vec(&record.document)
            .map_err(|e| MessagingError::Transport(format!("serialise push document: {e}")))?;
        let body = vta_sdk::tsp_binding::wrap_envelope(&doc);
        let tsp = self.atm.tsp();
        let err = |e: affinidi_tdk::messaging::errors::ATMError| {
            MessagingError::Transport(format!("TSP send to {dest}: {e}"))
        };

        // Re-establish a relationship the peer (or this node) lost, as
        // `send_reestablishing` does — open-coded because that call seals
        // internally and so gives no access to the bytes the evidence id is
        // computed over.
        if matches!(
            tsp.send_readiness(&self.profile, dest).await.map_err(err)?,
            SendReadiness::Reestablish
        ) && let Err(e) = tsp.form_relationship_routed(&self.profile, dest).await
        {
            let after = tsp.send_readiness(&self.profile, dest).await.map_err(err)?;
            if !invite_refusal_is_benign(after) {
                return Err(err(e));
            }
        }

        match record.peer_tsp_mediator.as_deref() {
            Some(peer_mediator) if peer_mediator != self.mediator_did => {
                tsp.send_nested_routed(
                    &self.profile,
                    &[self.mediator_did.clone(), peer_mediator.to_string()],
                    dest,
                    &body,
                )
                .await
                .map_err(err)?;
                Ok(SendReceipt {
                    via: TransportKind::Tsp,
                    hop_id: None,
                })
            }
            _ => {
                let inner = tsp.pack(&self.profile, dest, &body).await.map_err(err)?;
                tsp.send_routed_opaque(
                    &self.profile,
                    &[self.mediator_did.clone(), dest.to_string()],
                    &inner,
                )
                .await
                .map_err(err)?;
                Ok(SendReceipt {
                    via: TransportKind::Tsp,
                    hop_id: Some(sha256_hex(tsp.encode(&inner).as_bytes())),
                })
            }
        }
    }

    fn connection_state(&self) -> watch::Receiver<ConnState> {
        self.conn.clone()
    }

    fn inbound(&self) -> BoxStream<'static, Inbound> {
        // Inbound TSP already arrives on the DIDComm socket's frame stream.
        Box::pin(futures_util::stream::empty())
    }

    async fn ack(&self, _ack: InboundAck) -> Result<(), MessagingError> {
        Ok(())
    }
}

#[cfg(feature = "tsp")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Sends a push over the HTTPS binding: `POST {base}/trust-tasks` with
/// the signed document as the body (HTTPS binding 0.2 §2, §6.1). No bearer
/// token — this node holds none for the recipient's server — so the
/// document's own proof is what authenticates it (§2 item 2).
pub struct RestPushTransport {
    http: reqwest::Client,
    pushes: KeyspaceHandle,
    // REST has no connection to lose: each send is its own request, and a
    // failed one is an `Err` from `send`. Held so the receiver never reads a
    // closed channel.
    _conn_tx: watch::Sender<ConnState>,
    conn: watch::Receiver<ConnState>,
}

impl RestPushTransport {
    /// `http` fetches foreign URLs, so give it the node's foreign-fetch
    /// profile (bounded timeouts, no redirects to private ranges).
    pub fn new(pushes: KeyspaceHandle, http: reqwest::Client) -> Self {
        let (tx, rx) = watch::channel(ConnState::Connected);
        Self {
            http,
            pushes,
            _conn_tx: tx,
            conn: rx,
        }
    }
}

#[async_trait::async_trait]
impl MessageTransport for RestPushTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Rest
    }

    async fn send(&self, dest: &str, packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
        let record = document_for(&self.pushes, &packed).await?;
        let base = record.rest_base.as_deref().ok_or_else(|| {
            MessagingError::Transport(format!("{dest} advertises no TrustTaskHTTPS endpoint"))
        })?;
        let url = format!("{}/trust-tasks", base.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&record.document)
            .send()
            .await
            .map_err(|e| MessagingError::Transport(format!("POST {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(MessagingError::Transport(format!(
                "POST {url} answered {}",
                resp.status()
            )));
        }
        Ok(SendReceipt {
            via: TransportKind::Rest,
            hop_id: None,
        })
    }

    fn connection_state(&self) -> watch::Receiver<ConnState> {
        self.conn.clone()
    }

    fn inbound(&self) -> BoxStream<'static, Inbound> {
        Box::pin(futures_util::stream::empty())
    }

    async fn ack(&self, _ack: InboundAck) -> Result<(), MessagingError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(services: Value) -> Value {
        json!({ "id": "did:example:peer", "service": services })
    }

    /// Selection is by service `type`, never by `#id`.
    #[test]
    fn reach_matches_on_service_type() {
        let d = doc(json!([
            { "id": "#whatever", "type": "TSPTransport", "serviceEndpoint": "did:example:med" },
            { "id": "#x", "type": "DIDCommMessaging", "serviceEndpoint": { "uri": "did:example:med" } },
            { "id": "#y", "type": "TrustTaskHTTPS", "serviceEndpoint": "https://peer.example/" },
        ]));
        let r = Reach::from_document(&d);
        assert_eq!(r.tsp_mediator.as_deref(), Some("did:example:med"));
        assert!(r.didcomm);
        assert_eq!(r.rest_base.as_deref(), Some("https://peer.example/"));
    }

    /// An application REST API is not a Trust Task endpoint: only
    /// `TrustTaskHTTPS` makes REST a candidate for a push.
    #[test]
    fn only_trust_task_https_counts_as_rest() {
        let d = doc(json!([
            { "id": "#rest", "type": "VTARest", "serviceEndpoint": "https://vta.example" },
        ]));
        let r = Reach::from_document(&d);
        assert!(r.rest_base.is_none());
        assert!(!r.advertises_anything());
    }

    #[test]
    fn a_document_without_services_advertises_nothing() {
        assert!(!Reach::from_document(&json!({ "id": "did:key:z6Mk" })).advertises_anything());
    }
}
