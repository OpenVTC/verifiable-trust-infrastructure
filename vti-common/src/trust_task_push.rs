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
//! resend of one document carries unchanged (VTI-TRN-043).
//!
//! # Freshness: a push outlives the document it started with
//!
//! A push's deadline runs to hours or days — thirty for a removal notice — but
//! a VTI consumer accepts a document only for
//! [`ACCEPTANCE_WINDOW`](crate::trust_task::ACCEPTANCE_WINDOW) after its
//! `issuedAt`, plus its skew tolerance (VTI-OPS-024), and refuses anything
//! older as `expired`. An attempt queued after that — an escalation an hour
//! in, an attempt re-queued after a crash, a hop the mediator refused for
//! twenty minutes, or a copy the recipient collected on reconnecting the next
//! morning — would deliver a document the recipient refuses, and nothing here
//! would learn of it.
//!
//! Re-signing the same document under the same `id` is not the fix. SPEC §8.4
//! defines a retry as the bit-for-bit identical document, and §7.2 item 11
//! requires a consumer that already accepted an `id` to refuse different
//! content under it with `idConflict` — a re-stamped `issuedAt` and a new proof
//! are different content. And no `expiresAt` helps: VTI consumers apply their
//! window to `issuedAt` whatever `expiresAt` says, and cap the replay record at
//! it, so that a producer cannot choose how long a consumer must remember it.
//!
//! So the engine issues a **new attempt** (SPEC §8.4, last paragraph) whenever
//! it would otherwise put a document past its acceptance window on the wire:
//! a fresh `id`, a fresh `issuedAt`, the node's proof again
//! ([`PushReissuer`]), and everything else unchanged. The attempt stays in the
//! original's thread — its `threadId`, or the original's `id` where the
//! original opened the thread — so a reply correlates as it would have, and an
//! `idempotencyKey` the original carried rides every attempt (VTI-OPS-064), so a
//! consumer that keys the task performs it once however many attempts reach
//! it. A task without a key is one whose repeat is harmless (VTI-OPS-060); a
//! task whose repeat leaves a second artefact must carry one.
//!
//! Where it happens:
//!
//! - **Queuing** any attempt — the first, an escalation, a re-queue — with a
//!   document already past the window.
//! - **An attempt still waiting to be handed off** when its document crosses
//!   the window: it is superseded by a new attempt on the same transport,
//!   inside the same attempt window.
//! - **A copy collected after the window** (a recipient that was offline):
//!   collection is evidence the recipient is online now, and not that it
//!   accepted what it collected, so a new attempt follows on the same
//!   transport.
//!
//! What it cannot reach: a copy held by a mediator is sealed and out of this
//! node's hands until the recipient collects it, so a recipient offline past
//! the window receives one refused copy before the new attempt.
//! [`MAX_REISSUES`] bounds how many new attempts one push may make.

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
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use trust_tasks_rs::freshness::DEFAULT_SKEW;
use vta_sdk::protocol::matching::{
    DIDCOMM_SERVICE_TYPE, Protocol, ServiceCapabilities, TRUST_TASK_HTTPS_SERVICE_TYPE,
};

use crate::capability_client::TRUST_TASK_ENVELOPE_TYPE;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::trust_task::ACCEPTANCE_WINDOW;
use crate::tsp_reach::TspReachability;

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
    /// Which peers were recently seen sending to this node over TSP. A
    /// recipient whose document advertises no transport at all is reached
    /// over TSP first when it is fresh here. `None` learns nothing.
    pub learned_tsp: Option<&'a TspReachability>,
    /// Signs the new attempts the engine issues when a push outlives its
    /// document's acceptance window (see the module docs). `None` never
    /// re-issues: a document past the window is still sent, and refused.
    pub reissuer: Option<&'a dyn PushReissuer>,
}

/// A node's signature on a new attempt at a push (SPEC §8.4).
///
/// The engine builds the attempt ([`new_attempt`]); only the node holds the key
/// that signed the original, so only the node can sign it again.
#[async_trait::async_trait]
pub trait PushReissuer: Send + Sync {
    /// Attach this node's proof to `next`, a new attempt at `previous`.
    /// `previous` still carries its own proof, so an implementation can sign
    /// `next` the way `previous` was signed.
    async fn sign_new_attempt(&self, previous: &Value, next: &mut Value) -> Result<(), AppError>;
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

/// The most new attempts one push may issue (see the module docs). Each is a
/// signature — a KMS decrypt on a TEE node — so a transport that refuses every
/// hop for a thirty-day deadline must not re-sign every ten minutes for all of
/// it. Enough for an hour of refused hops on two transports, and a late
/// collection besides.
pub const MAX_REISSUES: u32 = 12;

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
    /// The signed Trust Task document every attempt sends: unchanged across
    /// resends, and replaced only by a new attempt ([`new_attempt`]) once it is
    /// past its acceptance window.
    document: Value,
    /// How many new attempts this push has issued ([`MAX_REISSUES`]).
    #[serde(default)]
    reissues: u32,
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

// ─── freshness ───────────────────────────────────────────────────────────

/// The document's `issuedAt`, when it carries a readable one.
fn issued_at(doc: &Value) -> Option<DateTime<Utc>> {
    doc.get("issuedAt")?.as_str()?.parse::<DateTime<Utc>>().ok()
}

/// Whether a VTI consumer has stopped accepting `doc` by `now`, before its skew
/// tolerance: the point past which the engine will not put it on the wire
/// again. A document with no readable `issuedAt` cannot be placed in any
/// window, so it is never judged past one — it is sent as it is.
fn past_acceptance(doc: &Value, now: DateTime<Utc>) -> bool {
    issued_at(doc).is_some_and(|t| now >= t + ACCEPTANCE_WINDOW)
}

/// Whether every VTI consumer refuses `doc` at `now`, skew tolerance included.
/// A copy collected past this point was refused, whatever the collection
/// evidence says.
fn refused_when_collected(doc: &Value, now: DateTime<Utc>) -> bool {
    issued_at(doc).is_some_and(|t| now > t + ACCEPTANCE_WINDOW + DEFAULT_SKEW)
}

/// A **new attempt** at `previous` (SPEC §8.4): a fresh `id`, a fresh
/// `issuedAt`, no `proof` — sign it before sending — and every other member
/// unchanged, including any `idempotencyKey`, which every attempt at one
/// logical operation must carry (VTI-OPS-064).
///
/// The attempt stays in `previous`'s thread. Where `previous` carried a
/// `threadId` it is kept; where `previous` opened the thread, SPEC §4.9 names
/// that thread by `previous`'s `id`, so the attempt carries that `id` as its
/// `threadId`. Without it a new attempt would open a new exchange, and an
/// answer keyed to the original — a presentation challenge committed to the
/// original `id`, a reply the sender waits on — would never correlate.
///
/// `issuedAt` is whole seconds (VTI-KEY-107). Refused when `previous` states an
/// `expiresAt` that has passed: the producer said the request lapses then, and
/// a new attempt would override it.
pub fn new_attempt(previous: &Value, now: DateTime<Utc>) -> Result<Value, AppError> {
    let obj = previous
        .as_object()
        .ok_or_else(|| AppError::Validation("a Trust Task document is a JSON object".into()))?;
    let previous_id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| AppError::Validation("the document carries no id".into()))?;
    if let Some(expires_at) = obj
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        && expires_at <= now
    {
        return Err(AppError::Validation(format!(
            "{previous_id} lapsed at its own expiresAt ({expires_at}); a new attempt would \
             outlive what its producer asked"
        )));
    }
    let mut next = obj.clone();
    if !next.contains_key("threadId") {
        next.insert("threadId".into(), Value::String(previous_id.to_string()));
    }
    next.insert(
        "id".into(),
        Value::String(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
    );
    next.insert(
        "issuedAt".into(),
        Value::String(now.to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
    next.remove("proof");
    Ok(Value::Object(next))
}

/// Whether [`reissue`] could replace the push's document now — checked before a
/// sweep sets out to, so a push that cannot re-issue (no signer, spent, or past
/// its own `expiresAt`) waits quietly instead of warning every pass.
fn may_reissue(ctx: &PushContext<'_>, record: &PushRecord, now: DateTime<Utc>) -> bool {
    let lapsed = record
        .document
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .is_some_and(|t| t <= now);
    ctx.reissuer.is_some() && record.reissues < MAX_REISSUES && !lapsed
}

/// Replace the push's document with a signed new attempt at it. `false` — and
/// the document unchanged — when this node cannot sign one, the push has spent
/// [`MAX_REISSUES`], or the document may not be re-issued; the caller then
/// carries on with what it has, which is what the engine did before it could
/// re-issue at all.
async fn reissue(ctx: &PushContext<'_>, record: &mut PushRecord) -> bool {
    let Some(signer) = ctx.reissuer else {
        warn!(
            push = %record.id,
            recipient = %record.recipient,
            "push document is past its acceptance window and this node cannot re-issue it; \
             the recipient will refuse it as expired"
        );
        return false;
    };
    if record.reissues >= MAX_REISSUES {
        warn!(
            push = %record.id,
            recipient = %record.recipient,
            reissues = record.reissues,
            "push has issued as many new attempts as it may; sending the document it has"
        );
        return false;
    }
    let mut next = match new_attempt(&record.document, Utc::now()) {
        Ok(next) => next,
        Err(e) => {
            warn!(push = %record.id, error = %e, "cannot issue a new attempt at the push");
            return false;
        }
    };
    if let Err(e) = signer.sign_new_attempt(&record.document, &mut next).await {
        warn!(push = %record.id, error = %e, "could not sign a new attempt at the push");
        return false;
    }
    let previous = record
        .document
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let next_id = next
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    record.document = next;
    record.reissues += 1;
    info!(
        push = %record.id,
        recipient = %record.recipient,
        previous = %previous,
        next = %next_id,
        "push outlived its document's acceptance window; issued a new attempt"
    );
    true
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
///
/// An endpoint that is not `https://` (or `http://` to an exact loopback host
/// — [`vta_sdk::protocol::matching::is_https_or_loopback`]) is refused and logged, the same
/// rule [`ServiceCapabilities::from_did_document`] applies to a `VTARest`/
/// `TrustTaskHTTPS` candidate: a peer advertising plain `http://` must not
/// receive a signed Trust Task in the clear. The refusal makes this function
/// report no REST endpoint at all — `plan`/`choose` then simply do not offer
/// REST for this peer, and the push fails closed if no other transport is
/// shared.
fn trust_task_https_base(doc: &Value) -> Option<String> {
    let uri = doc.get("service")?.as_array()?.iter().find_map(|svc| {
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
    })?;
    if vta_sdk::protocol::matching::is_https_or_loopback(&uri) {
        Some(uri)
    } else {
        let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        warn!(
            did,
            endpoint = %uri,
            "ignoring a plaintext http:// TrustTaskHTTPS endpoint advertised to a non-loopback host"
        );
        None
    }
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
    let learned_tsp = ctx.learned_tsp.is_some_and(|seen| seen.fresh(recipient));
    let plan = choose(&reach, &ours, learned_tsp);
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

/// The transports both sides speak, TSP > DIDComm > REST.
///
/// A recipient that advertises nothing is reached over DIDComm through this
/// node's mediator — and over TSP first when it was recently seen sending
/// here over TSP (`learned_tsp`). DIDComm stays behind TSP in that plan,
/// because a peer that switched back to DIDComm since gives no error on TSP,
/// only silence, and escalation is what recovers from silence.
fn choose(reach: &Reach, ours: &Ours, learned_tsp: bool) -> Vec<Protocol> {
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
    if plan.is_empty() && !reach.advertises_anything() {
        if ours.tsp && learned_tsp {
            plan.push(Protocol::Tsp);
        }
        if ours.didcomm {
            plan.push(Protocol::Didcomm);
        }
    }
    plan
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
        reissues: 0,
    };
    // An attempt that cannot even be queued moves straight on; only when no
    // transport will take it is the push refused.
    loop {
        match queue_attempt(ctx, &mut record, None).await {
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
///
/// `window_end_ms` pins when the attempt's window closes, for an attempt that
/// supersedes one on the same transport: the transport keeps the window it was
/// given, rather than a fresh one each time its document is renewed — which,
/// for a transport refusing every hop, would hold the push on it forever.
/// `None` gives the attempt its share of what is left of the deadline.
///
/// A document already past its acceptance window is replaced by a new attempt
/// first (see the module docs): whatever the reason this attempt is late, the
/// document it would carry is one every VTI consumer refuses.
async fn queue_attempt(
    ctx: &PushContext<'_>,
    record: &mut PushRecord,
    window_end_ms: Option<u64>,
) -> Result<(), AppError> {
    if past_acceptance(&record.document, Utc::now()) {
        reissue(ctx, record).await;
    }
    let messaging = ctx.messaging;
    let now = now_ms();
    let remaining_ms = record.deadline_ms.saturating_sub(now).max(1_000);
    // The last attempt gets whatever is left. Every other one gets its share
    // of it, capped at `ATTEMPT_WINDOW`, so a short deadline still leaves room
    // to escalate: a 15-minute consent request tries each of three transports
    // for five minutes, where taking the whole deadline first would never
    // reach the second.
    let window_ms = if let Some(end) = window_end_ms {
        end.saturating_sub(now).max(1_000)
    } else if record.remaining.is_empty() {
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
        let window_end_ms = entry.as_ref().map(|e| e.deliver_by_ms);
        let entry_state = entry.map(|e| e.state);
        let clock = Utc::now();
        match entry_state {
            // Collected, but only after every VTI consumer had stopped
            // accepting the document: the recipient was offline past the
            // window, is online now, and refused what it collected. Collection
            // is evidence of the first and not of acceptance, so a new attempt
            // follows on the transport the recipient just proved it reads.
            Some(OutboxState::Delivered)
                if record.current != Protocol::Rest
                    && now < record.deadline_ms
                    && refused_when_collected(&record.document, clock)
                    && may_reissue(ctx, &record, clock) =>
            {
                warn!(
                    push = %record.id,
                    recipient = %record.recipient,
                    via = %record.current,
                    "push collected after its acceptance window closed; the recipient refused \
                     it as expired, so a new attempt follows"
                );
                if reissue(ctx, &mut record).await {
                    record.attempt += 1;
                    if let Err(e) = queue_attempt(ctx, &mut record, None).await {
                        warn!(push = %record.id, error = %e, "could not queue the new attempt");
                        escalate(ctx, &mut record).await?;
                    }
                } else {
                    finish(ctx, &mut record, true, "collected").await?;
                }
            }
            Some(OutboxState::Delivered) => {
                finish(ctx, &mut record, true, "collected").await?;
            }
            // REST has no collection signal, and needs none: a 2xx is the
            // recipient's own server acknowledging the document.
            Some(OutboxState::Sent) if record.current == Protocol::Rest => {
                let _ = messaging.service.confirm(&record.attempt_key).await;
                finish(ctx, &mut record, true, "reply").await?;
            }
            // Still waiting to be handed off — the mediator or the recipient's
            // server has refused every hop so far — and its document has now
            // crossed the acceptance window, so the hop that finally succeeds
            // would carry a refused document. Superseded by a new attempt on
            // the same transport, inside the same window.
            //
            // Not a `Sent` attempt: that copy is sealed and held by a mediator,
            // out of this node's reach, and a copy per window for an offline
            // recipient would fill the mediator's queue for them. The arm above
            // picks it up when it is collected.
            Some(OutboxState::Queued)
                if !expired
                    && past_acceptance(&record.document, clock)
                    && may_reissue(ctx, &record, clock) =>
            {
                if reissue(ctx, &mut record).await {
                    record.attempt += 1;
                    if let Err(e) = queue_attempt(ctx, &mut record, window_end_ms).await {
                        warn!(push = %record.id, error = %e, "could not queue the new attempt");
                        escalate(ctx, &mut record).await?;
                    }
                }
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
                if let Err(e) = queue_attempt(ctx, &mut record, None).await {
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
    if let Err(e) = queue_attempt(ctx, record, None).await {
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

    /// A peer advertising `TrustTaskHTTPS` over plain `http://` is not
    /// reachable over REST at all — a signed Trust Task is not encrypted, and
    /// this node must not send one in the clear.
    #[test]
    fn a_plaintext_trust_task_https_endpoint_is_not_a_rest_candidate() {
        let d = doc(json!([
            { "id": "#tt", "type": "TrustTaskHTTPS", "serviceEndpoint": "http://peer.example/" },
        ]));
        let r = Reach::from_document(&d);
        assert!(r.rest_base.is_none());
        assert!(!r.advertises_anything());
    }

    /// Lookalike hosts are ordinary DNS names, not loopback, and are refused
    /// exactly like any other plaintext endpoint.
    #[test]
    fn plaintext_lookalike_loopback_is_not_a_rest_candidate() {
        for endpoint in ["http://127.0.0.1.evil.com/", "http://localhost.evil/"] {
            let d = doc(json!([
                { "id": "#tt", "type": "TrustTaskHTTPS", "serviceEndpoint": endpoint },
            ]));
            let r = Reach::from_document(&d);
            assert!(r.rest_base.is_none(), "{endpoint}");
        }
    }

    /// Plain `http://` to exact loopback is still a candidate, for local
    /// development.
    #[test]
    fn plaintext_http_to_loopback_is_still_a_rest_candidate() {
        let d = doc(json!([
            { "id": "#tt", "type": "TrustTaskHTTPS", "serviceEndpoint": "http://127.0.0.1:8100/" },
        ]));
        let r = Reach::from_document(&d);
        assert_eq!(r.rest_base.as_deref(), Some("http://127.0.0.1:8100/"));
    }

    fn ours_all() -> Ours {
        Ours {
            tsp: true,
            didcomm: true,
            rest: true,
        }
    }

    /// A peer that advertises nothing but spoke TSP to this node recently is
    /// tried over TSP first, with DIDComm behind it for escalation.
    #[test]
    fn a_silent_peer_seen_on_tsp_is_tried_over_tsp_then_didcomm() {
        let silent = Reach::default();
        assert_eq!(
            choose(&silent, &ours_all(), true),
            vec![Protocol::Tsp, Protocol::Didcomm]
        );
        assert_eq!(choose(&silent, &ours_all(), false), vec![Protocol::Didcomm]);
    }

    /// What a peer advertises wins over what was learned: learning only fills
    /// in for a document that says nothing.
    #[test]
    fn learned_reach_never_overrides_an_advertised_document() {
        let didcomm_only = Reach {
            didcomm: true,
            ..Reach::default()
        };
        assert_eq!(
            choose(&didcomm_only, &ours_all(), true),
            vec![Protocol::Didcomm]
        );
    }

    #[test]
    fn a_node_without_tsp_ignores_learned_reach() {
        let ours = Ours {
            tsp: false,
            ..ours_all()
        };
        assert_eq!(
            choose(&Reach::default(), &ours, true),
            vec![Protocol::Didcomm]
        );
    }

    fn signed_at(issued_at: DateTime<Utc>) -> Value {
        json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": "https://trusttasks.org/spec/credential-exchange/issue/0.1",
            "issuer": "did:example:vtc",
            "recipient": "did:example:member",
            "issuedAt": issued_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "idempotencyKey": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "payload": { "credential": "x" },
            "proof": { "type": "DataIntegrityProof", "proofPurpose": "authentication" },
        })
    }

    /// The engine stops putting a document on the wire at the consumer's
    /// window, and judges a collected copy refused only once the consumer's
    /// skew tolerance has passed too.
    #[test]
    fn a_document_is_past_acceptance_at_the_window_and_refused_after_the_skew() {
        // Whole seconds, as `issuedAt` is on the wire.
        let issued = chrono::SubsecRound::trunc_subsecs(Utc::now() - ACCEPTANCE_WINDOW, 0);
        let doc = signed_at(issued);
        let at_window = issued + ACCEPTANCE_WINDOW;
        assert!(!past_acceptance(
            &doc,
            at_window - chrono::TimeDelta::seconds(1)
        ));
        assert!(past_acceptance(&doc, at_window));
        assert!(!refused_when_collected(&doc, at_window + DEFAULT_SKEW));
        assert!(refused_when_collected(
            &doc,
            at_window + DEFAULT_SKEW + chrono::TimeDelta::seconds(1)
        ));
    }

    /// A document with no `issuedAt` cannot be placed in any window, so it is
    /// never replaced: the engine sends what it was given.
    #[test]
    fn a_document_without_an_issued_at_is_never_past_acceptance() {
        let doc = json!({ "id": "urn:uuid:x", "type": "t", "payload": {} });
        let far = Utc::now() + chrono::TimeDelta::days(365);
        assert!(!past_acceptance(&doc, far));
        assert!(!refused_when_collected(&doc, far));
    }

    /// SPEC §8.4: anything that changes the bytes is a new document and must
    /// carry a fresh `id` — re-signing under the old one is the `idConflict`
    /// case of §7.2 item 11. Everything else carries over, the key included
    /// (VTI-OPS-064), and the proof is cleared for the node to sign again.
    #[test]
    fn a_new_attempt_has_a_fresh_id_and_issued_at_and_keeps_the_key_and_payload() {
        let issued = Utc::now() - chrono::TimeDelta::hours(2);
        let previous = signed_at(issued);
        let now = Utc::now();
        let next = new_attempt(&previous, now).expect("a new attempt");

        assert_ne!(next["id"], previous["id"], "a fresh id");
        assert!(next["id"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(
            issued_at(&next).map(|t| t.timestamp()),
            Some(now.timestamp()),
            "a fresh issuedAt, in whole seconds"
        );
        assert!(!past_acceptance(&next, now));
        assert!(
            next.get("proof").is_none(),
            "unsigned until the node signs it"
        );
        for member in ["type", "issuer", "recipient", "payload", "idempotencyKey"] {
            assert_eq!(next[member], previous[member], "{member} carries over");
        }
    }

    /// A new attempt stays in the original's thread: the original's own `id`
    /// where it opened the thread, its `threadId` where it had one.
    #[test]
    fn a_new_attempt_stays_in_the_original_thread() {
        let previous = signed_at(Utc::now() - chrono::TimeDelta::hours(1));
        let next = new_attempt(&previous, Utc::now()).unwrap();
        assert_eq!(next["threadId"], previous["id"]);

        let again = new_attempt(&next, Utc::now()).unwrap();
        assert_eq!(
            again["threadId"], previous["id"],
            "a second attempt stays in the same thread, not the first attempt's"
        );
    }

    /// A producer that said its request lapses at `expiresAt` is not
    /// overridden by a new attempt past it.
    #[test]
    fn a_document_past_its_own_expiry_is_not_re_issued() {
        let now = Utc::now();
        let mut previous = signed_at(now - chrono::TimeDelta::hours(1));
        previous["expiresAt"] = json!((now - chrono::TimeDelta::minutes(1)).to_rfc3339());
        assert!(new_attempt(&previous, now).is_err());
    }

    #[test]
    fn a_document_without_services_advertises_nothing() {
        assert!(!Reach::from_document(&json!({ "id": "did:key:z6Mk" })).advertises_anything());
    }
}
