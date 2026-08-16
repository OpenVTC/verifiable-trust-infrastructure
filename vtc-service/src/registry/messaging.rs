//! `MessagingRegistryClient` — the trust-registry client that addresses the
//! registry by **DID**, over TSP or DIDComm, using the canonical `registry/*`
//! Trust Tasks.
//!
//! ## Why this exists
//!
//! [`UpstreamRegistryClient`](super::upstream::UpstreamRegistryClient) reaches
//! the registry at a configured `registry.url` over HTTP. That works for the
//! two TRQP *reads* the upstream exposes on its HTTP surface, but:
//!
//! - every **write** was a `Permanent` stub, so membership never synced;
//! - a URL is not always available — a registry is named by DID in the
//!   community's DID document (`#trust-registry` referral), and a deployment
//!   may publish nothing else;
//! - `health()` was an HTTP `GET /.well-known/did.json`, which stays green
//!   while every write fails (R6.2: a health flag must be driven by a signal
//!   that can go false again — this one could not).
//!
//! This client closes all three. It speaks the registry's Trust Tasks —
//! `registry/record/{put,delete,query}/0.1` and `registry/recognition/0.1` —
//! over the transport both parties advertise, and derives liveness from a real
//! round-trip rather than from a URL being up.
//!
//! ## Transport selection
//!
//! Per CLAUDE.md the DID document is authoritative and the preference order is
//! TSP > DIDComm > REST, matched on the service **`type`** (never the `#id`
//! fragment). We resolve the registry's DID, read its
//! [`ServiceCapabilities`], intersect with what this build can speak, and take
//! the highest-preference overlap. An empty intersection is a typed error, not
//! a silent downgrade — [`select_protocol`] returns `NoMatchingProtocol`
//! carrying both advertised sets so the operator can see which side is missing
//! what.
//!
//! REST remains reachable as the last-resort arm: when the match lands on
//! `Protocol::Rest` we delegate to the HTTP client, which is why
//! `registry.url` stays meaningful for a registry that advertises `TRQPRest`
//! and nothing else.
//!
//! ## Replies
//!
//! Both messaging transports are one-way sends; the answer arrives back on the
//! inbound listener as a separate frame. We register a waiter keyed by the
//! request document id **before** sending (so a fast reply cannot be lost) and
//! the inbound demux completes it by `threadId` — the same
//! [`PendingReplies`] the git-trust hook writer uses, which is why a registry
//! reply needs no new inbound plumbing on the DIDComm side.
//!
//! R1.1 discipline throughout: a send returning `Ok` means "accepted locally",
//! never "delivered". A call is complete only when a correlated reply arrives;
//! no reply within the window is `Transient`, which the syncer retries.
//!
//! ## The TSP envelope
//!
//! TSP frames to the registry are wrapped in the `trust-tasks-tsp` binding
//! envelope (`{"type": <ENVELOPE_TYPE>, "document": <TrustTask>}`). This is
//! **not** what the rest of this workspace does over TSP — VTI sends bare
//! Trust-Task document bytes (see `vta_sdk::session::DIDCommSession::
//! send_document` and `messaging::handle_tsp`) — but the registry's TSP
//! binding rejects a payload without the envelope, and the envelope is the
//! published binding. We therefore emit the envelope and accept **either**
//! shape inbound.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_delivery::Delivery;
use affinidi_messaging_didcomm::Message;
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use tracing::debug;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};

use vti_common::capability_client::{TRUST_TASK_ENVELOPE_TYPE, build_document};

use crate::credentials::LocalSigner;
use crate::hooks::PendingReplies;
use crate::messaging::VtcMessaging;

use super::client::{RegistryError, RegistryTransport, TrustRegistryClient};
use super::model::{RegistryRecord, RegistryStatus};
use super::upstream::UpstreamRegistryClient;
use super::{RECOGNISE_ACTION, TRUST_GRAPH_RESOURCE};

/// The `trust-tasks-tsp` binding envelope type.
///
/// Mirrored from `trust_tasks_tsp::ENVELOPE_TYPE` rather than depended upon:
/// pulling the binding crate in would drag a second TSP stack into the build
/// graph for one constant. [`tsp_envelope_type_matches_the_binding`] pins the
/// string.
const TSP_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/tsp/0.1/envelope";

/// Canonical `registry/*` Trust Task type URIs.
const RECORD_PUT: &str = "https://trusttasks.org/spec/registry/record/put/0.1";
const RECORD_DELETE: &str = "https://trusttasks.org/spec/registry/record/delete/0.1";
const RECORD_QUERY: &str = "https://trusttasks.org/spec/registry/record/query/0.1";
const RECOGNITION: &str = "https://trusttasks.org/spec/registry/recognition/0.1";

/// Default wait for the registry's reply before a call is deemed transient.
/// Matches the hook writer's window — same mediator, same round trip.
pub const DEFAULT_REPLY_TIMEOUT_SECONDS: u64 = 60;

/// Trust-registry client addressing the registry by DID over TSP / DIDComm,
/// with the HTTP client as the REST arm.
pub struct MessagingRegistryClient {
    /// DID of the community's trust registry — the recipient of every task.
    registry_did: String,
    /// Our own DID: the TRQP `authority_id` on every record we write or query,
    /// and the issuer of every document we sign. `None` before setup completes,
    /// in which case every call refuses rather than writing a half-keyed record.
    authority_did: Option<String>,
    /// Messaging handle. Empty until the listener is up — a not-yet-running
    /// messaging is transient, not permanent.
    didcomm: Arc<OnceCell<Arc<VtcMessaging>>>,
    /// The VTC's assertion signer (`{vtc_did}#key-0`), the same identity that
    /// mints VMC/VEC. The community is the authority its records are written
    /// under, so this is the right key — and its canonical form already
    /// verifies at the registry (proven by the git-trust path).
    signer: Arc<LocalSigner>,
    /// Shared with the inbound demux; completed by `threadId`.
    replies: PendingReplies,
    /// Resolver for the registry's DID document (transport selection).
    did_resolver: Option<DIDCacheClient>,
    reply_timeout: Duration,
    /// REST arm — present when `registry.url` is configured.
    http: Option<UpstreamRegistryClient>,
    /// What the last transport selection saw and chose, for the diagnostics
    /// surface.
    ///
    /// Written on every [`select`](Self::select) rather than cached at boot,
    /// because the selection is itself per-call: a registry that adds `#tsp`
    /// mid-life changes this without a restart, and an operator looking at the
    /// page needs the answer for the call that just ran, not the one at boot.
    ///
    /// A `std::sync::RwLock` and not a tokio one on purpose — every critical
    /// section here is a field assignment with no `await` inside it (R1.3).
    transport: Arc<RwLock<RegistryTransport>>,
}

impl std::fmt::Debug for MessagingRegistryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessagingRegistryClient")
            .field("registry_did", &self.registry_did)
            .field("authority_did", &self.authority_did)
            .field("http_arm", &self.http.is_some())
            .finish()
    }
}

impl MessagingRegistryClient {
    pub fn new(
        registry_did: String,
        authority_did: Option<String>,
        didcomm: Arc<OnceCell<Arc<VtcMessaging>>>,
        signer: Arc<LocalSigner>,
        replies: PendingReplies,
        did_resolver: Option<DIDCacheClient>,
        http: Option<UpstreamRegistryClient>,
    ) -> Self {
        let transport = Arc::new(RwLock::new(RegistryTransport {
            did: Some(registry_did.clone()),
            url: http.as_ref().map(|c| c.base_url().to_string()),
            ..RegistryTransport::default()
        }));
        Self {
            registry_did,
            authority_did,
            didcomm,
            signer,
            replies,
            did_resolver,
            reply_timeout: Duration::from_secs(DEFAULT_REPLY_TIMEOUT_SECONDS),
            http,
            transport,
        }
    }

    /// Shorten the reply window. Test-only: the production window is a
    /// deliberate 60s, and the silence case would otherwise take that long to
    /// assert.
    #[cfg(any(test, feature = "didcomm-harness"))]
    pub fn with_reply_timeout(mut self, timeout: Duration) -> Self {
        self.reply_timeout = timeout;
        self
    }

    /// Our own DID as TRQP authority, or a `Permanent` refusal.
    fn authority(&self) -> Result<&str, RegistryError> {
        self.authority_did.as_deref().ok_or_else(|| {
            RegistryError::Permanent(
                "vtc_did not configured — cannot address the trust registry (complete `vtc setup` \
                 first)"
                    .into(),
            )
        })
    }

    /// Which transport to use for the registry, this call.
    ///
    /// Re-evaluated per call rather than cached at boot: a registry that adds
    /// `#tsp` mid-life should be reached over TSP on the next attempt, and the
    /// resolver's own cache keeps this cheap.
    async fn select(&self) -> Result<Protocol, RegistryError> {
        match self.select_inner().await {
            Ok((protocol, advertised)) => {
                self.record_selection(advertised, Some(protocol), None);
                Ok(protocol)
            }
            Err((e, advertised)) => {
                // Record the failure *with* whatever we learned about the peer.
                // "Advertised [tsp], active none, error: no transport in common"
                // is a diagnosis; "unreachable" on its own is not.
                self.record_selection(advertised, None, Some(e.to_string()));
                Err(e)
            }
        }
    }

    /// [`select`](Self::select) without the bookkeeping. Returns the peer's
    /// advertised set alongside either outcome so the failure path can report
    /// it too.
    async fn select_inner(
        &self,
    ) -> Result<(Protocol, Vec<Protocol>), (RegistryError, Vec<Protocol>)> {
        let Some(resolver) = self.did_resolver.as_ref() else {
            // No resolver configured: we cannot read the peer's document, and
            // guessing is exactly the failure mode CLAUDE.md forbids.
            return Err((
                RegistryError::Permanent(
                    "no DID resolver configured — cannot read the trust registry's advertised \
                     transports"
                        .into(),
                ),
                Vec::new(),
            ));
        };
        let resolved = resolver.resolve(&self.registry_did).await.map_err(|e| {
            // Resolution failure is a network-shaped condition (the DID host or
            // the resolver sidecar is down), so it is retriable.
            (
                RegistryError::Unreachable(format!(
                    "could not resolve trust-registry DID {}: {e}",
                    self.registry_did
                )),
                Vec::new(),
            )
        })?;
        let doc = serde_json::to_value(&resolved.doc).map_err(|e| {
            (
                RegistryError::Transient(format!(
                    "could not read the registry's DID document: {e}"
                )),
                Vec::new(),
            )
        })?;
        let theirs = ServiceCapabilities::from_did_document(&doc);
        let advertised = theirs.advertised();
        let ours = self.our_capabilities();
        let matched = select_protocol(&ours, &theirs, &self.registry_did).map_err(|e| {
            (
                classify_no_match(&ours, &advertised, e.to_string()),
                advertised.clone(),
            )
        })?;
        debug!(
            registry_did = %self.registry_did,
            protocol = %matched.protocol.as_str(),
            "selected trust-registry transport",
        );
        Ok((matched.protocol, advertised))
    }

    /// Publish what the last selection saw, for the diagnostics surface.
    fn record_selection(
        &self,
        advertised: Vec<Protocol>,
        active: Option<Protocol>,
        error: Option<String>,
    ) {
        let mut slot = match self.transport.write() {
            Ok(slot) => slot,
            // A poisoned lock means a panic while holding it. Diagnostics are
            // not worth propagating that into a registry call, so drop the
            // update rather than unwrap.
            Err(_) => return,
        };
        slot.advertised = advertised.iter().map(|p| p.as_str().to_string()).collect();
        slot.active = active.map(|p| p.as_str().to_string());
        slot.error = error;
    }

    /// What *this* VTC can speak to a peer, as a capability set.
    ///
    /// Not our advertised document: this is the **client** side. TSP and
    /// DIDComm need our mediator (hence the messaging handle), REST needs only
    /// an HTTP client, which we always have when a URL is configured. The
    /// endpoint strings are never read for our own side — [`select_protocol`]
    /// only tests presence — so they carry our identity for readability.
    fn our_capabilities(&self) -> ServiceCapabilities {
        let messaging_up = self.didcomm.get().is_some();
        ServiceCapabilities {
            tsp: (messaging_up && cfg!(feature = "tsp")).then(|| self.registry_did.clone()),
            didcomm: messaging_up.then(|| self.registry_did.clone()),
            rest: self.http.is_some().then(|| "rest-client".to_string()),
        }
    }

    /// Build, optionally sign, send, and await the reply for one task.
    ///
    /// `sign` is the spec's `IS_PROOF_REQUIRED` for the type: writes
    /// (`record/put`, `record/delete`) carry the VTC's Data-Integrity proof;
    /// reads (`record/query`, `recognition`) do not.
    async fn round_trip(
        &self,
        type_uri: &str,
        payload: Value,
        sign: bool,
        protocol: Protocol,
    ) -> Result<TrustTask<Value>, RegistryError> {
        let issuer = self.authority()?.to_string();
        let messaging = self.didcomm.get().ok_or_else(|| {
            RegistryError::Transient("VTC messaging is not running yet".to_string())
        })?;

        let mut doc = build_document(&issuer, &self.registry_did, type_uri, payload);
        if sign {
            let mut as_value = serde_json::to_value(&doc)
                .map_err(|e| RegistryError::Transient(format!("serialise document: {e}")))?;
            self.signer
                .sign_doc(&mut as_value)
                .await
                .map_err(|e| RegistryError::Transient(format!("sign document: {e}")))?;
            doc = serde_json::from_value(as_value)
                .map_err(|e| RegistryError::Transient(format!("reparse signed document: {e}")))?;
        }

        // Register before sending: a reply can land while the send is still
        // returning.
        let receiver = self.replies.register(&doc.id);
        let send = match protocol {
            Protocol::Tsp => self.send_tsp(messaging, &doc).await,
            Protocol::Didcomm => self.send_didcomm(messaging, &doc).await,
            // Handled by the callers, which delegate to the HTTP arm before
            // ever reaching a round trip.
            Protocol::Rest => Err(RegistryError::Permanent(
                "REST transport does not use the Trust-Task round trip".into(),
            )),
        };
        if let Err(e) = send {
            self.replies.abandon(&doc.id);
            return Err(e);
        }

        match tokio::time::timeout(self.reply_timeout, receiver).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_closed)) => {
                self.replies.abandon(&doc.id);
                Err(RegistryError::Transient("reply channel closed".to_string()))
            }
            Err(_elapsed) => {
                self.replies.abandon(&doc.id);
                // The registry may simply be slow, or the frame may have been
                // dropped in a reconnect. Either way the syncer's backoff owns
                // the retry — this is never a delivery confirmation.
                Err(RegistryError::Unreachable(format!(
                    "no reply from the trust registry within {}s",
                    self.reply_timeout.as_secs()
                )))
            }
        }
    }

    /// Pack the document in the DIDComm trust-task envelope and hand it to the
    /// delivery layer.
    async fn send_didcomm(
        &self,
        messaging: &VtcMessaging,
        doc: &TrustTask<Value>,
    ) -> Result<(), RegistryError> {
        let body = serde_json::to_value(doc)
            .map_err(|e| RegistryError::Transient(format!("serialise envelope body: {e}")))?;
        let envelope = Message::build(
            format!("urn:uuid:{}", Uuid::new_v4()),
            TRUST_TASK_ENVELOPE_TYPE.to_string(),
            body,
        )
        .from(messaging.vtc_did.clone())
        .to(self.registry_did.clone())
        .thid(doc.id.clone())
        .finalize();

        let (packed, _) = messaging
            .atm
            .pack_encrypted(
                &envelope,
                &self.registry_did,
                Some(&messaging.vtc_did),
                Some(&messaging.vtc_did),
            )
            .await
            .map_err(|e| RegistryError::Unreachable(format!("pack failed: {e}")))?;

        messaging
            .service
            .send(
                &self.registry_did,
                packed.into_bytes(),
                Delivery::BestEffort,
            )
            .await
            .map_err(|e| RegistryError::Unreachable(format!("send failed: {e}")))?;
        Ok(())
    }

    /// Seal the document in the `trust-tasks-tsp` binding envelope and route it
    /// to the registry over the existing mediator socket.
    #[cfg(feature = "tsp")]
    async fn send_tsp(
        &self,
        messaging: &VtcMessaging,
        doc: &TrustTask<Value>,
    ) -> Result<(), RegistryError> {
        let body = tsp_envelope(doc)?;
        // Route: our mediator, then the registry. TSP send is an HTTP post
        // through the same profile the pickup socket is bound to — no second
        // websocket (the mediator permits one per DID).
        let route = vec![messaging.mediator_did.clone(), self.registry_did.clone()];
        messaging
            .atm
            .tsp()
            .send_routed(&messaging.profile, &route, &body)
            .await
            .map_err(|e| RegistryError::Unreachable(format!("TSP send failed: {e}")))?;
        Ok(())
    }

    #[cfg(not(feature = "tsp"))]
    async fn send_tsp(
        &self,
        _messaging: &VtcMessaging,
        _doc: &TrustTask<Value>,
    ) -> Result<(), RegistryError> {
        // Unreachable in practice: `our_capabilities` never offers TSP without
        // the feature, so the match can't land here. Kept as a typed refusal
        // rather than an `unreachable!` so a future caller can't panic a daemon.
        Err(RegistryError::Permanent(
            "this build has no `tsp` feature and cannot send TSP frames".into(),
        ))
    }

    /// The TRQP record key for one member of this community.
    ///
    /// The four parts must match [`UpstreamRegistryClient::recognise`]'s query
    /// tuple exactly, or we publish records nobody looks up — a silent,
    /// green-status failure. Both sides read the same constants.
    fn record_key(&self, member_did: &str) -> Result<(String, String), RegistryError> {
        Ok((member_did.to_string(), self.authority()?.to_string()))
    }
}

/// Is an empty transport intersection a configuration fault, or are we just not
/// ready yet?
///
/// The distinction is load-bearing and was got wrong at first: at boot the
/// registry client exists before the messaging listener has published its
/// handle, so `our_capabilities` is momentarily **empty** and every peer looks
/// like "no transport in common". Reported as `Permanent` — which is what an
/// empty intersection normally means — that transient startup window would park
/// the first sync jobs in `Failed`, where the syncer never retries them. The
/// health probe recovered on its next tick and looked fine; the queue would not
/// have.
///
/// So: if *we* can currently speak nothing, this is our own startup race and it
/// is retriable. Only an intersection that is empty while we do have a
/// transport available is the operator's configuration to fix.
fn classify_no_match(
    ours: &ServiceCapabilities,
    theirs: &[Protocol],
    detail: String,
) -> RegistryError {
    if ours.advertised().is_empty() {
        return RegistryError::Transient(format!(
            "no transport available yet to reach the trust registry (VTC messaging is still \
             starting, and no REST arm is configured); the registry advertises {theirs:?}",
        ));
    }
    RegistryError::Permanent(detail)
}

/// Wrap a document in the `trust-tasks-tsp` binding envelope.
fn tsp_envelope(doc: &TrustTask<Value>) -> Result<Vec<u8>, RegistryError> {
    let document = serde_json::to_value(doc)
        .map_err(|e| RegistryError::Transient(format!("serialise document: {e}")))?;
    serde_json::to_vec(&json!({ "type": TSP_ENVELOPE_TYPE, "document": document }))
        .map_err(|e| RegistryError::Transient(format!("serialise TSP envelope: {e}")))
}

/// Classify a reply document into "the task succeeded" or a typed failure.
///
/// The split that matters is retriable versus not: an `internalError` or
/// `unavailable` is worth another attempt, whereas `permissionDenied` (the
/// VTC's DID is not in the registry's `admin_dids`) or `proofInvalid` needs an
/// operator and must not spin.
fn classify(doc: &TrustTask<Value>, expect_slug: &str) -> Result<(), RegistryError> {
    let slug = doc.type_uri.slug();
    if slug == "trust-task-error" {
        let code = doc
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let message = doc
            .payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("");
        let detail = format!("registry rejected {expect_slug}: {code}");
        let detail = if message.is_empty() {
            detail
        } else {
            format!("{detail} ({message})")
        };
        return match code {
            "internalError" | "unavailable" => Err(RegistryError::Transient(detail)),
            _ => Err(RegistryError::Permanent(detail)),
        };
    }
    if !doc.type_uri.is_response() || slug != expect_slug {
        // A correlated reply of the wrong type is a contract bug on one side or
        // the other. Retrying cannot fix it, but calling it permanent would
        // strand a job that a redeploy would fix — transient and loud.
        return Err(RegistryError::Transient(format!(
            "expected a {expect_slug} response, got `{}`",
            doc.type_uri
        )));
    }
    Ok(())
}

/// Build the TRQP record for a member as this community asserts it.
///
/// The spec's `TrustRecord` carries no validity window, so the membership
/// status and its dates ride in `context` — the record's own opaque governance
/// object. `recognized` is the machine-readable half: an active member is
/// recognised, a departed one is not, which is what a TRQP verifier reads.
fn trust_record(authority_did: &str, record: &RegistryRecord) -> Value {
    let recognised = matches!(record.status, RegistryStatus::Active);
    let mut context = json!({
        "status": if recognised { "active" } else { "departed" },
        "activeFrom": record.active_from.to_rfc3339(),
    });
    if let Some(active_to) = record.active_to {
        context["activeTo"] = json!(active_to.to_rfc3339());
    }
    json!({
        "entity_id": record.member_did,
        "authority_id": authority_did,
        "action": RECOGNISE_ACTION,
        "resource": TRUST_GRAPH_RESOURCE,
        "record_type": "recognition",
        "recognized": recognised,
        "context": context,
    })
}

/// Rebuild a [`RegistryRecord`] from a TRQP record returned by the registry.
///
/// Absence is read restrictively (R3.3): a record whose `recognized` is missing
/// is not treated as an active member.
fn registry_record_from(value: &Value) -> Option<RegistryRecord> {
    let member_did = value.get("entity_id")?.as_str()?.to_string();
    let recognised = value
        .get("recognized")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let context = value.get("context");
    let parse_time = |key: &str| {
        context
            .and_then(|c| c.get(key))
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    let now = chrono::Utc::now();
    Some(RegistryRecord {
        member_did,
        status: if recognised {
            RegistryStatus::Active
        } else {
            RegistryStatus::Departed
        },
        active_from: parse_time("activeFrom").unwrap_or(now),
        active_to: parse_time("activeTo"),
        last_synced_at: now,
    })
}

#[async_trait]
impl TrustRegistryClient for MessagingRegistryClient {
    async fn publish_member(&self, record: &RegistryRecord) -> Result<(), RegistryError> {
        let authority = self.authority()?.to_string();
        match self.select().await? {
            Protocol::Rest => self.rest()?.publish_member(record).await,
            protocol => {
                let payload = json!({ "record": trust_record(&authority, record) });
                let reply = self.round_trip(RECORD_PUT, payload, true, protocol).await?;
                classify(&reply, "registry/record/put")
            }
        }
    }

    async fn delete_member(&self, member_did: &str) -> Result<(), RegistryError> {
        let (entity_id, authority_id) = self.record_key(member_did)?;
        match self.select().await? {
            Protocol::Rest => self.rest()?.delete_member(member_did).await,
            protocol => {
                let payload = json!({
                    "entity_id": entity_id,
                    "authority_id": authority_id,
                    "action": RECOGNISE_ACTION,
                    "resource": TRUST_GRAPH_RESOURCE,
                });
                let reply = self
                    .round_trip(RECORD_DELETE, payload, true, protocol)
                    .await?;
                classify(&reply, "registry/record/delete")
            }
        }
    }

    async fn read_member(&self, member_did: &str) -> Result<Option<RegistryRecord>, RegistryError> {
        let (entity_id, authority_id) = self.record_key(member_did)?;
        match self.select().await? {
            Protocol::Rest => self.rest()?.read_member(member_did).await,
            protocol => {
                // Deliberately *not* a fully-keyed fetch: supplying all four key
                // parts makes this an exact lookup that errors on a miss, and a
                // missing member is a normal answer, not a failure. Three
                // filters keep it an enumeration — empty list on a miss — and
                // we match `resource` here.
                let payload = json!({
                    "entity_id": entity_id,
                    "authority_id": authority_id,
                    "action": RECOGNISE_ACTION,
                    "limit": 50,
                });
                let reply = self
                    .round_trip(RECORD_QUERY, payload, false, protocol)
                    .await?;
                classify(&reply, "registry/record/query")?;
                let found = reply
                    .payload
                    .get("records")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|r| {
                        r.get("resource").and_then(Value::as_str) == Some(TRUST_GRAPH_RESOURCE)
                    })
                    .and_then(registry_record_from);
                Ok(found)
            }
        }
    }

    async fn recognise(&self, foreign_issuer_did: &str) -> Result<bool, RegistryError> {
        let authority = self.authority()?.to_string();
        match self.select().await? {
            Protocol::Rest => self.rest()?.recognise(foreign_issuer_did).await,
            protocol => {
                let payload = json!({
                    "entity_id": foreign_issuer_did,
                    "authority_id": authority,
                    "action": RECOGNISE_ACTION,
                    "resource": TRUST_GRAPH_RESOURCE,
                });
                let reply = self
                    .round_trip(RECOGNITION, payload, false, protocol)
                    .await?;
                classify(&reply, "registry/recognition")?;
                // Absence is "not recognised", never "recognised" — the
                // restrictive reading a missing scope field always gets
                // (R3.3). This is also what makes the Trust-Task arm immune to
                // the HTTP arm's `recognized`-optionality defect, where an
                // omitted field parsed as a transport failure and surfaced as
                // an indefinite 503.
                Ok(reply
                    .payload
                    .get("recognized")
                    .and_then(Value::as_bool)
                    .unwrap_or(false))
            }
        }
    }

    fn transport(&self) -> RegistryTransport {
        // A poisoned lock only happens if a writer panicked mid-update; report
        // the address we were configured with rather than failing a diagnostics
        // read over it.
        self.transport
            .read()
            .map(|t| t.clone())
            .unwrap_or_else(|_| RegistryTransport {
                did: Some(self.registry_did.clone()),
                ..RegistryTransport::default()
            })
    }

    async fn health(&self) -> Result<(), RegistryError> {
        match self.select().await? {
            Protocol::Rest => self.rest()?.health().await,
            protocol => {
                // A read-only `record/query` round trip. It needs no proof and
                // no admin ACL, so it works on a registry that would refuse our
                // writes — but unlike an HTTP GET of a static document it
                // exercises the whole path we actually depend on: mediator,
                // transport, dispatcher, storage.
                //
                // Any correlated reply proves liveness, **including a rejection**
                // — the registry answered. Only silence is unhealthy, which is
                // what makes this signal re-falsifiable (R6.2).
                let payload = json!({ "limit": 1 });
                match self
                    .round_trip(RECORD_QUERY, payload, false, protocol)
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(RegistryError::Permanent(e)) => {
                        // A rejection still proves the registry is answering.
                        debug!(error = %e, "registry health probe answered with a rejection");
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }
}

impl MessagingRegistryClient {
    /// The REST arm, or a `Permanent` refusal when the registry advertises
    /// `TRQPRest` but no `registry.url` is configured.
    fn rest(&self) -> Result<&UpstreamRegistryClient, RegistryError> {
        self.http.as_ref().ok_or_else(|| {
            RegistryError::Permanent(
                "the trust registry advertises only REST, but `registry.url` is not configured — \
                 set it, or advertise a messaging transport on the registry's DID"
                    .into(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chrono::{TimeZone, Utc};

    /// The `#response` to `request_type`.
    ///
    /// Built from the whole request URI rather than by interpolating a slug
    /// into a `trusttasks.org/spec/…` template: the canonical-task census
    /// scans source for `spec/` literals and asserts the registry publishes
    /// each one, so a templated URI reads to it as a bound task named
    /// `{slug}`.
    fn record_doc(request_type: &str, payload: Value) -> TrustTask<Value> {
        TrustTask::new(
            "urn:uuid:reply".to_string(),
            format!("{request_type}#response").parse().unwrap(),
            payload,
        )
    }

    fn error_doc(code: &str) -> TrustTask<Value> {
        // Takes the version from the emitter rather than naming one, so a
        // framework bump moves this fixture with the code under test instead of
        // stranding it a version behind. Backward acceptance of an *older*
        // error document is covered deliberately, and separately, by
        // `tests/registry_didcomm.rs`, which pins `0.1`.
        TrustTask::new(
            "urn:uuid:err".to_string(),
            crate::trust_tasks::helpers::framework_error_type_uri(),
            json!({ "code": code, "message": "nope" }),
        )
    }

    #[test]
    fn tsp_envelope_type_matches_the_binding() {
        // Pinned against `trust_tasks_tsp::ENVELOPE_TYPE`. A drift here is a
        // silent interop break: the registry rejects an envelope whose `type`
        // it does not recognise, and the failure surfaces only as a timeout.
        assert_eq!(
            TSP_ENVELOPE_TYPE,
            "https://trusttasks.org/binding/tsp/0.1/envelope"
        );
    }

    #[test]
    fn tsp_envelope_wraps_the_document() {
        let doc = build_document(
            "did:webvh:vtc",
            "did:webvh:registry",
            RECORD_QUERY,
            json!({ "limit": 1 }),
        );
        let bytes = tsp_envelope(&doc).unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["type"], TSP_ENVELOPE_TYPE);
        assert_eq!(parsed["document"]["type"], RECORD_QUERY);
    }

    #[test]
    fn permission_denied_is_permanent_and_internal_error_is_transient() {
        // `permissionDenied` means the VTC's DID is not in the registry's
        // `admin_dids`. Retrying cannot fix that, and a retry loop would hide
        // it behind an ever-growing queue instead of surfacing a failed job.
        let denied = classify(&error_doc("permissionDenied"), "registry/record/put").unwrap_err();
        assert!(matches!(denied, RegistryError::Permanent(_)));
        assert!(!denied.is_retriable());

        let internal = classify(&error_doc("internalError"), "registry/record/put").unwrap_err();
        assert!(internal.is_retriable());
    }

    #[test]
    fn a_wrong_response_type_does_not_pass_as_success() {
        let wrong = record_doc(RECORD_QUERY, json!({ "records": [] }));
        assert!(classify(&wrong, "registry/record/put").is_err());
        let right = record_doc(RECORD_PUT, json!({ "ok": true, "created": true }));
        assert!(classify(&right, "registry/record/put").is_ok());
    }

    #[test]
    fn published_record_carries_the_query_tuple_and_recognition() {
        let mut record = RegistryRecord::fresh_active("did:key:zMember");
        record.active_from = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        let value = trust_record("did:webvh:vtc", &record);

        // The four key parts must equal the tuple `recognise()` queries with,
        // or we publish records that are never read.
        assert_eq!(value["entity_id"], "did:key:zMember");
        assert_eq!(value["authority_id"], "did:webvh:vtc");
        assert_eq!(value["action"], RECOGNISE_ACTION);
        assert_eq!(value["resource"], TRUST_GRAPH_RESOURCE);
        assert_eq!(value["record_type"], "recognition");
        assert_eq!(value["recognized"], true);
        assert_eq!(value["context"]["status"], "active");
        assert_eq!(value["context"]["activeFrom"], "2026-08-01T00:00:00+00:00");
    }

    #[test]
    fn a_departed_member_is_published_as_not_recognised() {
        let from = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        let record = RegistryRecord::departed("did:key:zGone", from, Some(to));
        let value = trust_record("did:webvh:vtc", &record);
        assert_eq!(value["recognized"], false);
        assert_eq!(value["context"]["status"], "departed");
        assert_eq!(value["context"]["activeTo"], "2026-08-01T00:00:00+00:00");
    }

    #[test]
    fn a_record_without_recognized_reads_as_departed() {
        // Absence is read restrictively: a record we cannot confirm is a
        // recognition is not treated as live membership.
        let parsed = registry_record_from(&json!({
            "entity_id": "did:key:zMember",
            "authority_id": "did:webvh:vtc",
            "action": RECOGNISE_ACTION,
            "resource": TRUST_GRAPH_RESOURCE,
            "record_type": "recognition",
        }))
        .unwrap();
        assert_eq!(parsed.status, RegistryStatus::Departed);
    }

    #[test]
    fn record_round_trips_through_the_wire_shape() {
        let record = RegistryRecord::fresh_active("did:key:zMember");
        let wire = trust_record("did:webvh:vtc", &record);
        let back = registry_record_from(&wire).unwrap();
        assert_eq!(back.member_did, record.member_did);
        assert_eq!(back.status, RegistryStatus::Active);
        assert_eq!(back.active_from.timestamp(), record.active_from.timestamp());
    }

    /// A client with no messaging, no resolver and no REST arm — enough to
    /// exercise everything that happens before a transport is chosen.
    fn client_with(authority_did: Option<&str>) -> MessagingRegistryClient {
        MessagingRegistryClient::new(
            "did:webvh:registry".into(),
            authority_did.map(str::to_string),
            Arc::new(OnceCell::new()),
            Arc::new(LocalSigner::from_ed25519_seed(
                "did:webvh:vtc".into(),
                &[7u8; 32],
            )),
            PendingReplies::new(),
            None,
            None,
        )
    }

    #[test]
    fn not_being_ready_is_transient_but_a_real_mismatch_is_permanent() {
        // The boot race: the registry client is built before the messaging
        // listener publishes its handle, so for a moment we can speak nothing
        // and every peer reads as "no transport in common". Permanent there
        // would park the first sync jobs in `Failed`, which the syncer never
        // retries — the health probe would recover on its next tick and the
        // queue would stay broken.
        let not_ready = ServiceCapabilities::default();
        let err = classify_no_match(&not_ready, &[Protocol::Didcomm], "no overlap".into());
        assert!(err.is_retriable(), "got {err:?}");
        assert!(
            err.to_string().contains("still \nstarting")
                || err.to_string().contains("still starting"),
            "the message should name the startup race: {err}",
        );

        // We can speak DIDComm and the peer offers only TSP: a genuine
        // configuration fault, and retrying it forever would hide it behind an
        // ever-growing queue.
        let ready = ServiceCapabilities {
            didcomm: Some("did:webvh:mediator".into()),
            ..ServiceCapabilities::default()
        };
        let err = classify_no_match(&ready, &[Protocol::Tsp], "no overlap".into());
        assert!(!err.is_retriable(), "got {err:?}");
    }

    #[test]
    fn the_transport_snapshot_carries_the_did_before_any_call() {
        // The diagnostics surface must be able to name the registry from the
        // moment it is configured. Waiting for the first successful call would
        // leave the page blank in exactly the situation an operator opens it:
        // nothing is working yet.
        let client = client_with(None);
        let snapshot = client.transport();
        assert_eq!(snapshot.did.as_deref(), Some("did:webvh:registry"));
        assert!(snapshot.advertised.is_empty());
        assert_eq!(snapshot.active, None);
    }

    #[test]
    fn a_failed_selection_records_the_peer_set_alongside_the_error() {
        // "advertised [tsp], active none, error: no transport in common" is a
        // diagnosis an operator can act on. Recording the error while dropping
        // what the peer offered would leave them resolving the DID by hand to
        // learn the half that matters.
        let client = client_with(None);
        client.record_selection(vec![Protocol::Tsp], None, Some("no overlap".into()));
        let snapshot = client.transport();
        assert_eq!(snapshot.advertised, vec!["tsp".to_string()]);
        assert_eq!(snapshot.active, None);
        assert_eq!(snapshot.error.as_deref(), Some("no overlap"));
    }

    #[test]
    fn a_later_success_clears_the_earlier_error() {
        // Selection is re-evaluated per call, so the snapshot has to be
        // re-falsifiable in both directions (R6.2): a registry that adds the
        // missing service must stop reading as broken without a restart.
        let client = client_with(None);
        client.record_selection(vec![], None, Some("no overlap".into()));
        client.record_selection(vec![Protocol::Didcomm], Some(Protocol::Didcomm), None);
        let snapshot = client.transport();
        assert_eq!(snapshot.advertised, vec!["didcomm".to_string()]);
        assert_eq!(snapshot.active.as_deref(), Some("didcomm"));
        assert_eq!(snapshot.error, None);
    }

    #[test]
    fn our_capabilities_offer_rest_only_with_a_url_and_messaging_only_when_up() {
        let client = client_with(Some("did:webvh:vtc"));
        let caps = client.our_capabilities();
        // Messaging is not up (empty OnceCell) and no URL is configured, so we
        // can speak nothing — `select_protocol` will say so rather than the
        // client silently picking a transport it cannot use.
        assert_eq!(caps.advertised(), Vec::<Protocol>::new());
    }

    #[tokio::test]
    async fn every_call_refuses_before_setup() {
        // No `vtc_did` means no TRQP authority: writing a half-keyed record
        // would publish rows under an empty authority that nothing can query.
        let client = client_with(None);
        let err = client
            .delete_member("did:key:zMember")
            .await
            .expect_err("refuses without an authority DID");
        assert!(matches!(err, RegistryError::Permanent(_)));
        assert!(err.to_string().contains("vtc_did"));
    }

    #[tokio::test]
    async fn a_write_is_transient_while_messaging_is_down() {
        // Messaging comes up after the client is built; a call in that window
        // must be retriable, not a permanent failure that parks the job.
        let client =
            client_with(Some("did:webvh:vtc")).with_reply_timeout(Duration::from_millis(50));
        let err = client
            .round_trip(
                RECORD_QUERY,
                json!({ "limit": 1 }),
                false,
                Protocol::Didcomm,
            )
            .await
            .expect_err("messaging is not running");
        assert!(err.is_retriable(), "got {err:?}");
    }
}
