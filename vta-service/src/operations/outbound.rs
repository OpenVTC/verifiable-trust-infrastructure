//! Sending a Trust Task to another party, over whatever that party advertises.
//!
//! # Why this is one place
//!
//! Adding an external service should be choosing a task URI and a recipient
//! DID. It was not: `room_host` hand-rolled REST, `webvh_didcomm` hand-rolled
//! DIDComm, and the TSP path hand-rolled its own carriage — three carriages for
//! one wire contract, and a fourth service would have been a fourth.
//!
//! The cost of that was not duplication, which is cheap. It was **divergence
//! nobody could see**: the two existing paths disagreed about whether a reply is
//! evidence. `room_host` verified the proof and bound the signer to the party it
//! addressed; `webvh_didcomm` verified nothing at all. Both were reasonable
//! inside their own file and only one of them can be right, and the difference
//! was invisible because there was no place the question was asked once. Hence
//! [`ReplyTrust`]: the answer is now an argument, so a caller that wants the
//! weaker one has to write it down.
//!
//! # What this is not
//!
//! Not a Trust-Task *client* in the `vta-sdk` sense, and not a second document
//! layer. [`vta_sdk::client::VtaClient`] signs from a `ClientIdentity` holding a
//! raw `private_key_multibase`, and **a VTA never holds its own keys in that
//! shape** — it derives, signs and zeroizes behind
//! [`crate::operations::keys::sign_payload`]. So the caller builds and signs its
//! own document, and only the bytes travel here.
//!
//! # What this is deliberately not: pushing to a device
//!
//! `trust_tasks::step_up::try_push_over_tsp` and the DIDComm fallback beside it
//! also put Trust Tasks on a wire, and they are **not** folded in here. Three
//! reasons, and the first is the one that decides it:
//!
//! - **Selection cannot be by advertisement.** A device is a wallet behind a
//!   mediator; its DID often advertises nothing a sender could dial. The push
//!   path chooses by *learned reachability* — `tsp_reach`, a fact recorded from
//!   inbound frames — which is a different question from "what does this peer
//!   say it accepts", and the right one for a device.
//! - **There is no reply to correlate.** A push is delivered, not asked.
//! - **Delivery is durable and has a doorbell**: a buffered `PendingResponse`
//!   and a gateway wake, neither of which means anything for a request whose
//!   answer the caller is waiting on.
//!
//! Giving this function a no-reply mode and a pluggable selection strategy to
//! absorb that would make it less clear about what it does, not more. What the
//! two paths **do** share is the thing that matters for adding a transport: the
//! binding. Both go through `vta_sdk::tsp_binding` for TSP, and both would go
//! through the next one the same way.
//!
//! # Transport: an intersection, not a downgrade
//!
//! The protocol used is the highest-preference one present in **both** parties'
//! advertisements. [`Protocol::PREFERENCE_ORDER`] is the workspace order — TSP,
//! then DIDComm, then REST — and [`OUTBOUND_SUPPORTED`] is this VTA's half.
//! A peer with nothing in the intersection gets a **loud typed refusal naming
//! both sets**, never a quiet fallback: downgrading past what a peer advertises
//! is forbidden, and being honest that this agent cannot yet *initiate* on a
//! protocol is a different statement. The error says which it is.
//!
//! # Fire-and-forget, and what correlation actually is
//!
//! A Trust Task is a document. Correlation is a document concern — SPEC §4.9's
//! `threadId`, falling back to `id` — and none of the three transports has
//! request/response semantics of its own. REST happens to hand the reply back on
//! the same socket; that is REST's accident, not the framework's model.
//!
//! This is what TSP took longest to get. TSP's binding (`trust-tasks-tsp`)
//! offers `pack` and `unpack` and nothing else, by design, so reaching it was
//! **not** a matter of building a request/reply call over `send_routed`: it was
//! teaching the inbound path that a document threading to one we sent is a reply
//! rather than a request — which `messaging::tsp_inbound::dispatch_one` did not
//! do, since it authorizes every frame and dispatches it as a request. Until
//! that landed, naming TSP in `OUTBOUND_SUPPORTED` would have produced a request
//! that is sent and never answered: worse than an honest refusal, because it
//! times out instead of saying why. It is named there now, under `cfg(tsp)`,
//! because the spine correlates the reply.

use serde_json::Value;
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities};
use vti_common::error::{AppError, bad_gateway_error};

#[cfg(feature = "didcomm")]
use crate::didcomm_bridge::DIDCommBridge;

/// How long to wait for a reply over DIDComm, in seconds.
#[cfg(feature = "didcomm")]
const DIDCOMM_REPLY_TIMEOUT_SECS: u64 = 30;

/// The DIDComm message `type` every Trust Task rides under.
///
/// Named once, here, for every caller. It used to be produced per client — and
/// the one that did it took care to return it from a single function precisely
/// because getting it wrong fails *silently*: a conformant host rejects a
/// message typed with the task URI without telling you why. That care is now
/// structural instead of local; a caller has no way to supply a message type,
/// so there is nothing to get wrong.
const DIDCOMM_MESSAGE_TYPE: &str = trust_tasks_didcomm::ENVELOPE_TYPE;

/// The protocols this VTA can **initiate** a Trust-Task request on.
///
/// Order here is not the preference order — [`Protocol::PREFERENCE_ORDER`] is,
/// and [`pick_transport`] walks that and consults this only for membership. A
/// second ordering would be a second thing to keep in step.
pub const OUTBOUND_SUPPORTED: &[Protocol] = &[
    // Only where this build can actually initiate it. A VTA compiled without
    // `didcomm` has no bridge to send on, and naming a protocol here that the
    // build cannot reach would turn a compile-time absence into a runtime
    // "named in OUTBOUND_SUPPORTED but has no send path" — a worse way to find
    // out.
    #[cfg(feature = "tsp")]
    Protocol::Tsp,
    #[cfg(feature = "didcomm")]
    Protocol::Didcomm,
    Protocol::Rest,
];

/// How long to wait for a reply over TSP, in seconds.
///
/// The same window DIDComm gets. TSP delivers through the same mediator socket,
/// so the thing being waited on is the peer's processing time either way.
#[cfg(feature = "tsp")]
const TSP_REPLY_TIMEOUT_SECS: u64 = 30;

/// What makes a reply believable.
///
/// A reply is bytes off a socket. What licenses acting on it is a separate
/// question from how it arrived, and the two callers of this module had
/// different answers to it — which is the reason this is an argument rather
/// than a policy baked in here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyTrust {
    /// Require a verifying proof whose signer **is the party we addressed**.
    ///
    /// The default for anything whose answer is acted on. Both halves matter and
    /// the second is the one easy to omit: a proof by
    /// `did:webvh:…:someone-else#key-1` verifies perfectly well, and that it is
    /// not the party you asked is a separate check. Skipping it turns "signed by
    /// somebody" into "signed by the host".
    SignedByRecipient,

    /// Believe the authenticated transport alone, and nothing further.
    ///
    /// Only defensible where the transport authenticates the peer end to end
    /// **and** the reply confers nothing — a path reservation, an availability
    /// probe. A caller choosing this is asserting both; the variant exists so
    /// that assertion is written at the call site instead of being the silent
    /// consequence of nobody having added a check.
    TransportAuthenticated,
}

/// A TSP transport, plus the registry that turns it into a round trip.
///
/// Carriage is [`TspTransport`](crate::messaging::tsp_transport::TspTransport)'s
/// job and lives there, shared with the inbound reply path and the device push.
/// The only thing this adds is the half those two do not need: TSP has no
/// request/response — `trust-tasks-tsp` is `pack` and `unpack`, deliberately,
/// because correlation belongs to the document layer — so a round trip here is
/// a send now and an inbound document later, and without somewhere to keep the
/// waiter between them an agent can only receive.
///
/// That split is why the mediator is not a field: it belongs to the transport,
/// which reads it off the profile that will seal to it. This struct used to
/// carry its own copy out of `AppConfig`, which was a second source for one fact
/// with nothing checking that the two agreed.
#[cfg(feature = "tsp")]
use affinidi_messaging_sdk::RecoveryAction;

/// The outcome of one send-and-await-reply over TSP.
#[cfg(feature = "tsp")]
enum TspAttempt {
    /// The peer answered; the reply document.
    Reply(Value),
    /// No answer within the window — the §7.2.2 silent-drop signature.
    Timeout,
    /// The reply waiter was cancelled (the registry was cleared) — not a timeout.
    Cancelled,
    /// The seal/route failed before the frame left; carries the reason.
    SendFailed(String),
}

/// Whether a Trust Task is safe to blind-resend after re-forming a relationship.
/// A §7.2.2 drop is indistinguishable from a lost reply, so only a task whose
/// second execution does no harm is resent; the rest are healed and surfaced.
/// Same gate as the client-side self-repair (vta-sdk #1544).
#[cfg(feature = "tsp")]
fn resend_after_reform(type_uri: &str) -> bool {
    vta_sdk::retry_safety::retry_safety(type_uri).is_some_and(|c| c.is_blind_retry_safe())
}

/// Wall-clock milliseconds for the recovery coordinator's clock.
#[cfg(feature = "tsp")]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(feature = "tsp")]
#[derive(Clone)]
pub struct TspSender {
    transport: crate::messaging::tsp_transport::TspTransport,
    replies: crate::trust_tasks::pending_replies::PendingReplies,
    /// Shared D6 single-flight/backoff recovery, owned by `AppState`. Cloned in
    /// (an `Arc`) rather than rebuilt per sender so concurrent sends to one peer
    /// coalesce onto a single re-invite.
    recovery: std::sync::Arc<affinidi_messaging_sdk::RecoveryCoordinator>,
    /// How long to wait for a reply before treating a send as a §7.2.2 drop.
    /// A field rather than the bare [`TSP_REPLY_TIMEOUT_SECS`] const only so a
    /// test can shorten it — production always gets the const default.
    reply_timeout: std::time::Duration,
}

#[cfg(feature = "tsp")]
impl TspSender {
    /// `None` when this node cannot initiate TSP — no live mediator session, so
    /// no profile that can seal. Absence here removes TSP from selection rather
    /// than failing at send time, which is the difference between a peer being
    /// reached over its next-preferred transport and a request that errors.
    pub(crate) fn from_app_state(state: &crate::server::AppState) -> Option<Self> {
        Some(Self {
            transport: state.tsp_transport()?,
            replies: state.pending_replies.clone(),
            recovery: state.tsp_recovery.clone(),
            reply_timeout: std::time::Duration::from_secs(TSP_REPLY_TIMEOUT_SECS),
        })
    }

    /// Shorten the reply timeout — test-only, so a recovery test does not wait
    /// the full 30s per dropped attempt. Gated on `transport-harness` too,
    /// because that is where its only callers (the D6 tests) live; a plain
    /// `cfg(test)` build without the harness feature would see it as dead code.
    #[cfg(all(test, feature = "transport-harness"))]
    pub(crate) fn with_reply_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.reply_timeout = timeout;
        self
    }

    /// The shared recovery coordinator, for asserting attempt/give-up counts in
    /// a test.
    #[cfg(all(test, feature = "transport-harness"))]
    pub(crate) fn recovery(&self) -> &affinidi_messaging_sdk::RecoveryCoordinator {
        &self.recovery
    }

    /// Drive the D6 recovery for a `recipient` whose send just timed out —
    /// exposed for the recovery test; production reaches it through
    /// [`send_tsp`](Outbound::send_tsp).
    #[cfg(all(test, feature = "transport-harness"))]
    pub(crate) async fn recover_for_test(
        &self,
        recipient: &str,
        thread: &str,
        framed: &[u8],
        type_uri: &str,
    ) -> Result<Value, AppError> {
        self.recover_send_tsp(recipient, thread, framed, type_uri)
            .await
    }

    /// Register a reply waiter for `thread`, send `framed` to `recipient`, and
    /// await the reply within the TSP window. One attempt, no recovery.
    /// `reestablish` picks the re-inviting send (`send_reestablishing`) over the
    /// plain routed send — the recovery path uses it after a reset.
    async fn send_and_await(
        &self,
        recipient: &str,
        thread: &str,
        framed: &[u8],
        reestablish: bool,
    ) -> TspAttempt {
        // Registered before the frame leaves: a reply that arrived between
        // sending and registering would find nothing waiting.
        let waiting = self.replies.register(thread);
        let sent = if reestablish {
            self.transport.send_reestablishing(recipient, framed).await
        } else {
            self.transport.send_to(recipient, framed).await
        };
        if let Err(e) = sent {
            self.replies.abandon(thread);
            return TspAttempt::SendFailed(e.to_string());
        }
        match tokio::time::timeout(self.reply_timeout, waiting).await {
            Ok(Ok(reply)) => match serde_json::to_value(reply) {
                Ok(v) => TspAttempt::Reply(v),
                Err(e) => TspAttempt::SendFailed(format!("re-serialise the reply: {e}")),
            },
            Ok(Err(_)) => {
                self.replies.abandon(thread);
                TspAttempt::Cancelled
            }
            Err(_elapsed) => {
                self.replies.abandon(thread);
                TspAttempt::Timeout
            }
        }
    }

    /// D6 self-repair on a reply-timeout (design note `tsp-relationship-recovery.md`).
    ///
    /// A §7.2.2 drop is silent, so a reply-timeout may mean the peer lost its
    /// half of the relationship. Ask the shared [`RecoveryCoordinator`] whether
    /// to act: `Start` gives this call the single-flight token (a concurrent send
    /// to the same peer gets `InFlight` and coalesces, so one lost peer is not
    /// invite-flooded); `Backoff`/`GiveUp` cap a genuinely-down peer. On `Start`
    /// we reset our stale half (safe against a false positive via D2 reconcile),
    /// then for a retry-safe task re-invite-and-resend once — recovering in this
    /// call — while a task that could double-execute is only healed, its resend
    /// left to the caller.
    async fn recover_send_tsp(
        &self,
        recipient: &str,
        thread: &str,
        framed: &[u8],
        type_uri: &str,
    ) -> Result<Value, AppError> {
        let timed_out = || {
            bad_gateway_error(format!(
                "`{recipient}` did not answer over TSP within {TSP_REPLY_TIMEOUT_SECS}s"
            ))
        };
        let Some(our) = self.transport.our_vid() else {
            return Err(timed_out());
        };
        let now = now_ms();

        // One jittered base-backoff hold-off per failed attempt; the coordinator
        // still caps the peer at `max_attempts` (GiveUp). Growing the delay with
        // the attempt count needs an accessor the coordinator does not expose, so
        // this first increment uses the base delay — single-flight and the cap
        // are the herd-control properties that matter here.
        let backoff = || {
            self.recovery
                .retry_delay(0, 1.0)
                .unwrap_or(std::time::Duration::from_secs(1))
        };

        match self.recovery.begin(&our, recipient, now).await {
            RecoveryAction::Start => {
                if let Err(e) = self.transport.reset_relationship(recipient).await {
                    self.recovery
                        .settle_failure(&our, recipient, now, backoff())
                        .await;
                    return Err(bad_gateway_error(format!(
                        "could not re-establish the TSP relationship with `{recipient}`: {e}"
                    )));
                }
                if resend_after_reform(type_uri) {
                    match self.send_and_await(recipient, thread, framed, true).await {
                        TspAttempt::Reply(v) => {
                            self.recovery.settle_success(&our, recipient).await;
                            Ok(v)
                        }
                        _ => {
                            self.recovery
                                .settle_failure(&our, recipient, now, backoff())
                                .await;
                            Err(bad_gateway_error(format!(
                                "`{recipient}` did not answer over TSP after re-establishing the \
                                 relationship"
                            )))
                        }
                    }
                } else {
                    // Not safe to blind-resend — a duplicate could double-execute.
                    // Re-invite so the caller's retry lands, then report.
                    if let Err(e) = self.transport.relate(recipient).await {
                        self.recovery
                            .settle_failure(&our, recipient, now, backoff())
                            .await;
                        return Err(bad_gateway_error(format!(
                            "could not re-establish the TSP relationship with `{recipient}`: {e}"
                        )));
                    }
                    self.recovery.settle_success(&our, recipient).await;
                    Err(bad_gateway_error(format!(
                        "`{recipient}` did not answer over TSP; the relationship was re-established \
                         — retry the operation"
                    )))
                }
            }
            RecoveryAction::InFlight => Err(bad_gateway_error(format!(
                "re-establishing the TSP relationship with `{recipient}` is already in flight — retry"
            ))),
            RecoveryAction::Backoff(_) => Err(bad_gateway_error(format!(
                "backing off before re-establishing the TSP relationship with `{recipient}` — retry \
                 later"
            ))),
            RecoveryAction::GiveUp => Err(bad_gateway_error(format!(
                "gave up re-establishing the TSP relationship with `{recipient}` after repeated \
                 failures"
            ))),
        }
    }
}

/// The transports this VTA can reach a peer on, and the things needed to use
/// them.
///
/// A struct rather than loose arguments because the set travels together: drop
/// the resolver and there is nothing to read a peer's advertisement from; drop
/// the bridge and DIDComm silently stops being selectable.
pub struct Outbound<'a> {
    // Private, and the constructors below are the only way in. A struct literal
    // is how a caller silently opts out of a transport: `webvh_didcomm` built
    // one, so adding TSP here broke it at compile time — which was lucky. The
    // next field added would have broken it the same way, or worse, been given
    // a plausible default that quietly removed a transport from selection.
    resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    /// What a TSP send needs: the socket, the profile that seals, the mediator
    /// to route through, and somewhere to leave the waiter. Absent in a build
    /// without `tsp`, along with its arm and its entry in
    /// [`OUTBOUND_SUPPORTED`].
    #[cfg(feature = "tsp")]
    tsp: Option<TspSender>,
    /// Absent in a build without `didcomm`, along with the arm that uses it and
    /// the entry in [`OUTBOUND_SUPPORTED`] that would select it.
    #[cfg(feature = "didcomm")]
    bridge: &'a DIDCommBridge,
}

impl<'a> Outbound<'a> {
    /// A seam assembled from borrowed parts rather than from an `AppState`.
    ///
    /// For a caller whose own dependencies were threaded to it — today that is
    /// the webvh layer, whose client is constructed deep inside
    /// `WebvhTransport` and which carries a [`TspSender`] down from its
    /// `WebvhDeps`. Passing `tsp: None` is a real answer, not a shortcut: a
    /// CLI or a setup wizard holds no mediator socket, and the seam correctly
    /// falls to DIDComm there.
    ///
    /// This replaced a `didcomm_or_rest` constructor that hardcoded `None` and
    /// so silently removed TSP from selection for every webvh call. The name is
    /// the difference: a caller now has to pass *something* for TSP, and
    /// passing `None` is visible at the call site.
    pub fn from_parts(
        resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
        #[cfg(feature = "didcomm")] bridge: &'a DIDCommBridge,
        #[cfg(feature = "tsp")] tsp: Option<TspSender>,
    ) -> Self {
        Self {
            resolver,
            #[cfg(feature = "tsp")]
            tsp,
            #[cfg(feature = "didcomm")]
            bridge,
        }
    }

    /// Borrow what this needs from an [`AppState`](crate::server::AppState).
    ///
    /// A constructor rather than five struct literals because the bridge is
    /// feature-gated: without this, every call site would carry the same `cfg`
    /// and the next one added would omit it and break a build nobody runs
    /// locally. Same reason `WebvhDeps::from_app_state` exists.
    ///
    /// `resolver` is threaded separately because `AppState` holds it as an
    /// `Option` — the caller unwraps it, surfacing the typed "DID resolver not
    /// available" reject, before there is anything to send.
    pub fn from_app_state(
        state: &'a crate::server::AppState,
        resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    ) -> Self {
        Self {
            resolver,
            #[cfg(feature = "tsp")]
            tsp: TspSender::from_app_state(state),
            #[cfg(feature = "didcomm")]
            bridge: state.didcomm_bridge.as_ref(),
        }
    }
}

/// The highest-preference protocol both this VTA and `peer` can do, with the
/// endpoint to reach it on.
pub fn pick_transport(
    caps: &ServiceCapabilities,
    peer: &str,
) -> Result<(Protocol, String), AppError> {
    for protocol in Protocol::PREFERENCE_ORDER {
        if !OUTBOUND_SUPPORTED.contains(&protocol) {
            continue;
        }
        if let Some(endpoint) = caps.endpoint(protocol) {
            return Ok((protocol, endpoint.to_string()));
        }
    }

    let advertised: Vec<&str> = Protocol::PREFERENCE_ORDER
        .iter()
        .filter(|p| caps.endpoint(**p).is_some())
        .map(|p| p.as_str())
        .collect();
    let ours: Vec<&str> = OUTBOUND_SUPPORTED.iter().map(|p| p.as_str()).collect();

    Err(AppError::Validation(format!(
        "no transport in common with `{peer}`: it advertises [{}] and this agent can \
         initiate [{}]. This is not a peer that cannot be reached — it is one this agent cannot \
         yet start a conversation with, which is a gap in the agent rather than in the peer.",
        if advertised.is_empty() {
            "nothing".to_string()
        } else {
            advertised.join(", ")
        },
        ours.join(", "),
    )))
}

impl Outbound<'_> {
    /// Send an already-signed Trust-Task `document` to `recipient` and return
    /// the reply document, verified per `trust`.
    ///
    /// The reply is returned rather than interpreted: what a given `#response`
    /// or refusal *means* is the caller's family to read, and a shared reader
    /// would have to know every family to do it.
    pub async fn send(
        &self,
        recipient: &str,
        document: Value,
        trust: ReplyTrust,
    ) -> Result<Value, AppError> {
        // Boxed, and this is load bearing rather than tidiness.
        //
        // This future is large: a DID resolution, a transport round trip and a
        // proof verification, each with its own awaited sub-futures. In a debug
        // build the compiler inlines all of that into the *caller's* frame, so
        // every caller pays the whole thing in stack whether or not it is deep
        // already.
        //
        // `webvh_didcomm` is deep already — it sits under `create_did_webvh`,
        // which is itself several awaits down — and calling this inline
        // overflowed the 2MB stack a `#[tokio::test]` worker gets. It surfaced
        // as `mock_vta` aborting with SIGABRT during a full-workspace run, on a
        // *different* test each time and never when that binary ran alone,
        // which reads exactly like resource-pressure flakiness and was not:
        // the same suite on the parent commit passes with zero overflows.
        //
        // Boxing here rather than at each call site because the size is this
        // function's, not its callers'. A caller cannot know it has become too
        // large to inline, and the next one added would rediscover this the
        // same expensive way.
        Box::pin(self.send_inner(recipient, document, trust)).await
    }

    async fn send_inner(
        &self,
        recipient: &str,
        document: Value,
        trust: ReplyTrust,
    ) -> Result<Value, AppError> {
        let resolved = self.resolver.resolve(recipient).await.map_err(|e| {
            AppError::Validation(format!(
                "`{recipient}` does not resolve, so there is nothing to send to: {e}"
            ))
        })?;
        let doc_value = serde_json::to_value(&resolved.doc)
            .map_err(|e| AppError::Internal(format!("serialise the peer's DID document: {e}")))?;
        let caps = ServiceCapabilities::from_did_document(&doc_value);
        let (protocol, endpoint) = pick_transport(&caps, recipient)?;

        let reply = match protocol {
            Protocol::Rest => self.send_rest(recipient, &endpoint, &document).await?,
            #[cfg(feature = "tsp")]
            Protocol::Tsp => self.send_tsp(recipient, document).await?,
            #[cfg(not(feature = "tsp"))]
            Protocol::Tsp => {
                return Err(AppError::Internal(
                    "TSP was selected in a build without the `tsp` feature".into(),
                ));
            }
            #[cfg(feature = "didcomm")]
            Protocol::Didcomm => self.send_didcomm(recipient, document).await?,
            // Not selectable in this build — it is not in `OUTBOUND_SUPPORTED`
            // — but the arm must exist for the match to be exhaustive.
            #[cfg(not(feature = "didcomm"))]
            Protocol::Didcomm => {
                return Err(AppError::Internal(
                    "DIDComm was selected in a build without the `didcomm` feature".into(),
                ));
            }
        };

        verify_reply(self.resolver, &reply, recipient, trust).await?;
        Ok(reply)
    }

    async fn send_rest(
        &self,
        recipient: &str,
        endpoint: &str,
        document: &Value,
    ) -> Result<Value, AppError> {
        let url = format!("{}/trust-tasks", endpoint.trim_end_matches('/'));
        let response = vta_sdk::http::rest_client()
            .post(&url)
            .header("content-type", "application/json")
            .json(document)
            .send()
            .await
            .map_err(|e| {
                bad_gateway_error(format!("`{recipient}` at {url} did not answer: {e}"))
            })?;

        // The body is read once, and before the status is judged: a refusal
        // arrives as a `trust-task-error` document with a code an operator can
        // act on, and throwing on the status first would discard it (guide rule
        // R3.7).
        let body = response.text().await.map_err(|e| {
            bad_gateway_error(format!("`{recipient}` sent an unreadable body: {e}"))
        })?;
        serde_json::from_str(&body).map_err(|e| {
            bad_gateway_error(format!(
                "`{recipient}` sent a body that is not a Trust-Task document: {e}: {body}"
            ))
        })
    }

    /// Seal a Trust Task to `recipient` over TSP and wait for the reply to come
    /// back as its own inbound frame.
    ///
    /// The shape is forced by the binding rather than chosen. TSP has no
    /// request/response: `pack` and `unpack` is the whole of it, because
    /// correlation is a document concern (SPEC §4.9 `threadId`). So this is a
    /// send now, and later an inbound document that the dispatch spine
    /// recognises as an answer and hands to the receiver registered here.
    ///
    /// **The waiter is registered before the frame is sealed.** A reply that
    /// arrived between sending and registering would find nothing waiting, be
    /// dispatched as a request, and be refused — while this call sat here until
    /// it timed out. The window is small and the mediator is fast, which is
    /// exactly the combination that makes it rare enough to survive testing.
    #[cfg(feature = "tsp")]
    async fn send_tsp(&self, recipient: &str, document: Value) -> Result<Value, AppError> {
        let tsp = self.tsp.as_ref().ok_or_else(|| {
            AppError::Internal(
                "TSP was selected but this node has no TSP transport; it should not have been \
                 offered"
                    .into(),
            )
        })?;

        // The thread the reply will name, not the request's id — see
        // `reply_thread_of`, which is the contract `trust-tasks-rs` applies when
        // it builds the response.
        let thread = crate::trust_tasks::pending_replies::reply_thread_of(&document)
            .ok_or_else(|| {
                AppError::Internal(
                    "an outbound Trust Task with neither `threadId` nor `id` cannot be answered"
                        .into(),
                )
            })?
            .to_string();

        let type_uri = document
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let body = serde_json::to_vec(&document)
            .map_err(|e| AppError::Internal(format!("serialise the request: {e}")))?;
        let framed = vta_sdk::tsp_binding::wrap_envelope(&body);

        match tsp.send_and_await(recipient, &thread, &framed, false).await {
            TspAttempt::Reply(v) => Ok(v),
            TspAttempt::SendFailed(e) => Err(bad_gateway_error(format!(
                "`{recipient}` could not be reached over TSP: {e}"
            ))),
            TspAttempt::Cancelled => Err(bad_gateway_error(format!(
                "the wait for `{recipient}`'s reply was cancelled"
            ))),
            // §7.2.2 D6: a silent reply-timeout may mean the peer lost the
            // relationship. Hand off to the coordinator-gated self-repair.
            TspAttempt::Timeout => {
                tsp.recover_send_tsp(recipient, &thread, &framed, &type_uri)
                    .await
            }
        }
    }

    #[cfg(feature = "didcomm")]
    async fn send_didcomm(&self, recipient: &str, document: Value) -> Result<Value, AppError> {
        // The message is addressed to the **peer's** DID; the endpoint it
        // advertises is the mediator it can be reached through, and the delivery
        // layer resolves that route. Addressing the mediator would address the
        // mediator.
        let reply = self
            .bridge
            .send_and_wait(
                recipient,
                DIDCOMM_MESSAGE_TYPE,
                document,
                // The expected *outer* type is the envelope we sent: on this
                // binding a reply rides the same envelope, so success and
                // refusal are indistinguishable out here. Both are told apart on
                // the inner document, by the caller.
                DIDCOMM_MESSAGE_TYPE,
                // A DIDComm problem report can still arrive *ahead* of the
                // envelope — an unroutable message never reaches the far side's
                // dispatcher — so it stays mapped to a typed error.
                vta_sdk::protocols::PROBLEM_REPORT_TYPE,
                DIDCOMM_REPLY_TIMEOUT_SECS,
            )
            .await?;
        Ok(reply.body)
    }
}

/// Apply `trust` to a reply.
///
/// An **error document is exempt from the proof requirement**, whichever
/// trust level applies. A refusal's `type` resolves to the framework's
/// `trust-task-error` specification, whose own proof requirement is
/// RECOMMENDED rather than REQUIRED (SPEC §8.1) — demanding one would make
/// every conforming refusal unreadable, including the ones whose entire
/// purpose is to carry a reason back to an operator. A refusal is believed
/// only to the extent of being a refusal; it confers nothing and grants
/// nothing, which is why the framework asks less of it.
///
/// A free function rather than a method: verifying a reply needs the resolver
/// and nothing else, and a method would have made every test of this property
/// stand up a DIDComm bridge to ask a question that has no transport in it.
async fn verify_reply(
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    reply: &Value,
    recipient: &str,
    trust: ReplyTrust,
) -> Result<(), AppError> {
    if trust == ReplyTrust::TransportAuthenticated {
        return Ok(());
    }
    let doc_type = reply
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if doc_type.starts_with("https://trusttasks.org/spec/trust-task-error/") {
        return Ok(());
    }

    let doc: trust_tasks_rs::TrustTask<Value> =
        serde_json::from_value(reply.clone()).map_err(|e| {
            bad_gateway_error(format!(
                "`{recipient}` sent a reply this agent cannot read as a Trust-Task \
                 document: {e}"
            ))
        })?;

    let vm_resolver = vti_common::auth::TrustTaskVmResolver::from_optional(Some(resolver.clone()));
    let signer = vti_common::auth::verify_trust_task_proof_with(&doc, &vm_resolver)
        .await
        .map_err(|e| {
            AppError::Forbidden(format!(
                "the reply from `{recipient}` is unsigned or its proof does not verify \
                 ({e}), so nothing in it can be believed — an unsigned answer is bytes, not \
                 evidence"
            ))
        })?;

    if signer != recipient {
        return Err(AppError::Forbidden(format!(
            "the reply claiming to come from `{recipient}` is signed by `{signer}`. The \
             proof verifies, which means somebody really signed it — just not the party this \
             agent asked"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_from(services: Value) -> ServiceCapabilities {
        ServiceCapabilities::from_did_document(&serde_json::json!({ "service": services }))
    }

    async fn test_resolver() -> affinidi_did_resolver_cache_sdk::DIDCacheClient {
        affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("a resolver for tests")
    }

    /// A refusal is exempt, and deliberately: `trust-task-error` declares its
    /// proof RECOMMENDED, so demanding one would make every conforming refusal
    /// unreadable — including the `hostRefused` whose whole job is to carry the
    /// host's reason back.
    #[tokio::test]
    async fn a_refusal_is_read_without_a_proof() {
        let reply = serde_json::json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
            "payload": { "code": "notAMember", "reason": "no" }
        });
        verify_reply(
            &test_resolver().await,
            &reply,
            "did:example:host",
            ReplyTrust::SignedByRecipient,
        )
        .await
        .expect("a refusal needs no proof");
    }

    /// An unsigned success reply is refused. Bytes off a socket attest to
    /// nothing, and every check downstream of this one is about *shape* — so an
    /// intermediary that rewrote a record listing would pass all of them.
    #[tokio::test]
    async fn an_unsigned_success_reply_is_refused() {
        let reply = serde_json::json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "type": "https://trusttasks.org/spec/rooms/epoch/chain/0.1#response",
            "issuer": "did:example:host",
            "recipient": "did:example:agent",
            "issuedAt": "2026-01-01T00:00:00Z",
            "payload": { "links": [] }
        });
        let err = verify_reply(
            &test_resolver().await,
            &reply,
            "did:example:host",
            ReplyTrust::SignedByRecipient,
        )
        .await
        .expect_err("an unsigned success reply must not be believed");
        let msg = err.to_string();
        assert!(
            msg.contains("bytes, not") || msg.contains("unsigned"),
            "the refusal must say why an unsigned answer is worthless: {msg}"
        );
    }

    // ── Selection: an intersection, walked in the workspace's order ──────────

    #[test]
    fn a_peer_serving_rest_is_reachable() {
        let caps = caps_from(serde_json::json!([{
            "id": "#rest", "type": "VTARest", "serviceEndpoint": "https://host.example"
        }]));
        let (protocol, endpoint) = pick_transport(&caps, "did:example:peer").expect("reachable");
        assert_eq!(protocol, Protocol::Rest);
        assert_eq!(endpoint, "https://host.example");
    }

    /// The case that matters in practice: a room host started with
    /// `--mediator-did` publishes DIDComm there and need not open an HTTP port
    /// at all.
    #[test]
    fn a_didcomm_only_peer_is_reachable() {
        let caps = caps_from(serde_json::json!([{
            "id": "#didcomm",
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{ "uri": "did:example:mediator", "accept": ["didcomm/v2"] }]
        }]));
        let (protocol, _) = pick_transport(&caps, "did:example:peer").expect("reachable");
        assert_eq!(protocol, Protocol::Didcomm);
    }

    /// Preference, not availability: the rule is the highest-preference
    /// protocol present in **both** sets, never the first that happens to work.
    #[test]
    fn didcomm_is_preferred_over_rest_when_a_peer_offers_both() {
        let caps = caps_from(serde_json::json!([
            { "id": "#rest", "type": "VTARest", "serviceEndpoint": "https://host.example" },
            { "id": "#didcomm", "type": "DIDCommMessaging",
              "serviceEndpoint": [{ "uri": "did:example:mediator", "accept": ["didcomm/v2"] }] }
        ]));
        let (protocol, _) = pick_transport(&caps, "did:example:peer").expect("reachable");
        assert_eq!(
            protocol,
            Protocol::Didcomm,
            "REST was chosen while the peer also advertised DIDComm"
        );
    }

    /// The ordering lives in one place. `OUTBOUND_SUPPORTED` is a membership
    /// set and must never become a second preference list — its own order is
    /// deliberately the opposite of the one that must win, so anything that
    /// starts reading it in order trips here.
    #[test]
    fn preference_comes_from_preference_order_not_from_this_list() {
        let rank = |p: Protocol| Protocol::PREFERENCE_ORDER.iter().position(|q| *q == p);
        assert!(rank(Protocol::Didcomm) < rank(Protocol::Rest));
        assert!(
            OUTBOUND_SUPPORTED.contains(&Protocol::Didcomm)
                && OUTBOUND_SUPPORTED.contains(&Protocol::Rest)
        );
    }

    /// A peer advertising only TSP, as this file's two builds see it. One
    /// helper because the peer is the same in both; only what this agent can do
    /// about it differs.
    fn tsp_only_peer() -> ServiceCapabilities {
        caps_from(serde_json::json!([{
            "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:example:mediator"
        }]))
    }

    /// The honest refusal. A peer speaking only TSP is not unreachable in
    /// principle — this agent cannot start the conversation — and the message
    /// has to say which, or an operator goes looking at the peer.
    ///
    /// **Only in a build without `tsp`.** With the feature on this VTA can
    /// initiate TSP, so the intersection is non-empty and there is nothing to
    /// refuse — see the sibling test. The gate is load-bearing rather than
    /// tidiness: this assertion used to be unconditional, which held only for as
    /// long as nothing in a workspace build turned `tsp` on for `vta-service`.
    /// The first thing that did (a sibling crate's dev-dependency asking for it,
    /// feature unification doing the rest) made it panic — in a crate whose own
    /// `cargo test -p vta-service` was green, because that build has no `tsp`
    /// either. A test that asserts a refusal must say which build it is
    /// describing.
    #[cfg(not(feature = "tsp"))]
    #[test]
    fn a_tsp_only_peer_is_refused_naming_both_sides() {
        let caps = tsp_only_peer();
        let msg = pick_transport(&caps, "did:example:peer")
            .expect_err("no common transport")
            .to_string();
        assert!(
            msg.contains("tsp"),
            "must name what the peer advertises: {msg}"
        );
        assert!(
            msg.contains("didcomm") && msg.contains("rest"),
            "must name everything this agent can do, not just one: {msg}"
        );
        assert!(
            msg.contains("gap in the agent"),
            "must say whose limitation it is: {msg}"
        );
    }

    /// And the other half of that statement: in a build that *can* initiate TSP,
    /// the same peer is reached over it rather than refused. Asserting both
    /// sides keeps the refusal above a claim about this build, not about TSP.
    #[cfg(feature = "tsp")]
    #[test]
    fn a_tsp_only_peer_is_reached_over_tsp_when_this_build_can_initiate_it() {
        let (protocol, endpoint) = pick_transport(&tsp_only_peer(), "did:example:peer")
            .expect("TSP is in the intersection when this build can initiate it");

        assert_eq!(
            protocol,
            Protocol::Tsp,
            "a TSP-only peer must be reached over TSP, not refused"
        );
        assert_eq!(
            endpoint, "did:example:mediator",
            "and over the mediator the peer's `#tsp` service names"
        );
    }

    #[test]
    fn a_peer_advertising_nothing_says_so() {
        let err = pick_transport(&caps_from(serde_json::json!([])), "did:example:peer")
            .expect_err("nothing advertised");
        assert!(err.to_string().contains("nothing"));
    }

    // ── Reply trust: the question the two hand-rolled paths answered
    //    differently ───────────────────────────────────────────────────────────

    /// The weaker level is a decision, and this is what it decides. Asserted so
    /// that `TransportAuthenticated` cannot quietly become "verify anyway" or
    /// the reverse without a test saying so.
    #[tokio::test]
    async fn transport_authenticated_believes_an_unsigned_reply() {
        let reply = serde_json::json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "type": "https://trusttasks.org/spec/did-management/did/check-name/0.1#response",
            "issuer": "did:example:peer",
            "recipient": "did:example:agent",
            "issuedAt": "2026-01-01T00:00:00Z",
            "payload": { "available": true }
        });
        verify_reply(
            &test_resolver().await,
            &reply,
            "did:example:peer",
            ReplyTrust::TransportAuthenticated,
        )
        .await
        .expect("this level asks nothing of the document");
    }

    /// The envelope type goes on the message; a task type never does. This
    /// fails silently on the wire — a conformant host rejects a message typed
    /// with the task URI and the sender learns nothing — so it is asserted here,
    /// at the one place that now decides it for every caller.
    #[test]
    fn the_didcomm_message_carries_the_binding_envelope_type() {
        assert_eq!(DIDCOMM_MESSAGE_TYPE, trust_tasks_didcomm::ENVELOPE_TYPE);
        assert!(
            !DIDCOMM_MESSAGE_TYPE.starts_with("https://trusttasks.org/spec/"),
            "a `spec/` URI here is a task type on the wire: {DIDCOMM_MESSAGE_TYPE}"
        );
    }
}
