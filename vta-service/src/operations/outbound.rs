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
//! binding. Both go through `messaging::tsp_binding` for TSP, and both would go
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
//! This matters for the transport still missing here. TSP's binding
//! (`trust-tasks-tsp`) offers `pack` and `unpack` and nothing else, by design.
//! Reaching it is therefore **not** a matter of building a request/reply call
//! over `send_routed`: it is teaching the inbound path that a document threading
//! to one we sent is a reply rather than a request, which
//! `messaging::tsp_inbound::dispatch_one` does not do — it authorizes every
//! frame and dispatches it as a request. Until that exists, naming TSP in
//! `OUTBOUND_SUPPORTED` would produce a request that is sent and never answered:
//! worse than the refusal below, because it would time out instead of saying
//! why.

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
    #[cfg(feature = "didcomm")]
    Protocol::Didcomm,
    Protocol::Rest,
];

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

/// The transports this VTA can reach a peer on, and the things needed to use
/// them.
///
/// A struct rather than loose arguments because the set travels together: drop
/// the resolver and there is nothing to read a peer's advertisement from; drop
/// the bridge and DIDComm silently stops being selectable.
pub struct Outbound<'a> {
    pub resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    /// Absent in a build without `didcomm`, along with the arm that uses it and
    /// the entry in [`OUTBOUND_SUPPORTED`] that would select it.
    #[cfg(feature = "didcomm")]
    pub bridge: &'a DIDCommBridge,
}

impl<'a> Outbound<'a> {
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
            // Its own arm rather than a catch-all, so naming TSP in
            // `OUTBOUND_SUPPORTED` fails to compile here instead of silently
            // doing nothing. See the module header for what it needs.
            Protocol::Tsp => {
                return Err(AppError::Internal(format!(
                    "{} is named in OUTBOUND_SUPPORTED but has no send path here",
                    protocol.as_str()
                )));
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

    /// The honest refusal. A peer speaking only TSP is not unreachable in
    /// principle — this agent cannot start the conversation — and the message
    /// has to say which, or an operator goes looking at the peer.
    #[test]
    fn a_tsp_only_peer_is_refused_naming_both_sides() {
        let caps = caps_from(serde_json::json!([{
            "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:example:mediator"
        }]));
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
