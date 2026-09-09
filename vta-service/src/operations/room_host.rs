//! Calling a room's host, as the member's agent.
//!
//! # Why this exists at all
//!
//! Every host-served room verb — `rooms/create`, `rooms/records/*`,
//! `rooms/epoch/*` — needs a channel to the host. The surfaces people actually
//! use hold a channel to their own agent and to no third party: a browser
//! extension's bridge passes a task type and a payload and addresses everything
//! to the wallet's own VTA, so a document naming a host is simply not sendable
//! from there. `rooms/keys/backfill` and `rooms/owner/register` move that call
//! to the party that *can* make it, and this module is how it makes it.
//!
//! # What this is not
//!
//! It is **not** a second Trust-Task client. The document layer is already
//! transport-agnostic — that is what a Trust Task is — and `vta-sdk` already
//! owns the selection: [`ServiceCapabilities::from_did_document`] reads what a
//! peer advertises by service **type**, and [`Protocol::PREFERENCE_ORDER`] is
//! the workspace's TSP > DIDComm > REST. This module composes those with the
//! one thing the SDK's own client cannot do here.
//!
//! That one thing is signing. [`vta_sdk::client::VtaClient`] signs from a
//! `ClientIdentity` carrying a raw `private_key_multibase`, and **a VTA never
//! holds its own keys in that shape** — it derives, signs and zeroizes behind
//! [`crate::operations::keys::sign_payload`], where the context gates live. So
//! the document is built and signed here, through the same `Signer` seam
//! `RoomKeySigner` uses, and only the bytes travel.
//!
//! # Transport: an intersection, not a downgrade
//!
//! The rule is that the protocol used is the highest-preference one present in
//! **both** parties' advertisements. [`OUTBOUND_SUPPORTED`] is this VTA's half,
//! and it is deliberately a named constant rather than an implicit assumption:
//! today it holds REST alone, because initiating TSP or DIDComm needs a
//! correlated reply this service does not yet keep for outbound requests (it has
//! `send_routed`, but only reply-side, and no pending-reply waiter of the kind
//! `vtc-service` keeps).
//!
//! A host advertising nothing in that intersection is therefore a **loud typed
//! refusal naming both sets**, never a quiet fallback. That distinction is the
//! whole of the workspace rule: downgrading past what a peer advertises is
//! forbidden; being honest that this VTA cannot yet initiate on a protocol is
//! not the same thing, and the error says which it is.

use serde_json::Value;
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities};
use vti_common::error::{AppError, bad_gateway_error};

use crate::operations::room_issuance::{SigningContext, VtaKeySigner};

/// The protocols this VTA can **initiate** a Trust-Task request on, in
/// preference order.
///
/// Adding TSP here takes one thing: a pending-reply registry keyed by the
/// document's `threadId`, so a `send_routed` can be awaited. `vtc-service`'s
/// `state.pending_replies` is the shape. Until that exists, naming TSP here
/// would produce a request that is sent and never answered.
pub const OUTBOUND_SUPPORTED: [Protocol; 1] = [Protocol::Rest];

/// The highest-preference protocol both this VTA and `host` can do, with the
/// endpoint to reach it on.
fn pick_transport(caps: &ServiceCapabilities, host: &str) -> Result<(Protocol, String), AppError> {
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
        "no transport in common with room host `{host}`: it advertises [{}] and this agent can \
         initiate [{}]. This is not a host that cannot be reached — it is one this agent cannot \
         yet start a conversation with, which is a gap in the agent rather than in the host.",
        if advertised.is_empty() {
            "nothing".to_string()
        } else {
            advertised.join(", ")
        },
        ours.join(", "),
    )))
}

/// Build the Trust-Task document that carries `task` to a host.
///
/// Extracted so the outbound shape is assertable without a live host — the same
/// reason `webvh_didcomm::build_envelope_document` exists, and for the same
/// class of bug: a malformed document is refused by the far side in words about
/// the *payload*, and nothing local would have caught it.
pub fn build_room_task(task: &str, host: &str, issuer: &str, payload: Value) -> Value {
    serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": task,
        // Addressed to the host per SPEC §4.8. A host authorizes from the
        // document's own proof, but an unaddressed document is one a stricter
        // peer is entitled to refuse.
        "recipient": host,
        "issuer": issuer,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    })
}

/// Check that a host's reply is actually from the host, before believing a word
/// of it.
///
/// # Why this is not optional
///
/// A reply is bytes off a socket. Without a proof it attests to nothing: an
/// intermediary can rewrite a record listing, change the epoch a chain claims to
/// reach, or answer for a host that never spoke — and every downstream check
/// would pass, because the downstream checks are about *shape*.
///
/// Two things are required and the second is the one that is easy to omit: the
/// proof must **verify**, and its proven signer must be **the host we
/// addressed**. `verify_trust_task_proof_with` says so in its own docs — a proof
/// by `did:webvh:…:someone-else#key-0` verifies perfectly well, and that it is
/// not the party you expected is a separate check. Skipping it turns "signed by
/// somebody" into "signed by the host", which is the whole property.
///
/// # Why an error document is exempt
///
/// A refusal's `type` resolves to the framework's `trust-task-error`
/// specification, whose own proof requirement is **RECOMMENDED**, not REQUIRED
/// (SPEC §8.1). Demanding one would make every conforming refusal unreadable —
/// including the `hostRefused` this family declares, whose entire purpose is to
/// carry the host's reason back to an operator. A refusal is believed only to
/// the extent of being a refusal; it confers nothing and grants nothing, which
/// is why the framework asks less of it.
async fn verify_host_reply(
    reply: &Value,
    host: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> Result<(), AppError> {
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
                "room host `{host}` sent a reply this agent cannot read as a Trust-Task \
                 document: {e}"
            ))
        })?;

    let vm_resolver = vti_common::auth::TrustTaskVmResolver::from_optional(Some(resolver.clone()));
    let signer = vti_common::auth::verify_trust_task_proof_with(&doc, &vm_resolver)
        .await
        .map_err(|e| {
            AppError::Forbidden(format!(
                "the reply from room host `{host}` is unsigned or its proof does not verify \
                 ({e}), so nothing in it can be believed — an unsigned answer is bytes, not \
                 evidence"
            ))
        })?;

    if signer != host {
        return Err(AppError::Forbidden(format!(
            "the reply claiming to come from room host `{host}` is signed by `{signer}`. The \
             proof verifies, which means somebody really signed it — just not the party this \
             agent asked"
        )));
    }
    Ok(())
}

/// Read a host's reply, distinguishing the three things it can be.
///
/// A room host answers a Trust Task with the task's own `#response`, or with a
/// `trust-task-error` document carrying its refusal. The second is **not** a
/// transport failure and must not be flattened into one: the host's own code and
/// reason are the operator-facing half of every `hostRefused` this family
/// declares, and a 502 in their place tells an operator their network is broken
/// when their room policy declined.
pub fn read_reply(doc: &Value, expected: &str, host: &str) -> Result<Value, AppError> {
    let doc_type = doc.get("type").and_then(Value::as_str).unwrap_or_default();

    if doc_type == expected {
        return Ok(doc.get("payload").cloned().unwrap_or(Value::Null));
    }

    if doc_type.starts_with("https://trusttasks.org/spec/trust-task-error/") {
        let payload = doc.get("payload").cloned().unwrap_or(Value::Null);
        let code = payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unspecified");
        let reason = payload
            .get("reason")
            .or_else(|| payload.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("no reason given");
        return Err(AppError::Forbidden(format!(
            "room host `{host}` refused: {code}: {reason}"
        )));
    }

    Err(AppError::Internal(format!(
        "room host `{host}` answered `{doc_type}` where `{expected}` was expected; a reply that \
         threads to our request but answers a different task is a contract break rather than a \
         task failure"
    )))
}

/// Room tasks that CHANGE a room, as opposed to reading one.
///
/// The list is by URI rather than by a flag on the task, because the decision it
/// feeds is this agent's and not the specification's: a host is entitled to
/// serve all of these, and what changes is whether *this* agent is willing to
/// hand it more material.
const MUTATING_ROOM_TASKS: &[&str] = &[
    vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
    vti_rooms::wire::ROOMS_RECORDS_CURATE_TYPE,
    vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE,
    vti_rooms::wire::ROOMS_OWNER_TRANSFER_TYPE,
];

/// Refuse to write to a host this agent has caught contradicting itself.
///
/// # The rule, and why it is asymmetric
///
/// **Serve reads, refuse writes.** Reading is how a member gathers the evidence,
/// and the records that would prove what happened are inside the room a refusal
/// would lock them out of — by their own agent, over somebody else's act.
/// Writing to a host you have caught is what compounds the damage: it hands more
/// material to a party you now have reason to believe will misrepresent what it
/// holds.
///
/// # Why here rather than in one task
///
/// This is a property of the agent's outbound path, not of any single verb. Put
/// it in a write task and the next write task has to remember it; put it here
/// and every one of them inherits it. The refusal names the room and says what
/// was observed, because a member who is told only "refused" concludes their own
/// agent is broken — and a detection attributed to the wrong party is worse than
/// no detection.
///
/// A conflict this agent cannot read is not a host that behaved: a storage
/// failure answers `Ok`, because refusing every write on an unreadable history
/// would turn a local fault into an accusation.
pub async fn refuse_if_caught(
    groups: &vti_common::store::KeyspaceHandle,
    room_id: &str,
    task: &str,
) -> Result<(), AppError> {
    if !MUTATING_ROOM_TASKS.contains(&task) {
        return Ok(());
    }
    let history = match crate::operations::room_groups::root_history(groups, room_id).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(
                room = %room_id,
                error = %e,
                "could not read this agent's root history; allowing the write rather than \
                 turning a local fault into an accusation"
            );
            return Ok(());
        }
    };
    if let Some(caught) = history.caught_at {
        return Err(AppError::Forbidden(format!(
            "this agent has been given two different record sets for `{room_id}`, both \
             claimed at version {caught}. One of them is wrong, and a write cannot explain \
             the difference — a write moves the version. Reading this room still works, and \
             is how the evidence is gathered; writing to a host that has contradicted itself \
             is refused."
        )));
    }
    Ok(())
}

/// Send one room task to `host` and return the response document's `payload`.
///
/// `signing_key_id` and `issuer` name the identity this VTA signs as. For a
/// member's backfill that is the agent itself — the host binds the presentation
/// to the DID that signed the envelope, so the presentation must have been
/// minted for this same DID or the host will (correctly) refuse it.
pub async fn send_room_task(
    ctx: SigningContext<'_>,
    groups: &vti_common::store::KeyspaceHandle,
    room_id: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &str,
    signing_key_id: &str,
    issuer: &str,
    verification_method: &str,
    task: &str,
    response_task: &str,
    payload: Value,
) -> Result<Value, AppError> {
    // Before anything leaves. Threaded through the seam rather than left to each
    // caller: a write task added later inherits the refusal instead of having to
    // remember it, which is the difference between a rule and a convention.
    refuse_if_caught(groups, room_id, task).await?;

    let resolved = resolver.resolve(host).await.map_err(|e| {
        AppError::Validation(format!(
            "the room host `{host}` does not resolve, so there is nothing to send to: {e}"
        ))
    })?;
    let doc_value = serde_json::to_value(&resolved.doc)
        .map_err(|e| AppError::Internal(format!("serialise the host's DID document: {e}")))?;

    let caps = ServiceCapabilities::from_did_document(&doc_value);
    let (protocol, endpoint) = pick_transport(&caps, host)?;

    let mut document = build_room_task(task, host, issuer, payload);
    let signer = VtaKeySigner::new(ctx, signing_key_id, verification_method);
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &document,
        &signer,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .map_err(|e| {
        // The cause, not just "signing failed" — every refusal worth acting on
        // (an unknown key, a context the caller may not reach, a policy limit
        // spent) lives in the source chain and `DataIntegrityError` renders
        // only its own outer message.
        let mut cause = String::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
        while let Some(inner) = src {
            cause = format!("{cause}: {inner}");
            src = inner.source();
        }
        AppError::Internal(format!(
            "sign the request to room host `{host}`: {e}{cause}"
        ))
    })?;
    document["proof"] = serde_json::to_value(proof)
        .map_err(|e| AppError::Internal(format!("serialise the proof: {e}")))?;

    match protocol {
        Protocol::Rest => {
            let url = format!("{}/trust-tasks", endpoint.trim_end_matches('/'));
            let response = vta_sdk::http::rest_client()
                .post(&url)
                .header("content-type", "application/json")
                .json(&document)
                .send()
                .await
                .map_err(|e| {
                    bad_gateway_error(format!("room host `{host}` at {url} did not answer: {e}"))
                })?;

            // The body is read once, and before the status is judged: a refusal
            // arrives as a `trust-task-error` document with a code an operator
            // can act on, and throwing on the status first would discard it
            // (guide rule R3.7).
            let body = response.text().await.map_err(|e| {
                bad_gateway_error(format!("room host `{host}` sent an unreadable body: {e}"))
            })?;
            let reply: Value = serde_json::from_str(&body).map_err(|e| {
                bad_gateway_error(format!(
                    "room host `{host}` sent a body that is not a Trust-Task document: {e}: {body}"
                ))
            })?;
            verify_host_reply(&reply, host, resolver).await?;
            read_reply(&reply, response_task, host)
        }
        // Unreachable while `OUTBOUND_SUPPORTED` holds REST alone; kept as an
        // arm rather than a catch-all so adding a protocol there fails to
        // compile here instead of silently doing nothing.
        Protocol::Tsp | Protocol::Didcomm => Err(AppError::Internal(format!(
            "{} is named in OUTBOUND_SUPPORTED but has no send path here",
            protocol.as_str()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_from(services: Value) -> ServiceCapabilities {
        ServiceCapabilities::from_did_document(&serde_json::json!({ "service": services }))
    }

    #[test]
    fn a_host_serving_rest_is_reachable() {
        let caps = caps_from(serde_json::json!([{
            "id": "#rest", "type": "VTARest", "serviceEndpoint": "https://host.example"
        }]));
        let (protocol, endpoint) = pick_transport(&caps, "did:example:host").expect("reachable");
        assert_eq!(protocol, Protocol::Rest);
        assert_eq!(endpoint, "https://host.example");
    }

    /// The honest refusal. A host that speaks only TSP is not unreachable in
    /// principle — this agent cannot start the conversation — and the message
    /// has to say which, or an operator goes looking at the host.
    #[test]
    fn a_tsp_only_host_is_refused_naming_both_sides() {
        let caps = caps_from(serde_json::json!([{
            "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:example:mediator"
        }]));
        let err = pick_transport(&caps, "did:example:host").expect_err("no common transport");
        let msg = err.to_string();
        assert!(
            msg.contains("tsp"),
            "must name what the host advertises: {msg}"
        );
        assert!(
            msg.contains("rest"),
            "must name what this agent can do: {msg}"
        );
        assert!(
            msg.contains("gap in the agent"),
            "must say whose limitation it is: {msg}"
        );
    }

    #[test]
    fn a_host_advertising_nothing_says_so() {
        let err = pick_transport(&caps_from(serde_json::json!([])), "did:example:host")
            .expect_err("nothing advertised");
        assert!(err.to_string().contains("nothing"));
    }

    #[test]
    fn the_document_is_addressed_and_attributed() {
        let doc = build_room_task(
            "https://trusttasks.org/spec/rooms/epoch/chain/0.1",
            "did:example:host",
            "did:example:agent",
            serde_json::json!({ "roomId": "did:example:room" }),
        );
        assert_eq!(doc["recipient"], "did:example:host");
        assert_eq!(doc["issuer"], "did:example:agent");
        assert_eq!(doc["payload"]["roomId"], "did:example:room");
        assert!(doc["id"].as_str().unwrap().starts_with("urn:uuid:"));
    }

    #[test]
    fn a_response_yields_its_payload() {
        let reply = serde_json::json!({
            "type": "https://trusttasks.org/spec/rooms/epoch/chain/0.1#response",
            "payload": { "links": [] }
        });
        let got = read_reply(
            &reply,
            "https://trusttasks.org/spec/rooms/epoch/chain/0.1#response",
            "did:example:host",
        )
        .expect("a response");
        assert_eq!(got["links"], serde_json::json!([]));
    }

    /// A refusal is the host's answer, not a broken network. Flattening it to a
    /// gateway error tells an operator to check their connection when their
    /// room policy declined.
    #[test]
    fn a_refusal_carries_the_hosts_own_code_and_reason() {
        let reply = serde_json::json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
            "payload": { "code": "private-tier-not-enabled", "reason": "this community has not enabled private rooms" }
        });
        let err = read_reply(&reply, "irrelevant", "did:example:host").expect_err("a refusal");
        let msg = err.to_string();
        assert!(msg.contains("private-tier-not-enabled"), "{msg}");
        assert!(msg.contains("has not enabled private rooms"), "{msg}");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "a refusal, not a 502"
        );
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
        verify_host_reply(&reply, "did:example:host", &test_resolver().await)
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
        let err = verify_host_reply(&reply, "did:example:host", &test_resolver().await)
            .await
            .expect_err("an unsigned success reply must not be believed");
        let msg = err.to_string();
        assert!(
            msg.contains("bytes, not") || msg.contains("unsigned"),
            "the refusal must say why an unsigned answer is worthless: {msg}"
        );
    }

    async fn test_resolver() -> affinidi_did_resolver_cache_sdk::DIDCacheClient {
        affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("a resolver for tests")
    }

    #[test]
    fn a_reply_answering_a_different_task_is_a_contract_break() {
        let reply =
            serde_json::json!({ "type": "https://trusttasks.org/spec/rooms/create/0.1#response" });
        let err = read_reply(
            &reply,
            "https://trusttasks.org/spec/rooms/epoch/chain/0.1#response",
            "did:example:host",
        )
        .expect_err("wrong task");
        assert!(err.to_string().contains("contract break"));
    }
}

#[cfg(test)]
mod write_gate_tests {
    use super::*;
    use crate::operations::room_groups::observe_head;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";
    const A: &str = "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";
    const B: &str = "zQmXo1sV5aJ7bT2kQdF9wRnPzYcH4uMgLtEjV6NrBqWsDpK";

    async fn open() -> (tempfile::TempDir, vti_common::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace(crate::keyspaces::ROOM_GROUPS).unwrap();
        (dir, ks)
    }

    /// The asymmetry, which is the whole rule: a caught host still serves reads.
    ///
    /// Refusing the read would punish the member for the host's act and lock
    /// them out of the room holding the records that would show what happened.
    #[tokio::test]
    async fn a_caught_host_is_refused_writes_and_still_serves_reads() {
        let (_d, ks) = open().await;
        observe_head(&ks, ROOM, 412, A).await.unwrap();
        observe_head(&ks, ROOM, 412, B).await.unwrap();

        let refused = refuse_if_caught(&ks, ROOM, vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
            .await
            .expect_err("a write to a caught host must be refused");
        let said = refused.to_string();
        assert!(
            said.contains("412") && said.contains("Reading this room still works"),
            "the refusal must name what was observed and what still works: {said}"
        );

        refuse_if_caught(&ks, ROOM, vti_rooms::wire::ROOMS_RECORDS_GET_TYPE)
            .await
            .expect("reads are served");
        refuse_if_caught(&ks, ROOM, vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE)
            .await
            .expect("listings are served");
    }

    /// A room that has only ever agreed is written to without ceremony.
    #[tokio::test]
    async fn a_host_that_has_not_been_caught_is_not_refused() {
        let (_d, ks) = open().await;
        observe_head(&ks, ROOM, 412, A).await.unwrap();
        observe_head(&ks, ROOM, 413, B).await.unwrap();
        refuse_if_caught(&ks, ROOM, vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
            .await
            .expect("two moments are not a contradiction");
    }

    /// The refusal outlives the observation that produced it.
    ///
    /// A conflict is a fact about the past, and the pair that revealed it is
    /// prunable — an agent that recomputed "caught" from what it still holds
    /// would exonerate a host by doing enough reading.
    #[tokio::test]
    async fn being_caught_survives_the_history_being_pruned() {
        let (_d, ks) = open().await;
        observe_head(&ks, ROOM, 1, A).await.unwrap();
        observe_head(&ks, ROOM, 1, B).await.unwrap();
        // Push the conflicting pair off the end of the bounded map.
        for v in 2..=64u64 {
            observe_head(&ks, ROOM, v, A).await.unwrap();
        }
        assert!(
            refuse_if_caught(&ks, ROOM, vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
                .await
                .is_err(),
            "reading past a conflict must not clear it"
        );
    }

    /// A local storage fault is not a host that misbehaved.
    #[tokio::test]
    async fn a_room_with_no_history_at_all_is_written_to() {
        let (_d, ks) = open().await;
        refuse_if_caught(&ks, ROOM, vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
            .await
            .expect("nothing observed is not something caught");
    }
}
