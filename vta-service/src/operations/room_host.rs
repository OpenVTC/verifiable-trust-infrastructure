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

/// Send one room task to `host` and return the response document's `payload`.
///
/// `signing_key_id` and `issuer` name the identity this VTA signs as. For a
/// member's backfill that is the agent itself — the host binds the presentation
/// to the DID that signed the envelope, so the presentation must have been
/// minted for this same DID or the host will (correctly) refuse it.
pub async fn send_room_task(
    ctx: SigningContext<'_>,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &str,
    signing_key_id: &str,
    issuer: &str,
    verification_method: &str,
    task: &str,
    response_task: &str,
    payload: Value,
) -> Result<Value, AppError> {
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
