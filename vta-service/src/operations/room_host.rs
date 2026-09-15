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
//! # What is here, and what is not
//!
//! **Carriage is not here.** Choosing a transport from what the host advertises,
//! applying that transport's binding, and deciding whether a reply is evidence
//! all live in [`crate::operations::outbound`], because none of it is about
//! rooms — it was here only because this was the first caller to need it, and a
//! second caller would have copied it. What stays is the part that *is* about
//! rooms: the document, the refusal to write to a host caught contradicting
//! itself, and reading a room reply's three outcomes apart.
//!
//! Signing also stays, and cannot move: [`vta_sdk::client::VtaClient`] signs
//! from a `ClientIdentity` carrying a raw `private_key_multibase`, and **a VTA
//! never holds its own keys in that shape** — it derives, signs and zeroizes
//! behind [`crate::operations::keys::sign_payload`], where the context gates
//! live. The document is signed here, through the same `Signer` seam
//! `RoomKeySigner` uses, and only the bytes travel.

use serde_json::Value;
use vti_common::error::AppError;

use crate::operations::outbound::{Outbound, ReplyTrust};
use crate::operations::room_issuance::{SigningContext, VtaKeySigner};

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
/// Send one room task to `host` and return the response document's `payload`.
///
/// `signing_key_id` and `issuer` name the identity this VTA signs as. For a
/// member's backfill that is the agent itself — the host binds the presentation
/// to the DID that signed the envelope, so the presentation must have been
/// minted for this same DID or the host will (correctly) refuse it.
#[allow(clippy::too_many_arguments)]
pub async fn send_room_task(
    ctx: SigningContext<'_>,
    groups: &vti_common::store::KeyspaceHandle,
    room_id: &str,
    out: &Outbound<'_>,
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

    // `SignedByRecipient`, and not because a room host is special: a reply that
    // is acted on has to be evidence, and everything this returns is acted on.
    let reply = out
        .send(host, document, ReplyTrust::SignedByRecipient)
        .await?;
    read_reply(&reply, response_task, host)
}

#[cfg(test)]
mod tests {
    use super::*;

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
