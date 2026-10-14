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
/// reason `webvh_host::build_request_document` exists, and for the same
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
    read_reply_typed(doc, expected, host).map_err(RoomTaskError::into_app_error)
}

/// Why a room task sent to a host did not produce its response.
///
/// Two outcomes a caller must not confuse. A **refusal** is the host's answer:
/// the task definitely did not take effect there. **Anything else** — a host
/// that could not be reached, a reply that could not be read — leaves the
/// outcome unknown: the host may have acted and the answer been lost. A caller
/// whose local state must follow the host's (an epoch advance) keeps its
/// pending change on the second and discards it only on the first.
#[derive(Debug)]
pub enum RoomTaskError {
    /// The host answered with a `trust-task-error`.
    Refused {
        host: String,
        code: String,
        reason: String,
    },
    /// No usable answer: the outcome at the host is unknown.
    Unknown(AppError),
}

impl RoomTaskError {
    /// The error every caller that does not distinguish the two has always seen.
    pub fn into_app_error(self) -> AppError {
        match self {
            Self::Refused { host, code, reason } => {
                AppError::Forbidden(format!("room host `{host}` refused: {code}: {reason}"))
            }
            Self::Unknown(e) => e,
        }
    }
}

/// [`read_reply`], keeping a refusal apart from everything else.
pub fn read_reply_typed(doc: &Value, expected: &str, host: &str) -> Result<Value, RoomTaskError> {
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
        return Err(RoomTaskError::Refused {
            host: host.to_string(),
            code: code.to_string(),
            reason: reason.to_string(),
        });
    }

    Err(RoomTaskError::Unknown(AppError::Internal(format!(
        "room host `{host}` answered `{doc_type}` where `{expected}` was expected; a reply that \
         threads to our request but answers a different task is a contract break rather than a \
         task failure"
    ))))
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
    member: &crate::operations::room_groups::Member,
    task: &str,
) -> Result<(), AppError> {
    if !MUTATING_ROOM_TASKS.contains(&task) {
        return Ok(());
    }
    let room_id = member.room_id();
    let history = match crate::operations::room_groups::root_history(groups, member).await {
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
    member: &crate::operations::room_groups::Member,
    out: &Outbound<'_>,
    host: &str,
    signing_key_id: &str,
    issuer: &str,
    verification_method: &str,
    task: &str,
    response_task: &str,
    payload: Value,
) -> Result<Value, AppError> {
    send_room_task_typed(
        ctx,
        groups,
        member,
        out,
        host,
        signing_key_id,
        issuer,
        verification_method,
        task,
        response_task,
        payload,
    )
    .await
    .map_err(RoomTaskError::into_app_error)
}

/// [`send_room_task`], keeping the host's refusal apart from an unknown outcome
/// ([`RoomTaskError`]). Anything that fails before the request leaves is a
/// definite non-event, and reported as `Unknown` only because it carries no
/// host code; a caller that must reconcile treats it like any other.
#[allow(clippy::too_many_arguments)]
pub async fn send_room_task_typed(
    ctx: SigningContext<'_>,
    groups: &vti_common::store::KeyspaceHandle,
    member: &crate::operations::room_groups::Member,
    out: &Outbound<'_>,
    host: &str,
    signing_key_id: &str,
    issuer: &str,
    verification_method: &str,
    task: &str,
    response_task: &str,
    payload: Value,
) -> Result<Value, RoomTaskError> {
    // Before anything leaves. Threaded through the seam rather than left to each
    // caller: a write task added later inherits the refusal instead of having to
    // remember it, which is the difference between a rule and a convention.
    refuse_if_caught(groups, member, task)
        .await
        .map_err(RoomTaskError::Unknown)?;

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
        RoomTaskError::Unknown(AppError::Internal(format!(
            "sign the request to room host `{host}`: {e}{cause}"
        )))
    })?;
    document["proof"] = serde_json::to_value(proof).map_err(|e| {
        RoomTaskError::Unknown(AppError::Internal(format!("serialise the proof: {e}")))
    })?;

    // `SignedByRecipient`, and not because a room host is special: a reply that
    // is acted on has to be evidence, and everything this returns is acted on.
    let reply = out
        .send(host, document, ReplyTrust::SignedByRecipient)
        .await
        .map_err(RoomTaskError::Unknown)?;
    read_reply_typed(&reply, response_task, host)
}

/// The key, and the verification method it is published as, that this agent signs
/// with **as** `owner`.
pub type OwnerKey = crate::operations::persona::PersonaKey;

/// The stores [`owner_signing_key`] reads.
pub type OwnerKeyStores<'a> = crate::operations::persona::PersonaStores<'a>;

/// Find the key this agent may sign with as `owner`, for `auth`.
///
/// `rooms/create` is issued by the room's **Owner** (its `parties`), and a host records as
/// owner only the party whose proof is on the request (`vti_rooms::authz::authorize_create`).
/// `rooms/owner/register` has the key holder "speak to the host as its principal", so the
/// document it sends must be signed by the owner — never by this agent under its own DID
/// while naming someone else.
///
/// The owner is a **persona** the caller may act as
/// ([`crate::operations::persona::persona_signing_key`]: a `did:webvh` this agent minted, or
/// a `did:key` it holds, in a context the caller acts in) — or, as before personas, **this
/// agent's own DID**, signing with its `#key-0`; whether the caller may sign as the agent is
/// the oracle's question, asked when the proof is made. That second case is kept here, and
/// only here: the agent's DID is not a persona and no other room path accepts it.
///
/// Anything else is refused as `Forbidden` — the same refusal whether the DID is unknown or
/// held in a context the caller cannot reach, so the answer does not say which DIDs this
/// agent holds for others. The oracle re-checks the key when it signs, so this decides only
/// *which* key; it confers nothing.
pub async fn owner_signing_key(
    stores: OwnerKeyStores<'_>,
    auth: &crate::auth::AuthClaims,
    owner: &str,
    vta_did: Option<&str>,
) -> Result<OwnerKey, AppError> {
    if vta_did == Some(owner) {
        return Ok(OwnerKey {
            key_id: format!("{owner}#key-0"),
            verification_method: crate::operations::credentials::vta_signing_vm(owner),
        });
    }
    crate::operations::persona::persona_signing_key(stores, auth, owner)
        .await?
        .ok_or_else(|| {
            AppError::Forbidden(format!(
                "this agent holds no signing key for `{owner}` that you may use, so it cannot \
                 register a room in its name. Name as `ownerDid` a DID this agent minted in a \
                 context you act in — a host records as owner only the party that signed the \
                 request"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A room owner's identity as this agent mints one: a real published `did:webvh` log
    /// whose document numbers its signing method `#key-1` (as the templates do), over a
    /// key minted through the real path into `context`. The key record is named after
    /// nothing in particular — the resolver matches by key, never by name.
    struct Owner {
        did: String,
        key_id: String,
        public_key: [u8; 32],
    }

    struct Fixture {
        ts: crate::test_support::TestStore,
        seed: std::sync::Arc<dyn vti_secrets::SeedStore>,
    }

    impl Fixture {
        async fn new() -> Self {
            let ts = crate::test_support::open_test_store().await;
            for (id, name) in [("rooms", "Rooms"), ("other", "Other")] {
                crate::contexts::create_context(&ts.contexts_ks, id, name)
                    .await
                    .expect("create context");
            }
            Self {
                ts,
                seed: std::sync::Arc::new(crate::test_support::TestSeedStore(vec![7u8; 32])),
            }
        }

        fn stores(&self) -> OwnerKeyStores<'_> {
            OwnerKeyStores {
                keys_ks: &self.ts.keys_ks,
                #[cfg(feature = "webvh")]
                webvh_ks: &self.ts.webvh_ks,
            }
        }

        fn signing<'a>(&'a self, auth: &'a crate::auth::AuthClaims) -> SigningContext<'a> {
            SigningContext {
                keys_ks: &self.ts.keys_ks,
                imported_ks: &self.ts.imported_ks,
                internal_ks: &self.ts.internal_ks,
                contexts_ks: &self.ts.contexts_ks,
                acl_ks: &self.ts.acl_ks,
                seed_store: &self.seed,
                audit: &self.ts.audit,
                auth,
            }
        }

        async fn mint_key(&self, context: &str, key_id: &str) -> (String, [u8; 32]) {
            let raw = crate::operations::persona::test_fixture::mint_key(
                &self.ts.keys_ks,
                &self.ts.internal_ks,
                &self.ts.contexts_ks,
                &self.ts.acl_ks,
                &self.seed,
                &self.ts.audit,
                context,
                key_id,
            )
            .await;
            (vta_sdk::did_key::ed25519_multibase_pubkey(&raw), raw)
        }

        #[cfg(feature = "webvh")]
        async fn owner_in(&self, context: &str) -> Owner {
            let p = crate::operations::persona::test_fixture::webvh_persona(
                &self.ts.keys_ks,
                &self.ts.internal_ks,
                &self.ts.contexts_ks,
                &self.ts.acl_ks,
                &self.ts.webvh_ks,
                &self.seed,
                &self.ts.audit,
                context,
                &format!("owner-signing-{context}"),
            )
            .await;
            Owner {
                did: p.did,
                key_id: p.key_id,
                public_key: p.public_key,
            }
        }
    }

    /// The fix, end to end at this agent's edge: `rooms/create` leaves signed by the owner,
    /// under the method the owner's document publishes, with a proof that verifies against
    /// the owner's published key — and the rule every host applies to a registration
    /// (`authorize_create`: the signer is the owner named) holds. Before, the document was
    /// signed by this agent while naming the caller, which that rule refuses.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn register_signs_rooms_create_as_the_owner() {
        let f = Fixture::new().await;
        let owner = f.owner_in("rooms").await;
        let caller = crate::test_support::admin_claims_for_context("rooms");

        let key = owner_signing_key(
            f.stores(),
            &caller,
            &owner.did,
            Some("did:webvh:QmAgent:agent.example"),
        )
        .await
        .expect("the owner's key");
        assert_eq!(key.key_id, owner.key_id);
        assert_eq!(key.verification_method, format!("{}#key-1", owner.did));

        let room = "did:webvh:QmRoom:rooms.example:northwind";
        let document = build_room_task(
            vti_rooms::wire::ROOMS_CREATE_TYPE,
            "did:webvh:QmHost:community.example",
            &owner.did,
            serde_json::json!({ "roomId": room, "visibility": "attributed", "ownerDid": owner.did }),
        );
        let signer = VtaKeySigner::new(f.signing(&caller), &key.key_id, &key.verification_method);
        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &document,
            &signer,
            affinidi_data_integrity::SignOptions::new(),
        )
        .await
        .expect("sign as the owner");

        assert_eq!(document["issuer"], owner.did);
        assert_eq!(proof.verification_method, format!("{}#key-1", owner.did));
        assert_eq!(proof.proof_purpose, "assertionMethod");
        proof
            .verify_with_public_key(
                &document,
                &owner.public_key,
                affinidi_data_integrity::VerifyOptions::new(),
            )
            .expect("the proof verifies against the owner's published key");
        vti_rooms::authz::authorize_create(room, &owner.did, &proof.verification_method)
            .expect("a host records the signer as the owner it names");
    }

    /// A DID this agent holds for another context is not the caller's to speak as — and the
    /// refusal does not say that the DID is held at all.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn an_owner_in_another_context_is_refused() {
        let f = Fixture::new().await;
        let elsewhere = f.owner_in("other").await;
        let caller = crate::test_support::admin_claims_for_context("rooms");

        let err = owner_signing_key(f.stores(), &caller, &elsewhere.did, None)
            .await
            .expect_err("another context's DID");
        assert!(matches!(err, AppError::Forbidden(_)), "{err}");
        let unknown = owner_signing_key(
            f.stores(),
            &caller,
            "did:webvh:QmNobody:nowhere.example",
            None,
        )
        .await
        .expect_err("an unknown DID");
        assert_eq!(
            err.to_string(),
            unknown
                .to_string()
                .replace("did:webvh:QmNobody:nowhere.example", &elsewhere.did,),
            "held-elsewhere and unknown read the same"
        );
    }

    /// With no `ownerDid` the owner is the caller — and a caller whose key lives in their own
    /// client (a `pnm` session's `did:key`) is not one this agent can sign as. Refused, with
    /// what to do instead, rather than signed as this agent.
    #[tokio::test]
    async fn a_caller_whose_key_this_agent_does_not_hold_is_refused() {
        let f = Fixture::new().await;
        let caller = crate::test_support::admin_claims_for_context("rooms");
        let err = owner_signing_key(f.stores(), &caller, &caller.did, None)
            .await
            .expect_err("a client-held key");
        assert!(matches!(err, AppError::Forbidden(_)), "{err}");
        assert!(err.to_string().contains("ownerDid"), "{err}");
    }

    /// A `did:key` this agent holds the key for, in the caller's context, signs as itself.
    #[tokio::test]
    async fn a_held_did_key_owner_signs_as_itself() {
        let f = Fixture::new().await;
        let (_, raw) = f.mint_key("rooms", "a-did-key-owner").await;
        let id = vta_sdk::did_key::ed25519_multibase_pubkey(&raw);
        let did = format!("did:key:{id}");
        let caller = crate::test_support::admin_claims_for_context("rooms");
        let key = owner_signing_key(f.stores(), &caller, &did, None)
            .await
            .expect("a held did:key");
        assert_eq!(key.key_id, "a-did-key-owner");
        assert_eq!(key.verification_method, format!("{did}#{id}"));

        let other = crate::test_support::admin_claims_for_context("other");
        owner_signing_key(f.stores(), &other, &did, None)
            .await
            .expect_err("not from another context");
    }

    /// The agent's own DID keeps signing as the agent, as it did before.
    #[tokio::test]
    async fn the_agents_own_did_signs_with_its_own_key() {
        let f = Fixture::new().await;
        let caller = crate::test_support::super_admin_claims();
        let vta = "did:webvh:QmAgent:agent.example";
        let key = owner_signing_key(f.stores(), &caller, vta, Some(vta))
            .await
            .expect("the agent itself");
        assert_eq!(key.key_id, format!("{vta}#key-0"));
        assert_eq!(key.verification_method, format!("{vta}#key-0"));
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

#[cfg(test)]
mod write_gate_tests {
    use super::*;
    use crate::operations::room_groups::observe_head;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";
    const A: &str = "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";
    const B: &str = "zQmXo1sV5aJ7bT2kQdF9wRnPzYcH4uMgLtEjV6NrBqWsDpK";

    fn member() -> crate::operations::room_groups::Member {
        crate::operations::room_groups::Member::new(ROOM, "did:key:zAlice").unwrap()
    }

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
        observe_head(&ks, &member(), 412, A).await.unwrap();
        observe_head(&ks, &member(), 412, B).await.unwrap();

        let refused = refuse_if_caught(&ks, &member(), vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
            .await
            .expect_err("a write to a caught host must be refused");
        let said = refused.to_string();
        assert!(
            said.contains("412") && said.contains("Reading this room still works"),
            "the refusal must name what was observed and what still works: {said}"
        );

        refuse_if_caught(&ks, &member(), vti_rooms::wire::ROOMS_RECORDS_GET_TYPE)
            .await
            .expect("reads are served");
        refuse_if_caught(&ks, &member(), vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE)
            .await
            .expect("listings are served");
    }

    /// A room that has only ever agreed is written to without ceremony.
    #[tokio::test]
    async fn a_host_that_has_not_been_caught_is_not_refused() {
        let (_d, ks) = open().await;
        observe_head(&ks, &member(), 412, A).await.unwrap();
        observe_head(&ks, &member(), 413, B).await.unwrap();
        refuse_if_caught(&ks, &member(), vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
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
        observe_head(&ks, &member(), 1, A).await.unwrap();
        observe_head(&ks, &member(), 1, B).await.unwrap();
        // Push the conflicting pair off the end of the bounded map.
        for v in 2..=64u64 {
            observe_head(&ks, &member(), v, A).await.unwrap();
        }
        assert!(
            refuse_if_caught(&ks, &member(), vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
                .await
                .is_err(),
            "reading past a conflict must not clear it"
        );
    }

    /// A local storage fault is not a host that misbehaved.
    #[tokio::test]
    async fn a_room_with_no_history_at_all_is_written_to() {
        let (_d, ks) = open().await;
        refuse_if_caught(&ks, &member(), vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE)
            .await
            .expect("nothing observed is not something caught");
    }
}
