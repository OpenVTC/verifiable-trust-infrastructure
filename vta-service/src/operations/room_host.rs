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
    send_room_task_typed(
        ctx,
        groups,
        room_id,
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
    room_id: &str,
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
    refuse_if_caught(groups, room_id, task)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKey {
    /// The key record the gated oracle signs with.
    pub key_id: String,
    /// The method the owner's DID document lists the key under, which the proof names.
    pub verification_method: String,
}

/// The stores [`owner_signing_key`] reads.
pub struct OwnerKeyStores<'a> {
    pub keys_ks: &'a vti_common::store::KeyspaceHandle,
    /// The `did:webvh` logs this agent publishes. A build without `webvh` publishes none,
    /// so a `did:webvh` owner is one it cannot hold a key for.
    #[cfg(feature = "webvh")]
    pub webvh_ks: &'a vti_common::store::KeyspaceHandle,
}

/// Find the key this agent may sign with as `owner`, for `auth`.
///
/// `rooms/create` is issued by the room's **Owner** (its `parties`), and a host records as
/// owner only the party whose proof is on the request (`vti_rooms::authz::authorize_create`).
/// `rooms/owner/register` has the key holder "speak to the host as its principal", so the
/// document it sends must be signed by the owner — never by this agent under its own DID
/// while naming someone else.
///
/// The owner is a DID this agent holds the signing key for, in a context the caller may act
/// in:
///
/// - **This agent's own DID**: its `#key-0`, as before. Whether the caller may sign as the
///   agent is the oracle's question, asked when the proof is made.
/// - **A `did:webvh` this agent minted**: the caller must act in the DID's context. The
///   method is read from the DID's **own log** (no resolution: this agent published it, and a
///   registration that depends on the network is one a host can shape), as the first
///   `assertionMethod` entry whose public key is an active key record of that same context.
/// - **A `did:key`**: an active key record with that public key, in a context the caller
///   acts in.
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
    let keys_ks = stores.keys_ks;
    let not_held = || {
        AppError::Forbidden(format!(
            "this agent holds no signing key for `{owner}` that you may use, so it cannot \
             register a room in its name. Name as `ownerDid` a DID this agent minted in a \
             context you act in — a host records as owner only the party that signed the \
             request"
        ))
    };

    if vta_did == Some(owner) {
        return Ok(OwnerKey {
            key_id: format!("{owner}#key-0"),
            verification_method: crate::operations::credentials::vta_signing_vm(owner),
        });
    }

    if let Some(id) = owner.strip_prefix("did:key:") {
        let id = id.split('#').next().unwrap_or(id);
        let record = held_ed25519(keys_ks, id, |ctx| match ctx {
            Some(ctx) => auth.has_context_access(ctx),
            None => auth.is_super_admin(),
        })
        .await?
        .ok_or_else(not_held)?;
        return Ok(OwnerKey {
            key_id: record.key_id,
            verification_method: format!("did:key:{id}#{id}"),
        });
    }

    #[cfg(feature = "webvh")]
    if let Some(key) = webvh_owner_key(keys_ks, stores.webvh_ks, auth, owner).await? {
        return Ok(key);
    }
    Err(not_held())
}

/// The `did:webvh` arm of [`owner_signing_key`]: `None` when this agent holds no key it
/// may sign with as `owner`, for `auth`.
#[cfg(feature = "webvh")]
async fn webvh_owner_key(
    keys_ks: &vti_common::store::KeyspaceHandle,
    webvh_ks: &vti_common::store::KeyspaceHandle,
    auth: &crate::auth::AuthClaims,
    owner: &str,
) -> Result<Option<OwnerKey>, AppError> {
    let Some(record) = crate::webvh_store::get_did(webvh_ks, owner).await? else {
        return Ok(None);
    };
    if !auth.has_context_access(&record.context_id) {
        return Ok(None);
    }
    let Some(log) = crate::webvh_store::get_did_log(webvh_ks, owner).await? else {
        return Ok(None);
    };
    let document = crate::operations::protocol::document::current_document_from_log(&log)
        .map_err(|e| AppError::Internal(format!("read the current document of {owner}: {e}")))?;

    // Every method, by id, with its public key — `assertionMethod` may list ids or embed
    // the method itself.
    let mut methods: Vec<(String, String)> = Vec::new();
    let mut add = |m: &Value| {
        if let (Some(id), Some(pk)) = (
            m.get("id").and_then(Value::as_str),
            m.get("publicKeyMultibase").and_then(Value::as_str),
        ) {
            methods.push((id.to_string(), pk.to_string()));
        }
    };
    for m in document["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
    {
        add(m);
    }
    for m in document["assertionMethod"].as_array().into_iter().flatten() {
        add(m);
    }
    let absolute = |id: &str| {
        if id.starts_with('#') {
            format!("{owner}{id}")
        } else {
            id.to_string()
        }
    };
    for entry in document["assertionMethod"].as_array().into_iter().flatten() {
        let id = match entry {
            Value::String(s) => s.as_str(),
            other => match other.get("id").and_then(Value::as_str) {
                Some(s) => s,
                None => continue,
            },
        };
        let id = absolute(id);
        // Only the DID's own methods: a key named under another DID is not this owner's.
        if !id.starts_with(&format!("{owner}#")) {
            continue;
        }
        let Some((_, public_key)) = methods.iter().find(|(m, _)| absolute(m) == id) else {
            continue;
        };
        // Of the DID's own context only: a public key someone copied into their document
        // must not reach a record another context holds.
        if let Some(held) = held_ed25519(keys_ks, public_key, |ctx| {
            ctx == Some(record.context_id.as_str())
        })
        .await?
        {
            return Ok(Some(OwnerKey {
                key_id: held.key_id,
                verification_method: id,
            }));
        }
    }
    Ok(None)
}

/// An active Ed25519 key record holding `public_key`, in a context `in_scope` accepts.
///
/// Compared as key bytes, not as strings: a key published with its multicodec prefix and
/// one recorded without it are the same key.
async fn held_ed25519(
    keys_ks: &vti_common::store::KeyspaceHandle,
    public_key: &str,
    in_scope: impl Fn(Option<&str>) -> bool,
) -> Result<Option<vta_sdk::keys::KeyRecord>, AppError> {
    use vta_sdk::did_key::decode_ed25519_public_key_multibase as decode;
    let Ok(wanted) = decode(public_key) else {
        return Ok(None);
    };
    for (_, value) in keys_ks.prefix_iter_raw("key:").await? {
        let Ok(record) = serde_json::from_slice::<vta_sdk::keys::KeyRecord>(&value) else {
            continue;
        };
        if record.key_type == vta_sdk::keys::KeyType::Ed25519
            && record.status == vta_sdk::keys::KeyStatus::Active
            && decode(&record.public_key).is_ok_and(|k| k == wanted)
            && in_scope(record.context_id.as_deref())
        {
            return Ok(Some(record));
        }
    }
    Ok(None)
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
            let created = crate::operations::keys::create_key(
                &self.ts.keys_ks,
                &self.ts.internal_ks,
                &self.ts.contexts_ks,
                &self.seed,
                &self.ts.audit,
                &self.ts.acl_ks,
                &crate::test_support::super_admin_claims(),
                crate::operations::keys::CreateKeyParams {
                    key_type: vta_keys::KeyType::Ed25519,
                    internal: true,
                    derivation_path: None,
                    key_id: Some(key_id.into()),
                    mnemonic: None,
                    label: None,
                    context_id: Some(context.into()),
                },
                "test",
            )
            .await
            .expect("mint a key");
            let raw = vta_sdk::did_key::decode_ed25519_public_key_multibase(&created.public_key)
                .expect("the minted key");
            (created.public_key, raw)
        }

        #[cfg(feature = "webvh")]
        async fn owner_in(&self, context: &str) -> Owner {
            use didwebvh_rs::create::{CreateDIDConfig, create_did};
            use didwebvh_rs::parameters::Parameters as WebVHParameters;

            let key_id = format!("owner-signing-{context}");
            let (_, raw) = self.mint_key(context, &key_id).await;
            let published = vta_sdk::did_key::ed25519_multibase_pubkey(&raw);

            // The log's own update key is separate from the owner's signing key.
            let mut update = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(
                None,
                Some(&[9u8; 32]),
            );
            let update_pub = update.get_public_keymultibase().expect("update key");
            update.id = format!("did:key:{update_pub}#{update_pub}");
            let document = serde_json::json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "{DID}",
                "verificationMethod": [
                    { "id": "{DID}#key-1", "type": "Multikey", "controller": "{DID}",
                      "publicKeyMultibase": published },
                ],
                "authentication": ["{DID}#key-1"],
                "assertionMethod": ["{DID}#key-1"],
            });
            let cfg = CreateDIDConfig::builder()
                .address(format!("https://example.invalid/{context}/owner/did.jsonl"))
                .authorization_key(update)
                .did_document(document)
                .parameters(WebVHParameters {
                    update_keys: Some(std::sync::Arc::new(vec![update_pub.into()])),
                    ..Default::default()
                })
                .build()
                .expect("create config");
            let result = create_did(cfg).await.expect("create did");
            let did = result.did().to_string();
            let log = serde_json::to_string(result.log_entry()).expect("serialise log");
            crate::webvh_store::store_did_log(&self.ts.webvh_ks, &did, &log)
                .await
                .expect("store log");
            let now = chrono::Utc::now();
            crate::webvh_store::store_did(
                &self.ts.webvh_ks,
                &vta_sdk::webvh::WebvhDidRecord {
                    did: did.clone(),
                    server_id: "serverless".into(),
                    mnemonic: String::new(),
                    scid: "irrelevant".into(),
                    context_id: context.into(),
                    portable: false,
                    log_entry_count: 1,
                    pre_rotation_count: 0,
                    next_fragment_id: 2,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .expect("store did record");
            Owner {
                did,
                key_id,
                public_key: raw,
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
