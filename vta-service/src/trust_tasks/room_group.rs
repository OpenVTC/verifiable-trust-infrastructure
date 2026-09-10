//! The room group slice — `spec/rooms/keys/{key-package,welcome,commit,open}`.
//!
//! How a group reaches a key-holding agent, and what it does once it has one. The
//! orchestration is [`crate::operations::room_groups`]; this is the dispatch surface.
//!
//! # Four tasks, four different gates
//!
//! Deliberately not one gate applied four times, because these are four different acts:
//!
//! | | authorized by |
//! |---|---|
//! | `key-package` | an invitation — minting retains a private key, so a VTA that minted for anyone is one anyone can fill |
//! | `welcome` | that same invitation, **consumed** |
//! | `commit` | the group itself — MLS authenticates the committer as a member of the group we already hold |
//! | `open` | [`Capability::RoomOpen`] |
//!
//! Only the last is a capability, and that asymmetry is the point. The first three are
//! *inbound* — a room's owner reaching this VTA — and an ACL of ours has no opinion about
//! who a room's owner is. The fourth is our own principal's agent asking us to decrypt, and
//! that is exactly what a capability is for.
//!
//! # Every request type here is generated
//!
//! `rooms/keys/{key-package,welcome,commit}` merged upstream in
//! `trustoverip/dtgwg-trust-tasks-tf#355` and released in `trust-tasks-rs` 0.17.8, so none
//! of the four needs a hand-written request body. Only the responses are local, because a
//! handler returns a struct rather than a `Value`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::acl::Capability;

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::{room_groups, room_invitation};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, success_response,
};

/// How long an unused KeyPackage's private half is retained.
///
/// Bounded because the private half *is* retained key material: a caller that minted and
/// never joined has left a key behind, and one that minted repeatedly has left a pile.
const KEY_PACKAGE_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

// ─── Response types ──────────────────────────────────────────────────────
//
// Requests come from the generated bindings; only the responses are written
// here, and only because a handler returns a struct rather than a `Value`.

/// `rooms/keys/key-package/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageResponse {
    pub key_package: String,
    pub expires_at: String,
}

/// `rooms/keys/welcome/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WelcomeResponse {
    pub epoch: u64,
}

/// `rooms/keys/commit/0.1#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitResponse {
    pub epoch: u64,
}

// ─── Handlers ────────────────────────────────────────────────────────────

/// `rooms/keys/key-package/0.1`.
pub(super) async fn handle_key_package(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: trust_tasks_rs::specs::rooms::keys::key_package::v0_1::Payload =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    // Minting retains a private key against a Welcome that may never come, so it is not
    // free and is not offered unconditionally.
    if let Err(e) =
        require_invitation(state, req.invitation.as_deref(), &req.room_id, &auth.did).await
    {
        return app_error_to_reject(&doc, e);
    }

    let minted = match room_groups::mint_key_package(
        &state.room_groups_ks,
        &req.room_id,
        &auth.did,
        KEY_PACKAGE_LIFETIME_SECS,
        now(),
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    record(state, "rooms.keys.key-package", auth, &req.room_id).await;
    success_response(
        &doc,
        KeyPackageResponse {
            key_package: minted.key_package,
            expires_at: rfc3339(minted.expires_at),
        },
    )
}

/// `rooms/keys/welcome/0.1`.
pub(super) async fn handle_welcome(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: trust_tasks_rs::specs::rooms::keys::welcome::v0_1::Payload = match parse_payload(&doc)
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // The load-bearing gate. A Welcome carries a group's secrets; without a matching
    // invitation this VTA would be accepting key material for a room nobody agreed to join.
    let invitation =
        match require_invitation(state, req.invitation.as_deref(), &req.room_id, &auth.did).await {
            Ok(i) => i,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    let welcome = match decode_b64(&req.welcome, "welcome") {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let epoch = match room_groups::join(
        &state.room_groups_ks,
        &req.room_id,
        invitation.subject(),
        &welcome,
        now(),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Consumed only after the join succeeded. Burning it on a Welcome that then failed to
    // process would strand the member: the invitation is spent and they are not in.
    if let Err(e) = room_groups::consume_invitation(
        &state.room_invitations_ks,
        invitation.credential_id(),
        &req.room_id,
        now(),
    )
    .await
    {
        return app_error_to_reject(&doc, e);
    }

    record(state, "rooms.keys.welcome", auth, &req.room_id).await;
    success_response(&doc, WelcomeResponse { epoch })
}

/// `rooms/keys/commit/0.1`.
pub(super) async fn handle_commit(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: trust_tasks_rs::specs::rooms::keys::commit::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let commit = match decode_b64(&req.commit, "commit") {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // No gate of ours. MLS authenticates the committer as a member of the group we already
    // hold, and an ACL here would be this service deciding who may commit to a room it is
    // not part of — the mistake the whole family is arranged to avoid.
    let epoch = match room_groups::apply_commit(
        &state.room_groups_ks,
        &req.room_id,
        &commit,
        u64::from(req.epoch),
        now(),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    record(state, "rooms.keys.commit", auth, &req.room_id).await;
    success_response(&doc, CommitResponse { epoch })
}

/// `rooms/keys/seal/0.1`.
///
/// The mirror of [`handle_open`], and gated on the same capability for the same reason:
/// `RoomOpen` governs a principal's room records, and sealing one is acting on them.
///
/// Note what this returns and what it does not. It hands back ciphertext; it does not store
/// anything and does not reach the room's host. A caller that wanted the record written must
/// present its own authority there, which is the separation that keeps this VTA out of the
/// decision about what a room contains.
pub(super) async fn handle_seal(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "sealing a room record",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::keys::seal::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let plaintext = match base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &req.plaintext,
    ) {
        Ok(b) => b,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                vti_common::error::AppError::Validation(format!("plaintext is not base64url: {e}")),
            );
        }
    };

    let sealed = match room_groups::seal_record(
        &state.room_groups_ks,
        &req.room_id,
        &req.key,
        req.version,
        &plaintext,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    record(state, "rooms.keys.seal", auth, &req.room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "sealed": {
                "ciphertext": sealed.ciphertext,
                "nonce": sealed.nonce,
                "epoch": sealed.epoch,
            }
        }),
    )
}

/// `rooms/keys/list/0.1`.
///
/// Which rooms this VTA can open, and how far back each reads.
///
/// Gated on `RoomOpen` because that is the capability the answer is *about*: an agent that
/// may not open a principal's rooms has no business enumerating them, and the list is the
/// principal's room membership as key custody sees it — more than any single room operation
/// discloses.
pub(super) async fn handle_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "listing the rooms this VTA holds keys for",
    )
    .await
    {
        return r;
    }

    let rooms = match room_groups::list_rooms(&state.room_groups_ks).await {
        Ok(r) => r,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    record(state, "rooms.keys.list", auth, "").await;
    success_response(&doc, serde_json::json!({ "rooms": rooms }))
}

/// `rooms/keys/chain/0.1`.
///
/// The principal hands this VTA the room's epoch key chain, so it can open records sealed
/// before the principal joined.
///
/// # Gated on `RoomOpen`, and that is the whole of the authorization
///
/// The specification's entitlement is *being this key holder's own principal* — not a
/// credential the room issued. Fetching these rungs from a host took a room-issued `read`
/// chain; handing them on takes none, because this VTA is not being asked to believe
/// anything about the room. It is being handed material it will verify by trying to use it.
///
/// `RoomOpen` is the right capability because it is the one that governs *reading a room's
/// records*, and this extends how far back that reaches. Gating it on anything wider would
/// grant more than the task needs; on `Sign`, as the oracle's own docs argue, strictly more.
pub(super) async fn handle_chain(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "extending a room's readable history",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::keys::chain::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Converted rather than clamped: an epoch outside `u32` is a malformed rung, and
    // saturating it to `u32::MAX` would store one under an epoch nobody will ever ask for —
    // a delivery that reports success and extends nothing.
    let links: Result<Vec<vti_rooms::wire::EpochLink>, _> = req
        .links
        .iter()
        .map(|l| {
            u32::try_from(l.epoch).map(|epoch| vti_rooms::wire::EpochLink {
                epoch,
                wrapped: l.wrapped.clone(),
                nonce: l.nonce.clone(),
            })
        })
        .collect();
    let links = match links {
        Ok(l) => l,
        Err(_) => {
            return app_error_to_reject(
                &doc,
                vti_common::error::AppError::Validation(
                    "an epoch link names an epoch outside the representable range".into(),
                ),
            );
        }
    };

    let (earliest, stored) =
        match room_groups::store_links(&state.room_groups_ks, &req.room_id, links, now()).await {
            Ok(r) => r,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    record(state, "rooms.keys.chain", auth, &req.room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "roomId": req.room_id,
            "earliestReadableEpoch": earliest,
            "stored": stored,
        }),
    )
}

/// Everything the gated signer needs, gathered from the running service.
///
/// A copy of `room_owner`'s rather than a shared one: the two modules sign as
/// different identities and the struct is the argument list, not the policy.
fn signing_context<'a>(
    state: &'a AppState,
    auth: &'a AuthClaims,
) -> crate::operations::room_issuance::SigningContext<'a> {
    crate::operations::room_issuance::SigningContext {
        keys_ks: &state.keys_ks,
        imported_ks: &state.imported_ks,
        internal_ks: &state.internal_ks,
        contexts_ks: &state.contexts_ks,
        acl_ks: &state.acl_ks,
        seed_store: &state.seed_store,
        auth,
    }
}

/// `rooms/keys/backfill/0.1` — fetch the chain from the host and keep it.
///
/// Three hops folded into one, performed by the party that can perform all three:
/// mint a presentation, ask the host for the rungs, store what comes back. The
/// member could do the first and third and not the second — a browser reaches its
/// own agent and no third party — which is the whole reason this task exists.
///
/// **The presentation is minted for this VTA's own DID**, not the caller's, and
/// that is load-bearing rather than incidental. `room_oracle::present` attenuates
/// the principal's authority to whichever agent is named, and a host binds the
/// presentation to the DID that signed the request envelope. This VTA is what
/// signs the outbound document, so a presentation minted for anyone else is one
/// the host is right to refuse — and the refusal would read as the member lacking
/// authority rather than as an agent presenting somebody else's grant.
pub(super) async fn handle_backfill(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "fetching a room's readable history",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::keys::backfill::v0_1::Payload = match parse_payload(&doc)
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let (vta_did, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // `read`, and only `read`. Reading the room and reading the parts of it
    // written earlier are the same act, so they take the same grant; asking for
    // more would hand the host authority the operation never needed.
    //
    // The caller-named `host` is NOT bound into the presentation, and used to be
    // — passed as the leaf's `audience`, which named the party that had to
    // present the credential rather than the one it was sent to, so every
    // backfill this VTA attempted was refused. What makes a caller-named host
    // safe is that the leaf grants to `vta_did`: a host of the caller's
    // choosing receives something only this agent can act with, so naming one
    // transfers no standing. What it does gain is sight of the principal's
    // credentials, which is a disclosure rather than an escalation — see
    // `rooms/keys/backfill/0.1`.
    let minted =
        match crate::operations::room_oracle::present(state, auth, &vta_did, &req.room_id, "read")
            .await
        {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    let mut payload = serde_json::json!({
        "roomId": req.room_id,
        "presentation": minted.presentation,
    });
    if let Some(from) = req.from_epoch {
        payload["fromEpoch"] = serde_json::json!(u64::from(from));
    }
    if let Some(limit) = req.limit {
        payload["limit"] = serde_json::json!(u64::from(limit));
    }

    let key = format!("{vta_did}#key-0");
    let reply = match crate::operations::room_host::send_room_task(
        signing_context(state, auth),
        &state.room_groups_ks,
        &req.room_id,
        &resolver,
        &req.host,
        &key,
        &vta_did,
        &key,
        vti_rooms::wire::ROOMS_EPOCH_CHAIN_TYPE,
        &format!("{}#response", vti_rooms::wire::ROOMS_EPOCH_CHAIN_TYPE),
        payload,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let links: Vec<vti_rooms::wire::EpochLink> =
        match serde_json::from_value(reply.get("links").cloned().unwrap_or(Value::Array(vec![]))) {
            Ok(l) => l,
            Err(e) => {
                return app_error_to_reject(
                    &doc,
                    vti_common::error::AppError::Internal(format!(
                        "room host `{}` served rungs this agent cannot read: {e}",
                        req.host
                    )),
                );
            }
        };
    let fetched = links.len();

    // Nothing served is a real answer rather than an error — the host holds no
    // rungs below what this agent already reads — and it needs no special case:
    // `store_links` with an empty delivery stores nothing and still walks what
    // is held, which is the reach this must report either way.
    let (earliest, stored) =
        match room_groups::store_links(&state.room_groups_ks, &req.room_id, links, now()).await {
            Ok(r) => r,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    record(state, "rooms.keys.backfill", auth, &req.room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "roomId": req.room_id,
            "earliestReadableEpoch": earliest,
            "fetched": fetched,
            "stored": stored,
        }),
    )
}

/// This agent's own DID and a resolver, or the refusal that says which is missing.
///
/// Every task in this family that acts **outward** needs both: it presents as
/// itself, and it has to find the host it was told to speak to. Extracted when
/// the third caller appeared — `backfill`, `read` and `browse` refusing in three
/// slightly different sentences would be three chances for one of them to say
/// something untrue about why.
async fn outbound_identity(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Result<(String, affinidi_did_resolver_cache_sdk::DIDCacheClient), TrustTaskOutcome> {
    let Some(vta_did) = state.config.read().await.vta_did.clone() else {
        return Err(app_error_to_reject(
            doc,
            vti_common::error::AppError::Validation(
                "this agent has no DID of its own, so it cannot present to a host as itself".into(),
            ),
        ));
    };
    let Some(resolver) = state.did_resolver.clone() else {
        return Err(app_error_to_reject(
            doc,
            vti_common::error::AppError::Validation(
                "this agent has no DID resolver configured, so it cannot find the host".into(),
            ),
        ));
    };
    Ok((vta_did, resolver))
}

/// The three values a host asserts about a room, as this agent passes them on.
///
/// All three or none: a root without the state it describes is not comparable
/// to another root, which is the whole of `headVersion` — see
/// `trust-tasks-tf#422`.
fn head_of(
    commitment: Option<&String>,
    record_count: Option<u64>,
    head_version: Option<u64>,
) -> Option<Value> {
    match (commitment, record_count, head_version) {
        (Some(c), Some(n), Some(v)) => Some(serde_json::json!({
            "dataCommitment": c,
            "recordCount": n,
            "headVersion": v,
        })),
        _ => None,
    }
}

/// Record what a host asserted about a room, and say what comparing it came to.
///
/// **This is the comparison no other party on the member's side can make.** A
/// tab does not outlive itself and a CLI keeps nothing; the agent is the only
/// one that saw both reads.
///
/// It is keyed by **room, not host**, which buys a comparison the specification
/// does not list: two hosts of one room reporting different roots at one
/// `headVersion` is exactly as damning as one host disagreeing with itself, and
/// a room may deliberately have several — a mirror serving reads while its
/// primary takes writes. A mirror that merely *lags* reports a lower
/// `headVersion` and is correctly not compared at all.
///
/// A host that asserted nothing is `notChecked` rather than `noneHeld`: one says
/// nothing was found, the other says nothing was looked for.
async fn compare_head(state: &AppState, room_id: &str, head: Option<&Value>) -> &'static str {
    let Some(head) = head else {
        return "notChecked";
    };
    let (Some(version), Some(root)) = (
        head["headVersion"].as_u64(),
        head["dataCommitment"].as_str(),
    ) else {
        return "notChecked";
    };
    match room_groups::observe_head(&state.room_groups_ks, room_id, version, root).await {
        Ok(room_groups::RootVerdict::Agree) => "agree",
        Ok(room_groups::RootVerdict::Conflict) => "conflict",
        Ok(room_groups::RootVerdict::NoneHeld) => "noneHeld",
        Err(e) => {
            // A memory this agent could not read is not a host that behaved. It
            // says so rather than reporting a comparison it did not make.
            tracing::error!(
                room = %room_id,
                error = %e,
                "could not read this agent's root history; answering without a comparison"
            );
            "notChecked"
        }
    }
}

/// Replay a record's trace against the commitment served **beside it**.
///
/// The leaf preimage is the response payload with its verification members
/// removed, which is exactly `CommittedRecord` — so this hashes what it was
/// given rather than reconstructing anything, and a reader that cannot reach the
/// leaf has been served a record that does not match what the host committed to.
///
/// Never a root from an earlier read. A trace is a statement about the tree it
/// was cut from, and a room moves.
fn verify_trace(reply: &vti_rooms::wire::GetRecordResponse) -> &'static str {
    let (Some(commitment), Some(trace)) = (&reply.data_commitment, &reply.trace) else {
        // A host that maintains no tree must not invent a root, so its silence
        // is legal and informative rather than a failure.
        return "notOffered";
    };
    let Ok(root) = vti_rooms::merkle::from_multibase(commitment) else {
        return "failed";
    };
    let Ok(leaf) = vti_rooms::merkle::leaf_hash(&reply.record) else {
        return "failed";
    };
    if vti_rooms::merkle::verify_inclusion(&root, &leaf, trace) {
        "verified"
    } else {
        "failed"
    }
}

/// `rooms/keys/read/0.1`.
///
/// Mint the presentation, ask the host, check what came back, open it. The
/// fourth act is why the other three are here: the epoch key never leaves this
/// agent, so a surface that fetched the record itself would come back to open
/// it anyway, holding a half-verified record in between.
pub(super) async fn handle_read(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "reading a room record",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::keys::read::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let (vta_did, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // `read`, and only `read`. The caller-named host is not bound into the
    // presentation: what makes naming one safe is that the leaf grants to
    // `vta_did`, so a host of the caller's choosing receives something only this
    // agent can act with. What it gains is sight of the credentials, which is a
    // disclosure rather than an escalation.
    let minted =
        match crate::operations::room_oracle::present(state, auth, &vta_did, &req.room_id, "read")
            .await
        {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    let key = format!("{vta_did}#key-0");
    let reply = match crate::operations::room_host::send_room_task(
        signing_context(state, auth),
        &state.room_groups_ks,
        &req.room_id,
        &resolver,
        &req.host,
        &key,
        &vta_did,
        &key,
        vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
        &format!("{}#response", vti_rooms::wire::ROOMS_RECORDS_GET_TYPE),
        serde_json::json!({
            "roomId": req.room_id,
            "key": req.key,
            "presentation": minted.presentation,
        }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // `send_room_task` has already verified the reply's proof AND bound the
    // proven signer to the host that was addressed — a proof that verifies
    // against some other party is a reply from somebody else.
    let served: vti_rooms::wire::GetRecordResponse = match serde_json::from_value(reply) {
        Ok(r) => r,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                vti_common::error::AppError::Internal(format!(
                    "room host `{}` served a record this agent cannot read: {e}",
                    req.host
                )),
            );
        }
    };

    let trace = verify_trace(&served);

    // Opened here or nowhere. A tombstone has no body and that is an answer
    // rather than a failure: the record's standing is what the caller asked for.
    let mut payload = serde_json::json!({
        "roomId": req.room_id,
        "key": served.record.key,
        "version": served.record.version,
        "status": served.record.status,
        "updatedAt": served.record.updated_at,
        "verification": { "trace": trace },
    });
    if let Some(author) = &served.record.author {
        payload["author"] = serde_json::json!(author);
    }
    let head = head_of(
        served.data_commitment.as_ref(),
        served.record_count,
        served.head_version,
    );
    payload["verification"]["priorRoots"] =
        serde_json::json!(compare_head(state, &req.room_id, head.as_ref()).await);
    if let Some(head) = head {
        payload["verification"]["head"] = head;
    }

    if let Some(sealed) = &served.record.sealed {
        let plaintext = match room_groups::open_record(
            &state.room_groups_ks,
            &req.room_id,
            &served.record.key,
            served.record.version,
            &sealed.ciphertext,
            &sealed.nonce,
            sealed.epoch,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => return app_error_to_reject(&doc, e),
        };
        payload["plaintext"] = serde_json::json!(plaintext);
    } else if let Some(cleartext) = &served.record.cleartext {
        payload["cleartext"] = cleartext.clone();
    }

    record(state, "rooms.keys.read", auth, &req.room_id).await;
    success_response(&doc, payload)
}

/// `rooms/keys/browse/0.1`.
///
/// Metadata, never bodies — a property of the task rather than of the tier, and
/// why browsing and reading are two: looking at a room's shelf should not
/// decrypt the room.
pub(super) async fn handle_browse(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "listing a room's records",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::keys::browse::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let (vta_did, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let minted =
        match crate::operations::room_oracle::present(state, auth, &vta_did, &req.room_id, "read")
            .await
        {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    let key = format!("{vta_did}#key-0");
    let mut records: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut head: Option<Value> = None;
    let mut complete = false;
    // A listing is read to its END, and absence of the cursor is the only thing
    // that says so. A short page says nothing — which is exactly why the count
    // check below is conditioned on having reached the end.
    const MAX_PAGES: usize = 64;
    for page in 0..MAX_PAGES {
        let mut payload = serde_json::json!({
            "roomId": req.room_id,
            "presentation": minted.presentation,
        });
        if let Some(p) = &req.prefix {
            payload["prefix"] = serde_json::json!(p);
        }
        if let Some(v) = req.since_version {
            payload["sinceVersion"] = serde_json::json!(v);
        }
        if let Some(l) = req.limit {
            payload["limit"] = serde_json::json!(u64::from(l));
        }
        if let Some(c) = &cursor {
            payload["cursor"] = serde_json::json!(c);
        }

        let reply = match crate::operations::room_host::send_room_task(
            signing_context(state, auth),
            &state.room_groups_ks,
            &req.room_id,
            &resolver,
            &req.host,
            &key,
            &vta_did,
            &key,
            vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
            &format!("{}#response", vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE),
            payload,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => return app_error_to_reject(&doc, e),
        };

        let listing: vti_rooms::wire::ListRecordsResponse = match serde_json::from_value(reply) {
            Ok(l) => l,
            Err(e) => {
                return app_error_to_reject(
                    &doc,
                    vti_common::error::AppError::Internal(format!(
                        "room host `{}` served a listing this agent cannot read: {e}",
                        req.host
                    )),
                );
            }
        };

        // The head is the LAST page's, because that is the snapshot the caller's
        // view ends at. Taking the first page's would label a set the agent went
        // on to extend.
        head = head_of(
            listing.data_commitment.as_ref(),
            listing.record_count,
            listing.head_version,
        );
        records.extend(listing.records);

        match listing.cursor {
            Some(next) => cursor = Some(next),
            None => {
                complete = true;
                break;
            }
        }
        // Stopping of this agent's own accord is not the end of the listing, and
        // saying otherwise would turn a page bound into a withheld record.
        if page + 1 == MAX_PAGES {
            break;
        }
    }

    // The one check a listing can make with no anchor and no second party — and
    // it is only meaningful against a complete, unfiltered listing. Anything
    // else legitimately holds fewer, and comparing it is a discrepancy the
    // reader manufactured.
    let filtered = req.prefix.is_some() || req.since_version.is_some();
    let count = match (&head, complete, filtered) {
        (None, _, _) => "notOffered",
        (Some(_), false, _) | (Some(_), _, true) => "notComparable",
        (Some(h), true, false) => {
            let committed = h["recordCount"].as_u64().unwrap_or_default();
            if records.len() as u64 == committed {
                "agrees"
            } else {
                "short"
            }
        }
    };

    let mut verification = serde_json::json!({
        "priorRoots": compare_head(state, &req.room_id, head.as_ref()).await,
        "count": count,
    });
    if let Some(h) = head {
        verification["head"] = h;
    }

    record(state, "rooms.keys.browse", auth, &req.room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "roomId": req.room_id,
            "records": records,
            "complete": complete,
            "verification": verification,
        }),
    )
}

/// `rooms/keys/open/0.1`.
pub(super) async fn handle_open(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "opening a room record",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::keys::open::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let plaintext = match room_groups::open_record(
        &state.room_groups_ks,
        &req.room_id,
        &req.key,
        u64::from(req.version),
        &req.sealed.ciphertext,
        &req.sealed.nonce,
        u32::try_from(u64::from(req.sealed.epoch)).unwrap_or(u32::MAX),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    record(state, "rooms.keys.open", auth, &req.room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "plaintext": base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &plaintext,
            )
        }),
    )
}

// ─── Shared ──────────────────────────────────────────────────────────────

/// Verify the invitation, and refuse if it is missing, bad, or already spent.
async fn require_invitation(
    state: &AppState,
    encoded: Option<&str>,
    room_id: &str,
    member_did: &str,
) -> Result<room_invitation::VerifiedInvitation, vti_common::error::AppError> {
    let encoded = encoded.ok_or_else(|| {
        vti_common::error::AppError::Validation(format!(
            "no invitation presented for room `{room_id}`; joining a room is a two-party \
             act and the invitation is the other party's half"
        ))
    })?;

    let keys = vti_rooms_dtg::DataIntegrityKeys(state.trust_task_vm_resolver());
    let invitation = room_invitation::verify(encoded, room_id, member_did, &keys).await?;

    if room_invitation::is_consumed(&state.room_invitations_ks, invitation.credential_id()).await? {
        return Err(vti_common::error::AppError::Conflict(format!(
            "invitation `{}` has already been used",
            invitation.credential_id()
        )));
    }
    Ok(invitation)
}

fn decode_b64(s: &str, what: &str) -> Result<Vec<u8>, vti_common::error::AppError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| vti_common::error::AppError::Validation(format!("decode the {what}: {e}")))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rfc3339(unix_seconds: u64) -> String {
    chrono::DateTime::from_timestamp(unix_seconds as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch is in range"))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Audit one group operation.
///
/// Every one of these is consequential: joining a room, advancing its keys, or opening one
/// of its records. "Which agent got into which room, and when" is the sentence an incident
/// review needs, and none of it is reconstructible from anywhere else.
pub(super) async fn record(state: &AppState, action: &str, auth: &AuthClaims, room_id: &str) {
    if let Err(e) = audit::record(
        &state.audit_sink,
        action,
        &auth.did,
        Some(room_id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
    )
    .await
    {
        tracing::error!(error = %e, action, "failed to record a room-group audit entry");
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    use vti_rooms::{Record, RecordStatus};

    fn room() -> Vec<Record> {
        ["a", "b", "c"]
            .iter()
            .enumerate()
            .map(|(i, key)| Record {
                key: (*key).into(),
                version: i as u64 + 1,
                epoch: Some(2),
                status: RecordStatus::Active,
                pinned: false,
                sealed: Some("c2VhbGVkLWJvZHk".into()),
                nonce: Some("bm9uY2UtMTI".into()),
                cleartext: None,
                author: None,
                updated_at: 1_756_000_000,
            })
            .collect()
    }

    /// A host that serves a real trace is believed, and one that serves a bad
    /// one is not — checked from the response alone, which is all the agent has.
    #[test]
    fn a_trace_is_replayed_against_the_root_served_beside_it() {
        let mut records = room();
        let head = vti_rooms::merkle::tree_head(&mut records).expect("commits");
        let leaves: Vec<_> = records
            .iter()
            .map(|r| vti_rooms::merkle::leaf_hash(&r.committed()).expect("hashes"))
            .collect();
        let trace = vti_rooms::merkle::inclusion_proof(&leaves, 1).expect("a trace");

        let good = vti_rooms::wire::GetRecordResponse::of(&records[1], Some(&head), Some(trace));
        assert_eq!(verify_trace(&good), "verified");

        // The same trace against a different record. The arithmetic does not
        // close, and this is the case a host that substitutes a record produces.
        let wrong = vti_rooms::wire::GetRecordResponse {
            record: records[0].committed(),
            ..good.clone()
        };
        assert_eq!(verify_trace(&wrong), "failed");
    }

    /// A host that maintains no tree is legal, and its silence is not a failure.
    ///
    /// The distinction matters because the two would otherwise be rendered the
    /// same: a member told "unverified" for a host that never claimed anything
    /// learns nothing, while one told "notOffered" has learned that this host
    /// offers no completeness guarantee — which is true, and theirs to act on.
    #[test]
    fn a_host_that_offers_no_tree_is_not_a_host_that_failed() {
        let records = room();
        let bare = vti_rooms::wire::GetRecordResponse::of(&records[0], None, None);
        assert_eq!(verify_trace(&bare), "notOffered");

        // A commitment with no trace is the same answer: there is nothing to
        // replay, and calling that a failure would accuse a host of arithmetic
        // it never did.
        let mut records = room();
        let head = vti_rooms::merkle::tree_head(&mut records).expect("commits");
        let rootless = vti_rooms::wire::GetRecordResponse::of(&records[0], Some(&head), None);
        assert_eq!(verify_trace(&rootless), "notOffered");
    }

    /// The head travels whole or not at all.
    ///
    /// A root without the state it describes is not comparable to another root,
    /// so passing one on alone would hand a member a value that looks like
    /// evidence and cannot be used as any.
    #[test]
    fn a_partial_head_is_no_head() {
        assert!(head_of(Some(&"zQm…".to_string()), Some(118), Some(412)).is_some());
        assert!(head_of(Some(&"zQm…".to_string()), None, Some(412)).is_none());
        assert!(head_of(Some(&"zQm…".to_string()), Some(118), None).is_none());
        assert!(head_of(None, Some(118), Some(412)).is_none());
    }
}
