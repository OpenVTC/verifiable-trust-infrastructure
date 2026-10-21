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
//! | `key-package` | an invitation naming a persona the caller may act as — minting retains a private key, so a VTA that minted for anyone is one anyone can fill |
//! | `welcome` | that same invitation, **consumed** |
//! | `commit` | the group itself — MLS authenticates the committer as a member of the group we already hold |
//! | `open` | [`Capability::RoomOpen`] |
//!
//! The member a group admits is the **persona** the invitation names — a DID this VTA
//! holds for the person ([`crate::operations::persona`]) — and their MLS leaf carries it.
//! The caller is whoever delivers the invitation, and is never the member's identity.
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
use crate::operations::{room_groups, room_invitation, room_member};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, success_response,
};

/// How long an unused KeyPackage's private half is retained.
///
/// Bounded because the private half *is* retained key material: a caller that minted and
/// never joined has left a key behind, and one that minted repeatedly has left a pile.
const KEY_PACKAGE_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

/// How long a KeyPackage `rooms/keys/key-package/0.2` minted is held.
///
/// Longer than 0.1's because 0.2's KeyPackage is the one an acceptance begun on one
/// surface is finished with on another, and the community keeps the Welcome for it for
/// seven days **from the admission**, which comes after the mint. Held seven days from
/// the mint, the KeyPackage would expire first and an acceptance the community still
/// offers to finish could not be (key-package 0.2 *The private half is retained*: a
/// recipient SHOULD NOT expire one sooner than the communities it serves keep theirs).
/// Fourteen covers an admission up to a week after the mint; the private half is still
/// discarded the moment the Welcome is processed.
const KEY_PACKAGE_V0_2_LIFETIME_SECS: u64 = 14 * 24 * 60 * 60;

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

/// `rooms/keys/key-package/0.2#response`: 0.1's, with `expiresAt` required and
/// `alreadyMinted` saying whether this is the KeyPackage already held.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageResponseV0_2 {
    pub key_package: String,
    pub expires_at: String,
    pub already_minted: bool,
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
    //
    // The leaf the KeyPackage carries identifies the persona the invitation names — the
    // member's identity in the room — never the client that asked for it.
    let invitation =
        match require_invitation(state, req.invitation.as_deref(), &req.room_id, auth).await {
            Ok(i) => i,
            Err(e) => return app_error_to_reject(&doc, e),
        };

    // Kept under that persona: another persona on this VTA invited to the same room mints
    // its own, and neither overwrites the other's private half.
    let member = match room_member::member_as(state, auth, &req.room_id, invitation.subject()).await
    {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let minted = match room_groups::mint_key_package(
        &state.room_groups_ks,
        &member,
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

/// `rooms/keys/key-package/0.2`: the KeyPackage already held for this room, member and
/// invitation while it is outstanding (recipient item 3), else a new one (item 4).
///
/// What lets a member finish, from any surface, an acceptance another began: the second
/// surface is given the KeyPackage the community already admitted, and the community
/// answers its acceptance with the Welcome it kept. Under 0.1 the second surface's mint
/// replaced the first's private half — the one that Welcome is sealed to.
pub(super) async fn handle_key_package_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    let req: trust_tasks_rs::specs::rooms::keys::key_package::v0_2::Payload =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };
    let room_id = req.room_id.to_string();
    // Item 1: never without a valid invitation to the room. Item 2: the member is its
    // subject, and the caller must act as them.
    let invitation =
        match require_invitation(state, Some(req.invitation.as_str()), &room_id, auth).await {
            Ok(i) => i,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    let member = match room_member::member_as(state, auth, &room_id, invitation.subject()).await {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    // Item 6: the invitation is identified by its credential id, never by what it says.
    let (pending, already_minted) = match room_groups::outstanding_or_mint(
        &state.room_groups_ks,
        &member,
        invitation.credential_id(),
        KEY_PACKAGE_V0_2_LIFETIME_SECS,
        now(),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    if !already_minted {
        record(state, "rooms.keys.key-package", auth, &room_id).await;
    }
    success_response(
        &doc,
        KeyPackageResponseV0_2 {
            key_package: pending.key_package,
            expires_at: rfc3339(pending.expires_at),
            already_minted,
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
        match verify_invitation(state, req.invitation.as_deref(), &req.room_id, auth).await {
            Ok(i) => i,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    // A spent invitation is the join already made — by this request's lost answer, or by
    // another surface finishing the same acceptance. For the member who joined with it,
    // that is `alreadyJoined` (welcome/0.1: a recipient already holding group state for the
    // member the invitation names MUST answer it), which a surface reads as success; for
    // anyone else it is a used invitation.
    match room_invitation::is_consumed(&state.room_invitations_ks, invitation.credential_id()).await
    {
        Ok(false) => {}
        Ok(true) => {
            let joined =
                match room_member::member_as(state, auth, &req.room_id, invitation.subject()).await
                {
                    Ok(member) => room_groups::load(&state.room_groups_ks, &member)
                        .await
                        .is_ok_and(|g| g.is_some()),
                    Err(_) => false,
                };
            if joined {
                return super::helpers::reject_declared(
                    &doc,
                    trust_tasks_rs::specs::rooms::keys::welcome::v0_1::error_codes::ALREADY_JOINED,
                    format!(
                        "this VTA already holds group state for `{}` in room `{}`, joined with \
                         this invitation",
                        invitation.subject(),
                        req.room_id
                    ),
                );
            }
            return app_error_to_reject(&doc, used_invitation(&invitation));
        }
        Err(e) => return app_error_to_reject(&doc, e),
    }

    let welcome = match decode_b64(&req.welcome, "welcome") {
        Ok(b) => b,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // The member joining is the invitation's subject, and "already joined" is asked of
    // that member alone: another persona this VTA holds for somebody else in the same room
    // is a different leaf, and its group is no reason to refuse this one.
    let member = match room_member::member_as(state, auth, &req.room_id, invitation.subject()).await
    {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let epoch = match room_groups::join(&state.room_groups_ks, &member, &welcome, now()).await {
        Ok(e) => e,
        Err(room_groups::JoinError::AlreadyJoined) => {
            return super::helpers::reject_declared(
                &doc,
                trust_tasks_rs::specs::rooms::keys::welcome::v0_1::error_codes::ALREADY_JOINED,
                format!(
                    "this VTA already holds group state for `{}` in room `{}`; leaving and \
                     rejoining is a removal and a fresh invitation, not a second welcome",
                    member.persona(),
                    req.room_id
                ),
            );
        }
        Err(room_groups::JoinError::KeyPackageExpired) => {
            return super::helpers::reject_declared(
                &doc,
                trust_tasks_rs::specs::rooms::keys::welcome::v0_1::error_codes::WELCOME_INVALID,
                format!(
                    "the key package this welcome is sealed to expired and has been discarded; \
                     mint a fresh one for room `{}` (rooms/keys/key-package) and have the owner \
                     add that",
                    req.room_id
                ),
            );
        }
        Err(room_groups::JoinError::App(e)) => return app_error_to_reject(&doc, e),
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

    // No gate of ours on the committer. MLS authenticates the committer as a member of the
    // group we already hold, and an ACL here would be this service deciding who may commit
    // to a room it is not part of — the mistake the whole family is arranged to avoid.
    //
    // *Which* group is ours to decide, though: the one member the caller acts as. A caller
    // in another context reaches no group here, and is told what a room nobody holds is.
    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let member =
        match room_member::require_acting_as(state, auth, &req.room_id, named.as_deref()).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    let epoch = match room_groups::apply_commit(
        &state.room_groups_ks,
        &member,
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

    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let member =
        match room_member::require_acting_as(state, auth, &req.room_id, named.as_deref()).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    let sealed = match room_groups::seal_record(
        &state.room_groups_ks,
        &member,
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

    // The caller's personas only. A room another context's persona holds is not one this
    // caller can open, and listing it would tell them who else this VTA serves.
    let members = match room_member::held_by_caller(state, auth).await {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let mut rooms = Vec::with_capacity(members.len());
    for m in &members {
        match room_groups::held_room(&state.room_groups_ks, m).await {
            Ok(r) => rooms.push((r, held_by(state, auth, m).await)),
            Err(e) => return app_error_to_reject(&doc, e),
        }
    }
    rooms.sort_by(|(a, pa), (b, pb)| {
        a.room_id
            .cmp(&b.room_id)
            .then_with(|| pa["member"].as_str().cmp(&pb["member"].as_str()))
    });
    let (rooms, held): (Vec<_>, Vec<_>) = rooms.into_iter().unzip();

    record(state, "rooms.keys.list", auth, "").await;
    // One entry per (room, member): a caller who may act as two members of one room — an
    // administrator whose VTA also holds the community's own place in it — gets the room
    // twice. The specification's entry has no member of its own and forbids extra ones, so
    // whose each entry is rides in `ext`, index for index (`held[i]` is `rooms[i]`'s).
    // Without it the two entries are indistinguishable, and a client cannot name the member
    // its next request acts as ([`room_member::MEMBER_EXT`]).
    success_response(
        &doc,
        serde_json::json!({
            "rooms": rooms,
            "ext": { room_member::MEMBER_EXT: { "held": held } },
        }),
    )
}

/// What `rooms/keys/list` says about whose an entry is: the member (persona DID), the
/// trust context its key lives in, and the actions the room's grant to it confers — so a
/// client can tell the community's own place in a room (one that administers it) from a
/// member's. `context` and `actions` are descriptions, never gates, and are left out
/// where they cannot be read rather than failing the listing.
pub(super) async fn held_by(state: &AppState, auth: &AuthClaims, m: &room_groups::Member) -> Value {
    let mut out = serde_json::json!({ "member": m.persona() });
    let stores = crate::operations::persona::PersonaStores::from_state(state);
    if let Ok(Some(key)) =
        crate::operations::persona::persona_signing_key(stores, auth, m.persona()).await
        && let Ok(Some(record)) = state
            .keys_ks
            .get::<vta_sdk::keys::KeyRecord>(vta_keys::store_key(&key.key_id))
            .await
        && let Some(context) = record.context_id
    {
        out["context"] = Value::String(context);
    }
    if let Ok(principals) =
        crate::operations::room_oracle::principals(state, auth, m.room_id()).await
        && let Some(p) = principals.iter().find(|p| p.did == m.persona())
    {
        out["actions"] = serde_json::json!(p.actions());
    }
    out
}

/// The member the request names in `ext["org.openvtc.rooms"].member`
/// ([`room_member::named_member`]), or a malformed-request refusal.
#[allow(clippy::result_large_err)]
fn named_member(doc: &TrustTask<Value>) -> Result<Option<String>, TrustTaskOutcome> {
    room_member::named_member(&doc.payload).map_err(super::helpers::malformed_request_response)
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

    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let member =
        match room_member::require_acting_as(state, auth, &req.room_id, named.as_deref()).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    let (earliest, stored) =
        match room_groups::store_links(&state.room_groups_ks, &member, links, now()).await {
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
pub(super) fn signing_context<'a>(
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
        audit: &state.audit_sink,
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
/// **This VTA acts as its principal** (`rooms/keys/backfill/0.1`, *What the recipient
/// presents, and to whom*): the `read` grant is the principal persona's own, narrowed
/// to `read` and granted to the persona, and the `rooms/epoch/chain` document is
/// issued and signed by the persona ([`send_as_member`]). This VTA's own DID never
/// reaches the host — it used to be the leaf's subject, the document's issuer and its
/// signer, which named an identity no room admitted and, for a context-scoped caller,
/// failed outright: the caller may not sign with the VTA's `#key-0`.
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

    let resolver = match outbound_resolver(state, &doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // `read`, and only `read`. Reading the room and reading the parts of it
    // written earlier are the same act, so they take the same grant; asking for
    // more would hand the host authority the operation never needed.
    //
    // The caller-named `host` is not bound into the presentation. What makes a
    // caller-named host safe is that the leaf grants to the principal and is
    // usable only by a party that can sign as the principal: a host of the
    // caller's choosing receives something it cannot act with. What it does gain
    // is sight of the principal's credentials, which is a disclosure rather than
    // an escalation — see `rooms/keys/backfill/0.1`.
    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let member = match presenting_member(state, auth, &req.room_id, named.as_deref()).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let mut payload = serde_json::json!({ "roomId": req.room_id });
    if let Some(from) = req.from_epoch {
        payload["fromEpoch"] = serde_json::json!(u64::from(from));
    }
    if let Some(limit) = req.limit {
        payload["limit"] = serde_json::json!(u64::from(limit));
    }

    let reply = match send_as_member_typed(
        state,
        auth,
        &member,
        &resolver,
        &req.host,
        vti_rooms::wire::ROOMS_EPOCH_CHAIN_TYPE,
        payload,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            use trust_tasks_rs::specs::rooms::keys::backfill::v0_1::error_codes as codes;
            return host_failure(
                &doc,
                e,
                &req.host,
                codes::HOST_UNREACHABLE,
                codes::HOST_REFUSED,
            );
        }
    };
    let member = member.member;

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
        match room_groups::store_links(&state.room_groups_ks, &member, links, now()).await {
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

/// The member a presentation-bearing task acts as, and the presentation it carries.
///
/// One resolution for both: the persona whose credentials are presented
/// ([`crate::operations::room_oracle::principal`]) is the member whose group opens what
/// comes back and whose root memory the host's answer is compared against. Resolving them
/// separately could pair one persona's authority with another's keys.
pub(super) struct PresentingMember {
    /// The member — the persona, in this room — whose group state is used.
    pub member: room_groups::Member,
    /// The persona's DID: the documents' issuer and signer, and the leaf's subject.
    pub did: String,
    /// The persona's own `read` authority, narrowed to `read` and granted to the persona.
    pub presentation: Value,
}

/// [`PresentingMember`] for `room_id`: the principal persona, and their own `read` grant.
///
/// The grant is made out to **the persona**, never to this VTA: the host authenticates
/// the persona as presenter, because the persona signs what it receives
/// ([`send_as_member`]). `rooms/keys/{read,browse,backfill}/0.1` require exactly this, and
/// that this VTA's own identifier never reach the host.
///
/// `named` is the member the request names ([`room_member::named_member`]); `None` keeps the
/// rule that a caller who may act as several members of the room is refused.
pub(super) async fn presenting_member(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    named: Option<&str>,
) -> Result<PresentingMember, vti_common::error::AppError> {
    let principal =
        crate::operations::room_oracle::principal_named(state, auth, room_id, named).await?;
    let member = room_member::member_as(state, auth, room_id, &principal.did).await?;
    let minted = crate::operations::room_oracle::present_as(
        state,
        auth,
        &principal,
        &principal.did,
        room_id,
        "read",
    )
    .await?;
    Ok(PresentingMember {
        member,
        did: principal.did,
        presentation: minted.presentation,
    })
}

/// Send one room request to `host` **as the member**: the member's presentation in the
/// payload, the member as `issuer`, the member's `authentication` proof
/// ([`crate::operations::room_act::sign_as`]) — and return the response's `payload`.
pub(super) async fn send_as_member(
    state: &AppState,
    auth: &AuthClaims,
    member: &PresentingMember,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &str,
    task: &str,
    payload: Value,
) -> Result<Value, vti_common::error::AppError> {
    send_as_member_typed(state, auth, member, resolver, host, task, payload)
        .await
        .map_err(MemberSendError::into_app_error)
}

/// Why [`send_as_member_typed`] got no answer: something here, or the host.
pub(super) enum MemberSendError {
    /// Building or signing the request failed before anything was sent.
    Local(vti_common::error::AppError),
    /// The host refused, could not be reached, or answered unusably.
    Host(crate::operations::room_host::RoomTaskError),
}

impl MemberSendError {
    pub(super) fn into_app_error(self) -> vti_common::error::AppError {
        match self {
            Self::Local(e) => e,
            Self::Host(e) => e.into_app_error(),
        }
    }
}

/// [`send_as_member`], keeping the host's failures apart from this agent's, so a task that
/// declares `hostUnreachable` / `hostRefused` can say which.
pub(super) async fn send_as_member_typed(
    state: &AppState,
    auth: &AuthClaims,
    member: &PresentingMember,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &str,
    task: &str,
    mut payload: Value,
) -> Result<Value, MemberSendError> {
    payload["presentation"] = member.presentation.clone();
    let document = crate::operations::room_host::build_room_task(task, host, &member.did, payload);
    crate::operations::room_act::check_schema(&document).map_err(MemberSendError::Local)?;
    let document = crate::operations::room_act::sign_as(state, auth, &member.did, document)
        .await
        .map_err(MemberSendError::Local)?;
    crate::operations::room_host::send_signed_room_task_typed(
        &state.room_groups_ks,
        &member.member,
        &crate::operations::outbound::Outbound::from_app_state(state, resolver),
        host,
        document,
        &format!("{task}#response"),
    )
    .await
    .map_err(MemberSendError::Host)
}

/// A failed send as the task's declared `hostUnreachable` / `hostRefused` (`rooms/keys/read`
/// and `rooms/keys/backfill` 0.1). A host that could not be found or did not answer is
/// `unreachable`, never a malformed request: the request was fine.
fn host_failure(
    doc: &TrustTask<Value>,
    e: MemberSendError,
    host: &str,
    unreachable: trust_tasks_rs::DeclaredErrorCode,
    refused: trust_tasks_rs::DeclaredErrorCode,
) -> TrustTaskOutcome {
    use crate::operations::room_host::RoomTaskError;
    match e {
        MemberSendError::Local(e) => app_error_to_reject(doc, e),
        MemberSendError::Host(RoomTaskError::Refused { code, reason, .. }) => {
            super::helpers::reject_with_code(
                doc,
                declared(refused),
                format!("room host `{host}` refused: {code}: {reason}"),
                Some(serde_json::json!({ "code": code, "reason": reason })),
            )
        }
        MemberSendError::Host(RoomTaskError::Unknown(e)) => super::helpers::reject_with_code(
            doc,
            declared(unreachable),
            format!("room host `{host}` could not be reached: {e}"),
            None,
        ),
    }
}

/// A resolver, or the refusal that says there is none — every task that speaks to a host
/// has to find it.
pub(super) fn outbound_resolver(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Result<affinidi_did_resolver_cache_sdk::DIDCacheClient, TrustTaskOutcome> {
    state.did_resolver.clone().ok_or_else(|| {
        app_error_to_reject(
            doc,
            vti_common::error::AppError::Validation(
                "this agent has no DID resolver configured, so it cannot find the host".into(),
            ),
        )
    })
}

/// This agent's own DID and a resolver, or the refusal that says which is missing.
///
/// Every task in this family that acts **outward** needs both: it presents as
/// itself, and it has to find the host it was told to speak to. Extracted when
/// the third caller appeared — `backfill`, `read` and `browse` refusing in three
/// slightly different sentences would be three chances for one of them to say
/// something untrue about why.
pub(super) async fn outbound_identity(
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
pub(super) fn head_of(
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
/// Compare a host's head against the room's **own witnessed anchor**.
///
/// The only one of this family's comparisons a first-time reader can make:
/// `priorRoots` needs this agent to have read the room before, and `count` needs
/// a complete unfiltered listing. This needs neither — every member resolves the
/// same room DID and reads the same witness-co-signed entry.
///
/// A resolver failure answers `notChecked` rather than a verdict. An agent that
/// could not resolve the room has learned nothing about the host, and saying
/// otherwise would put a network failure in the same sentence as a finding.
pub(super) async fn compare_anchor(
    state: &AppState,
    room_id: &str,
    head: Option<&Value>,
) -> &'static str {
    use crate::operations::room_anchor::{AnchorVerdict, compare_to_anchor};

    let Some(head) = head else {
        return AnchorVerdict::NotChecked.as_wire();
    };
    let Some(version) = head["headVersion"].as_u64() else {
        return AnchorVerdict::NotChecked.as_wire();
    };
    let Some(resolver) = state.did_resolver.as_ref() else {
        return AnchorVerdict::NotChecked.as_wire();
    };
    let Ok(resolved) = resolver.resolve(room_id).await else {
        return AnchorVerdict::NotChecked.as_wire();
    };
    let Ok(document) = serde_json::to_value(&resolved.doc) else {
        return AnchorVerdict::NotChecked.as_wire();
    };
    compare_to_anchor(&document, version, head["dataCommitment"].as_str()).as_wire()
}

pub(super) async fn compare_head(
    state: &AppState,
    member: &room_groups::Member,
    head: Option<&Value>,
) -> &'static str {
    let room_id = member.room_id();
    let Some(head) = head else {
        return "notChecked";
    };
    let (Some(version), Some(root)) = (
        head["headVersion"].as_u64(),
        head["dataCommitment"].as_str(),
    ) else {
        return "notChecked";
    };
    match room_groups::observe_head(&state.room_groups_ks, member, version, root).await {
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
pub(super) fn verify_trace(reply: &vti_rooms::wire::GetRecordResponse) -> &'static str {
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

    let resolver = match outbound_resolver(state, &doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // `read`, and only `read`, granted to the principal and sent as the principal
    // (`rooms/keys/read/0.1`, *What the recipient presents, and to whom*). The
    // caller-named host is not bound into the presentation: what makes naming one safe
    // is that the leaf grants to the principal, usable only by a party that can sign as
    // the principal. What it gains is sight of the credentials, which is a disclosure
    // rather than an escalation.
    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let presenting = match presenting_member(state, auth, &req.room_id, named.as_deref()).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    use trust_tasks_rs::specs::rooms::keys::read::v0_1::error_codes as read_codes;
    let reply = match send_as_member_typed(
        state,
        auth,
        &presenting,
        &resolver,
        &req.host,
        vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
        serde_json::json!({ "roomId": req.room_id, "key": req.key }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return host_failure(
                &doc,
                e,
                &req.host,
                read_codes::HOST_UNREACHABLE,
                read_codes::HOST_REFUSED,
            );
        }
    };
    let member = presenting.member.clone();

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
        serde_json::json!(compare_head(state, &member, head.as_ref()).await);
    payload["verification"]["anchor"] =
        serde_json::json!(compare_anchor(state, &req.room_id, head.as_ref()).await);
    if let Some(head) = head {
        payload["verification"]["head"] = head;
    }

    // The room's own profile is how the room describes itself, not a record a member wrote
    // into it (`SealedRecordBody`, *A profile record*): it is not opened here, and the
    // answer says where to read it.
    if is_profile_location(state, &member, &served.record).await {
        payload["ext"] = serde_json::json!({
            room_member::MEMBER_EXT: { "roomProfile": true },
        });
        record(state, "rooms.keys.read", auth, &req.room_id).await;
        return success_response(&doc, payload);
    }

    if let Some(sealed) = &served.record.sealed {
        // Opened at the version the body was sealed at, which a curation moves the record
        // past (rooms `_shared/0.1` `SealedRecord.version`). A record curated by a host that
        // predates that member carries none, and is searched for.
        let sealed_at = match sealed.sealed_at(served.record.version) {
            Ok(v) => v,
            Err(why) => {
                return app_error_to_reject(
                    &doc,
                    vti_common::error::AppError::Validation(format!(
                        "room host `{}` {why}",
                        req.host
                    )),
                );
            }
        };
        let search = if sealed.version.is_some() {
            room_groups::Search::Exact
        } else {
            room_groups::Search::Earlier
        };
        // Repair before refusing (`rooms/keys/read/0.1`, *Opening, and when it cannot*): a
        // member who is behind applies the commits the host relays, one who joined late
        // fetches the links, each at most once per request; a removed member is never
        // repaired. Only then is it `cannotOpen`, with the reason.
        let mut repaired: Option<Result<(), String>> = None;
        let (plaintext, opened_at) = loop {
            let opened = room_groups::open_record_at(
                &state.room_groups_ks,
                &member,
                &served.record.key,
                sealed_at,
                &sealed.ciphertext,
                &sealed.nonce,
                sealed.epoch,
                search,
            )
            .await;
            match opened {
                Ok(opened) => break opened,
                Err(
                    e @ (room_groups::OpenError::NotDelivered { .. }
                    | room_groups::OpenError::BeyondChain { .. }),
                ) if repaired.is_none() => {
                    let outcome = super::room_catch_up::repair(
                        state,
                        auth,
                        &presenting,
                        &resolver,
                        &req.host,
                        &e,
                    )
                    .await;
                    if let Err(why) = &outcome {
                        tracing::warn!(
                            room = %req.room_id,
                            epoch = sealed.epoch,
                            reason = %why,
                            "could not repair this member's epoch state before opening a record"
                        );
                    }
                    repaired = Some(outcome);
                }
                Err(e) => {
                    return read_cannot_open(&doc, e, sealed.epoch, repaired.and_then(Result::err));
                }
            }
        };
        // A record this agent could not place before the repair may be the room's own
        // profile, which is not opened here.
        if repaired.is_some() && is_profile_location(state, &member, &served.record).await {
            payload["ext"] = serde_json::json!({
                room_member::MEMBER_EXT: { "roomProfile": true },
            });
            record(state, "rooms.keys.read", auth, &req.room_id).await;
            return success_response(&doc, payload);
        }
        // A reader checks the author's signed location against the version the body was
        // sealed at; where that is not the record's own, say which it is.
        if opened_at != served.record.version {
            payload["ext"] = serde_json::json!({
                room_member::MEMBER_EXT: { "sealedAt": opened_at },
            });
        }
        // base64url, as the spec gives it — not the bytes, which serialize as an array.
        payload["plaintext"] = serde_json::json!(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            plaintext
        ));
    } else if let Some(cleartext) = &served.record.cleartext {
        payload["cleartext"] = cleartext.clone();
    }

    record(state, "rooms.keys.read", auth, &req.room_id).await;
    success_response(&doc, payload)
}

/// Every key the room's profile can be at for `member`: `profile_key(E)` for each epoch its
/// chain reaches on a sealed tier, and `room-profile` on an `open` room (where this VTA holds
/// no group). A location this VTA cannot compute is not one it can tell apart, so it is not
/// in the set.
async fn profile_keys(
    state: &AppState,
    member: &room_groups::Member,
) -> std::collections::HashSet<String> {
    let mut keys = std::collections::HashSet::new();
    match room_groups::load(&state.room_groups_ks, member).await {
        Ok(Some(_)) => {
            if let Ok(found) =
                room_groups::profile_locations(&state.room_groups_ks, member, usize::MAX).await
            {
                keys.extend(found.into_iter().map(|(_, k)| k));
            }
        }
        _ => {
            keys.insert(vti_rooms::profile::OPEN_PROFILE_KEY.to_string());
        }
    }
    keys
}

/// Whether `record` sits at the room's profile location for the epoch it was sealed under
/// (or, on an `open` room, at `room-profile`).
async fn is_profile_location(
    state: &AppState,
    member: &room_groups::Member,
    record: &vti_rooms::wire::CommittedRecord,
) -> bool {
    match &record.sealed {
        Some(sealed) => {
            room_groups::profile_location(&state.room_groups_ks, member, Some(sealed.epoch))
                .await
                .is_ok_and(|(key, _)| key == record.key)
        }
        None => record.key == vti_rooms::profile::OPEN_PROFILE_KEY,
    }
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

    let resolver = match outbound_resolver(state, &doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // As the principal, with the principal's own `read` grant — as `read` does.
    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let presenting = match presenting_member(state, auth, &req.room_id, named.as_deref()).await {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    let mut records: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut head: Option<Value> = None;
    let mut complete = false;
    // A listing is read to its END, and absence of the cursor is the only thing
    // that says so. A short page says nothing — which is exactly why the count
    // check below is conditioned on having reached the end.
    const MAX_PAGES: usize = 64;
    for page in 0..MAX_PAGES {
        let mut payload = serde_json::json!({ "roomId": req.room_id });
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

        let reply = match send_as_member(
            state,
            auth,
            &presenting,
            &resolver,
            &req.host,
            vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
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

    let member = presenting.member;
    // Counted above against everything the host listed; the room's own profile records are
    // then left out — they are how the room describes itself, not records of it
    // (`SealedRecordBody`, *A profile record*; `rooms/keys/profile/read`).
    let profile_keys = profile_keys(state, &member).await;
    records.retain(|r| {
        r.get("key")
            .and_then(Value::as_str)
            .is_none_or(|k| !profile_keys.contains(k))
    });
    let mut verification = serde_json::json!({
        "priorRoots": compare_head(state, &member, head.as_ref()).await,
        "anchor": compare_anchor(state, &req.room_id, head.as_ref()).await,
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

/// Which version of a `rooms/keys/{open,file-key}` request is being answered. The
/// request and response are the same at both; what differs is what `unknownEpoch` may
/// say (`rooms/keys/{open,file-key}/0.2` *What changed from 0.1*).
#[derive(Clone, Copy, PartialEq, Eq)]
enum EpochVersion {
    V0_1,
    V0_2,
}

/// `rooms/keys/open/0.1`.
pub(super) async fn handle_open(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    open_at(state, auth, doc, EpochVersion::V0_1).await
}

/// `rooms/keys/open/0.2`: 0.1, with `unknownEpoch`'s `details` declared — including
/// `beyondChain` for an older epoch the retained chain does not reach, which 0.1 answered
/// as a bare failure.
pub(super) async fn handle_open_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    open_at(state, auth, doc, EpochVersion::V0_2).await
}

/// The request members `open` reads — the same at 0.1 and 0.2, each parsed through its
/// own version's generated type.
struct OpenRequest {
    room_id: String,
    key: String,
    version: u64,
    ciphertext: String,
    nonce: String,
    epoch: u64,
}

async fn open_at(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    at: EpochVersion,
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

    let parsed = match at {
        EpochVersion::V0_1 => parse_payload::<
            trust_tasks_rs::specs::rooms::keys::open::v0_1::Payload,
        >(&doc)
        .map(|r| OpenRequest {
            room_id: r.room_id.to_string(),
            key: r.key.to_string(),
            version: u64::from(r.version),
            ciphertext: r.sealed.ciphertext.to_string(),
            nonce: r.sealed.nonce.to_string(),
            epoch: u64::from(r.sealed.epoch),
        }),
        EpochVersion::V0_2 => parse_payload::<
            trust_tasks_rs::specs::rooms::keys::open::v0_2::Payload,
        >(&doc)
        .map(|r| OpenRequest {
            room_id: r.room_id.to_string(),
            key: r.key.to_string(),
            version: u64::from(r.version),
            ciphertext: r.sealed.ciphertext.to_string(),
            nonce: r.sealed.nonce.to_string(),
            epoch: u64::from(r.sealed.epoch),
        }),
    };
    let req = match parsed {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let member =
        match room_member::require_acting_as(state, auth, &req.room_id, named.as_deref()).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    // `version` is where the caller believes the body was sealed: `sealed.version` from the
    // host where it served one, else the record's own. A record curated by a host that
    // predates `sealed.version` opens at neither, so earlier versions are searched — and the
    // answer says which opened, because the caller verifies the author's signed location
    // against it (rooms `_shared/0.1` `SealedRecordBody`).
    let (plaintext, opened_at) = match room_groups::open_record_at(
        &state.room_groups_ks,
        &member,
        &req.key,
        req.version,
        &req.ciphertext,
        &req.nonce,
        u32::try_from(req.epoch).unwrap_or(u32::MAX),
        room_groups::Search::Earlier,
    )
    .await
    {
        Ok(opened) => opened,
        Err(e) => return open_refused(&doc, e, at),
    };

    record(state, "rooms.keys.open", auth, &req.room_id).await;
    let mut payload = serde_json::json!({
        "plaintext": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &plaintext,
        )
    });
    if opened_at != req.version {
        payload["ext"] = serde_json::json!({
            room_member::MEMBER_EXT: { "sealedAt": opened_at },
        });
    }
    success_response(&doc, payload)
}

/// `rooms/keys/file-key/0.1`.
pub(super) async fn handle_file_key(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    file_key_at(state, auth, doc, EpochVersion::V0_1).await
}

/// `rooms/keys/file-key/0.2`: 0.1, with `unknownEpoch` reason `removed` for a file sealed
/// at or after the member's removal.
pub(super) async fn handle_file_key_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    file_key_at(state, auth, doc, EpochVersion::V0_2).await
}

/// `rooms/keys/file-key`, at either version.
///
/// The one `rooms/keys/*` task that releases a key. `open` keeps the key and returns
/// plaintext; a file can be a gigabyte, and its bytes must not pass through this VTA, so
/// the member's own client gets **that file's** key and does the encryption itself. What
/// crosses opens one file: it is derived per file from the epoch's storage key, which never
/// leaves, so no sibling can be derived from it.
///
/// Gated on `RoomOpen` for both purposes, as `seal` and `open` are: a sealing key opens the
/// file it seals.
///
/// The request is parsed through 0.2's generated type at both versions: 0.2's request
/// schema is 0.1's unchanged, and the error codes' strings are the slug's, not the
/// version's.
async fn file_key_at(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    at: EpochVersion,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::rooms::keys::file_key::v0_2 as spec;

    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "releasing a room file's key",
    )
    .await
    {
        return r;
    }

    let req: spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // `purpose` is non-exhaustive in the generated binding: a purpose this build does not
    // know is refused, never treated as either of the two it does.
    let purpose = match req.purpose {
        spec::PayloadPurpose::Seal => "seal",
        spec::PayloadPurpose::Open => "open",
        _ => {
            return super::helpers::malformed_request_response(format!(
                "unknown purpose `{}`",
                req.purpose
            ));
        }
    };
    // Which epoch is the caller's choice only when opening. A sealing key is always
    // derived under the current epoch — letting a caller pick an older one would seal new
    // files under a key a removed member can still derive.
    let open_epoch = match (purpose, req.epoch) {
        ("seal", None) => None,
        ("open", Some(e)) => match u32::try_from(e.get()) {
            Ok(e) => Some(e),
            Err(_) => {
                return super::helpers::malformed_request_response(format!(
                    "epoch {e} is beyond any epoch a room reaches"
                ));
            }
        },
        ("seal", Some(_)) => {
            return super::helpers::malformed_request_response(
                "a sealing key is always derived under the current epoch; `epoch` is \
                 forbidden with purpose `seal`"
                    .into(),
            );
        }
        _ => {
            return super::helpers::malformed_request_response(
                "`epoch` is required with purpose `open`: it is the epoch the file's \
                 manifest names"
                    .into(),
            );
        }
    };

    let file_id = match vti_rooms::files::decode_file_id(&req.file_id) {
        Ok(id) => id,
        Err(e) => return super::helpers::malformed_request_response(e.to_string()),
    };

    let named = match named_member(&doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let member = match room_member::acting_as(state, auth, &req.room_id, named.as_deref()).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return super::helpers::reject_declared(
                &doc,
                spec::error_codes::NO_GROUP,
                format!("this VTA holds no group for room `{}`", req.room_id),
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let (key, epoch) =
        match room_groups::file_key(&state.room_groups_ks, &member, &file_id, open_epoch).await {
            Ok(k) => k,
            // Declared rather than `taskFailed` + a reason: the framework has no standard
            // not-found code, and a caller deciding whether to deliver a welcome needs to tell
            // this apart from a failure.
            Err(room_groups::FileKeyError::NoGroup) => {
                return super::helpers::reject_declared(
                    &doc,
                    spec::error_codes::NO_GROUP,
                    format!("this VTA holds no group for room `{}`", req.room_id),
                );
            }
            Err(room_groups::FileKeyError::App(e)) => return app_error_to_reject(&doc, e),
            Err(room_groups::FileKeyError::NotDelivered { epoch, held }) => {
                return super::helpers::reject_with_code(
                    &doc,
                    declared(spec::error_codes::UNKNOWN_EPOCH),
                    format!(
                        "the file is sealed under epoch {epoch} and this VTA holds room `{}` \
                         at epoch {held}; a commit has not been delivered",
                        req.room_id
                    ),
                    Some(serde_json::json!({ "reason": "notDelivered", "heldEpoch": held })),
                );
            }
            // 0.2 oracle item 4: `removed`, with `removedAtEpoch`, takes precedence over
            // `notDelivered` — an oracle that knows of the removal MUST NOT tell the
            // caller to catch up. 0.1's closed `detailsSchema` has only `notDelivered`
            // and `beyondChain`, and an epoch later than any the oracle holds is
            // `notDelivered` by that item's own definition; there the message says what
            // the reason cannot, and `heldEpoch` is left out because no epoch this VTA
            // could reach would open the file.
            Err(room_groups::FileKeyError::Removed { epoch, removed_at }) => {
                let details = match at {
                    EpochVersion::V0_2 => serde_json::json!({
                        "reason": "removed",
                        "removedAtEpoch": removed_at,
                    }),
                    EpochVersion::V0_1 => serde_json::json!({ "reason": "notDelivered" }),
                };
                return super::helpers::reject_with_code(
                    &doc,
                    declared(spec::error_codes::UNKNOWN_EPOCH),
                    format!(
                        "the file is sealed under epoch {epoch}, and this member was removed \
                         from room `{}`'s group at epoch {removed_at}: no commit will make its \
                         key derivable here",
                        req.room_id
                    ),
                    Some(details),
                );
            }
            Err(room_groups::FileKeyError::BeyondChain { epoch, earliest }) => {
                return super::helpers::reject_with_code(
                    &doc,
                    declared(spec::error_codes::UNKNOWN_EPOCH),
                    format!(
                        "the file is sealed under epoch {epoch}, which this VTA cannot reach — \
                         the epoch key chain reaches back only to {earliest}"
                    ),
                    Some(serde_json::json!({
                        "reason": "beyondChain",
                        "earliestEpoch": earliest,
                    })),
                );
            }
        };

    // Who asked for which file's key, for what, under which epoch — never the key. This
    // row is how a principal sees which files their agents and clients opened.
    if let Err(e) = audit::record_with_detail(
        &state.audit_sink,
        "rooms.keys.file-key",
        &auth.did,
        Some(&req.room_id),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        Some(&format!(
            "fileId={} purpose={purpose} epoch={epoch}",
            req.file_id.as_str()
        )),
    )
    .await
    {
        tracing::error!(error = %e, "failed to record a room file-key audit entry");
    }

    success_response(
        &doc,
        serde_json::json!({
            "key": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key),
            "epoch": epoch,
        }),
    )
}

/// `rooms/keys/read/0.1`'s `cannotOpen`: the record was fetched and its epoch key is not
/// held, after the repair its reason admits. `details` carries the epoch and the reason in
/// `rooms/keys/open/0.2`'s words, and the repair's failure where it failed, so a member is
/// told which party has to act. Anything else that stopped the open is not an epoch case.
fn read_cannot_open(
    doc: &TrustTask<Value>,
    e: room_groups::OpenError,
    epoch: u32,
    repair_failed: Option<String>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::rooms::keys::read::v0_1::error_codes::CANNOT_OPEN;
    let mut message = e.to_string();
    let mut details = match e {
        room_groups::OpenError::NotDelivered { held, .. } => {
            serde_json::json!({ "reason": "notDelivered", "heldEpoch": held })
        }
        room_groups::OpenError::BeyondChain { earliest, .. } => {
            serde_json::json!({ "reason": "beyondChain", "earliestEpoch": earliest })
        }
        room_groups::OpenError::Removed { removed_at, .. } => {
            serde_json::json!({ "reason": "removed", "removedAtEpoch": removed_at })
        }
        room_groups::OpenError::App(e) => return app_error_to_reject(doc, e),
    };
    details["epoch"] = serde_json::json!(epoch);
    if let Some(why) = repair_failed {
        message = format!("{message} (fetching what was missing from the host: {why})");
    }
    super::helpers::reject_with_code(doc, declared(CANNOT_OPEN), message, Some(details))
}

/// `rooms/keys/open`'s refusal for a record that did not open.
///
/// The epoch cases are the declared `unknownEpoch` with `details.reason` saying which, as
/// `rooms/keys/open/0.2` declares them: `notDelivered` (catch up with the commits),
/// `removed` (nothing will — this member was removed) and `beyondChain` (the retained
/// chain does not reach back). A client tells them apart by reason, never by message.
///
/// At 0.1, which declares no `details` for `unknownEpoch`, the first two are sent as they
/// always were, and an unreachable older epoch stays the bare validation failure it was.
fn open_refused(
    doc: &TrustTask<Value>,
    e: room_groups::OpenError,
    at: EpochVersion,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::rooms::keys::open::v0_2::error_codes::UNKNOWN_EPOCH;
    let message = e.to_string();
    match e {
        room_groups::OpenError::NotDelivered { held, .. } => super::helpers::reject_with_code(
            doc,
            declared(UNKNOWN_EPOCH),
            message,
            Some(serde_json::json!({ "reason": "notDelivered", "heldEpoch": held })),
        ),
        room_groups::OpenError::Removed { removed_at, .. } => super::helpers::reject_with_code(
            doc,
            declared(UNKNOWN_EPOCH),
            message,
            Some(serde_json::json!({ "reason": "removed", "removedAtEpoch": removed_at })),
        ),
        room_groups::OpenError::BeyondChain { earliest, .. } if at == EpochVersion::V0_2 => {
            super::helpers::reject_with_code(
                doc,
                declared(UNKNOWN_EPOCH),
                message,
                Some(serde_json::json!({ "reason": "beyondChain", "earliestEpoch": earliest })),
            )
        }
        room_groups::OpenError::BeyondChain { .. } => {
            app_error_to_reject(doc, vti_common::error::AppError::Validation(message))
        }
        room_groups::OpenError::App(e) => app_error_to_reject(doc, e),
    }
}

/// A declared code, as the framework's extended form.
pub(super) fn declared(code: trust_tasks_rs::DeclaredErrorCode) -> trust_tasks_rs::TrustTaskCode {
    trust_tasks_rs::TrustTaskCode::Extended {
        slug: code.namespace().to_string(),
        local: code.local().to_string(),
    }
}

// ─── Shared ──────────────────────────────────────────────────────────────

/// Verify the invitation, and refuse if it is missing, bad, or already spent.
///
/// The subject must be a **persona** the caller may act as
/// ([`crate::operations::persona::persona_signing_key`]) — the DID this agent holds for the
/// member, in a context the caller acts in. Never the caller's own DID merely because it is
/// the caller: an interface client's key lives in the client, and a member is the same
/// member whichever client they joined from.
async fn require_invitation(
    state: &AppState,
    encoded: Option<&str>,
    room_id: &str,
    auth: &AuthClaims,
) -> Result<room_invitation::VerifiedInvitation, vti_common::error::AppError> {
    let invitation = verify_invitation(state, encoded, room_id, auth).await?;
    if room_invitation::is_consumed(&state.room_invitations_ks, invitation.credential_id()).await? {
        return Err(used_invitation(&invitation));
    }
    Ok(invitation)
}

fn used_invitation(
    invitation: &room_invitation::VerifiedInvitation,
) -> vti_common::error::AppError {
    vti_common::error::AppError::Conflict(format!(
        "invitation `{}` has already been used",
        invitation.credential_id()
    ))
}

/// [`require_invitation`] without the check that it is unspent.
async fn verify_invitation(
    state: &AppState,
    encoded: Option<&str>,
    room_id: &str,
    auth: &AuthClaims,
) -> Result<room_invitation::VerifiedInvitation, vti_common::error::AppError> {
    let encoded = encoded.ok_or_else(|| {
        vti_common::error::AppError::Validation(format!(
            "no invitation presented for room `{room_id}`; joining a room is a two-party \
             act and the invitation is the other party's half"
        ))
    })?;

    let keys = vti_rooms_dtg::DataIntegrityKeys(state.trust_task_vm_resolver());
    let stores = crate::operations::persona::PersonaStores::from_state(state);
    let invitation = room_invitation::verify(
        encoded,
        room_id,
        async |subject: &str| {
            Ok(
                crate::operations::persona::persona_signing_key(stores, auth, subject)
                    .await?
                    .is_some(),
            )
        },
        &keys,
    )
    .await?;
    Ok(invitation)
}

fn decode_b64(s: &str, what: &str) -> Result<Vec<u8>, vti_common::error::AppError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| vti_common::error::AppError::Validation(format!("decode the {what}: {e}")))
}

pub(super) fn now() -> u64 {
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
                sealed_version: None,
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

/// `rooms/keys/file-key` and `rooms/keys/open` refusals, as a caller receives them: the
/// declared code, and `details` that validate against the `detailsSchema` the
/// specification declares — 0.1's for 0.1, 0.2's for 0.2.
#[cfg(test)]
mod file_key_refusal_tests {
    use super::*;
    use trust_tasks_rs::TypeUri;
    use vti_rooms::mls::{IdentitySnapshot, RoomGroup};
    use vti_rooms::sealed::SealedRoom;

    const ROOM: &str = "did:webvh:example.com:rooms:northwind";
    const FILE_ID: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn request(payload: Value) -> TrustTask<Value> {
        request_at(vta_sdk::trust_tasks::TASK_ROOMS_KEYS_FILE_KEY_0_1, payload)
    }

    fn request_at(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().unwrap();
        TrustTask::new("urn:uuid:file-key-test", uri, payload)
    }

    fn body(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("the outcome is a document")
    }

    /// A room this VTA holds at epoch 2 for a persona the super-admin acts as, with no rung
    /// back to 1. Returns the member.
    async fn hold_room_at_epoch_2(state: &AppState) -> room_groups::Member {
        let alice = crate::test_support::seed_holder_key(state, "m/44'/0'/9'/0'/1'", None).await;
        let mut room = SealedRoom::new(ROOM, RoomGroup::create(&alice).unwrap());
        let (_bob, kp) = IdentitySnapshot::mint("did:key:zBob").unwrap();
        room.add_member(&kp).unwrap();
        room_groups::store_for_test(
            &state.room_groups_ks,
            &room_groups::Member::new(ROOM, &alice).unwrap(),
            room.group(),
            Vec::new(),
        )
        .await
        .unwrap();
        room_groups::Member::new(ROOM, &alice).unwrap()
    }

    async fn ask(state: &AppState, payload: Value) -> Value {
        let auth = crate::test_support::super_admin_claims();
        body(handle_file_key(state, &auth, request(payload)).await)
    }

    async fn ask_v0_2(state: &AppState, payload: Value) -> Value {
        let auth = crate::test_support::super_admin_claims();
        body(
            handle_file_key_v0_2(
                state,
                &auth,
                request_at(vta_sdk::trust_tasks::TASK_ROOMS_KEYS_FILE_KEY_0_2, payload),
            )
            .await,
        )
    }

    async fn open_at_version(state: &AppState, uri: &str, epoch: u32) -> Value {
        let auth = crate::test_support::super_admin_claims();
        let payload = serde_json::json!({
            "roomId": ROOM,
            "key": "k",
            "version": 1,
            "sealed": { "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA", "nonce": "AAAAAAAAAAAAAAAA", "epoch": epoch },
        });
        let doc = request_at(uri, payload);
        let out = if uri == vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_2 {
            handle_open_v0_2(state, &auth, doc).await
        } else {
            handle_open(state, &auth, doc).await
        };
        body(out)
    }

    /// `rooms/keys/file-key/0.2` oracle item 4: a file sealed at or after the member's
    /// removal is `removed`, with `removedAtEpoch` — never `notDelivered`, whose remedy
    /// (catch up) cannot work. 0.1, whose closed schema has no `removed`, still answers
    /// `notDelivered` with the removal in its message.
    #[tokio::test]
    async fn file_key_0_2_says_removed_where_0_1_could_only_say_not_delivered() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let member = hold_room_at_epoch_2(&state).await;
        room_groups::record_removal_for_test(&state.room_groups_ks, &member, 3)
            .await
            .unwrap();
        let open =
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "open", "epoch": 3 });

        let doc = ask_v0_2(&state, open.clone()).await;
        assert_eq!(
            doc["payload"]["code"], "rooms/keys/file-key:unknownEpoch",
            "{doc}"
        );
        let details = &doc["payload"]["details"];
        assert_eq!(details["reason"], "removed", "{doc}");
        assert_eq!(details["removedAtEpoch"], 3, "{doc}");
        trust_tasks_rs::specs::rooms::keys::file_key::v0_2::error_codes::UNKNOWN_EPOCH
            .check_details(details)
            .unwrap_or_else(|e| panic!("0.2 detailsSchema: {e}: {details}"));

        let doc = ask(&state, open).await;
        assert_unknown_epoch(&doc, "notDelivered");
        assert!(
            doc["payload"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("was removed")),
            "{doc}"
        );
    }

    /// An epoch before the removal is not `removed`: the removal says nothing about it.
    #[tokio::test]
    async fn file_key_0_2_before_the_removal_is_not_removed() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let member = hold_room_at_epoch_2(&state).await;
        room_groups::record_removal_for_test(&state.room_groups_ks, &member, 5)
            .await
            .unwrap();
        let doc = ask_v0_2(
            &state,
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "open", "epoch": 4 }),
        )
        .await;
        assert_eq!(doc["payload"]["details"]["reason"], "notDelivered", "{doc}");
        let doc = ask_v0_2(
            &state,
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "open", "epoch": 1 }),
        )
        .await;
        assert_eq!(doc["payload"]["details"]["reason"], "beyondChain", "{doc}");
        trust_tasks_rs::specs::rooms::keys::file_key::v0_2::error_codes::UNKNOWN_EPOCH
            .check_details(&doc["payload"]["details"])
            .unwrap();
    }

    /// `rooms/keys/open/0.2`: an older epoch the retained chain does not reach is
    /// `unknownEpoch` reason `beyondChain`, with `earliestEpoch` — where 0.1 answered a
    /// bare failure, which it still does.
    #[tokio::test]
    async fn open_0_2_says_beyond_chain_for_an_epoch_the_chain_does_not_reach() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        hold_room_at_epoch_2(&state).await;

        let doc = open_at_version(&state, vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_2, 1).await;
        assert_eq!(
            doc["payload"]["code"], "rooms/keys/open:unknownEpoch",
            "{doc}"
        );
        let details = &doc["payload"]["details"];
        assert_eq!(details["reason"], "beyondChain", "{doc}");
        assert_eq!(details["earliestEpoch"], 2, "{doc}");
        trust_tasks_rs::specs::rooms::keys::open::v0_2::error_codes::UNKNOWN_EPOCH
            .check_details(details)
            .unwrap_or_else(|e| panic!("0.2 detailsSchema: {e}: {details}"));

        let doc = open_at_version(&state, vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_1, 1).await;
        assert_ne!(
            doc["payload"]["code"], "rooms/keys/open:unknownEpoch",
            "{doc}"
        );
    }

    /// `rooms/keys/open/0.2`: `notDelivered` and `removed` carry the declared details.
    #[tokio::test]
    async fn open_0_2_reasons_match_the_declared_details_schema() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let member = hold_room_at_epoch_2(&state).await;
        let check = |doc: &Value, reason: &str| {
            assert_eq!(
                doc["payload"]["code"], "rooms/keys/open:unknownEpoch",
                "{doc}"
            );
            assert_eq!(doc["payload"]["details"]["reason"], reason, "{doc}");
            trust_tasks_rs::specs::rooms::keys::open::v0_2::error_codes::UNKNOWN_EPOCH
                .check_details(&doc["payload"]["details"])
                .unwrap_or_else(|e| panic!("0.2 detailsSchema: {e}: {doc}"));
        };
        let doc = open_at_version(&state, vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_2, 4).await;
        check(&doc, "notDelivered");

        room_groups::record_removal_for_test(&state.room_groups_ks, &member, 3)
            .await
            .unwrap();
        let doc = open_at_version(&state, vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_2, 4).await;
        check(&doc, "removed");
        assert_eq!(doc["payload"]["details"]["removedAtEpoch"], 3, "{doc}");
    }

    fn assert_unknown_epoch(doc: &Value, reason: &str) {
        assert_eq!(
            doc["payload"]["code"], "rooms/keys/file-key:unknownEpoch",
            "{doc}"
        );
        let details = &doc["payload"]["details"];
        assert_eq!(details["reason"], reason, "{doc}");
        // Checked against the schema the specification declares, carried by the
        // generated code, rather than a copy of it kept here.
        trust_tasks_rs::specs::rooms::keys::file_key::v0_1::error_codes::UNKNOWN_EPOCH
            .check_details(details)
            .unwrap_or_else(|e| {
                panic!("details must match the declared detailsSchema: {e}: {details}")
            });
    }

    #[tokio::test]
    async fn no_group_is_the_declared_no_group_code() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let doc = ask(
            &state,
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "seal" }),
        )
        .await;
        assert_eq!(
            doc["payload"]["code"], "rooms/keys/file-key:noGroup",
            "{doc}"
        );
    }

    #[tokio::test]
    async fn an_epoch_not_yet_delivered_says_so_and_names_the_held_epoch() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        hold_room_at_epoch_2(&state).await;
        let doc = ask(
            &state,
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "open", "epoch": 3 }),
        )
        .await;
        assert_unknown_epoch(&doc, "notDelivered");
        assert_eq!(doc["payload"]["details"]["heldEpoch"], 2, "{doc}");
    }

    #[tokio::test]
    async fn an_epoch_beyond_the_chain_names_the_earliest_reachable() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        hold_room_at_epoch_2(&state).await;
        let doc = ask(
            &state,
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "open", "epoch": 1 }),
        )
        .await;
        assert_unknown_epoch(&doc, "beyondChain");
        assert_eq!(doc["payload"]["details"]["earliestEpoch"], 2, "{doc}");
    }

    #[tokio::test]
    async fn a_held_room_releases_a_sealing_key_under_its_current_epoch() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        hold_room_at_epoch_2(&state).await;
        let doc = ask(
            &state,
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "seal" }),
        )
        .await;
        let response: trust_tasks_rs::specs::rooms::keys::file_key::v0_1::Response =
            serde_json::from_value(doc["payload"].clone()).expect("a typed response");
        assert_eq!(response.epoch.get(), 2);
    }

    #[tokio::test]
    async fn an_epoch_with_seal_or_without_it_on_open_is_malformed() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        hold_room_at_epoch_2(&state).await;
        for payload in [
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "seal", "epoch": 2 }),
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "open" }),
            serde_json::json!({ "roomId": ROOM, "fileId": FILE_ID, "purpose": "open", "epoch": 4_294_967_296u64 }),
        ] {
            let doc = ask(&state, payload).await;
            assert_eq!(doc["payload"]["code"], "malformedRequest", "{doc}");
        }
    }
}

/// `rooms/keys/{key-package,welcome}`: the member is the persona the invitation names.
///
/// The invitation names its subject, and the subject is the member's identity in the room —
/// the DID their leaf carries and their credentials name. So it is a persona this VTA holds
/// for the person, and the caller must be able to act as it. The caller's own DID — an
/// interface client's key — is never the member merely because it is the caller.
#[cfg(test)]
mod persona_invitation_tests {
    use super::*;
    use crate::operations::persona::test_fixture::{self as personas, Persona};
    use chrono::{Duration as Span, Utc};
    use dtg_credentials::DTGCredential;
    use trust_tasks_rs::TypeUri;
    use vti_rooms_dtg::test_support::Party;

    const HOST: &str = "did:webvh:QmHost:host.example";

    fn request(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().unwrap();
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn body(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("the outcome is a document")
    }

    async fn state_with_two_contexts() -> (AppState, tempfile::TempDir) {
        let (state, dir) = crate::test_support::build_signing_test_app_state().await;
        for (id, name) in [("alice", "Alice"), ("bob", "Bob")] {
            crate::contexts::create_context(&state.contexts_ks, id, name)
                .await
                .expect("create context");
        }
        (state, dir)
    }

    async fn did_key_persona(state: &AppState, context: &str, key_id: &str) -> Persona {
        personas::did_key_persona(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.acl_ks,
            &state.seed_store,
            &state.audit_sink,
            context,
            key_id,
        )
        .await
    }

    #[cfg(feature = "webvh")]
    async fn webvh_persona(state: &AppState, context: &str, key_id: &str) -> Persona {
        personas::webvh_persona(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.acl_ks,
            &state.webvh_ks,
            &state.seed_store,
            &state.audit_sink,
            context,
            key_id,
        )
        .await
    }

    /// The room's invitation to `subject`, as JSON text.
    async fn invitation(room: &Party, subject: &str) -> String {
        let now = Utc::now();
        let mut vic = DTGCredential::new_vic(
            room.did.clone(),
            dtg_credentials::IssuerScope::Public,
            subject.to_string(),
            now - Span::minutes(1),
            Some(now + Span::hours(1)),
        )
        .with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        vic.sign(&room.secret, None)
            .await
            .expect("sign the invitation");
        serde_json::to_string(vic.credential()).expect("serialise")
    }

    async fn key_package(state: &AppState, auth: &AuthClaims, room: &str, vic: &str) -> Value {
        body(
            handle_key_package(
                state,
                auth,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_KEY_PACKAGE_0_1,
                    serde_json::json!({ "roomId": room, "invitation": vic }),
                ),
            )
            .await,
        )
    }

    fn reason(doc: &Value) -> String {
        doc["payload"]["message"]
            .as_str()
            .or_else(|| doc["payload"]["reason"].as_str())
            .unwrap_or_default()
            .to_string()
    }

    /// An owner's group for `room`, to test what a KeyPackage's leaf identifies the way an
    /// owner's key holder does: it admits the KeyPackage only for the member its leaf names.
    async fn owner_group(room: &str) -> (AppState, tempfile::TempDir) {
        let (owner, dir) = crate::test_support::build_signing_test_app_state().await;
        room_groups::create_group(&owner.room_groups_ks, &owner_member(room), 0)
            .await
            .expect("an owner's group");
        (owner, dir)
    }

    fn owner_member(room: &str) -> room_groups::Member {
        room_groups::Member::new(room, "did:key:zOwner").unwrap()
    }

    fn decode(kp: &Value) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(kp.as_str().expect("a KeyPackage"))
            .expect("base64url")
    }

    /// **A `did:webvh` persona joins, end to end.** The invitation names alice's persona,
    /// a caller acting in alice's context asks, and the KeyPackage's leaf identifies the
    /// persona — an owner admits it as the persona and refuses it as the caller. Then the
    /// Welcome lands, the invitation is spent, and the group this VTA holds is the persona's.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn a_persona_named_by_the_invitation_joins_as_itself() {
        let (state, _dir) = state_with_two_contexts().await;
        let alice = webvh_persona(&state, "alice", "alice-persona").await;
        let room = Party::new();
        let caller = crate::test_support::admin_claims_for_context("alice");
        let vic = invitation(&room, &alice.did).await;

        let minted = key_package(&state, &caller, &room.did, &vic).await;
        let kp = decode(&minted["payload"]["keyPackage"]);

        let (owner, _odir) = owner_group(&room.did).await;
        assert!(
            matches!(
                room_groups::prepare_add(
                    &owner.room_groups_ks,
                    &owner_member(&room.did),
                    HOST,
                    &caller.did,
                    &kp,
                    0
                )
                .await,
                Err(room_groups::PrepareAddError::KeyPackageInvalid(_))
            ),
            "the leaf must not identify the client that asked"
        );
        let pending = room_groups::prepare_add(
            &owner.room_groups_ks,
            &owner_member(&room.did),
            HOST,
            &alice.did,
            &kp,
            0,
        )
        .await
        .unwrap_or_else(|_| panic!("the leaf identifies the persona"));

        let joined = body(
            handle_welcome(
                &state,
                &caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WELCOME_0_1,
                    serde_json::json!({
                        "roomId": room.did, "welcome": pending.welcome, "invitation": vic,
                    }),
                ),
            )
            .await,
        );
        assert!(joined["payload"]["epoch"].is_u64(), "{joined}");
        let held = room_groups::load(
            &state.room_groups_ks,
            &room_groups::Member::new(&room.did, &alice.did).unwrap(),
        )
        .await
        .unwrap()
        .expect("the group");
        let group = vti_rooms::mls::RoomGroup::restore(&held.snapshot).unwrap();
        assert!(group.leaf_of(&alice.did).is_some(), "the persona's leaf");

        // Spent: keyed on the invitation, whoever delivers it next.
        let again = key_package(&state, &caller, &room.did, &vic).await;
        assert!(reason(&again).contains("already been used"), "{again}");
    }

    /// A held `did:key` persona in the caller's context is a member like any other.
    #[tokio::test]
    async fn a_held_did_key_persona_is_invited() {
        let (state, _dir) = state_with_two_contexts().await;
        let alice = did_key_persona(&state, "alice", "alice-key").await;
        let room = Party::new();
        let vic = invitation(&room, &alice.did).await;
        let minted = key_package(
            &state,
            &crate::test_support::admin_claims_for_context("alice"),
            &room.did,
            &vic,
        )
        .await;
        let kp = decode(&minted["payload"]["keyPackage"]);
        let (owner, _odir) = owner_group(&room.did).await;
        room_groups::prepare_add(
            &owner.room_groups_ks,
            &owner_member(&room.did),
            HOST,
            &alice.did,
            &kp,
            0,
        )
        .await
        .unwrap_or_else(|_| panic!("the leaf identifies the persona"));
    }

    /// **The privilege boundary.** An invitation naming bob's persona, delivered by a caller
    /// acting in alice's context, is refused — in the same words as an invitation naming a
    /// DID this VTA holds nothing for, so the refusal does not tell alice's caller that bob's
    /// persona is held here.
    #[tokio::test]
    async fn another_contexts_persona_is_refused_like_an_unknown_one() {
        let (state, _dir) = state_with_two_contexts().await;
        let bob = did_key_persona(&state, "bob", "bob-key").await;
        let nobody = Party::new().did;
        let room = Party::new();
        let caller = crate::test_support::admin_claims_for_context("alice");

        let to_bob = key_package(
            &state,
            &caller,
            &room.did,
            &invitation(&room, &bob.did).await,
        )
        .await;
        let to_nobody = key_package(
            &state,
            &caller,
            &room.did,
            &invitation(&room, &nobody).await,
        )
        .await;
        assert!(to_bob["payload"]["keyPackage"].is_null(), "{to_bob}");
        assert!(
            reason(&to_bob).contains("not a persona you may act as"),
            "{to_bob}"
        );
        assert_eq!(
            reason(&to_bob),
            reason(&to_nobody).replace(&nobody, &bob.did),
            "held-for-someone-else and held-for-nobody read the same"
        );

        // Bob's own caller is served.
        let ok = key_package(
            &state,
            &crate::test_support::admin_claims_for_context("bob"),
            &room.did,
            &invitation(&room, &bob.did).await,
        )
        .await;
        assert!(ok["payload"]["keyPackage"].is_string(), "{ok}");
    }

    /// An invitation naming the caller's own client key — which is what every invitation had
    /// to name before — is refused: a key that lives in the client cannot be a member.
    #[tokio::test]
    async fn an_invitation_to_the_client_key_is_refused() {
        let (state, _dir) = state_with_two_contexts().await;
        let room = Party::new();
        let caller = crate::test_support::admin_claims_for_context("alice");
        let out = key_package(
            &state,
            &caller,
            &room.did,
            &invitation(&room, &caller.did).await,
        )
        .await;
        assert!(out["payload"]["keyPackage"].is_null(), "{out}");
        assert!(
            reason(&out).contains("not a persona you may act as"),
            "{out}"
        );

        // Nor a Welcome under one: nothing joins.
        let welcome = body(
            handle_welcome(
                &state,
                &caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WELCOME_0_1,
                    serde_json::json!({
                        "roomId": room.did, "welcome": "AAAA",
                        "invitation": invitation(&room, &caller.did).await,
                    }),
                ),
            )
            .await,
        );
        assert!(
            reason(&welcome).contains("not a persona you may act as"),
            "{welcome}"
        );
        assert!(
            room_groups::holders(&state.room_groups_ks, &room.did)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

/// One VTA, several members of one room: group state is the **member's** — per (room,
/// persona) — never the VTA's per room. A family on one VTA, or a team on a company one, can
/// all be in the same room, each reading and writing as themselves, and none reaching
/// another's group.
#[cfg(test)]
mod per_member_tests {
    use super::*;
    use crate::operations::persona::test_fixture::{self as personas, Persona};
    use crate::operations::room_groups::Member;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use chrono::{Duration as Span, Utc};
    use dtg_credentials::DTGCredential;
    use trust_tasks_rs::TypeUri;
    use vti_rooms::mls::RoomGroup;
    use vti_rooms::sealed::SealedRoom;
    use vti_rooms::wire::SealedContent;
    use vti_rooms_dtg::test_support::Party;

    const HOST: &str = "did:webvh:QmHost:host.example";
    const OWNER: &str = "did:key:zOwner";

    fn request(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().unwrap();
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn body(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("the outcome is a document")
    }

    fn alice_caller() -> AuthClaims {
        crate::test_support::admin_claims_for_context("alice")
    }

    fn bob_caller() -> AuthClaims {
        crate::test_support::admin_claims_for_context("bob")
    }

    /// One VTA serving two principals, alice and bob, each with a persona in their own
    /// context.
    async fn shared_vta() -> (AppState, tempfile::TempDir, Persona, Persona) {
        let (state, dir) = crate::test_support::build_signing_test_app_state().await;
        for (id, name) in [("alice", "Alice"), ("bob", "Bob")] {
            crate::contexts::create_context(&state.contexts_ks, id, name)
                .await
                .expect("create context");
        }
        let persona = |context: &'static str, key: &'static str| {
            let state = &state;
            async move {
                personas::did_key_persona(
                    &state.keys_ks,
                    &state.internal_ks,
                    &state.contexts_ks,
                    &state.acl_ks,
                    &state.seed_store,
                    &state.audit_sink,
                    context,
                    key,
                )
                .await
            }
        };
        let alice = persona("alice", "alice-key").await;
        let bob = persona("bob", "bob-key").await;
        (state, dir, alice, bob)
    }

    /// The room's owner, on a VTA of their own: the group, founded.
    async fn owner(room: &str) -> (AppState, tempfile::TempDir, Member) {
        let (state, dir) = crate::test_support::build_signing_test_app_state().await;
        let owner = Member::new(room, OWNER).unwrap();
        room_groups::create_group(&state.room_groups_ks, &owner, 0)
            .await
            .expect("an owner's group");
        (state, dir, owner)
    }

    async fn invitation(room: &Party, subject: &str) -> String {
        let now = Utc::now();
        let mut vic = DTGCredential::new_vic(
            room.did.clone(),
            dtg_credentials::IssuerScope::Public,
            subject.to_string(),
            now - Span::minutes(1),
            Some(now + Span::hours(1)),
        )
        .with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        vic.sign(&room.secret, None).await.expect("sign");
        serde_json::to_string(vic.credential()).expect("serialise")
    }

    /// `persona` joins `room` through this VTA, as `caller` would drive it: a KeyPackage,
    /// the owner's admission (accepted at its host), the Welcome. Returns the admission.
    async fn join(
        state: &AppState,
        caller: &AuthClaims,
        room: &Party,
        persona: &str,
        owner_state: &AppState,
        owner: &Member,
    ) -> (room_groups::PendingAdvance, Value) {
        let vic = invitation(room, persona).await;
        let minted = body(
            handle_key_package(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_KEY_PACKAGE_0_1,
                    serde_json::json!({ "roomId": room.did, "invitation": vic }),
                ),
            )
            .await,
        );
        let kp = B64
            .decode(minted["payload"]["keyPackage"].as_str().expect("{minted}"))
            .unwrap();
        let admission =
            room_groups::prepare_add(&owner_state.room_groups_ks, owner, HOST, persona, &kp, 0)
                .await
                .unwrap_or_else(|e| panic!("the owner admits {persona}: {e:?}"));
        room_groups::promote_pending_advance(&owner_state.room_groups_ks, owner, &admission, 0)
            .await
            .unwrap();
        let welcomed = body(
            handle_welcome(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WELCOME_0_1,
                    serde_json::json!({
                        "roomId": room.did, "welcome": admission.welcome, "invitation": vic,
                    }),
                ),
            )
            .await,
        );
        (admission, welcomed)
    }

    async fn open(state: &AppState, caller: &AuthClaims, room: &str, rec: &SealedContent) -> Value {
        body(
            handle_open(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_1,
                    serde_json::json!({
                        "roomId": room, "key": "notes/1", "version": 1,
                        "sealed": {
                            "ciphertext": rec.ciphertext, "nonce": rec.nonce, "epoch": rec.epoch,
                        },
                    }),
                ),
            )
            .await,
        )
    }

    async fn seal(state: &AppState, caller: &AuthClaims, room: &str, text: &str) -> Value {
        body(
            handle_seal(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_SEAL_0_1,
                    serde_json::json!({
                        "roomId": room, "key": "notes/1", "version": 1,
                        "plaintext": B64.encode(text),
                    }),
                ),
            )
            .await,
        )
    }

    async fn commit(
        state: &AppState,
        caller: &AuthClaims,
        room: &str,
        advance: &room_groups::PendingAdvance,
    ) -> Value {
        body(
            handle_commit(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_COMMIT_0_1,
                    // The MLS epoch the commit produces, one below the room's.
                    serde_json::json!({
                        "roomId": room, "commit": advance.commit, "epoch": advance.epoch - 1,
                    }),
                ),
            )
            .await,
        )
    }

    async fn list(state: &AppState, caller: &AuthClaims) -> Value {
        body(
            handle_list(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_LIST_0_1,
                    serde_json::json!({}),
                ),
            )
            .await,
        )
    }

    fn plaintext(doc: &Value) -> Vec<u8> {
        B64.decode(
            doc["payload"]["plaintext"]
                .as_str()
                .unwrap_or_else(|| panic!("{doc}")),
        )
        .unwrap()
    }

    fn sealed(doc: &Value) -> SealedContent {
        serde_json::from_value(doc["payload"]["sealed"].clone())
            .unwrap_or_else(|e| panic!("{e}: {doc}"))
    }

    /// **The defect, end to end.** Alice and Bob share one VTA, each in their own context.
    /// Both are admitted to one room; Bob's Welcome — refused before, as "this VTA already
    /// holds group state" — joins; each reads what the owner seals and writes what the owner
    /// reads, through their own caller; each sees the room once in their own list.
    #[tokio::test]
    async fn two_personas_in_two_contexts_on_one_vta_both_join_one_room() {
        let (state, _d, alice, bob) = shared_vta().await;
        let room = Party::new();
        let (owner_state, _od, owner) = owner(&room.did).await;

        let (_, joined) = join(
            &state,
            &alice_caller(),
            &room,
            &alice.did,
            &owner_state,
            &owner,
        )
        .await;
        assert!(joined["payload"]["epoch"].is_u64(), "alice joins: {joined}");
        let (to_bob, joined) =
            join(&state, &bob_caller(), &room, &bob.did, &owner_state, &owner).await;
        assert!(
            joined["payload"]["epoch"].is_u64(),
            "bob joins the room alice is already in, on the same VTA: {joined}"
        );

        // Alice follows Bob's admission in her own group; Bob's is untouched by it.
        let followed = commit(&state, &alice_caller(), &room.did, &to_bob).await;
        assert_eq!(followed["payload"]["epoch"], 2, "{followed}");

        let from_owner =
            room_groups::seal_record(&owner_state.room_groups_ks, &owner, "notes/1", 1, b"to all")
                .await
                .unwrap();
        for (who, caller) in [("alice", alice_caller()), ("bob", bob_caller())] {
            let opened = open(&state, &caller, &room.did, &from_owner).await;
            assert_eq!(plaintext(&opened), b"to all", "{who} reads: {opened}");

            let written = seal(&state, &caller, &room.did, who).await;
            let read_back = room_groups::open_record(
                &owner_state.room_groups_ks,
                &owner,
                "notes/1",
                1,
                &sealed(&written).ciphertext,
                &sealed(&written).nonce,
                sealed(&written).epoch,
            )
            .await
            .unwrap_or_else(|e| panic!("the owner reads what {who} sealed: {e}"));
            assert_eq!(read_back, who.as_bytes());

            let listed = list(&state, &caller).await;
            let rooms = listed["payload"]["rooms"].as_array().expect("{listed}");
            assert_eq!(rooms.len(), 1, "{who} holds the room once: {listed}");
            assert_eq!(rooms[0]["roomId"], room.did);
        }

        // Two groups, two leaves, both on this VTA.
        let held = room_groups::holders(&state.room_groups_ks, &room.did)
            .await
            .unwrap();
        assert_eq!(held.len(), 2, "{held:?}");
    }

    async fn key_package_v0_2(
        state: &AppState,
        caller: &AuthClaims,
        room: &str,
        vic: &str,
    ) -> Value {
        body(
            handle_key_package_v0_2(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_KEY_PACKAGE_0_2,
                    serde_json::json!({ "roomId": room, "invitation": vic }),
                ),
            )
            .await,
        )
    }

    /// `rooms/keys/key-package/0.2`, end to end: an acceptance one surface began — it
    /// obtained the KeyPackage, the owner admitted it, and the surface stopped before the
    /// Welcome — is finished by another. The second surface is given the same KeyPackage
    /// (item 3), the Welcome sealed to it joins, and the first surface's late Welcome is
    /// `alreadyJoined`, which a surface reads as success.
    #[tokio::test]
    async fn an_acceptance_begun_on_one_surface_is_finished_on_another() {
        let (state, _d, alice, _bob) = shared_vta().await;
        let room = Party::new();
        let (owner_state, _od, owner) = owner(&room.did).await;
        let vic = invitation(&room, &alice.did).await;

        let portal = key_package_v0_2(&state, &alice_caller(), &room.did, &vic).await;
        assert_eq!(portal["payload"]["alreadyMinted"], false, "{portal}");
        let terminal = key_package_v0_2(&state, &alice_caller(), &room.did, &vic).await;
        assert_eq!(terminal["payload"]["alreadyMinted"], true, "{terminal}");
        assert_eq!(
            terminal["payload"]["keyPackage"], portal["payload"]["keyPackage"],
            "the same KeyPackage, so the community answers with the Welcome it kept"
        );
        assert_eq!(
            terminal["payload"]["expiresAt"], portal["payload"]["expiresAt"],
            "returning it again does not extend it"
        );
        // It outlives the week the community keeps the Welcome from the admission.
        let expires =
            chrono::DateTime::parse_from_rfc3339(portal["payload"]["expiresAt"].as_str().unwrap())
                .unwrap();
        assert!(expires > Utc::now() + Span::days(13), "{portal}");

        let kp = B64
            .decode(portal["payload"]["keyPackage"].as_str().unwrap())
            .unwrap();
        let admission = room_groups::prepare_add(
            &owner_state.room_groups_ks,
            &owner,
            HOST,
            &alice.did,
            &kp,
            0,
        )
        .await
        .unwrap();
        room_groups::promote_pending_advance(&owner_state.room_groups_ks, &owner, &admission, 0)
            .await
            .unwrap();

        let welcome = |state: &AppState| {
            let request = request(
                vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WELCOME_0_1,
                serde_json::json!({
                    "roomId": room.did, "welcome": admission.welcome, "invitation": vic,
                }),
            );
            let state = state.clone();
            async move { body(handle_welcome(&state, &alice_caller(), request).await) }
        };
        let joined = welcome(&state).await;
        assert!(joined["payload"]["epoch"].is_u64(), "{joined}");
        let late = welcome(&state).await;
        assert_eq!(
            late["payload"]["code"], "rooms/keys/welcome:alreadyJoined",
            "{late}"
        );
        let listed = list(&state, &alice_caller()).await;
        assert_eq!(
            listed["payload"]["rooms"][0]["roomId"], room.did,
            "{listed}"
        );
    }

    /// Item 6: a different invitation for the same room and member — after a removal and
    /// re-admission — is given a different KeyPackage; and a KeyPackage 0.1 minted, which
    /// records no invitation, is never returned by 0.2. Item 7: requests arriving together
    /// are given the same one.
    #[tokio::test]
    async fn only_the_same_invitation_is_given_the_held_key_package() {
        let (state, _d, alice, _bob) = shared_vta().await;
        let room = Party::new();
        let caller = alice_caller();

        let legacy = body(
            handle_key_package(
                &state,
                &caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_KEY_PACKAGE_0_1,
                    serde_json::json!({
                        "roomId": room.did,
                        "invitation": invitation(&room, &alice.did).await,
                    }),
                ),
            )
            .await,
        );
        let first_vic = invitation(&room, &alice.did).await;
        let first = key_package_v0_2(&state, &caller, &room.did, &first_vic).await;
        assert_eq!(first["payload"]["alreadyMinted"], false, "{first}");
        assert_ne!(
            first["payload"]["keyPackage"],
            legacy["payload"]["keyPackage"]
        );

        let second_vic = invitation(&room, &alice.did).await;
        let second = key_package_v0_2(&state, &caller, &room.did, &second_vic).await;
        assert_eq!(second["payload"]["alreadyMinted"], false, "{second}");
        assert_ne!(
            second["payload"]["keyPackage"],
            first["payload"]["keyPackage"]
        );

        let (a, b) = tokio::join!(
            key_package_v0_2(&state, &caller, &room.did, &second_vic),
            key_package_v0_2(&state, &caller, &room.did, &second_vic),
        );
        assert_eq!(a["payload"]["keyPackage"], second["payload"]["keyPackage"]);
        assert_eq!(b["payload"]["keyPackage"], second["payload"]["keyPackage"]);
    }

    /// The same member twice is still `alreadyJoined` — the spec's rule, asked of the member.
    #[tokio::test]
    async fn the_same_persona_welcomed_twice_is_already_joined() {
        let (state, _d, alice, _bob) = shared_vta().await;
        let room = Party::new();
        let (owner_state, _od, owner) = owner(&room.did).await;
        join(
            &state,
            &alice_caller(),
            &room,
            &alice.did,
            &owner_state,
            &owner,
        )
        .await;

        // A second invitation and package for the same persona: the group it would make
        // collides with the one held.
        let groups = &state.room_groups_ks;
        let member = Member::new(&room.did, &alice.did).unwrap();
        room_groups::mint_key_package(groups, &member, 3600, 0)
            .await
            .unwrap();
        let again = body(
            handle_welcome(
                &state,
                &alice_caller(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WELCOME_0_1,
                    serde_json::json!({
                        "roomId": room.did, "welcome": "AAAA",
                        "invitation": invitation(&room, &alice.did).await,
                    }),
                ),
            )
            .await,
        );
        assert_eq!(
            again["payload"]["code"], "rooms/keys/welcome:alreadyJoined",
            "{again}"
        );
    }

    /// A Welcome sealed to a KeyPackage past its expiry is refused `welcomeInvalid`, as
    /// `rooms/keys/act/0.3`'s `holds_key_package` already treats that package as not held —
    /// and the expired private half is discarded rather than used
    /// (`rooms/keys/key-package/0.1` *Retention*). Nothing is joined, and the invitation is
    /// not spent, so a fresh package can still be added under it.
    #[tokio::test]
    async fn a_welcome_to_an_expired_key_package_is_refused_and_the_package_discarded() {
        use base64::Engine as _;
        let (state, _d, alice, _bob) = shared_vta().await;
        let room = Party::new();
        let groups = &state.room_groups_ks;
        let member = Member::new(&room.did, &alice.did).unwrap();
        // Minted at the epoch's start with a one-second life: long expired by now.
        let pending = room_groups::mint_key_package(groups, &member, 1, 0)
            .await
            .unwrap();
        let mut owner = vti_rooms::mls::RoomGroup::create("did:example:owner").unwrap();
        let change = owner
            .add_member_from_bytes(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&pending.key_package)
                    .unwrap(),
            )
            .unwrap();
        let welcome =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(change.welcome.unwrap());

        let refused = body(
            handle_welcome(
                &state,
                &alice_caller(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_WELCOME_0_1,
                    serde_json::json!({
                        "roomId": room.did, "welcome": welcome,
                        "invitation": invitation(&room, &alice.did).await,
                    }),
                ),
            )
            .await,
        );
        assert_eq!(
            refused["payload"]["code"],
            trust_tasks_rs::specs::rooms::keys::welcome::v0_1::error_codes::WELCOME_INVALID.code,
            "{refused}"
        );
        assert!(
            room_groups::load(groups, &member).await.unwrap().is_none(),
            "nothing joined"
        );
        assert!(
            !room_groups::holds_key_package(
                groups,
                &member,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&pending.key_package)
                    .unwrap(),
                0,
            )
            .await
            .unwrap(),
            "the expired private half is gone, whatever the clock says"
        );
    }

    /// **Context isolation.** A room only Bob holds is, to a caller in Alice's context, a
    /// room nobody here holds: open, seal, commit and list all answer as they would for an
    /// unknown room, and Bob's group does not move.
    #[tokio::test]
    async fn a_caller_in_one_context_cannot_touch_another_contexts_group() {
        let (state, _d, _alice, bob) = shared_vta().await;
        let room = Party::new();
        let (owner_state, _od, owner) = owner(&room.did).await;
        join(&state, &bob_caller(), &room, &bob.did, &owner_state, &owner).await;
        let bobs = Member::new(&room.did, &bob.did).unwrap();
        let before = room_groups::load(&state.room_groups_ks, &bobs)
            .await
            .unwrap()
            .unwrap()
            .updated_at;

        let unknown = Party::new().did;
        let from_owner =
            room_groups::seal_record(&owner_state.room_groups_ks, &owner, "notes/1", 1, b"x")
                .await
                .unwrap();
        let opened = open(&state, &alice_caller(), &room.did, &from_owner).await;
        let opened_unknown = open(&state, &alice_caller(), &unknown, &from_owner).await;
        assert!(opened["payload"]["plaintext"].is_null(), "{opened}");
        assert_eq!(
            opened["payload"]["message"]
                .as_str()
                .map(|m| m.replace(&room.did, "R")),
            opened_unknown["payload"]["message"]
                .as_str()
                .map(|m| m.replace(&unknown, "R")),
            "bob's room reads to alice's caller as a room nobody holds"
        );
        let sealed_by_alice = seal(&state, &alice_caller(), &room.did, "x").await;
        assert!(
            sealed_by_alice["payload"]["sealed"].is_null(),
            "{sealed_by_alice}"
        );

        // A commit alice's caller delivers advances nothing of bob's.
        let (to_carol, _) = {
            let carol = crate::operations::persona::test_fixture::did_key_persona(
                &state.keys_ks,
                &state.internal_ks,
                &state.contexts_ks,
                &state.acl_ks,
                &state.seed_store,
                &state.audit_sink,
                "alice",
                "carol-key",
            )
            .await;
            join(
                &state,
                &alice_caller(),
                &room,
                &carol.did,
                &owner_state,
                &owner,
            )
            .await
        };
        // Carol, in alice's context, now holds the room too — so alice's caller's commit
        // lands on carol's group, never bob's.
        let delivered = commit(&state, &alice_caller(), &room.did, &to_carol).await;
        assert!(delivered["payload"]["epoch"].is_u64(), "{delivered}");
        let after = room_groups::load(&state.room_groups_ks, &bobs)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.updated_at, before, "bob's group did not move");
        assert_eq!(
            SealedRoom::new(&room.did, RoomGroup::restore(&after.snapshot).unwrap()).room_epoch(),
            2,
            "bob is still where his own deliveries left him"
        );

        let listed = list(&state, &alice_caller()).await;
        let rooms = listed["payload"]["rooms"].as_array().expect("{listed}");
        assert_eq!(
            rooms.len(),
            1,
            "carol's membership only, never bob's: {listed}"
        );
    }

    /// A caller who may act as several personas is answered without ambiguity where only
    /// one of them holds the room — and asked to choose where both do.
    #[tokio::test]
    async fn one_holder_resolves_and_two_ask_the_caller_to_choose() {
        let (state, _d, alice, bob) = shared_vta().await;
        let room = Party::new();
        let (owner_state, _od, owner) = owner(&room.did).await;
        let everywhere = crate::test_support::super_admin_claims();
        join(
            &state,
            &alice_caller(),
            &room,
            &alice.did,
            &owner_state,
            &owner,
        )
        .await;

        let from_owner =
            room_groups::seal_record(&owner_state.room_groups_ks, &owner, "notes/1", 1, b"one")
                .await
                .unwrap();
        let opened = open(&state, &everywhere, &room.did, &from_owner).await;
        assert_eq!(
            plaintext(&opened),
            b"one",
            "only alice holds the room, so it is hers: {opened}"
        );

        join(&state, &bob_caller(), &room, &bob.did, &owner_state, &owner).await;
        let ambiguous = open(&state, &everywhere, &room.did, &from_owner).await;
        assert!(
            ambiguous["payload"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("act from the context of the one you mean"),
            "{ambiguous}"
        );
        // Acting from one context resolves it.
        assert_eq!(
            plaintext(&open(&state, &alice_caller(), &room.did, &from_owner).await),
            b"one"
        );
    }

    async fn open_as(
        state: &AppState,
        caller: &AuthClaims,
        room: &str,
        rec: &SealedContent,
        member: &str,
    ) -> Value {
        body(
            handle_open(
                state,
                caller,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_OPEN_0_1,
                    serde_json::json!({
                        "roomId": room, "key": "notes/1", "version": 1,
                        "sealed": {
                            "ciphertext": rec.ciphertext, "nonce": rec.nonce, "epoch": rec.epoch,
                        },
                        "ext": { "org.openvtc.rooms": { "member": member } },
                    }),
                ),
            )
            .await,
        )
    }

    /// A caller who may act as two members of one room — an administrator whose VTA also
    /// holds the community's own place in it — is listed the room once per member, each
    /// entry saying whose it is, and names the one it means in
    /// `ext["org.openvtc.rooms"].member` instead of being refused.
    #[tokio::test]
    async fn two_members_of_one_room_are_listed_apart_and_named_to_act() {
        let (state, _d, alice, bob) = shared_vta().await;
        let room = Party::new();
        let (owner_state, _od, owner) = owner(&room.did).await;
        let everywhere = crate::test_support::super_admin_claims();
        join(
            &state,
            &alice_caller(),
            &room,
            &alice.did,
            &owner_state,
            &owner,
        )
        .await;
        let (to_bob, _) = join(&state, &bob_caller(), &room, &bob.did, &owner_state, &owner).await;
        commit(&state, &alice_caller(), &room.did, &to_bob).await;

        let listed = list(&state, &everywhere).await;
        let rooms = listed["payload"]["rooms"].as_array().expect("rooms");
        let held = listed["payload"]["ext"]["org.openvtc.rooms"]["held"]
            .as_array()
            .unwrap_or_else(|| panic!("whose each entry is: {listed}"));
        assert_eq!(rooms.len(), 2, "one entry per member: {listed}");
        assert_eq!(held.len(), rooms.len(), "index for index: {listed}");
        let mut members: Vec<&str> = held.iter().map(|h| h["member"].as_str().unwrap()).collect();
        members.sort_unstable();
        let mut want = vec![alice.did.as_str(), bob.did.as_str()];
        want.sort_unstable();
        assert_eq!(members, want, "{listed}");
        assert!(rooms.iter().all(|r| r["roomId"] == room.did));
        assert!(
            held.iter().all(|h| h["context"].is_string()),
            "each member's context: {listed}"
        );

        // A caller in one context is listed only its own member.
        let mine = list(&state, &alice_caller()).await;
        let held = mine["payload"]["ext"]["org.openvtc.rooms"]["held"]
            .as_array()
            .expect("held");
        assert_eq!(held.len(), 1, "{mine}");
        assert_eq!(held[0]["member"], alice.did);

        let from_owner =
            room_groups::seal_record(&owner_state.room_groups_ks, &owner, "notes/1", 1, b"one")
                .await
                .unwrap();
        for persona in [&alice.did, &bob.did] {
            let opened = open_as(&state, &everywhere, &room.did, &from_owner, persona).await;
            assert_eq!(plaintext(&opened), b"one", "as {persona}: {opened}");
        }
        // Naming only narrows: a member the caller may not act as is not one it gets.
        let refused = open_as(&state, &alice_caller(), &room.did, &from_owner, &bob.did).await;
        assert!(
            refused["payload"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no group state"),
            "{refused}"
        );
        // A member that is not a DID is malformed, never ignored.
        let malformed = open_as(&state, &everywhere, &room.did, &from_owner, "alice").await;
        assert!(
            malformed["payload"]["code"]
                .as_str()
                .unwrap_or_default()
                .contains("malformed"),
            "{malformed}"
        );
    }

    /// **An upgraded store.** A group the per-room build wrote at `room-group:<room>` still
    /// opens after the upgrade, for the persona its own leaf identifies — and is moved under
    /// that persona on the first touch. A caller in another context touching the room
    /// neither opens it nor moves it.
    #[tokio::test]
    async fn a_group_from_the_per_room_build_still_opens_and_is_moved() {
        let (state, _d, alice, _bob) = shared_vta().await;
        let room = Party::new();
        let group = RoomGroup::create(&alice.did).unwrap();
        let record = room_groups::RoomGroupRecord {
            snapshot: group.snapshot().unwrap(),
            member_did: alice.did.clone(),
            links: Vec::new(),
            updated_at: 0,
        };
        let sealed_before = SealedRoom::new(&room.did, group)
            .seal_record("notes/1", 1, b"from before the upgrade")
            .unwrap();
        let groups = &state.room_groups_ks;
        room_groups::legacy_for_test::store_group(groups, &room.did, &record).await;

        // Bob's caller is not alice's: nothing opens, nothing moves.
        let refused = open(&state, &bob_caller(), &room.did, &sealed_before).await;
        assert!(refused["payload"]["plaintext"].is_null(), "{refused}");
        assert_eq!(
            room_groups::legacy_rooms(groups).await.unwrap(),
            vec![room.did.clone()]
        );

        let opened = open(&state, &alice_caller(), &room.did, &sealed_before).await;
        assert_eq!(plaintext(&opened), b"from before the upgrade", "{opened}");
        assert!(room_groups::legacy_rooms(groups).await.unwrap().is_empty());
        assert!(
            room_groups::load(groups, &Member::new(&room.did, &alice.did).unwrap())
                .await
                .unwrap()
                .is_some(),
            "now kept under the persona"
        );
    }
}
