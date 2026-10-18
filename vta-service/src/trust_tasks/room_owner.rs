//! `rooms/owner/*` — the credentials a room issues, minted in the room's own name.
//!
//! # What authorizes these, and what deliberately does not
//!
//! Control of the room's signing key. These handlers name a key and the key oracle decides
//! whether this caller may use it — `require_context`, the caller's own key scope, and the
//! context policy's signing limit, which is resource-bound and binds a super-admin too. A
//! caller who may name a room's key could already have signed with it through `keys/sign`,
//! so nothing new is trusted here.
//!
//! What is **not** checked is that the caller is the room's owner. "Owner" is a fact about
//! the room's DID controller and this service is not a DID resolver; resolving to find out
//! would make issuance depend on the network and on an answer a host could shape. Control of
//! the signing key and control of the DID are the same thing while the key is the one the
//! document names — and where they have come apart, the credential minted here fails to
//! verify. At first use, loudly, by the party who cares.
//!
//! # The capability is `CredentialWrite`
//!
//! Not `RoomOpen`, which is about reading a room's records, and not `Sign`, which would be
//! strictly more than the task needs: an agent that may ask a room to admit a member is not
//! thereby an agent that may sign anything at all with its principal's keys. Issuing a
//! credential is what `CredentialWrite` is for, and these are credentials.

use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::acl::Capability;

use crate::auth::AuthClaims;
use crate::operations::room_host::RoomTaskError;
use crate::operations::room_issuance::{SigningContext, sign_as_room};
use crate::server::AppState;

use super::TrustTaskOutcome;
use super::helpers::{app_error_to_reject, parse_payload, success_response};
use super::room_group::record;

/// The signing context, assembled from state so each handler does not repeat it.
fn signing_context<'a>(state: &'a AppState, auth: &'a AuthClaims) -> SigningContext<'a> {
    SigningContext {
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

/// Give the credential an `id` before signing.
///
/// The id is bound into the proof, so it MUST be set first — and it is what tells a re-send
/// from a renewal, which is the distinction a room's owner needs and nothing else records.
fn with_fresh_id(c: dtg_credentials::DTGCredential) -> dtg_credentials::DTGCredential {
    c.with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()))
}

async fn issue(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    room_id: &str,
    signing_key_id: &str,
    audit_verb: &str,
    credential: dtg_credentials::DTGCredential,
) -> TrustTaskOutcome {
    let mut credential = with_fresh_id(credential);
    match sign_as_room(
        signing_context(state, auth),
        signing_key_id,
        room_id,
        &mut credential,
    )
    .await
    {
        Ok((serialised, id)) => {
            record(state, audit_verb, auth, room_id).await;
            success_response(
                doc,
                serde_json::json!({ "credential": serialised, "credentialId": id }),
            )
        }
        Err(e) => app_error_to_reject(doc, e),
    }
}

/// `rooms/owner/invite/0.1` — mint a VIC.
pub(super) async fn handle_invite(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "inviting a party to a room",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::owner::invite::v0_1::Payload = match parse_payload(&doc)
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // `issuerScope: public`: the room issues as itself, under the one DID every
    // party that verifies a room credential already knows — the room's scope.
    let vic = dtg_credentials::DTGCredential::new_vic(
        req.room_id.clone(),
        dtg_credentials::IssuerScope::Public,
        req.subject.clone(),
        chrono::Utc::now(),
        req.valid_until,
    );
    issue(
        state,
        auth,
        &doc,
        &req.room_id,
        &req.signing_key_id,
        "rooms.owner.invite",
        vic,
    )
    .await
}

/// `rooms/owner/issue-membership/0.1` — mint the VMC a member presents.
pub(super) async fn handle_issue_membership(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "admitting a member to a room",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::owner::issue_membership::v0_1::Payload =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    // The grant half of the pair. Room authorization verifies this one — it compares the
    // presented membership's subject against the authority chain's root — and never looks
    // for the member's acknowledgement, which is issued by the member and cannot be minted
    // here. See the spec's "One half of an edge, and the half that is checked".
    let vmc = dtg_credentials::DTGCredential::new_vmc(
        req.room_id.clone(),
        req.subject.clone(),
        chrono::Utc::now(),
        req.valid_until,
        // `personhood: false` — a room admits parties, and makes no claim about whether
        // one is a person. That is a community's question, asked through its own
        // personhood machinery, and a room asserting it would be a room speaking about
        // something it cannot check.
        false,
    );
    issue(
        state,
        auth,
        &doc,
        &req.room_id,
        &req.signing_key_id,
        "rooms.owner.issue-membership",
        vmc,
    )
    .await
}

/// `rooms/owner/issue-authority/0.1` — mint a VAC chain root.
pub(super) async fn handle_issue_authority(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "granting authority in a room",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::owner::issue_authority::v0_2::Payload =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    let actions: Vec<String> = req.actions.iter().map(|a| a.to_string()).collect();

    // A chain ROOT, issued by the party governing the scope. `new_vac` refuses an empty
    // action list rather than reading it as "everything", and the schema refuses it before
    // that — two layers, because "confers nothing" and "confers everything" are exactly the
    // two readings a careless consumer might choose between.
    // `validUntil` is not checked here any more, and its absence is not a case this
    // function can reach: `issue-authority/0.2` makes the member REQUIRED, so the generated
    // payload types it as a `DateTime` and the envelope schema rejects a request without one
    // before dispatch. The rule is unchanged — nothing about a subject's standing is
    // consulted when a chain is verified, so a root that does not expire is authority nobody
    // can withdraw by waiting — it is simply enforced a layer up now, which is where a
    // shape constraint belongs.
    // `issuerScope: public`: the room governs its own scope and issues the root under
    // the DID that scope names, which every verifier of the chain resolves.
    let vac = match dtg_credentials::DTGCredential::new_vac(
        req.room_id.clone(),
        dtg_credentials::IssuerScope::Public,
        req.subject.clone(),
        req.room_id.clone(),
        actions,
        chrono::Utc::now(),
        req.valid_until,
    ) {
        Ok(v) => v,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                vti_common::error::AppError::Validation(format!("build the grant: {e}")),
            );
        }
    };
    issue(
        state,
        auth,
        &doc,
        &req.room_id,
        &req.signing_key_id,
        "rooms.owner.issue-authority",
        vac,
    )
    .await
}

/// `rooms/owner/anchor/0.1`.
///
/// Write the room's current state into the room's own witnessed log, so that a
/// host serving a stale, forked or partial view of it becomes **evident rather
/// than merely possible**.
///
/// Everything else in this family produces values a host asserts. This is the
/// one statement a host does not make, cannot forge, and cannot show two members
/// two versions of — because witnesses co-sign the log entry it rides.
#[cfg(feature = "webvh")]
pub(super) async fn handle_anchor(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    // Boxed as defense-in-depth. `dispatch_typed` now `Box::pin`s every arm at
    // the dispatch seam, so this handler's future is already heap-allocated
    // there and no longer summed into the match frame — the reason this box was
    // originally added (a large handler paid for on the stack of every task
    // through the dispatcher) is gone. It is kept because this handler is large
    // (it presents, calls a host over the network, resolves a DID and publishes
    // a webvh update) and no default-stack test drives it: the canary that
    // caught it last time, `tests/mock_vta.rs::webvh_family_response_shapes`,
    // never calls this task. Boxing here caps the momentary construction of its
    // own future when the seam dispatches it, at no cost worth measuring.
    Box::pin(anchor_inner(state, auth, doc)).await
}

#[cfg(feature = "webvh")]
async fn anchor_inner(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "anchoring a room's state in its own log",
    )
    .await
    {
        return r;
    }

    let req: trust_tasks_rs::specs::rooms::owner::anchor::v0_1::Payload = match parse_payload(&doc)
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let resolver = match super::room_group::outbound_resolver(state, &doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // The authenticator this agent already holds. Every member derives it
    // independently and no host can compute it, which is what makes an anchored
    // one able to expose a forked group.
    //
    // The owner's, as the persona whose `read` grant is presented below: one resolution for
    // both, so the authenticator anchored and the head it is anchored beside come from the
    // same member. The read goes to the host as that persona — never as this agent.
    let presenting =
        match super::room_group::presenting_member(state, auth, &req.room_id, None).await {
            Ok(v) => v,
            Err(e) => return app_error_to_reject(&doc, e),
        };
    let (epoch, epoch_authenticator) = match crate::operations::room_groups::epoch_authenticator(
        &state.room_groups_ks,
        &presenting.member,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // The two values the agent does NOT hold. `rooms/epoch/mint` answers
    // `{roomId, epoch}` — the watermark and the commitment are facts about the
    // room's RECORDS, which live at the host — so an anchor is assembled from a
    // read, and all three head values come from ONE response.
    let reply = match super::room_group::send_as_member(
        state,
        auth,
        &presenting,
        &resolver,
        &req.host,
        vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
        // One record is enough: the head travels with any page, and asking for the room
        // would move a lot of metadata to learn three numbers.
        serde_json::json!({ "roomId": req.room_id, "limit": 1 }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let head: vti_rooms::wire::ListRecordsResponse = match serde_json::from_value(reply) {
        Ok(h) => h,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                vti_common::error::AppError::Validation(format!(
                    "room host `{}` served a head this agent cannot read: {e}",
                    req.host
                )),
            );
        }
    };
    let Some(head_version) = head.head_version else {
        return app_error_to_reject(
            &doc,
            vti_common::error::AppError::Validation(format!(
                "room host `{}` served no `headVersion`, so there is no state to anchor. A \
                 host that maintains no tree has nothing for this to pin.",
                req.host
            )),
        );
    };

    match crate::operations::room_anchor::publish(
        state,
        auth,
        &req.room_id,
        &req.signing_key_id,
        crate::operations::room_anchor::Anchor {
            epoch,
            epoch_authenticator,
            head_version,
            data_commitment: head.data_commitment.clone(),
            record_count: head.record_count,
        },
    )
    .await
    {
        Ok(published) => {
            record(state, "rooms.owner.anchor", auth, &req.room_id).await;
            success_response(
                &doc,
                serde_json::json!({
                    "roomId": req.room_id,
                    "anchored": published.anchored,
                    "versionId": published.version_id,
                    // A failed reconciliation does NOT stop the anchor. An owner
                    // withholding one from a suspect room leaves it with no
                    // witnessed statement at all, which is the position a
                    // misbehaving host benefits from.
                    "reconciled": head
                        .record_count
                        .is_none_or(|committed| committed == head.records.len() as u64
                            || head.cursor.is_some()),
                }),
            )
        }
        Err(e) => app_error_to_reject(&doc, e),
    }
}

/// Which `rooms/owner/register` is answered. The request schemas are the same; they differ
/// in what becomes of the room's revocation list (`0.2`, *The room's revocation list*).
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegisterVersion {
    V0_1,
    V0_2,
}

/// `rooms/owner/register/0.1` — tell a host about a room that already exists.
///
/// A list that did not reach the host is refused `hostUnreachable` / `hostRefused` with a
/// message saying the room **is** registered and naming the remedy: 0.1 declares no other
/// outcome, and `0.2` says that is the least harmful answer it can give.
pub(super) async fn handle_register(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    register_at(state, auth, doc, RegisterVersion::V0_1).await
}

/// `rooms/owner/register/0.2` — 0.1, and a registration the host accepted is answered with
/// success whatever became of the room's revocation list, which `revocation` reports:
/// `inForce` only when the host answered with the list's head (trust-tasks-tf #821).
pub(super) async fn handle_register_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    register_at(state, auth, doc, RegisterVersion::V0_2).await
}

/// `rooms/owner/register`, at either version — tell a host about a room that already exists.
///
/// `rooms/create` performed by the agent, for the same reason as
/// [`super::room_group::handle_backfill`]: the surfaces owners create rooms from
/// hold a channel to their own agent and to no third party.
///
/// **The order is unchanged and still forced.** The room's identity is minted
/// first — that is a separate act, and this does not perform it — and a host is
/// then told about a room that already exists. A host that named the room would
/// be a host the room could not leave.
///
/// This signs as the **owner** — a DID this agent holds the key for, in a context
/// the caller acts in ([`crate::operations::room_host::owner_signing_key`]) — not as
/// the room and not as this agent. A host records as owner only the party whose
/// proof is on the request (`vti_rooms::authz::authorize_create`), so a
/// registration signed by this agent while naming someone else is refused by every
/// host. Signing as the room would claim the room is asking to be stored, which is
/// neither true nor something the host can check.
async fn register_at(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    at: RegisterVersion,
) -> TrustTaskOutcome {
    // Both versions declare the same two codes under the same strings (the slug carries no
    // version), so 0.2's generated constants serve both.
    use trust_tasks_rs::specs::rooms::owner::register::v0_2::error_codes as codes;
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "registering a room with a host",
    )
    .await
    {
        return r;
    }

    // The request schemas are identical; the envelope was validated against its own.
    let req: trust_tasks_rs::specs::rooms::owner::register::v0_2::Payload =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    let vta_did = state.config.read().await.vta_did.clone();
    let Some(resolver) = state.did_resolver.clone() else {
        return app_error_to_reject(
            &doc,
            vti_common::error::AppError::Validation(
                "this agent has no DID resolver configured, so it cannot find the host".into(),
            ),
        );
    };

    // Absent `ownerDid` means the caller, per the specification. Defaulted here
    // rather than at the host, because the host has no view of who asked this
    // agent — it sees the agent.
    let owner_did = req.owner_did.clone().unwrap_or_else(|| auth.did.clone());

    let mut payload = serde_json::json!({
        "roomId": req.room_id,
        "visibility": req.visibility,
        "ownerDid": owner_did,
    });
    if let Some(policy) = &req.retention_policy {
        payload["retentionPolicy"] = serde_json::to_value(policy).unwrap_or(Value::Null);
    }
    if let Some(days) = req.retention_days {
        payload["retentionDays"] = serde_json::json!(u64::from(days));
    }

    // Signed as the owner, not as this agent: `rooms/create` is issued by its Owner, and a
    // host records as owner only the party whose proof is on the request. This is what
    // `rooms/owner/register` means by the key holder speaking "as its principal".
    // Authorization item 2: `permissionDenied`, before the host is contacted.
    let owner_key = match crate::operations::room_host::owner_signing_key(
        crate::operations::room_host::OwnerKeyStores {
            keys_ks: &state.keys_ks,
            #[cfg(feature = "webvh")]
            webvh_ks: &state.webvh_ks,
        },
        auth,
        &owner_did,
        vta_did.as_deref(),
    )
    .await
    {
        Ok(k) => k,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    // The owner's root memory gates the write: what this agent learned reading the room as
    // that persona, and nobody else's.
    let member = match crate::operations::room_groups::Member::new(&req.room_id, &owner_did) {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let reply = match crate::operations::room_host::send_room_task_typed(
        signing_context(state, auth),
        &state.room_groups_ks,
        &member,
        &crate::operations::outbound::Outbound::from_app_state(state, &resolver),
        &req.host,
        &owner_key.key_id,
        &owner_did,
        &owner_key.verification_method,
        vti_rooms::wire::ROOMS_CREATE_TYPE,
        &format!("{}#response", vti_rooms::wire::ROOMS_CREATE_TYPE),
        payload,
    )
    .await
    {
        Ok(v) => v,
        // These two report the registration alone (0.2): the host's own reason, carried in
        // `details`.
        Err(RoomTaskError::Refused { code, reason, .. }) => {
            return super::helpers::reject_with_code(
                &doc,
                super::room_group::declared(codes::HOST_REFUSED),
                format!(
                    "host `{}` declined to register room `{}`: {code}: {reason}",
                    req.host, req.room_id
                ),
                Some(serde_json::json!({ "code": code, "reason": reason })),
            );
        }
        Err(RoomTaskError::Unknown(e)) => {
            return super::helpers::reject_with_code(
                &doc,
                super::room_group::declared(codes::HOST_UNREACHABLE),
                format!(
                    "host `{}` did not answer the registration of room `{}`: {e}",
                    req.host, req.room_id
                ),
                None,
            );
        }
    };

    // What `rooms/owner/revoke` item 2 means by knowing the tier "from registering the
    // room": a later withdrawal naming a party is checked against it without asking a host.
    if let Some(tier) = serde_json::to_value(req.visibility)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        && let Err(e) = crate::operations::room_revocation::record_tier(
            &state.room_groups_ks,
            &req.room_id,
            &tier,
        )
        .await
    {
        tracing::warn!(room = %req.room_id, error = %e, "could not record the room's tier");
    }

    // The host's own answer for the epoch, not an assumption that a new room
    // starts at 1: a host that already held this room reports where it actually
    // stands, and a caller recording 1 over a live room would be recording a
    // fiction.
    let epoch = reply.get("epoch").and_then(Value::as_u64).unwrap_or(1);
    let mut body = serde_json::json!({
        "roomId": req.room_id,
        // Echoed from what was reached, per the specification.
        "host": req.host,
        "epoch": epoch,
    });

    // `rooms/owner/revoke`: a key holder that registers a room with a host delivers the list
    // it holds for the room to that host **after** the host accepted the registration and
    // **before answering** — a room moving hosts would otherwise arrive without its
    // withdrawals, and its new host honour what the old one refused (trust-tasks-tf #804).
    match at {
        RegisterVersion::V0_1 => {
            if let Err(r) =
                deliver_held_list(state, auth, &doc, &resolver, &req.room_id, &req.host).await
            {
                return r;
            }
        }
        RegisterVersion::V0_2 => {
            let delivered = deliver_after_registration(
                state,
                auth,
                &resolver,
                &req.room_id,
                &req.host,
                &owner_did,
            )
            .await;
            match delivered {
                Ok(Some(revocation)) => body["revocation"] = revocation,
                Ok(None) => {}
                // Item 2: the registration took effect, so this answers a `#response`
                // whatever became of the delivery. Reading the list this agent holds is the
                // one thing that can fail before a delivery is known to be owed at all.
                Err(e) => {
                    tracing::error!(room = %req.room_id, host = %req.host, error = %e,
                        "could not read the room's revocation list after registering it");
                    return app_error_to_reject(&doc, e);
                }
            }
        }
    }

    success_response(&doc, body)
}

/// `rooms/owner/register/0.2`, *The room's revocation list*: deliver the list this agent
/// holds for `room_id` to `host`, which has just accepted the registration, and say what
/// became of it — `None` when no list is held (item 3: `revocation` is then omitted).
///
/// Before the delivery is attempted it is retained as outstanding (the room, the host, the
/// sequence and the persona that delivers it), so a delivery left `pending` — or cut off by
/// the process dying — is carried on by the redelivery sweeper
/// ([`super::room_list_delivery`]), the single retry owner (item 4). `inForce` and `refused`
/// leave nothing behind; a refused list is never delivered again on its own (item 5).
async fn deliver_after_registration(
    state: &AppState,
    auth: &AuthClaims,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    room_id: &str,
    host: &str,
    owner_did: &str,
) -> Result<Option<Value>, vti_common::error::AppError> {
    use super::room_owner_group::{Delivery, HostCall};
    use crate::operations::room_revocation as revocation;
    let Some(list) = revocation::held(&state.room_groups_ks, room_id).await? else {
        return Ok(None);
    };
    let head = list.head().to_wire();
    let pending = || serde_json::json!({ "head": head, "status": "pending" });

    // The persona whose `admin` grant the delivery presents; the owner the room was
    // registered as when this agent holds no such grant for one the caller acts as — the
    // sweeper keeps trying as that persona, whose grant may yet be stored.
    let host_call = HostCall::for_persona(state, auth, resolver, room_id, None).await;
    let persona = match &host_call {
        Ok(h) => h.persona().to_string(),
        Err(_) => owner_did.to_string(),
    };
    if let Err(e) = revocation::retain_delivery(
        &state.room_groups_ks,
        &revocation::OutstandingDelivery {
            room_id: room_id.to_string(),
            host: host.to_string(),
            sequence: list.sequence(),
            persona,
        },
    )
    .await
    {
        tracing::error!(room = %room_id, %host, error = %e,
            "could not retain the room's revocation list as outstanding; if it is not \
             delivered now, deliver it with rooms/owner/revoke");
    }

    let host_call = match host_call {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(room = %room_id, %host, error = %e,
                "the room is registered, but this agent holds no `admin` grant to deliver its \
                 revocation list with; it is pending");
            return Ok(Some(pending()));
        }
    };
    let presentation = match host_call.presentation_as_admin().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(room = %room_id, %host, error = %e,
                "the room is registered, but its revocation list could not be presented for; \
                 it is pending");
            return Ok(Some(pending()));
        }
    };
    Ok(Some(
        match host_call.deliver_list(host, &list, &presentation).await {
            // `deliver_list` reports `Accepted` only when the host answered with this list's
            // head, and settles the outstanding delivery itself.
            Delivery::Accepted { .. } => serde_json::json!({ "head": head, "status": "inForce" }),
            Delivery::Refused { code, reason } => {
                tracing::warn!(room = %room_id, %host, %code, %reason,
                    "the room is registered, and its host refused the room's revocation list");
                revocation::drop_delivery(&state.room_groups_ks, room_id, host).await?;
                serde_json::json!({ "head": head, "status": "refused", "code": code })
            }
            Delivery::Unreachable(why) => {
                tracing::warn!(room = %room_id, %host, reason = %why,
                    "the room is registered, and its revocation list is pending at the host");
                pending()
            }
        },
    ))
}

/// Deliver the revocation list this agent holds for `room_id`, if any, to `host`, for
/// `rooms/owner/register/0.1`. The room is registered whatever this answers; a failure says so
/// and names the remedy, which is re-delivering with `rooms/owner/revoke` and no `withdraw`.
async fn deliver_held_list(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    room_id: &str,
    host: &str,
) -> Result<(), TrustTaskOutcome> {
    use super::room_owner_group::{Delivery, HostCall};
    use trust_tasks_rs::specs::rooms::owner::register::v0_1::error_codes as codes;
    let Some(list) = crate::operations::room_revocation::held(&state.room_groups_ks, room_id)
        .await
        .map_err(|e| app_error_to_reject(doc, e))?
    else {
        return Ok(());
    };
    let remedy = format!(
        "Room `{room_id}` is registered at `{host}`, but the room's revocation list (sequence \
         {}) is not in force there yet: deliver it with rooms/owner/revoke naming that host and \
         no `withdraw`",
        list.sequence()
    );
    let host_call =
        HostCall::as_owner(state, auth, resolver, room_id, doc, codes::HOST_REFUSED).await?;
    let presentation = host_call
        .admin_presentation(doc, codes::HOST_REFUSED)
        .await?;
    match host_call.deliver_list(host, &list, &presentation).await {
        Delivery::Accepted { .. } => Ok(()),
        Delivery::Refused { code, reason } => Err(super::helpers::reject_with_code(
            doc,
            super::room_group::declared(codes::HOST_REFUSED),
            format!(
                "host `{host}` declined the room's revocation list: {code}: {reason}. {remedy}"
            ),
            Some(serde_json::json!({ "code": code })),
        )),
        Delivery::Unreachable(why) => Err(super::helpers::reject_with_code(
            doc,
            super::room_group::declared(codes::HOST_UNREACHABLE),
            format!("host `{host}` did not answer the room's revocation list: {why}. {remedy}"),
            None,
        )),
    }
}
