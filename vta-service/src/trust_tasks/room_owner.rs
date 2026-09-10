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

    let vic = dtg_credentials::DTGCredential::new_vic(
        req.room_id.clone(),
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
    let vac = match dtg_credentials::DTGCredential::new_vac(
        req.room_id.clone(),
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
    // Boxed, for the reason `dispatch_trust_task` already documents at its own
    // split: the dispatch table's state machine **inlines every handler's
    // future**, so a large handler is paid for on the stack of every task that
    // goes through the dispatcher — not just its own. This one is large (it
    // presents, calls a host over the network, resolves a DID and publishes a
    // webvh update), and adding it to the table overflowed the test thread in
    // `tests/mock_vta.rs::webvh_family_response_shapes` — the same canary that
    // caught it the last time, in a test that never calls this task.
    //
    // Boxing puts this machine on the heap and leaves a pointer in the table.
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

    let (vta_did, resolver) = match super::room_group::outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // The authenticator this agent already holds. Every member derives it
    // independently and no host can compute it, which is what makes an anchored
    // one able to expose a forked group.
    let (epoch, epoch_authenticator) = match crate::operations::room_groups::epoch_authenticator(
        &state.room_groups_ks,
        &req.room_id,
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
        vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE,
        &format!("{}#response", vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE),
        serde_json::json!({
            "roomId": req.room_id,
            "presentation": minted.presentation,
            // One record is enough: the head travels with any page, and asking
            // for the room would move a lot of metadata to learn three numbers.
            "limit": 1,
        }),
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

/// `rooms/owner/register/0.1` — tell a host about a room that already exists.
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
/// This signs as the **agent**, not as the room. A registration is a request to
/// store something, authorised by the host's own creation policy against the
/// party asking; signing as the room would claim the room is asking to be stored,
/// which is neither true nor something the host can check.
pub(super) async fn handle_register(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
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

    let req: trust_tasks_rs::specs::rooms::owner::register::v0_1::Payload =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    let vta_did = match state.config.read().await.vta_did.clone() {
        Some(d) => d,
        None => {
            return app_error_to_reject(
                &doc,
                vti_common::error::AppError::Validation(
                    "this agent has no DID of its own, so it cannot speak to a host as itself"
                        .into(),
                ),
            );
        }
    };
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
        vti_rooms::wire::ROOMS_CREATE_TYPE,
        &format!("{}#response", vti_rooms::wire::ROOMS_CREATE_TYPE),
        payload,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // The host's own answer for the epoch, not an assumption that a new room
    // starts at 1: a host that already held this room reports where it actually
    // stands, and a caller recording 1 over a live room would be recording a
    // fiction.
    let epoch = reply.get("epoch").and_then(Value::as_u64).unwrap_or(1);

    success_response(
        &doc,
        serde_json::json!({
            "roomId": req.room_id,
            // Echoed from what was reached, per the specification.
            "host": req.host,
            "epoch": epoch,
        }),
    )
}
