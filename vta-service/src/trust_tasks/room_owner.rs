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

    let req: trust_tasks_rs::specs::rooms::owner::issue_authority::v0_1::Payload =
        match parse_payload(&doc) {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    let actions: Vec<String> = req.actions.iter().map(|a| a.to_string()).collect();

    // A chain ROOT, issued by the party governing the scope. `new_vac` refuses an empty
    // action list rather than reading it as "everything", and the schema refuses it before
    // that — two layers, because "confers nothing" and "confers everything" are exactly the
    // two readings a careless consumer might choose between.
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
