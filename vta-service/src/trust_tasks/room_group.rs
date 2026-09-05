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
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_common::acl::{Capability, role_has_capability};

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::{room_groups, room_invitation};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, parse_payload, reject_with,
    success_response,
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

/// `rooms/keys/open/0.1`.
pub(super) async fn handle_open(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if !role_has_capability(&auth.role, Capability::RoomOpen) {
        return reject_with(
            &doc,
            RejectReason::PermissionDenied {
                reason: format!(
                    "opening a room record denied: role {} does not carry RoomOpen",
                    auth.role
                ),
            },
        );
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
async fn record(state: &AppState, action: &str, auth: &AuthClaims, room_id: &str) {
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
