//! Operator read surface for the rooms this community hosts.
//!
//! # What an operator may see, and why it is not a contradiction
//!
//! A host cannot read a room's records and holds no member list — both by construction, and
//! the rest of the rooms design exists to keep it that way. What it *does* hold about each
//! room it stores is exactly what operating one requires: who is accountable for it, which
//! tier it was created at, which epoch it is on, and where it sits on the lifecycle clock.
//!
//! Invariant I1 makes the owner visible at **every** tier, including `private`, for this
//! reason: a room whose contents nobody here can read still has a party this operator must
//! be able to reach about quota, abuse, and the reclamation notice §9 obliges them to send.
//! An operator who cannot list their rooms cannot send it.
//!
//! So this returns the row and nothing derived from the room's contents. There is no
//! endpoint here that returns records, and there is no member list to return.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use vti_common::error::AppError;

use crate::auth::AdminAuth;
use crate::server::AppState;

/// One room, as its host can honestly describe it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostedRoom {
    pub room_id: String,
    /// The accountable party — visible at every tier, which is what makes the
    /// lifecycle notice deliverable.
    pub owner_did: String,
    pub visibility: String,
    /// Whether the room keeps its history readable across a membership change.
    pub retention_policy: String,
    pub epoch: u32,
    /// Where the room sits on the lifecycle clock: `live`, `lapsed`, `dormant`
    /// or `reclaimable`. Computed, never stored — minting an epoch *is* the
    /// renewal, so a stored state would be a second thing to keep true.
    pub lifecycle: String,
    /// When the current epoch expires. Absent means the room never lapses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_expires_at: Option<u64>,
    pub retention_days: u32,
    /// Present when this host serves a read-only copy rather than the room
    /// itself, naming the primary it pulls from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror_of: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// `GET /v1/rooms` — every room this community hosts.
#[utoipa::path(
    get,
    path = "/rooms",
    tag = "rooms",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Rooms hosted here", body = [HostedRoom]),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn list_rooms(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<HostedRoom>>, AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let rooms = vti_rooms::storage::list_rooms(&state.rooms_ks).await?;
    Ok(Json(
        rooms
            .into_iter()
            .map(|r| HostedRoom {
                lifecycle: r.lifecycle(now).as_str().to_string(),
                room_id: r.room_id,
                owner_did: r.owner_did,
                visibility: match r.visibility {
                    vti_rooms::Visibility::Open => "open",
                    vti_rooms::Visibility::Attributed => "attributed",
                    vti_rooms::Visibility::Private => "private",
                }
                .to_string(),
                retention_policy: match r.retention_policy {
                    vti_rooms::RetentionPolicy::Chained => "chained",
                    vti_rooms::RetentionPolicy::FromJoin => "fromJoin",
                }
                .to_string(),
                epoch: r.epoch,
                epoch_expires_at: r.epoch_expires_at,
                retention_days: r.retention_days,
                mirror_of: r.mirror_of,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect(),
    ))
}
