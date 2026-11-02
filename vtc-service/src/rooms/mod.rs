//! Data rooms — this service's Trust-Task surface over [`vti_rooms`].
//!
//! Storage, wire types and authorization live in the `vti-rooms` crate, because none of
//! them needs anything from a community service: a room is authorized by credentials the
//! room itself issued, so the code deciding a room operation cannot need a roster, a policy
//! engine, or a session store. What stays here is [`handlers`] — the dispatch surface, which
//! is this service's spine and therefore not extractable.
//!
//! The re-exports keep `crate::rooms::Room` and friends resolving, so nothing outside this
//! module had to move when the subsystem did.

pub mod community;
pub mod community_lifecycle;
pub mod community_profile;
pub mod community_renewal;
pub mod departures;
pub mod files;
pub mod handlers;
pub mod migration;
pub mod policy;
pub mod storage_auth;
pub mod storage_configs;
pub mod storage_credentials;
pub mod vta_access;
pub mod vta_storage;

pub use vti_rooms::{
    ROOM_RECORDS_KEYSPACE, ROOMS_KEYSPACE, Record, RecordStatus, Room, Visibility, authz, storage,
    wire,
};

/// Move room rows still in the earlier key layout, whose keys could name two rooms at once
/// (#2382), to the current one ([`storage::migrate_room_keys`]). Run at boot, before a room
/// is served, and after a backup import, which may restore rows written in that layout. A
/// row that cannot be attributed to exactly one room is left where it is and logged;
/// nothing reads it. `how` names the caller in the log.
pub async fn migrate_room_keys(
    state: &crate::server::AppState,
    how: &str,
) -> Result<storage::MigratedKeys, vti_common::error::AppError> {
    let out =
        storage::migrate_room_keys(&state.room_records_ks, &state.room_epoch_links_ks).await?;
    if out.records + out.epoch_links + out.commits > 0 {
        tracing::info!(
            how,
            records = out.records,
            epoch_links = out.epoch_links,
            commits = out.commits,
            "room rows moved to the current key layout"
        );
    }
    for row in &out.left {
        tracing::warn!(
            how,
            row,
            "a room row in the earlier key layout was left in place"
        );
    }
    Ok(out)
}
