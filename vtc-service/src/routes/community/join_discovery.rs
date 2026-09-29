//! Whether the join manifest answers a caller this community cannot identify:
//! `vtc/community/join-discovery/{show,update}/0.1`, served on the spine
//! (`trust_tasks::surface_tasks`). There is no REST route.
//!
//! It is deliberately *not* a member of the community
//! profile: `vtc/community/profile/show/0.1` is a published schema with
//! `additionalProperties: false`, and this is an operational choice about how
//! one endpoint behaves rather than part of the community's published
//! description. See [`crate::community::join_discovery`].

use axum::http::StatusCode;
use tracing::info;
use vti_common::audit::{AuditEvent, CommunityJoinDiscoveryUpdatedData};
use vti_common::error::AppError;

use crate::community::join_discovery::{JoinDiscovery, load_join_discovery, store_join_discovery};
use crate::server::AppState;

/// Whether the join manifest answers an unidentified caller.
pub(crate) async fn show_join_discovery(state: &AppState) -> Result<JoinDiscovery, AppError> {
    load_join_discovery(&state.community_ks).await
}

/// Replace the setting.
pub(crate) async fn update_join_discovery(
    state: &AppState,
    actor: &str,
    body: &JoinDiscovery,
) -> Result<JoinDiscovery, AppError> {
    // Fail closed, as the profile and branding routes do: a change that cannot
    // be audited is not made. Who closed a community's requirements, and when,
    // is exactly the kind of change an operator later needs to account for.
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;
    let before = load_join_discovery(&state.community_ks).await?;
    let stored = store_join_discovery(&state.community_ks, body).await?;
    if before != stored {
        writer
            .write(
                actor,
                None,
                AuditEvent::CommunityJoinDiscoveryUpdated(CommunityJoinDiscoveryUpdatedData {
                    public: stored.public,
                }),
            )
            .await?;
        info!(public = stored.public, "community join discovery updated");
    }
    Ok(stored)
}
