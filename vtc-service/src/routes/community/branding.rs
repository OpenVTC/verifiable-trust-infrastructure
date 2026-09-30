//! How the community presents itself to an applicant's client, published as
//! `branding` on `join-requests/manifest/0.2`.
//!
//! Signed documents only (`vtc/community/branding/{show,update}/0.1`,
//! `trust_tasks::surface_tasks`) — the admin-only bearer REST mounts this
//! module used to carry had no caller left once `vtc-client` and the admin
//! console signed the documents instead.

use axum::http::StatusCode;
use tracing::info;
use vta_sdk::protocols::vetting::read_branding;
use vti_common::audit::{AuditEvent, CommunityBrandingUpdatedData};
use vti_common::error::AppError;

use crate::community::branding::{fields_changed, load_branding, store_branding};
use crate::server::AppState;

/// Replace the branding as `actor` — `vtc/community/branding/update/0.1`, on
/// the route and the spine alike. The caller has established that `actor` is
/// an administrator.
pub(crate) async fn update_branding(
    state: &AppState,
    actor: &str,
    body: &serde_json::Value,
) -> Result<vta_sdk::protocols::join_requests::manifest::v0_2::CommunityBranding, AppError> {
    let body = read_branding(body).map_err(|e| AppError::Validation(e.to_string()))?;
    // Fail closed, as the profile route does: a change that cannot be audited
    // is not made.
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;
    let before = load_branding(&state.community_ks).await?;
    let stored = store_branding(&state.community_ks, &body).await?;
    let changed = fields_changed(&before, &stored);
    if !changed.is_empty() {
        writer
            .write(
                actor,
                None,
                AuditEvent::CommunityBrandingUpdated(CommunityBrandingUpdatedData {
                    fields_changed: changed.clone(),
                }),
            )
            .await?;
        info!(fields_changed = ?changed, "community branding updated");
    }
    Ok(stored)
}
