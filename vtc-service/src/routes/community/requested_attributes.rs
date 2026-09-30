//! What the community asks an applicant to tell it about themselves,
//! published as `requestedAttributes` on `join-requests/manifest/0.2`.
//!
//! Signed documents only
//! (`vtc/community/requested-attributes/{show,update}/0.1`,
//! `trust_tasks::surface_tasks`) — the admin-only bearer REST mounts this
//! module used to carry had no caller left once `vtc-client` signed the
//! documents instead. See [`crate::community::requested_attributes`] for why
//! an answer is never treated as attested.

use axum::http::StatusCode;
use serde_json::Value;
use tracing::info;
use vta_sdk::protocols::join_requests::manifest::v0_2::ResponseRequestedAttributesItem as RequestedAttribute;
use vti_common::audit::{AuditEvent, CommunityRequestedAttributesUpdatedData};
use vti_common::error::AppError;

use crate::community::requested_attributes::{diff, load_requested, store_requested};
use crate::server::AppState;

/// Replace the requested attributes as `actor` —
/// `vtc/community/requested-attributes/update/0.1`, on the route and the spine
/// alike. The caller has established that `actor` is an administrator.
pub(crate) async fn update_requested_attributes(
    state: &AppState,
    actor: &str,
    body: Value,
) -> Result<Vec<RequestedAttribute>, AppError> {
    // Parsed through the manifest's own generated item, which checks the type
    // token's grammar and the purpose's length: what is stored is what the
    // manifest can publish.
    let requested: Vec<RequestedAttribute> = serde_json::from_value(body)
        .map_err(|e| AppError::Validation(format!("requested attributes: {e}")))?;
    // Fail closed, as the branding route does: a change that cannot be audited
    // is not made.
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;
    let before = load_requested(&state.community_ks).await?;
    store_requested(&state.community_ks, &requested).await?;
    let (added, removed) = diff(&before, &requested);
    if !added.is_empty() || !removed.is_empty() {
        writer
            .write(
                actor,
                None,
                AuditEvent::CommunityRequestedAttributesUpdated(
                    CommunityRequestedAttributesUpdatedData {
                        added: added.clone(),
                        removed: removed.clone(),
                    },
                ),
            )
            .await?;
        info!(?added, ?removed, "community requested attributes updated");
    }
    Ok(requested)
}
