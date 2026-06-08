//! `GET /v1/join-requests/manifest` — pre-submit discovery
//! (`join-requests/manifest/1.0`) + a shared `manifest_inner` the
//! DIDComm handler calls into.
//!
//! Returns the community's registered Accepts criteria — each a named
//! DCQL Presentation Definition — plus this VTC's DID, so a prospective
//! applicant can assemble a presentation before opening a thread. A
//! stateless, unauthenticated public read: no thread, no challenge, no
//! audit.

use axum::Json;
use axum::extract::State;

use vta_sdk::protocols::join_requests::{JoinRequestManifestResponseBody, ManifestCriterion};
use vti_common::error::AppError;

use crate::schemas::accepts::list_accepts;
use crate::server::AppState;

pub async fn manifest(
    State(state): State<AppState>,
) -> Result<Json<JoinRequestManifestResponseBody>, AppError> {
    Ok(Json(manifest_inner(&state).await?))
}

/// Shared discovery read for REST + DIDComm: the community's join
/// evidence requirements.
pub async fn manifest_inner(state: &AppState) -> Result<JoinRequestManifestResponseBody, AppError> {
    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;

    let criteria = list_accepts(&state.schemas_ks)
        .await?
        .into_iter()
        .map(|c| ManifestCriterion {
            id: c.id,
            description: c.description,
            presentation_definition: c.query,
        })
        .collect();

    Ok(JoinRequestManifestResponseBody {
        community_did,
        criteria,
    })
}
