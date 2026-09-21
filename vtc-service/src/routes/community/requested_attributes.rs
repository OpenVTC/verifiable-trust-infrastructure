//! `GET`/`PUT /v1/community/requested-attributes` — what the community asks an
//! applicant to tell it about themselves, published as `requestedAttributes` on
//! `join-requests/manifest/0.2`.
//!
//! Admin REST with no Trust Task of its own, like the branding beside it. The
//! body is a JSON array of the manifest's own requested-attribute items
//! (`{type, required?, purpose?}`), replaced whole; an empty array asks for
//! nothing. See [`crate::community::requested_attributes`] for why an answer is
//! never treated as attested.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::Value;
use tracing::info;
use vta_sdk::openapi::JoinManifest02RequestedAttribute;
use vta_sdk::protocols::join_requests::manifest::v0_2::ResponseRequestedAttributesItem as RequestedAttribute;
use vti_common::audit::{AuditEvent, CommunityRequestedAttributesUpdatedData};
use vti_common::auth::{AdminAuth, AuthClaims};
use vti_common::error::AppError;

use crate::community::requested_attributes::{diff, load_requested, store_requested};
use crate::server::AppState;

/// What the community asks applicants to tell it; an empty array when nothing.
#[utoipa::path(
    get, path = "/community/requested-attributes",
    operation_id = "communityRequestedAttributesShow", tag = "community",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "The manifest's `requestedAttributes`", body = Vec<JoinManifest02RequestedAttribute>),
        (status = 401, description = "Missing or invalid bearer token"),
    ),
)]
pub async fn get_requested_attributes(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<Vec<JoinManifest02RequestedAttribute>>, AppError> {
    Ok(Json(
        load_requested(&state.community_ks)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

/// Replace what the community asks applicants to tell it. An empty array asks
/// for nothing.
#[utoipa::path(
    put, path = "/community/requested-attributes",
    operation_id = "communityRequestedAttributesUpdate", tag = "community",
    security(("bearer_jwt" = [])),
    request_body(content = Vec<JoinManifest02RequestedAttribute>, description = "Replaces the whole list. `type` is a persona claim-type token such as `name.display`."),
    responses(
        (status = 200, description = "What is now requested", body = Vec<JoinManifest02RequestedAttribute>),
        (status = 400, description = "An entry breaks its bounds, a type is requested twice, or more than 32 are given"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
        (status = 503, description = "Audit writer not configured — change refused"),
    ),
)]
pub async fn put_requested_attributes(
    admin: AdminAuth,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Vec<JoinManifest02RequestedAttribute>>, AppError> {
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
                &admin.0.did,
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
    Ok(Json(requested.into_iter().map(Into::into).collect()))
}
