//! `/v1/vetting/*` — the community-admin side of peer identity vetting.
//!
//! - `POST /v1/vetting/vetters` — name a member a vetter
//!   (`vtc/vetting/vetters/grant/0.1`). Auth: community Admin. The same task is
//!   dispatched as a Trust Task document for an admin on DIDComm or TSP; both
//!   go through [`crate::vetting::vetters::grant`]. A grant is withdrawn with
//!   `DELETE /v1/credentials/endorsements/{endorsementId}`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use vta_sdk::protocols::vetting::{VetterGrantBody, VetterGrantResponseBody};
use vti_common::auth::AuthClaims;
use vti_common::error::AppError;

use crate::server::AppState;

#[utoipa::path(
    post, path = "/vetting/vetters",
    operation_id = "vettingVetterGrant", tag = "vetting",
    security(("bearer_jwt" = [])),
    request_body = VetterGrantBody,
    responses(
        (status = 201, description = "Vetter role granted", body = VetterGrantResponseBody),
        (status = 200, description = "The member already holds a live vetter grant, which is returned", body = VetterGrantResponseBody),
        (status = 400, description = "Malformed body, or the member is not a current member"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not a community admin"),
    ),
)]
pub async fn grant_vetter(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(body): Json<VetterGrantBody>,
) -> Result<(StatusCode, Json<VetterGrantResponseBody>), AppError> {
    let grant = crate::vetting::vetters::grant(&state, &auth.did, &body).await?;
    let status = if grant.created() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(grant.response)))
}
