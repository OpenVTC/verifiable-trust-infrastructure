//! `GET /v1/recognition/check` — the operator's window into the trust
//! (recognition) graph.
//!
//! TRQP recognition is a **per-DID query** against the upstream trust registry,
//! not a listable set — the recognition graph lives in the registry, and a VTC
//! asks "do I recognise issuer X?" one DID at a time (`recognise`). This admin
//! lookup exposes exactly that: enter an issuer / community DID, get back
//! whether this community recognises it (the same verdict that decides whether a
//! third-party invitation issuer is trusted, M2). The configured-registry status
//! comes from `GET /v1/health/diagnostics`.

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use tracing::warn;

use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::server::AppState;

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct CheckQuery {
    /// The issuer / community DID to test for recognition.
    pub did: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecognitionCheck {
    /// Echo of the queried DID.
    pub did: String,
    /// Whether this community recognises the DID (TRQP `recognise`). `false`
    /// when no registry is configured or the query came back not-found.
    pub recognised: bool,
    /// Whether a trust registry is configured at all (no-registry mode → every
    /// foreign DID is unrecognised).
    pub registry_configured: bool,
    /// Set when the registry query failed (unreachable / parse) rather than
    /// returning a clean recognised/not-recognised verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[utoipa::path(
    get, path = "/recognition/check", tag = "recognition",
    params(CheckQuery),
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Recognition verdict", body = RecognitionCheck),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn check(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Query(q): Query<CheckQuery>,
) -> Result<Json<RecognitionCheck>, AppError> {
    let registry_configured = state.registry_client.is_some();
    let (recognised, error) = match state.registry_client.as_deref() {
        Some(registry) => match registry.recognise(&q.did).await {
            Ok(verdict) => (verdict, None),
            Err(e) => {
                warn!(did = %q.did, error = %e, "recognition check failed");
                (false, Some(e.to_string()))
            }
        },
        None => (false, None),
    };
    Ok(Json(RecognitionCheck {
        did: q.did,
        recognised,
        registry_configured,
        error,
    }))
}
