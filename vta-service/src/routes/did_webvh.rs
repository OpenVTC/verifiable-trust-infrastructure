use axum::extract::{Path, State};

use crate::error::AppError;
use crate::server::AppState;

// Server registration/list/domains/reconcile and DID create/list/get/log/
// delete/register-with-server were REST routes here. They are the
// `vta/webvh/{servers,dids}/*` Trust Tasks now (`crate::trust_tasks::webvh`),
// served on `/trust-tasks` like every other authenticated operation; the
// twelve REST handlers that stood here are gone.

/// `GET /did/{did}/log` — public, unauthenticated.
///
/// Returns the raw `did.jsonl` bytes for a DID the VTA knows. 404 if
/// unknown. Matches webvh's native design: DID logs are world-readable
/// (security is cryptographic via signatures + SCID anchoring, not
/// access-gated). Rate-limited per client IP by the router's `did-log`
/// limiter; cacheable like the self-hosted log routes (`ETag` + short
/// `max-age`, `If-None-Match` → 304).
///
/// This is a snapshot of the log at provisioning time — once the
/// integration boots and publishes on its own webvh host, that copy
/// becomes the live source of truth. Use this endpoint for audit,
/// debugging, or republication fallback; not as a general DID
/// resolver. See `docs/02-vta/provision-integration.md` §"did.jsonl
/// retrieval" for the full semantics.
#[utoipa::path(
    get, path = "/did/{did}/log", tag = "did-webvh",
    params(("did" = String, Path, description = "DID identifier")),
    responses(
        (status = 200, description = "did.jsonl log", content_type = "text/jsonl"),
        (status = 304, description = "Not modified: If-None-Match names the current ETag"),
        (status = 429, description = "Rate limited by the VTA (`x-rate-limit-source: vta`)"),
        (status = 404, description = "DID not found"),
    ),
)]
pub async fn get_did_log_public_handler(
    State(state): State<AppState>,
    Path(did): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, AppError> {
    let log = crate::webvh_store::get_did_log(&state.webvh_ks, &did).await?;
    let log = log.ok_or_else(|| AppError::NotFound(format!("webvh DID log not found: {did}")))?;
    Ok(super::self_hosted_did::did_log_response(&headers, log))
}
