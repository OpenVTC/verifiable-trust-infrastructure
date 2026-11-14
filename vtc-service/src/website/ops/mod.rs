//! Website management REST routes (Phase 5 M5.5).
//!
//! All endpoints under `/v1/website/*` are admin-gated and live in
//! the API sub-router. They mutate the filesystem rooted at
//! `website.root_dir` — the same directory the public-website
//! read handler ([`crate::website::serve`]) serves from. The
//! relationship is intentional: operators manage the served
//! content via these endpoints; the read handler observes the
//! result.
//!
//! Body-cap overrides for `PUT /files/{path}` (per-file) and
//! `POST /deploy` (per-bundle) attach in [`crate::routes::mod`]
//! at route-attach time so the global 1 MiB cap doesn't apply.

#[cfg(feature = "website")]
pub mod deploy;
#[cfg(feature = "website")]
pub mod files;
#[cfg(feature = "website")]
pub mod generations;

use axum::http::StatusCode;
use serde::Serialize;

use crate::error::AppError;
use crate::server::AppState;

/// Common 503 shape for website endpoints when the operator
/// hasn't configured a `website.root_dir`.
fn require_website_config<'a>(
    state: &'a AppState,
) -> Result<tokio::sync::RwLockReadGuard<'a, crate::config::AppConfig>, AppError> {
    let cfg = state.config.try_read().map_err(|_| {
        AppError::Internal("could not acquire config read lock for website route".into())
    })?;
    if cfg.website.root_dir.is_none() {
        return Err(AppError::Validation(
            "website.root_dir is not configured; set it in the daemon config to enable website management".into(),
        ));
    }
    Ok(cfg)
}

/// Common 200 envelope for write-style endpoints.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteWriteResponse {
    pub path: String,
    pub etag: String,
    pub size_bytes: u64,
}

#[allow(dead_code)]
fn _suppress_unused_status(_s: StatusCode) {}
