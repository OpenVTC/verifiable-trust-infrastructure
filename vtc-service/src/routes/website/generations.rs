//! `GET /v1/website/generations` + `POST /v1/website/rollback/{gen}`
//! (Phase 5 M5.5.4).
//!
//! Both endpoints are managed-mode-only. Live-mode requests
//! return 400 with `WebsiteNotManagedMode` (encoded as
//! [`AppError::Validation`] for MVP — see the route-module
//! comments).

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::Serialize;

use vti_common::audit::{AuditEvent, WebsiteGenerationRolledBackData};
use vti_common::auth::AdminAuth;

use crate::error::AppError;
use crate::server::AppState;
use crate::website::storage::{GenerationEntry, list_managed_generations, swap_current_symlink};

pub async fn list(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GenerationsResponse>, AppError> {
    let cfg = state.config.read().await;
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    if deploy_mode != "managed" {
        return Err(AppError::Validation(
            "GET /v1/website/generations is only available in managed deploy mode".into(),
        ));
    }

    let generations = list_managed_generations(&root_dir)?
        .into_iter()
        .map(GenerationRow::from)
        .collect();
    Ok(Json(GenerationsResponse { generations }))
}

/// `{ generations: [...] }` — the shape `vtc/website/generations/list/0.1`
/// publishes. The handler returned a top-level array until #1059's witness
/// compared it with its schema; the rows always conformed.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GenerationsResponse {
    pub generations: Vec<GenerationRow>,
}

/// One row of the listing, as the item schema names it.
///
/// A wire type distinct from the stored [`GenerationEntry`] because the two
/// disagree on purpose: a generation is a `u32` in storage, where arithmetic
/// and ordering want a number, and a string on the wire, where the schema
/// types it as one. `rollback` has always drawn that line the same way
/// (`gen_num.to_string()`); this listing sent the raw `u32` and named
/// `current` as `isCurrent` until #1095.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GenerationRow {
    /// Decimal, matching `rollback` — not `gen-N`, which is the directory
    /// name rather than the label the API has ever used.
    pub generation: String,
    pub current: bool,
    /// Both went upstream in trustoverip/dtgwg-trust-tasks-tf#262 — a
    /// rollback target is not much use without knowing when it was deployed
    /// or how big it is.
    pub deployed_at: DateTime<Utc>,
    pub size_bytes: u64,
}

impl From<GenerationEntry> for GenerationRow {
    fn from(e: GenerationEntry) -> Self {
        Self {
            generation: e.generation.to_string(),
            current: e.is_current,
            // RFC 3339, as the item schema types it — the stored row keeps
            // unix seconds. `website/files/list` drew the same line in #1095.
            deployed_at: DateTime::from_timestamp(e.deployed_at as i64, 0)
                .unwrap_or(DateTime::UNIX_EPOCH),
            size_bytes: e.size_bytes,
        }
    }
}

pub async fn rollback(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Path(gen_num): Path<u32>,
) -> Result<Json<RollbackResponse>, AppError> {
    let cfg = state.config.read().await;
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    if deploy_mode != "managed" {
        return Err(AppError::Validation(
            "POST /v1/website/rollback/{gen} is only available in managed deploy mode".into(),
        ));
    }

    let from = swap_current_symlink(&root_dir, gen_num)?;
    if from != gen_num
        && let Some(writer) = state.audit_writer.as_ref()
    {
        let _ = writer
            .write(
                "admin",
                None,
                AuditEvent::WebsiteGenerationRolledBack(WebsiteGenerationRolledBackData {
                    from_generation: from,
                    to_generation: gen_num,
                }),
            )
            .await;
    }
    // `noop` is the same condition the audit guard above tests: rolling back
    // to the generation already current changes nothing. The handler computed
    // it and discarded it, while the spec has always asked for it.
    Ok(Json(RollbackResponse {
        generation: gen_num.to_string(),
        current: true,
        noop: from == gen_num,
    }))
}

/// `{ generation, current, noop }` — the shape `vtc/website/rollback/0.1`
/// publishes. The handler returned 200 with zero bytes until #1059.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RollbackResponse {
    /// A string, as the spec types it — the same way the path segment is
    /// typed there, while this handler takes it as a `u32`. Rendering it back
    /// as a string keeps the response conforming; reconciling the two typings
    /// is a separate question for the spec.
    pub generation: String,
    /// Whether this generation is current after the swap. The spec types it
    /// as a boolean, not as a generation number — it answers "did the
    /// rollback take", not "which one is live". Always true on success; the
    /// symlink swap propagates as an error otherwise.
    pub current: bool,
    /// True when the target was already current, so nothing moved.
    pub noop: bool,
}
