//! `GET /v1/website/generations` + `POST /v1/website/rollback/{gen}`
//! (Phase 5 M5.5.4).
//!
//! Both endpoints are managed-mode-only. Live-mode requests
//! return 400 with `WebsiteNotManagedMode` (encoded as
//! [`AppError::Validation`] for MVP — see the route-module
//! comments).

use axum::Json;
use axum::extract::{Path, State};
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

    let generations = list_managed_generations(&root_dir)?;
    Ok(Json(GenerationsResponse { generations }))
}

/// `{ generations: [...] }` — the shape `vtc/website/generations/list/0.1`
/// publishes. The handler returned a top-level array until #1059's witness
/// compared it with its schema; the rows always conformed.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GenerationsResponse {
    // `GenerationEntry` comes from the website module and derives no
    // `ToSchema`; typed as an opaque object here rather than deriving it
    // there, which would pull utoipa into a module that has no other use for
    // it. The wire shape is unaffected.
    #[schema(value_type = Vec<Object>)]
    pub generations: Vec<GenerationEntry>,
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
