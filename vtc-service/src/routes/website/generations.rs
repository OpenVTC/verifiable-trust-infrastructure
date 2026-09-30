//! `vtc/website/generations/list/0.1` + `vtc/website/rollback/0.1` — managed
//! deploy mode's generation history and rollback, on the signed-document
//! spine (`trust_tasks::website_tasks`; neither has a REST route).
//!
//! Both are managed-mode-only. Live-mode requests refuse with
//! `notManaged` (encoded as [`AppError::Validation`] for MVP — see the
//! module-level history).

use chrono::{DateTime, Utc};
use serde::Serialize;

use vti_common::audit::{AuditEvent, WebsiteGenerationRolledBackData};

use crate::error::{AppError, TaskError};
use crate::server::AppState;
use crate::website::storage::{GenerationEntry, list_managed_generations, swap_current_symlink};

use trust_tasks_rs::specs::vtc::website as website_spec;

/// `vtc/website/generations/list:notManaged` — live mode has no generations.
pub const GENERATIONS_LIST_ERR_NOT_MANAGED: &str =
    website_spec::generations::list::v0_1::error_codes::NOT_MANAGED.code;
/// `vtc/website/rollback:notManaged` — live mode has nothing to roll back to.
pub const ROLLBACK_ERR_NOT_MANAGED: &str =
    website_spec::rollback::v0_1::error_codes::NOT_MANAGED.code;
/// `vtc/website/rollback:generationNotFound` — no generation with that label.
pub const ROLLBACK_ERR_GENERATION_NOT_FOUND: &str =
    website_spec::rollback::v0_1::error_codes::GENERATION_NOT_FOUND.code;

/// `vtc/website/generations/list/0.1`, called from `trust_tasks::website_tasks`.
pub(crate) async fn list(state: &AppState) -> Result<GenerationsResponse, TaskError> {
    let cfg = state.config.read().await;
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    if deploy_mode != "managed" {
        return Err(TaskError::declared(
            GENERATIONS_LIST_ERR_NOT_MANAGED,
            AppError::Validation(
                "website/generations/list is only available in managed deploy mode".into(),
            ),
        ));
    }

    let generations = list_managed_generations(&root_dir)?
        .into_iter()
        .map(GenerationRow::from)
        .collect();
    Ok(GenerationsResponse { generations })
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

/// `vtc/website/rollback/0.1`, called from `trust_tasks::website_tasks` with
/// `actor` the verified signer's DID (the audit trail's actor, in place of
/// the bearer route's hard-coded `"admin"`).
pub(crate) async fn rollback(
    state: &AppState,
    actor: &str,
    gen_num: u32,
) -> Result<RollbackResponse, TaskError> {
    let cfg = state.config.read().await;
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    if deploy_mode != "managed" {
        return Err(TaskError::declared(
            ROLLBACK_ERR_NOT_MANAGED,
            AppError::Validation(
                "website/rollback is only available in managed deploy mode".into(),
            ),
        ));
    }

    // The swap's one `NotFound` is its missing-generation check; the rest are
    // filesystem faults.
    let from = swap_current_symlink(&root_dir, gen_num).map_err(|e| match e {
        e @ AppError::NotFound(_) => TaskError::declared(ROLLBACK_ERR_GENERATION_NOT_FOUND, e),
        e => TaskError::App(e),
    })?;
    if from != gen_num
        && let Some(writer) = state.audit_writer.as_ref()
    {
        let _ = writer
            .write(
                actor,
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
    Ok(RollbackResponse {
        generation: gen_num.to_string(),
        current: true,
        noop: from == gen_num,
    })
}

/// `{ generation, current, noop }` — the shape `vtc/website/rollback/0.1`
/// publishes. The handler returned 200 with zero bytes until #1059.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = WebsiteRollbackResponse)]
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
