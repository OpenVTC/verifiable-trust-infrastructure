//! The community theme's write — `vtc/community/theme/update/0.1`.
//!
//! Signed documents only (`trust_tasks::surface_tasks`); there is no REST
//! mount. The read is in `community::theme::shown_stylesheet`.

use axum::http::StatusCode;
use chrono::Utc;
use tracing::info;
use vti_common::audit::{AuditEvent, CommunityThemeUpdatedData};
use vti_common::error::AppError;

use crate::community::theme::{
    MAX_STYLESHEET_BYTES, ProfileViolation, StoredTheme, check_stylesheet, load_theme, store_theme,
    stylesheet_digest,
};
use crate::server::AppState;

/// What an update answers: the stylesheet as stored (or as it would be), and
/// whether the stored theme changed.
pub(crate) struct ThemeUpdate {
    pub stylesheet: String,
    pub stored: bool,
    pub updated_at: Option<chrono::DateTime<Utc>>,
}

pub(crate) enum ThemeUpdateError {
    /// `vtc/community/theme/update:outsideProfile`.
    OutsideProfile(ProfileViolation),
    App(AppError),
}

impl From<AppError> for ThemeUpdateError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// Replace (or, on `dry_run`, only check) the theme as `actor`. The caller has
/// established that `actor` holds administrator standing (update item 1).
pub(crate) async fn update_theme(
    state: &AppState,
    actor: &str,
    stylesheet: &str,
    dry_run: bool,
) -> Result<ThemeUpdate, ThemeUpdateError> {
    // Item 2: the byte bound is `malformedRequest`, before the profile.
    if stylesheet.len() > MAX_STYLESHEET_BYTES {
        return Err(AppError::Validation(format!(
            "stylesheet is {} bytes; the bound is {MAX_STYLESHEET_BYTES}",
            stylesheet.len()
        ))
        .into());
    }
    // Items 3–4: the profile, comments removed.
    let normalised = check_stylesheet(stylesheet).map_err(ThemeUpdateError::OutsideProfile)?;
    let current = load_theme(&state.community_ks).await?;

    // Item 5: a dry run stores nothing and audits nothing.
    if dry_run {
        return Ok(ThemeUpdate {
            stylesheet: normalised,
            stored: false,
            updated_at: None,
        });
    }

    // Item 6: storing what is already stored changes nothing.
    let unchanged = match &current {
        Some(StoredTheme { stylesheet, .. }) => *stylesheet == normalised,
        None => normalised.is_empty(),
    };
    if unchanged {
        return Ok(ThemeUpdate {
            stylesheet: normalised,
            stored: false,
            updated_at: current.map(|t| t.updated_at),
        });
    }

    // Item 6: refuse rather than make an unaudited change. The record is
    // written before the row, so a change never lands without one.
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured".into(),
        })?;
    let removed = normalised.is_empty();
    let digest = (!removed).then(|| stylesheet_digest(&normalised));
    writer
        .write(
            actor,
            None,
            AuditEvent::CommunityThemeUpdated(CommunityThemeUpdatedData {
                digest: digest.clone(),
                bytes: u32::try_from(normalised.len()).unwrap_or(u32::MAX),
            }),
        )
        .await?;
    let row = store_theme(&state.community_ks, &normalised, Utc::now()).await?;
    info!(removed, digest = ?digest, "community theme updated");
    Ok(ThemeUpdate {
        stylesheet: normalised,
        stored: true,
        updated_at: row.map(|r| r.updated_at),
    })
}
