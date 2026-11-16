//! The community logo's write — `vtc/community/logo/update/0.1`.
//!
//! Signed documents only (`trust_tasks::surface_tasks`). The read is the
//! public route `GET /v1/community/logo` (`routes::community::logo`) and the
//! `logo` member of the public profile.

use axum::http::StatusCode;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use tracing::info;
use vtc_audit::{AuditEvent, CommunityLogoUpdatedData};
use vti_common::error::AppError;
use vti_specs::vtc::community::logo::update::v0_1::LogoImage;

use crate::community::logo::{LogoMeta, digest, load_record, store_logo};
use crate::directory::images::{MAX_IMAGE_BYTES, UploadError, reencode_logo};
use crate::server::AppState;

/// What an update answers: the logo now held, whether this request changed
/// it, and when it last changed.
pub(crate) struct LogoUpdate {
    pub logo: Option<LogoMeta>,
    pub stored: bool,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Why an update was refused, by the code the task declares.
pub(crate) enum LogoUpdateError {
    /// `tooLarge` (item 2).
    TooLarge,
    /// `notAnImage` (item 3).
    NotAnImage,
    /// `rateLimited` (item 5).
    RateLimited,
    App(AppError),
}

impl From<AppError> for LogoUpdateError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

/// Replace the logo with `image`, or remove it when `None`, as `actor`. The
/// caller has established that `actor` holds administrator standing before
/// anything here decodes (item 1).
pub(crate) async fn update_logo(
    state: &AppState,
    actor: &str,
    image: Option<&LogoImage>,
) -> Result<LogoUpdate, LogoUpdateError> {
    // Item 5, before any work: a refused update costs nothing.
    if !state.community_logo.admit_update(actor) {
        return Err(LogoUpdateError::RateLimited);
    }
    let current = load_record(&state.community_ks).await?;
    let held = current.as_ref().and_then(|r| r.logo.clone());

    let next = match image {
        None => None,
        Some(image) => {
            // Item 2: bounded before it is decoded as an image.
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(image.data.as_str())
                .map_err(|_| LogoUpdateError::NotAnImage)?;
            if bytes.len() > MAX_IMAGE_BYTES {
                return Err(LogoUpdateError::TooLarge);
            }
            // Items 3 and 4, off the runtime and one at a time.
            let media_type = image.media_type.to_string();
            let _permit = state
                .community_logo
                .encode
                .acquire()
                .await
                .map_err(|e| AppError::Internal(format!("logo re-encoding permit: {e}")))?;
            let encoded =
                match tokio::task::spawn_blocking(move || reencode_logo(&bytes, &media_type)).await
                {
                    Ok(Ok(e)) => e,
                    Ok(Err(UploadError::TooLarge)) => return Err(LogoUpdateError::TooLarge),
                    Ok(Err(UploadError::NotAnImage)) => return Err(LogoUpdateError::NotAnImage),
                    Err(e) => {
                        return Err(AppError::Internal(format!("logo re-encoding: {e}")).into());
                    }
                };
            let meta = LogoMeta {
                sha256: digest(&encoded.encoded.bytes),
                media_type: encoded.encoded.media_type.to_string(),
                size: u32::try_from(encoded.encoded.bytes.len())
                    .map_err(|_| LogoUpdateError::TooLarge)?,
                width: encoded.width,
                height: encoded.height,
            };
            Some((meta, encoded.encoded.bytes))
        }
    };

    // Item 6: storing what is already stored, or removing what is not held,
    // changes nothing and is not audited.
    let unchanged = match (&next, &held) {
        (None, None) => true,
        (Some((meta, _)), Some(h)) => meta.sha256 == h.sha256,
        _ => false,
    };
    if unchanged {
        return Ok(LogoUpdate {
            logo: held,
            stored: false,
            updated_at: current.map(|r| r.updated_at),
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
    let data = match &next {
        Some((meta, _)) => CommunityLogoUpdatedData {
            digest: Some(meta.sha256.clone()),
            media_type: Some(meta.media_type.clone()),
            bytes: meta.size,
        },
        None => CommunityLogoUpdatedData {
            digest: None,
            media_type: None,
            bytes: 0,
        },
    };
    let removed = next.is_none();
    writer
        .write(actor, None, AuditEvent::CommunityLogoUpdated(data))
        .await?;
    let record = store_logo(&state.community_ks, next, Utc::now()).await?;
    state.community_logo.invalidate();
    info!(
        removed,
        digest = ?record.logo.as_ref().map(|m| &m.sha256),
        "community logo updated"
    );
    Ok(LogoUpdate {
        logo: record.logo,
        stored: true,
        updated_at: Some(record.updated_at),
    })
}
