//! The community logo's write — `vtc/community/logo/update/0.1`.
//!
//! Signed documents only (`trust_tasks::surface_tasks`). The reads are
//! `vtc/community/logo/show/0.1`, the public route `GET /v1/community/logo`
//! (`routes::community::logo`) and the `logo` member of the public profile,
//! all answered from [`crate::community::logo::LogoState::snapshot`].

use axum::http::StatusCode;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use tracing::info;
use vtc_audit::{AuditEvent, CommunityLogoUpdatedData};
use vti_common::error::AppError;
use vti_specs::vtc::community::logo::update::v0_1::LogoImage;

use crate::community::logo::{LOGO_RECORD_KEY, LogoMeta, LogoRecord, digest, store_logo};
use crate::directory::images::{UploadError, reencode_logo};
use crate::server::AppState;

/// What an update asks for: a new logo, or `remove: true`.
pub(crate) enum LogoChange<'a> {
    Set(&'a LogoImage),
    Remove,
}

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

/// Replace the logo with `change`, or remove it, as `actor` — the
/// administrator the signer resolved to, never a delegated signing key, so the
/// rate limit is theirs however many keys they enrol (item 5). The caller has
/// established that `actor` holds administrator standing before anything here
/// decodes (item 1).
pub(crate) async fn update_logo(
    state: &AppState,
    actor: &str,
    change: LogoChange<'_>,
) -> Result<LogoUpdate, LogoUpdateError> {
    // Item 5: every request that passed item 1 counts, a no-op included, and
    // before `data` is decoded — decoding is the expensive step.
    if !state.community_logo.admit_update(actor) {
        return Err(LogoUpdateError::RateLimited);
    }
    // One update at a time, from the first read to the write: re-encoding is
    // CPU-bound, and two updates must not interleave their check and write.
    let _permit = state
        .community_logo
        .update
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("logo update permit: {e}")))?;

    // What is stored, read leniently: a record nothing here can read must
    // never stop an administrator replacing or removing it.
    let raw = state.community_ks.get_raw(LOGO_RECORD_KEY).await?;
    let record: Option<LogoRecord> = raw
        .as_deref()
        .and_then(|bytes| match serde_json::from_slice(bytes) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error = %e, "stored community logo record unreadable; it will be replaced");
                None
            }
        });
    let unreadable = raw.is_some() && record.is_none();
    // The logo actually servable now: its record well-formed and its bytes
    // matching. Only that counts as "already stored" below, so sending the
    // same image again repairs a store whose bytes were lost or altered.
    let held = state
        .community_logo
        .served(&state.community_ks)
        .await
        .map(|h| h.meta);

    let next = match change {
        LogoChange::Remove => None,
        LogoChange::Set(image) => {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(image.data.as_str())
                .map_err(|_| LogoUpdateError::NotAnImage)?;
            // Items 2–4, off the runtime. `reencode_logo` refuses more than
            // 262144 bytes before decoding them as an image (item 2).
            let media_type = image.media_type.to_string();
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

    // Item 7: storing what is already stored, or removing what is not held,
    // changes nothing and is not audited.
    // A removal is a no-op only when the record itself says nothing is held:
    // a record naming a logo that cannot be served is still removed.
    let unchanged = match (&next, &held) {
        (None, _) => !unreadable && record.as_ref().is_none_or(|r| r.logo.is_none()),
        (Some((meta, _)), Some(h)) => meta.sha256 == h.sha256,
        (Some(_), None) => false,
    };
    if unchanged {
        return Ok(LogoUpdate {
            logo: held,
            stored: false,
            updated_at: record.map(|r| r.updated_at),
        });
    }

    // Item 7: refuse with `unavailable` rather than make an unaudited change.
    // So the audit record is written first: were the rows written first, a
    // failed audit write (or the process dying between the two) would leave a
    // change in place with no record of who made it, which the item forbids.
    // The order's cost is the converse — a store write failing after the
    // audit write leaves a record of a change that did not land — and the
    // request is then refused, so the administrator sees it did not.
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
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "community logo update refused: the audit record could not be written");
            AppError::ServiceError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: "the audit record could not be written; nothing was stored".into(),
            }
        })?;
    let stored = store_logo(&state.community_ks, next, Utc::now()).await;
    state.community_logo.invalidate();
    let record = stored.inspect_err(|e| {
        tracing::error!(
            error = %e,
            security_alert = true,
            "community logo audited but not stored: the audit trail names a change that did not land"
        );
    })?;
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
