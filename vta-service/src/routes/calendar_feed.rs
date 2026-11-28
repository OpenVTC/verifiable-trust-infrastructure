//! `GET /calendar/feeds/{token}` — a private iCalendar feed (VTI-CAL-050 – 055, VTI-OPS-111).
//!
//! A calendar application subscribes by URL and can sign nothing, so this is a REST
//! exception (`deprecation::REST_EXCEPTIONS`, protocol "iCalendar subscription"); every
//! other calendar operation is a `vta/calendar/*` Trust Task. The address is the
//! credential: the token is kept only as a digest, never logged, and an unknown, revoked or
//! expired token is answered with the same bare 404 (VTI-CAL-052), so the route says
//! nothing about which feeds exist. The window is a year ahead and thirty days back; the
//! feed's contexts follow its creator's standing at each read (VTI-CAL-055).

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};

use crate::operations::calendar as cal;
use crate::server::AppState;

/// How far back and ahead a feed reaches.
const FEED_PAST_DAYS: i64 = 30;
const FEED_AHEAD_DAYS: i64 = 365;

/// Serve one feed. The `.ics` suffix the address carries is optional.
pub async fn calendar_feed_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let token = token.strip_suffix(".ics").unwrap_or(&token);
    // A token is 64 lowercase hex characters; anything else cannot name a feed.
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let now = Utc::now();
    let feed = match cal::open_feed(&state, token, now).await {
        Ok(Some(f)) => f,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "calendar feed: store read failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let body = match render(&state, &feed, now).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(feed = %feed.feed_id, error = %e, "calendar feed: render failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/calendar; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

async fn render(
    state: &AppState,
    feed: &cal::Feed,
    now: chrono::DateTime<Utc>,
) -> Result<String, vti_common::error::AppError> {
    let contexts = cal::feed_contexts(state, feed).await?;
    let listed = cal::list(
        state,
        &contexts,
        now - Duration::days(FEED_PAST_DAYS),
        now + Duration::days(FEED_AHEAD_DAYS),
        &feed.tiers,
    )
    .await?;
    Ok(cal::to_ics(&listed, &feed.detail, &feed.uid_salt, now))
}
