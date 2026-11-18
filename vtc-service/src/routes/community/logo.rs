//! `GET /v1/community/logo` — the logo the community stored with
//! `vtc/community/logo/update/0.1`, served from its own origin.
//!
//! Public and unauthenticated, like `public-profile` and `did-qr.svg`: the
//! sign-in pages draw it before the visitor holds any identity, and a logo is
//! public by design. It reveals nothing the public profile does not.
//!
//! What it serves is only ever the community's own re-encoding (update item
//! 4), with headers that keep any reader from treating the bytes as anything
//! but an image (item 9): the `Content-Type` comes from a fixed list, never
//! from the stored record's string; `nosniff`; and a CSP under which the
//! response, opened directly, may run nothing. Served from memory
//! (`LogoState::snapshot`), so a request — a 304 included — touches no store.
//!
//! One URL across updates (item 9), so a page embeds it once: it is
//! revalidated on every use (`no-cache`) against an `ETag` of the digest, and
//! a replaced logo is drawn on the next load. A query string is ignored.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::community::logo::MEDIA_TYPES;
use crate::server::AppState;

/// `Cache-Control`: one URL for whichever logo is stored, so a cache may keep
/// the bytes but revalidates them on each use — a 304 from memory.
const CACHE: &str = "public, no-cache";

/// Opened directly, the response runs and loads nothing.
const CSP: &str = "default-src 'none'; sandbox";

/// GET /community/logo — the community's stored logo image.
/// Public, unauthenticated.
#[utoipa::path(
    get, path = "/community/logo", tag = "community",
    responses(
        (status = 200, description = "The stored logo: the community's own PNG re-encoding",
            content_type = "image/png"),
        (status = 304, description = "Not modified (matches If-None-Match)"),
        (status = 404, description = "The community holds no logo"),
    ),
)]
pub async fn get_logo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(held) = state.community_logo.served(&state.community_ks).await else {
        return (StatusCode::NOT_FOUND, "no logo").into_response();
    };
    // `served` admits only a record naming one of these; the header value is
    // taken from the fixed list, never from the record's string.
    let Some(media) = MEDIA_TYPES.iter().find(|m| **m == held.meta.media_type) else {
        return (StatusCode::NOT_FOUND, "no logo").into_response();
    };
    let etag = format!("\"{}\"", held.meta.sha256);
    let fixed = [
        (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ),
        (
            header::HeaderName::from_static("cross-origin-resource-policy"),
            // A brand mark wallets and other sites may show.
            HeaderValue::from_static("cross-origin"),
        ),
    ];
    let etag_value = HeaderValue::from_str(&etag).expect("hex digest is a header value");
    let matches = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',').map(str::trim).any(|t| {
                // A weak validator (`W/"…"`) names the same bytes here.
                t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag
            })
        });
    if matches {
        return (
            StatusCode::NOT_MODIFIED,
            fixed,
            [(header::ETAG, etag_value)],
        )
            .into_response();
    }
    (
        StatusCode::OK,
        fixed,
        [
            (header::ETAG, etag_value),
            (header::CONTENT_TYPE, HeaderValue::from_static(media)),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("inline; filename=\"logo\""),
            ),
        ],
        held.bytes,
    )
        .into_response()
}
