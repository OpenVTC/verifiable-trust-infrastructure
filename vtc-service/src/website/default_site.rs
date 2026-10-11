//! Default community website (in-tree placeholder).
//!
//! Served when:
//!
//! - The `website` cargo feature is on, AND
//! - `website.root_dir` is unset in the daemon config.
//!
//! As soon as the operator sets `root_dir`, the filesystem-backed
//! handler in [`crate::website::serve`] takes over and this default
//! is unreachable. The default exists purely so a fresh
//! `cargo run` produces a working `GET /` instead of a 503.
//!
//! Source lives at `vtc-service/website-default/` and is baked at
//! compile time via [`include_dir::include_dir!`]. The CSP layer
//! attached to the website sub-router in
//! [`crate::routes::mod::assemble_with_website`] applies uniformly
//! — operator-supplied sites and this default get the same
//! `default-src 'self'` policy.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use include_dir::{Dir, include_dir};

/// In-binary copy of `vtc-service/website-default/`. Walked at
/// request time to map paths → file bytes.
pub static DEFAULT_SITE_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/website-default");

/// Look up a request path in the embedded default site. Returns
/// `Some(bytes)` for an exact match; callers should fall back to
/// `index.html` on miss.
fn lookup(rel_path: &str) -> Option<&'static [u8]> {
    let trimmed = rel_path.trim_start_matches('/');
    DEFAULT_SITE_DIR.get_file(trimmed).map(|f| f.contents())
}

/// Axum handler. Mounted as the website sub-router's fallback
/// when `website_state` is `None`.
///
/// Default-document rule: a directory request (path ending in
/// `/` or just `/`) serves `index.html`. Unmatched paths fall back
/// to `index.html` so the page handles routing client-side if it
/// ever grows that ambition.
pub async fn serve(req: Request<Body>) -> Response {
    let raw_path = req.uri().path();
    let req_path = if raw_path == "/" || raw_path.ends_with('/') {
        "/index.html".to_string()
    } else {
        raw_path.to_string()
    };

    // Track whether we served the requested path verbatim or fell
    // back to `index.html` for SPA-style client-routing. When we
    // fall back, the mime must reflect what we're actually returning
    // (`text/html`) — not what was requested. Without this, an
    // extensionless request like `/install` returns `index.html`'s
    // bytes under `application/octet-stream`, which the browser
    // treats as a file download instead of rendering as a page.
    let (bytes, mime) = match lookup(&req_path) {
        Some(b) => (
            b,
            mime_guess::from_path(&req_path)
                .first_or_octet_stream()
                .to_string(),
        ),
        None => match lookup("/index.html") {
            Some(b) => (b, "text/html; charset=utf-8".to_string()),
            None => {
                return (StatusCode::NOT_FOUND, "default site not embedded").into_response();
            }
        },
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "public, max-age=60")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response build").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_dir_has_index() {
        assert!(
            DEFAULT_SITE_DIR.get_file("index.html").is_some(),
            "index.html missing from website-default/ — was the source dir deleted?"
        );
    }

    #[test]
    fn lookup_returns_index_bytes() {
        let bytes = lookup("/index.html").expect("index.html");
        let body = std::str::from_utf8(bytes).unwrap();
        assert!(
            body.contains("Verifiable Trust Community"),
            "default index.html drifted: {body}"
        );
    }

    /// The home page, the member portal and the console share one token
    /// file. The page is static, so it carries a copy; this keeps the copy
    /// identical to the source of truth the two bundles import.
    #[test]
    fn site_tokens_are_the_shared_tokens() {
        let site = lookup("/tokens.css").expect("website-default/tokens.css");
        let shared = include_bytes!("../../admin-ui/src/styles/tokens.css");
        assert!(
            site == shared.as_slice(),
            "website-default/tokens.css has drifted from admin-ui/src/styles/tokens.css — \
             edit the latter and copy it over"
        );
    }

    /// The page links its fonts and tokens before its own stylesheet, and
    /// every face `fonts.css` names is embedded, so nothing is fetched from
    /// a third party under `default-src 'self'`.
    #[test]
    fn site_links_self_hosted_fonts_and_tokens() {
        let index = std::str::from_utf8(lookup("/index.html").unwrap()).unwrap();
        let fonts = index.find("href=\"/fonts.css\"").expect("fonts.css linked");
        let tokens = index
            .find("href=\"/tokens.css\"")
            .expect("tokens.css linked");
        let site = index.find("href=\"/site.css\"").expect("site.css linked");
        assert!(
            fonts < site && tokens < site,
            "fonts and tokens precede site.css"
        );

        let css = std::str::from_utf8(lookup("/fonts.css").unwrap()).unwrap();
        let mut named = 0;
        for part in css.split("url(\"").skip(1) {
            let path = &part[..part.find('"').unwrap()];
            assert!(
                lookup(path).is_some(),
                "fonts.css names {path}, which is not embedded"
            );
            named += 1;
        }
        assert!(named >= 12, "expected the Plex faces, found {named}");
        assert!(!css.contains("http"), "fonts must be same-origin");
    }

    #[test]
    fn lookup_misses_on_unknown_path() {
        assert!(lookup("/no-such-file").is_none());
    }
}
