//! Default community website (in-tree placeholder).
//!
//! Served when:
//!
//! - The `website` cargo feature is on, AND
//! - neither `website.root_dir` nor `website.landing_dir` is set in
//!   the daemon config.
//!
//! As soon as the operator sets `root_dir`, the filesystem-backed
//! handler in [`crate::website::serve`] takes over and this default
//! is unreachable. The default exists purely so a fresh
//! `cargo run` produces a working `GET /` instead of a 503.
//!
//! `website.landing_dir` replaces just this page with the operator's
//! own, read from disk per request ([`serve_dir`]); [`export`] writes
//! this one out as its starting point.
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

/// Boot check for `website.landing_dir`
/// ([`crate::website::paths::check_operator_dir`]): a readable `index.html`,
/// nothing world-writable.
pub fn check_landing_dir(dir: &std::path::Path) -> Result<(), String> {
    crate::website::paths::check_operator_dir(dir, "the landing page", "vtc website export")
}

/// `vtc website export <dir>`: write the built-in landing page to `dir`, to
/// customise and serve with `website.landing_dir`. Refuses a directory that
/// already holds anything, so an earlier customisation is never overwritten.
pub fn export(dir: &std::path::Path) -> Result<(), String> {
    if let Ok(mut entries) = std::fs::read_dir(dir)
        && entries.next().is_some()
    {
        return Err(format!(
            "{} is not empty — export into a new or empty directory so nothing \
             already there is overwritten",
            dir.display()
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    DEFAULT_SITE_DIR
        .extract(dir)
        .map_err(|e| format!("writing to {}: {e}", dir.display()))
}

/// Axum handler with `website.landing_dir` set: [`serve`]'s contract —
/// directory requests and misses fall back to `index.html`, served as HTML —
/// read from `dir` on every request, so an operator's edit shows on the next
/// load. Every path goes through the website's path-safety chain
/// ([`crate::website::paths::canonical_within_root`]): no hidden files, no
/// escaping `dir` (symlinks included), no executables. Responses are
/// revalidated (`no-cache`) for the same reason.
pub async fn serve_dir(dir: &std::path::Path, req: Request<Body>) -> Response {
    let raw_path = req.uri().path();
    let rel = if raw_path == "/" || raw_path.ends_with('/') {
        "/index.html"
    } else {
        raw_path
    };
    let resolve = |rel: &str| {
        crate::website::paths::canonical_within_root(dir, rel, &[])
            .ok()
            .filter(|p| p.is_file())
    };
    let (path, mime) = match resolve(rel) {
        Some(p) => {
            let mime = mime_guess::from_path(&p).first_or_octet_stream();
            let mime = if mime == mime_guess::mime::TEXT_HTML {
                "text/html; charset=utf-8".to_string()
            } else {
                mime.to_string()
            };
            (p, mime)
        }
        None => match resolve("/index.html") {
            Some(p) => (p, "text/html; charset=utf-8".to_string()),
            None => return (StatusCode::NOT_FOUND, "landing page not found").into_response(),
        },
    };
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "landing page not found").into_response(),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response build").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    async fn body_of(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// The exported page is the built-in one, passes the boot check, and is
    /// served from disk — an edit shows on the next request, no restart.
    #[tokio::test]
    async fn exported_landing_page_serves_from_disk_and_follows_edits() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("landing");
        export(&target).unwrap();
        check_landing_dir(&target).unwrap();

        let resp = serve_dir(&target, get("/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        let body = body_of(resp).await;
        assert_eq!(body.as_bytes(), lookup("/index.html").unwrap());

        let css = serve_dir(&target, get("/site.css")).await;
        assert!(
            css.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/css")
        );

        std::fs::write(target.join("index.html"), "<h1>Our community</h1>").unwrap();
        let body = body_of(serve_dir(&target, get("/")).await).await;
        assert_eq!(body, "<h1>Our community</h1>");
        // An unknown path falls back to the page, as HTML.
        let resp = serve_dir(&target, get("/about")).await;
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );

        let err = export(&target).unwrap_err();
        assert!(err.contains("not empty"), "{err}");
    }

    /// Nothing outside the directory, and no hidden file, is ever served.
    #[tokio::test]
    async fn landing_dir_serves_nothing_outside_it() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("landing");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("index.html"), "page").unwrap();
        std::fs::write(target.join(".env"), "secret").unwrap();
        std::fs::write(root.path().join("outside.txt"), "secret").unwrap();

        for path in ["/.env", "/../outside.txt", "/%2e%2e/outside.txt"] {
            let body = body_of(serve_dir(&target, get(path)).await).await;
            assert_eq!(body, "page", "{path} must fall back to the page");
        }
    }

    #[test]
    fn landing_dir_check_requires_index_and_refuses_world_writable() {
        let empty = tempfile::tempdir().unwrap();
        let err = check_landing_dir(empty.path()).unwrap_err();
        assert!(err.contains("vtc website export"), "{err}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let index = dir.path().join("index.html");
            std::fs::write(&index, "page").unwrap();
            check_landing_dir(dir.path()).unwrap();
            std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o666)).unwrap();
            let err = check_landing_dir(dir.path()).unwrap_err();
            assert!(err.contains("world-writable"), "{err}");
        }
    }

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

    /// The colour-theme script is embedded and runs in `<head>`, undeferred,
    /// so a pinned theme lands before first paint, and it shares the console's
    /// and member portal's storage key (`admin-ui/src/lib/theme.ts`).
    #[test]
    fn site_applies_the_shared_theme_before_paint() {
        let index = std::str::from_utf8(lookup("/index.html").unwrap()).unwrap();
        let script = index
            .find("<script src=\"/theme.js\"></script>")
            .expect("theme.js loaded without defer");
        let head_end = index.find("</head>").expect("</head>");
        assert!(script < head_end, "theme.js is loaded in <head>");
        assert!(
            index.contains("id=\"theme-switcher\""),
            "the switcher markup"
        );

        let js = std::str::from_utf8(lookup("/theme.js").expect("theme.js embedded")).unwrap();
        let shared = include_str!("../../admin-ui/src/lib/theme.ts");
        assert!(
            js.contains("\"vtc-admin-theme\"") && shared.contains("\"vtc-admin-theme\""),
            "the home page and the console store the theme under one key"
        );
    }

    /// The home page draws the logo the community stored before `logoUrl`, as
    /// the console and the member portal do (`chosenLogo`): only the stored one
    /// is on this origin, which the page's CSP requires.
    #[test]
    fn site_prefers_the_stored_logo_over_the_logo_url() {
        let js = std::str::from_utf8(lookup("/site.js").expect("site.js embedded")).unwrap();
        let stored = js.find("profile.logo.url").expect("reads the stored logo");
        let url = js.find(": profile.logoUrl").expect("falls back to logoUrl");
        assert!(stored < url, "the stored logo is tried first");
    }

    #[test]
    fn lookup_misses_on_unknown_path() {
        assert!(lookup("/no-such-file").is_none());
    }
}
