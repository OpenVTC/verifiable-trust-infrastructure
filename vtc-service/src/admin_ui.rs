//! Embedded admin UX (§12.2, Phase 5 M5.6 + M5.7).
//!
//! Static HTML/CSS/JS source lives at `vtc-service/admin-ui/` and
//! is baked into the binary at compile time via
//! [`include_dir::include_dir!`]. Per Phase 5 D1 the source is
//! **in-tree** — there is no sibling `OpenVTC/vtc-admin-ui` repo,
//! no signed-tarball fetch, no `VTC_OFFLINE_BUILD=1` env var.
//! `cargo build` builds the admin UX as part of the daemon
//! without any out-of-tree dependencies.
//!
//! Operators wanting a richer SPA replace the files in
//! `admin-ui/` and rebuild.

#![cfg(feature = "admin-ui")]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::Response;
use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};

/// In-binary copy of `vtc-service/admin-ui/dist/` — the Vite build
/// output. Produced by `build.rs` running `npm run build` before
/// this file compiles. Walked at request time to map paths → file
/// bytes. The admin SPA is a React app; client-side routing
/// (history mode) means most paths resolve to `index.html` and the
/// shell takes over.
pub static ADMIN_UI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/admin-ui/dist");

/// Metadata derived once at startup. Used by the build-info
/// endpoint and the `AdminUiServed` audit envelope.
#[derive(Debug, Clone)]
pub struct AdminUiInfo {
    /// SHA-256 of the baked `index.html`, hex-encoded.
    pub index_sha256: Arc<String>,
    /// Total file count in the baked directory.
    pub file_count: u32,
    /// `"embedded"` (default) or `"external"`.
    pub mode: Arc<String>,
}

impl AdminUiInfo {
    /// Compute from the embedded directory at startup.
    pub fn from_embedded(mode: &str) -> Self {
        let index_bytes = ADMIN_UI_DIR
            .get_file("index.html")
            .map(|f| f.contents())
            .unwrap_or_default();
        let index_sha256 = hex::encode(Sha256::digest(index_bytes));
        let file_count = count_files(&ADMIN_UI_DIR);
        Self {
            index_sha256: Arc::new(index_sha256),
            file_count,
            mode: Arc::new(mode.to_string()),
        }
    }
}

fn count_files(dir: &Dir<'_>) -> u32 {
    let mut total: u32 = 0;
    for f in dir.files() {
        let _ = f;
        total = total.saturating_add(1);
    }
    for sub in dir.dirs() {
        total = total.saturating_add(count_files(sub));
    }
    total
}

/// Look up a request path in the embedded directory. Returns
/// `Some(bytes)` for an exact match; the caller is responsible
/// for the SPA history-mode fallback to `index.html`.
pub fn lookup(rel_path: &str) -> Option<&'static [u8]> {
    let trimmed = rel_path.trim_start_matches('/');
    ADMIN_UI_DIR.get_file(trimmed).map(|f| f.contents())
}

/// Cache-control for an admin-UX response. The SPA shell
/// (`index.html`, served for `/admin`, `/admin/`, and every
/// history-mode fallback) must be revalidated each load —
/// otherwise after an upgrade a browser serves a stale shell
/// pointing at asset hashes the new binary dropped, breaking the
/// SPA for the TTL window. Only the content-hashed `/assets/*`
/// bundles (immutable by construction) keep the long TTL.
fn cache_control_for(rel: &str, served_shell: bool) -> &'static str {
    if !served_shell && rel.starts_with("/assets/") {
        "public, max-age=300"
    } else {
        "no-cache"
    }
}

/// Axum handler for `GET /admin/*`. Walks the request path
/// through the embedded directory; falls back to `index.html`
/// for client-side routing (SPA history mode).
pub async fn serve(req: Request<Body>) -> Response {
    let rel = req.uri().path().trim_start_matches("/admin");
    let rel = if rel.is_empty() || rel == "/" {
        "/index.html"
    } else {
        rel
    };

    // SPA history-mode fallback: extensionless paths like
    // `/admin/install` aren't on disk, so we serve `index.html` and
    // let the React router pick up the rest of the URL. The mime
    // must reflect the *served* bytes (`text/html`), not the
    // *requested* path — otherwise the browser sees
    // `application/octet-stream` and tries to download the page.
    let (bytes, mime, served_shell) = match lookup(rel) {
        Some(b) => (
            b,
            mime_guess::from_path(rel)
                .first_or_octet_stream()
                .to_string(),
            rel == "/index.html",
        ),
        None => match lookup("/index.html") {
            // History-mode fallback — we served the SPA shell.
            Some(b) => (b, "text/html; charset=utf-8".to_string(), true),
            None => {
                return (StatusCode::NOT_FOUND, "admin UX not embedded").into_response();
            }
        },
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache_control_for(rel, served_shell))
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response build").into_response())
}

// Re-export so the build-info handler in `routes::admin_ui` can
// reach the metadata without duplicating the SHA-256 computation.
use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_dir_has_index() {
        assert!(
            ADMIN_UI_DIR.get_file("index.html").is_some(),
            "index.html missing from embedded admin-ui — did the source dir get deleted?"
        );
    }

    #[test]
    fn cache_control_no_cache_for_shell_long_ttl_for_assets() {
        // SPA shell (index + every history-mode fallback) → no-cache.
        assert_eq!(cache_control_for("/index.html", true), "no-cache");
        assert_eq!(cache_control_for("/install", true), "no-cache"); // fallback
        // A non-asset root file is also revalidated.
        assert_eq!(cache_control_for("/favicon.ico", false), "no-cache");
        // Content-hashed bundles keep the long TTL.
        assert_eq!(
            cache_control_for("/assets/index-a1b2c3.js", false),
            "public, max-age=300"
        );
        // An /assets/* path that fell back to the shell is still
        // no-cache (we served index.html, not the bundle).
        assert_eq!(cache_control_for("/assets/missing.js", true), "no-cache");
    }

    #[test]
    fn lookup_returns_bytes_for_known_files() {
        let bytes = lookup("/index.html").expect("index.html");
        let body = std::str::from_utf8(bytes).unwrap();
        // Vite's `index.html` shim has `<title>VTC Admin</title>`
        // and a `<div id="root">` mount point. Both are stable
        // build-tool output.
        assert!(
            body.contains("<title>VTC Admin</title>"),
            "index.html title drifted: {body}"
        );
        assert!(
            body.contains("id=\"root\""),
            "index.html missing React mount point: {body}"
        );
    }

    #[test]
    fn lookup_returns_none_for_unknown() {
        assert!(lookup("/missing.html").is_none());
    }

    #[test]
    fn assets_dir_is_embedded() {
        // Vite emits hashed bundles under `assets/`. Without them
        // the index shim has nothing to execute. Walk the embedded
        // tree to confirm the `assets/` dir landed.
        let assets = ADMIN_UI_DIR
            .get_dir("assets")
            .expect("assets/ missing from dist — Vite build did not emit chunks");
        let js_present = assets
            .files()
            .any(|f| f.path().extension().is_some_and(|e| e == "js"));
        let css_present = assets
            .files()
            .any(|f| f.path().extension().is_some_and(|e| e == "css"));
        assert!(js_present, "no .js asset in dist/assets/");
        assert!(css_present, "no .css asset in dist/assets/");
    }

    #[test]
    fn info_carries_sha_of_index_html() {
        let info = AdminUiInfo::from_embedded("embedded");
        assert_eq!(info.index_sha256.len(), 64, "hex sha256 = 64 chars");
        assert!(
            info.file_count >= 3,
            "expect index + at least one js + one css"
        );
        assert_eq!(info.mode.as_str(), "embedded");
    }
}
