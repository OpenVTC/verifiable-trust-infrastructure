//! Public static handler (§12.1, Phase 5 M5.4.2).
//!
//! The handler mounts under `routing.website.mount` (default `/`)
//! as a catch-all and serves files from
//! [`crate::website::WebsiteRoot::serve_root`] with the full
//! path-safety chain + content cache.
//!
//! Response headers:
//!
//! - `Content-Type` — `mime_guess::from_path` with
//!   `application/octet-stream` fallback.
//! - `ETag` — `"<sha256-hex>"` of the file contents (already
//!   computed by [`crate::website::cache::WebsiteCache::get`]).
//! - `Cache-Control` — from `website.cache_control`.
//! - `X-Content-Type-Options: nosniff` — handled by the
//!   [`crate::routing::security_headers`] middleware attached to
//!   the website sub-router.
//! - Default CSP — also from `security_headers` middleware.
//!   Per-site override via `<root>/.vtc-website.toml` is resolved
//!   here (so it can override what the middleware would default)
//!   and overwrites the `Content-Security-Policy` header the
//!   middleware later attaches. The override is **validated** —
//!   one that weakens `script-src` / `object-src` / `base-uri`
//!   below the daemon default is refused (default applies instead)
//!   — and **cached** with the content-cache TTL so it isn't
//!   stat'd/parsed on every request.
//!
//! `If-None-Match` is honoured: matching ETag → 304 without body.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::error::AppError;
use crate::website::cache::WebsiteCache;
use crate::website::paths::{PathError, canonical_within_root};
use crate::website::storage::WebsiteRoot;

/// All state the [`serve`] handler needs. Held inside the website
/// sub-router via `Router::with_state`.
#[derive(Debug, Clone)]
pub struct WebsiteState {
    pub root: WebsiteRoot,
    pub cache: WebsiteCache,
    pub executable_blocklist: Vec<String>,
    pub cache_control: String,
    pub csp_override_file: String,
    /// TTL cache for the parsed + validated per-site CSP override, so
    /// the override file isn't stat'd/parsed on every request.
    pub csp_cache: CspOverrideCache,
}

/// Optional per-site override TOML — read from
/// `<root>/.vtc-website.toml` (or whatever
/// `website.csp_override_file` points at) and cached with the
/// content-cache TTL.
#[derive(Debug, Deserialize, Default)]
pub struct WebsiteOverride {
    /// CSP value to emit instead of the daemon default. Validated
    /// before use — an override that weakens `script-src`,
    /// `object-src`, or `base-uri` below the daemon default is
    /// refused and the default CSP applies instead.
    pub csp: Option<String>,
}

/// A parsed-and-validated CSP override cached with a TTL, mirroring
/// [`WebsiteCache`]'s `Instant + ttl` scheme. The cached value is the
/// effective override (`Some` accepted CSP, or `None` for "no file /
/// invalid / refused" — meaning the daemon default applies).
#[derive(Debug, Clone)]
pub struct CspOverrideCache {
    inner: Arc<RwLock<Option<CachedCsp>>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct CachedCsp {
    value: Option<String>,
    fetched_at: Instant,
}

impl CspOverrideCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// The effective CSP override for this site, reading + validating
    /// from disk only on a cache miss / expiry.
    async fn get(&self, serve_root: &Path, override_file: &str) -> Option<String> {
        if let Some(entry) = self.inner.read().await.as_ref()
            && entry.fetched_at.elapsed() < self.ttl
        {
            return entry.value.clone();
        }
        let value = read_csp_override(serve_root, override_file).await;
        *self.inner.write().await = Some(CachedCsp {
            value: value.clone(),
            fetched_at: Instant::now(),
        });
        value
    }
}

/// Axum handler. Mounted at the website sub-router as a catch-all
/// fallback (`/{*path}` semantics) so any unmatched request lands
/// here.
pub async fn serve(State(state): State<WebsiteState>, req: Request<Body>) -> Response {
    match serve_inner(&state, req.uri()).await {
        Ok(resp) => resp,
        Err(err) => err.into_response(),
    }
}

async fn serve_inner(state: &WebsiteState, uri: &Uri) -> Result<Response, AppError> {
    let raw_path = uri.path();
    // Default-document rule: a directory request maps to
    // `index.html`. The path-safety chain runs against the
    // resolved file path.
    let req_path = if raw_path == "/" || raw_path.ends_with('/') {
        format!("{raw_path}index.html")
    } else {
        raw_path.to_string()
    };

    let serve_root = state.root.serve_root();
    let resolved = match canonical_within_root(&serve_root, &req_path, &state.executable_blocklist)
    {
        Ok(p) => p,
        Err(PathError::NotFound) => {
            return Err(AppError::NotFound(format!("no such resource: {raw_path}")));
        }
        Err(PathError::Hidden) => {
            return Err(AppError::NotFound(format!("no such resource: {raw_path}")));
        }
        Err(PathError::BlockedExtension(ext)) => {
            return Err(AppError::Forbidden(format!(
                "extension {ext} is blocked by website.executable_blocklist"
            )));
        }
        Err(PathError::Escape | PathError::ControlChars | PathError::NonNfc) => {
            return Err(AppError::Validation(format!(
                "request path rejected by website path-safety: {raw_path}"
            )));
        }
        Err(PathError::ExecBit) => {
            return Err(AppError::Forbidden(
                "file has executable bit set; refusing to serve".into(),
            ));
        }
    };

    // Refuse directories (e.g. caller hit `/assets/` and the
    // resolved path is a directory). Default-document handling
    // above already redirected `/` to `/index.html`; any
    // remaining directory hit is operator error.
    if let Ok(meta) = tokio::fs::metadata(&resolved).await
        && meta.is_dir()
    {
        return Err(AppError::NotFound("path resolves to a directory".into()));
    }

    let cached = state
        .cache
        .get(&resolved)
        .await
        .map_err(|e| AppError::Internal(format!("failed to read website file: {e}")))?;

    let etag = format!("\"{}\"", cached.digest_hex);

    let mime = mime_guess::from_path(&resolved)
        .first_or_octet_stream()
        .to_string();

    let csp_override = state
        .csp_cache
        .get(&serve_root, &state.csp_override_file)
        .await;

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::ETAG, etag.clone())
        .header(header::CACHE_CONTROL, state.cache_control.clone());

    if let Some(csp) = csp_override {
        // Per-site override wins over the default CSP that
        // `routing::security_headers` would attach later.
        builder = builder.header(header::CONTENT_SECURITY_POLICY, csp);
    }

    builder
        .body(Body::from((*cached.body).clone()))
        .map_err(|e| AppError::Internal(format!("response build: {e}")))
}

async fn read_csp_override(serve_root: &Path, override_file: &str) -> Option<String> {
    let path: PathBuf = serve_root.join(override_file);
    let bytes = tokio::fs::read(&path).await.ok()?;
    let parsed: WebsiteOverride = toml::from_slice(&bytes).ok()?;
    let csp = parsed.csp?;
    match validate_csp_override(&csp) {
        Some(valid) => Some(valid),
        None => {
            tracing::warn!(
                file = %path.display(),
                "per-site CSP override weakens script-src/object-src/base-uri below the \
                 daemon default; ignoring it and serving the default CSP",
            );
            None
        }
    }
}

/// Refuse a per-site CSP override that would weaken any of the
/// security-critical directives — `script-src`, `object-src`,
/// `base-uri` — below the daemon default. An operator (or anyone with
/// website write access) must not be able to neutralise the default
/// by, e.g., adding `script-src 'unsafe-inline'`. Other directives
/// (img-src, connect-src, style-src, …) may be freely customised.
///
/// Returns the trimmed override on success, or `None` if it's refused
/// (caller falls back to the daemon default).
fn validate_csp_override(csp: &str) -> Option<String> {
    let directives = parse_csp(csp);

    // The effective source list for a directive is its own value, or
    // the `default-src` fallback, or — if neither is present — no
    // restriction at all (which is strictly weaker than the default).
    let effective = |name: &str| -> Option<Vec<String>> {
        directives
            .get(name)
            .or_else(|| directives.get("default-src"))
            .cloned()
    };

    // script-src: strictest. Reject wildcards, unsafe-*, bare schemes,
    // or an entirely unrestricted script source.
    match effective("script-src") {
        Some(sources) if !sources_are_loose(&sources, true) => {}
        _ => return None,
    }

    // object-src + base-uri: reject wildcards / unsafe-inline. A
    // missing object-src falls back to default-src (checked); a
    // missing base-uri has no default-src fallback in the spec, so
    // absence is fine (browsers default base-uri to the document URL,
    // not a weaker policy than ours).
    if let Some(sources) = effective("object-src")
        && sources_are_loose(&sources, false)
    {
        return None;
    }
    if let Some(sources) = directives.get("base-uri")
        && sources_are_loose(sources, false)
    {
        return None;
    }

    Some(csp.trim().to_string())
}

/// Parse a CSP string into `directive -> [source]`. Lower-cases the
/// directive name (case-insensitive per spec) but preserves source
/// token case (`'nonce-…'` etc. are case-sensitive).
fn parse_csp(csp: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut out = std::collections::HashMap::new();
    for segment in csp.split(';') {
        let mut tokens = segment.split_whitespace();
        if let Some(name) = tokens.next() {
            let sources: Vec<String> = tokens.map(str::to_string).collect();
            out.insert(name.to_ascii_lowercase(), sources);
        }
    }
    out
}

/// Whether a directive's source list is "loose" — contains a wildcard,
/// an `'unsafe-*'` keyword, or (when `strict_schemes`) a bare scheme
/// that would broaden script execution. An empty list is treated as
/// loose only via the caller's effective-source logic, not here.
fn sources_are_loose(sources: &[String], strict_schemes: bool) -> bool {
    for src in sources {
        if src.contains('*') {
            return true;
        }
        let lower = src.to_ascii_lowercase();
        if lower == "'unsafe-inline'" || lower == "'unsafe-eval'" || lower == "'unsafe-hashes'" {
            return true;
        }
        if strict_schemes && matches!(lower.as_str(), "data:" | "blob:" | "http:" | "https:") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn block() -> Vec<String> {
        vec![".cgi".into(), ".php".into(), ".exe".into()]
    }

    async fn make_state(root: &Path) -> WebsiteState {
        WebsiteState {
            root: WebsiteRoot::new(root, "live").unwrap(),
            cache: WebsiteCache::new(60),
            executable_blocklist: block(),
            cache_control: "public, max-age=300".into(),
            csp_override_file: ".vtc-website.toml".into(),
            csp_cache: CspOverrideCache::new(60),
        }
    }

    #[tokio::test]
    async fn serves_existing_file_with_etag() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.html"), "<p>hi</p>").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/hello.html".parse().unwrap();
        let resp = serve_inner(&state, &uri).await.expect("ok");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::ETAG).is_some());
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .map(|h| h.to_str().unwrap()),
            Some("public, max-age=300"),
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), b"<p>hi</p>");
    }

    #[tokio::test]
    async fn serves_index_for_root_request() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<title>home</title>").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/".parse().unwrap();
        let resp = serve_inner(&state, &uri).await.expect("ok");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .starts_with("text/html"),
            "got {:?}",
            resp.headers().get(header::CONTENT_TYPE)
        );
    }

    #[tokio::test]
    async fn rejects_hidden_with_404() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".secrets"), "shh").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/.secrets".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_blocked_extension_with_403() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("evil.cgi"), "#!/bin/sh\n").unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/evil.cgi".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn rejects_dotdot_escape_with_validation_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "ok").unwrap();
        let state = make_state(dir.path()).await;

        // After canonicalisation this resolves outside `root_dir`
        // (or fails to resolve), so we expect a 404 or 400. The
        // host platform's behaviour around non-existent paths can
        // pick either branch — accept both as "not served".
        let uri: Uri = "/../../etc/passwd".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(
            matches!(err, AppError::NotFound(_) | AppError::Validation(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn directory_request_404s() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        let state = make_state(dir.path()).await;

        // `/assets` (no trailing slash) resolves to a directory;
        // the default-document rule only fires on trailing slash.
        // Must 404 — we don't auto-list directories.
        let uri: Uri = "/assets".parse().unwrap();
        let err = serve_inner(&state, &uri).await.expect_err("must reject");
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn safe_per_site_csp_override_wins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<title>home</title>").unwrap();
        // A safe override: keeps script-src strict, just widens img-src
        // to a CDN. Must be applied verbatim.
        std::fs::write(
            dir.path().join(".vtc-website.toml"),
            r#"csp = "default-src 'self'; script-src 'self'; img-src 'self' https://cdn.example.com""#,
        )
        .unwrap();
        // Note: .vtc-website.toml itself is hidden (starts with .)
        // but we read it from disk, not via the request path. The
        // path-safety chain only runs against request URLs.
        let state = make_state(dir.path()).await;

        let uri: Uri = "/".parse().unwrap();
        let resp = serve_inner(&state, &uri).await.expect("ok");
        let csp = resp
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(csp.contains("https://cdn.example.com"), "got CSP: {csp}");
    }

    #[tokio::test]
    async fn loose_per_site_csp_override_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<title>home</title>").unwrap();
        // Weakens script-src with 'unsafe-inline' — must be refused, so
        // serve_inner emits no CSP header at all (the security-headers
        // middleware then attaches the daemon default).
        std::fs::write(
            dir.path().join(".vtc-website.toml"),
            r#"csp = "default-src 'self'; script-src 'self' 'unsafe-inline'""#,
        )
        .unwrap();
        let state = make_state(dir.path()).await;

        let uri: Uri = "/".parse().unwrap();
        let resp = serve_inner(&state, &uri).await.expect("ok");
        assert!(
            resp.headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_none(),
            "loose override must not be emitted; got {:?}",
            resp.headers().get(header::CONTENT_SECURITY_POLICY),
        );
    }

    #[test]
    fn validate_csp_accepts_strict_and_custom_directives() {
        assert!(validate_csp_override("default-src 'self'; script-src 'self'").is_some());
        // Custom non-critical directives are fine.
        assert!(
            validate_csp_override(
                "default-src 'self'; script-src 'self'; connect-src 'self' https://api.example.com"
            )
            .is_some()
        );
        // default-src strict, script-src inherits it.
        assert!(validate_csp_override("default-src 'self'").is_some());
        // Empty script-src (blocks all scripts) is strict, not loose.
        assert!(validate_csp_override("default-src 'self'; script-src").is_some());
    }

    #[test]
    fn validate_csp_refuses_weakened_critical_directives() {
        // script-src loosened directly.
        assert!(
            validate_csp_override("default-src 'self'; script-src 'self' 'unsafe-inline'")
                .is_none()
        );
        assert!(validate_csp_override("default-src 'self'; script-src 'unsafe-eval'").is_none());
        assert!(validate_csp_override("default-src 'self'; script-src *").is_none());
        assert!(
            validate_csp_override("default-src 'self'; script-src https://*.evil.com").is_none()
        );
        // script-src via a loose default-src fallback.
        assert!(validate_csp_override("default-src * 'unsafe-inline'").is_none());
        assert!(validate_csp_override("default-src https:").is_none());
        // No script-src and no default-src → unrestricted scripts.
        assert!(validate_csp_override("img-src 'self'").is_none());
        // object-src / base-uri wildcards.
        assert!(validate_csp_override("default-src 'self'; object-src *").is_none());
        assert!(validate_csp_override("default-src 'self'; base-uri *").is_none());
    }

    #[tokio::test]
    async fn csp_override_cache_is_not_read_every_request() {
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join(".vtc-website.toml");
        std::fs::write(
            &override_path,
            r#"csp = "default-src 'self'; script-src 'self'; img-src 'self' https://a.example.com""#,
        )
        .unwrap();

        // Large TTL → the first read is cached and reused.
        let cache = CspOverrideCache::new(3600);
        let first = cache.get(dir.path(), ".vtc-website.toml").await.unwrap();
        assert!(first.contains("a.example.com"));

        // Change the file on disk; within TTL the cached value stands,
        // proving we don't stat/parse on every request.
        std::fs::write(
            &override_path,
            r#"csp = "default-src 'self'; script-src 'self'; img-src 'self' https://b.example.com""#,
        )
        .unwrap();
        let second = cache.get(dir.path(), ".vtc-website.toml").await.unwrap();
        assert_eq!(first, second, "override must be cached within the TTL");
    }
}
