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
//! `admin-ui/` and rebuild — or, without rebuilding the daemon, set
//! `admin_ui.mode = "directory"` and serve the console from
//! `admin_ui.dir` ([`serve_dir`]). `vtc admin-ui export <dir>`
//! ([`export`]) writes the baked console out as the starting point.

#![cfg(feature = "admin-ui")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::Response;
use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};

/// In-binary copy of the Vite build output. Produced by `build.rs`
/// running `npm run build` before this file compiles. Walked at
/// request time to map paths → file bytes. The admin SPA is a
/// React app; client-side routing (history mode) means most paths
/// resolve to `index.html` and the shell takes over.
///
/// The bundle lives under `$OUT_DIR`, not `admin-ui/dist`, because
/// `include_dir!` makes every file here a compile input of this
/// lib — so a build script that regenerated them in the source
/// tree recompiled the whole crate on every `cargo build` (#1243).
/// `build.rs` owns the directory name; keep it in step with the
/// `BAKED_DIR` const there.
pub static ADMIN_UI_DIR: Dir<'_> = include_dir!("$OUT_DIR/admin-ui-dist");

/// In-binary copy of the **member portal** bundle (`vite.members.config.ts`),
/// served at `/members/*`. A separate application from the console: its own
/// bundle, its own sessions (`crate::member_portal`). `build.rs` owns the
/// directory name (`MEMBER_BAKED_DIR`).
pub static MEMBER_UI_DIR: Dir<'_> = include_dir!("$OUT_DIR/member-ui-dist");

/// Metadata derived once at startup. Used by the build-info
/// endpoint and the `AdminUiServed` audit envelope.
#[derive(Debug, Clone)]
pub struct AdminUiInfo {
    /// SHA-256 of the baked `index.html`, hex-encoded.
    pub index_sha256: Arc<String>,
    /// Total file count in the baked directory.
    pub file_count: u32,
    /// `"embedded"` (default), `"directory"` or `"external"`.
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

impl AdminUiInfo {
    /// The console actually being served under `config`: the directory's
    /// when `mode = "directory"`, the baked one otherwise. A directory
    /// that cannot be read reports an empty hash and no files rather than
    /// failing — the boot check ([`check_serve_dir`]) is the gate.
    pub fn for_config(config: &crate::config::AdminUiConfig) -> Self {
        match config.serve_dir() {
            Some(dir) => Self::from_directory(dir, &config.mode),
            None => Self::from_embedded(&config.mode),
        }
    }

    /// Compute from a console directory on disk.
    pub fn from_directory(dir: &Path, mode: &str) -> Self {
        let index_sha256 = std::fs::read(dir.join("index.html"))
            .map(|b| hex::encode(Sha256::digest(b)))
            .unwrap_or_default();
        Self {
            index_sha256: Arc::new(index_sha256),
            file_count: count_files_on_disk(dir),
            mode: Arc::new(mode.to_string()),
        }
    }
}

fn count_files_on_disk(dir: &Path) -> u32 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total: u32 = 0;
    for entry in entries.flatten() {
        // `file_type` does not follow symlinks, so a link cycle cannot
        // recurse forever; a linked file or directory is not counted.
        match entry.file_type() {
            Ok(t) if t.is_file() => total = total.saturating_add(1),
            Ok(t) if t.is_dir() => total = total.saturating_add(count_files_on_disk(&entry.path())),
            _ => {}
        }
    }
    total
}

/// Boot check for `admin_ui.mode = "directory"` and `admin_ui.members_dir`:
/// the directory must hold a
/// readable `index.html`, and neither may be world-writable. The console's
/// scripts run with the administrator's session and sign with their console
/// key (the portal's, with the member's session), so whoever can write that
/// directory can act as everyone who next opens it; a world-writable one
/// hands that to every local user. Fails closed — a VTC does not start serving a console it
/// cannot vouch for, nor silently fall back to the baked one.
pub fn check_serve_dir(dir: &Path) -> Result<(), String> {
    let index = dir.join("index.html");
    let meta = std::fs::metadata(&index).map_err(|e| {
        format!(
            "{}: cannot read index.html ({e}) — `vtc admin-ui export [--members] {}` \
             writes the built-in one there to start from",
            dir.display(),
            dir.display()
        )
    })?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", index.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [dir, index.as_path()] {
            let mode = std::fs::metadata(path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o002 != 0 {
                return Err(format!(
                    "{} is world-writable — anyone on this host could replace the \
                     admin console; run `chmod o-w {}`",
                    path.display(),
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// `vtc admin-ui export [--members] <dir>`: write a baked bundle
/// ([`ADMIN_UI_DIR`] or [`MEMBER_UI_DIR`]) to `dir` so an owner can customise
/// it and serve it with `admin_ui.mode = "directory"` / `admin_ui.members_dir`. Refuses
/// a directory that already holds anything, so an earlier customisation is
/// never overwritten.
pub fn export(dir: &Path, bundle: &'static Dir<'static>) -> Result<(), String> {
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
    bundle
        .extract(dir)
        .map_err(|e| format!("writing to {}: {e}", dir.display()))
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
    lookup_in(&ADMIN_UI_DIR, rel_path)
}

fn lookup_in(dir: &'static Dir<'static>, rel_path: &str) -> Option<&'static [u8]> {
    let trimmed = rel_path.trim_start_matches('/');
    dir.get_file(trimmed).map(|f| f.contents())
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
    serve_from(&ADMIN_UI_DIR, "/admin", "admin UX", req)
}

/// `GET /admin/*` with `admin_ui.mode = "directory"`: the same contract as
/// [`serve`] — shell revalidated, `/assets/*` cached, history-mode fallback
/// to `index.html` — read from `dir` on every request, so an owner's edit
/// shows on the next load. Every path goes through the website's
/// path-safety chain ([`crate::website::paths::canonical_within_root`]):
/// no hidden files, no escaping `dir` (symlinks included), no executables.
pub async fn serve_dir(dir: &Path, req: Request<Body>) -> Response {
    serve_dir_at(dir, "/admin", "admin UX", req).await
}

/// `GET /members/*` with `admin_ui.members_dir` set: [`serve_dir`] for the
/// member portal.
pub async fn serve_members_dir(dir: &Path, req: Request<Body>) -> Response {
    serve_dir_at(dir, "/members", "member portal", req).await
}

async fn serve_dir_at(dir: &Path, mount: &str, what: &str, req: Request<Body>) -> Response {
    let rel = shell_relative(req.uri().path(), mount);
    let (path, served_shell) = match resolve_in_dir(dir, rel) {
        Some(p) => (p, rel == "/index.html"),
        None => match resolve_in_dir(dir, "/index.html") {
            Some(p) => (p, true),
            None => return (StatusCode::NOT_FOUND, format!("{what} not found")).into_response(),
        },
    };
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, format!("{what} not found")).into_response(),
    };
    let mime = if served_shell {
        "text/html; charset=utf-8".to_string()
    } else {
        mime_guess::from_path(&path)
            .first_or_octet_stream()
            .to_string()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache_control_for(rel, served_shell))
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response build").into_response())
}

/// A regular file under `dir` for `rel`, through the path-safety chain;
/// `None` for anything else (missing, a directory, refused).
fn resolve_in_dir(dir: &Path, rel: &str) -> Option<PathBuf> {
    let path = crate::website::paths::canonical_within_root(dir, rel, &[]).ok()?;
    path.is_file().then_some(path)
}

/// The request path relative to `mount`, with the mount itself mapped to the
/// shell.
fn shell_relative<'a>(path: &'a str, mount: &str) -> &'a str {
    let rel = path.strip_prefix(mount).unwrap_or(path);
    if rel.is_empty() || rel == "/" {
        "/index.html"
    } else {
        rel
    }
}

/// Axum handler for `GET /members/*` — the member portal, served exactly as
/// the console is (shell revalidated, hashed assets cached, history-mode
/// fallback).
pub async fn serve_members(req: Request<Body>) -> Response {
    serve_from(&MEMBER_UI_DIR, "/members", "member portal", req)
}

fn serve_from(dir: &'static Dir<'static>, mount: &str, what: &str, req: Request<Body>) -> Response {
    let lookup = |p: &str| lookup_in(dir, p);
    let rel = shell_relative(req.uri().path(), mount);

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
                return (StatusCode::NOT_FOUND, format!("{what} not embedded")).into_response();
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
    fn member_portal_is_embedded_as_its_own_bundle() {
        let index = MEMBER_UI_DIR
            .get_file("index.html")
            .expect("member portal index.html missing — did build:members run?");
        let body = std::str::from_utf8(index.contents()).unwrap();
        assert!(body.contains("<title>VTC Members</title>"), "{body}");
        // Assets resolve under its own mount, not the console's.
        assert!(body.contains("/members/assets/"), "{body}");
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

    fn get(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    async fn body_of(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn console_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<title>Ours</title>").unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/app.css"), "body{}").unwrap();
        dir
    }

    #[tokio::test]
    async fn directory_console_serves_its_files_and_falls_back_to_its_shell() {
        let dir = console_dir();

        let resp = serve_dir(dir.path(), get("/admin/assets/app.css")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/css");
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "public, max-age=300");
        assert_eq!(body_of(resp).await, "body{}");

        // The mount, and an extensionless client-side route, serve the shell.
        for path in ["/admin", "/admin/", "/admin/members/approve"] {
            let resp = serve_dir(dir.path(), get(path)).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(
                resp.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8"
            );
            assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-cache");
            assert_eq!(body_of(resp).await, "<title>Ours</title>", "{path}");
        }

        // An owner's edit shows on the next load — nothing is cached.
        std::fs::write(dir.path().join("index.html"), "<title>Edited</title>").unwrap();
        assert_eq!(
            body_of(serve_dir(dir.path(), get("/admin/")).await).await,
            "<title>Edited</title>"
        );
    }

    #[tokio::test]
    async fn directory_console_never_serves_hidden_or_escaping_files() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        let dir = console_dir();
        std::fs::write(dir.path().join(".env"), "secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            dir.path().join("link.txt"),
        )
        .unwrap();

        for path in ["/admin/.env", "/admin/link.txt", "/admin/../secret.txt"] {
            let body = body_of(serve_dir(dir.path(), get(path)).await).await;
            assert_eq!(body, "<title>Ours</title>", "{path} must get the shell");
        }
    }

    #[tokio::test]
    async fn directory_without_a_shell_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let resp = serve_dir(dir.path(), get("/admin/")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn serve_dir_check_requires_index_and_refuses_world_writable() {
        let empty = tempfile::tempdir().unwrap();
        let err = check_serve_dir(empty.path()).unwrap_err();
        assert!(err.contains("vtc admin-ui export"), "{err}");

        let dir = console_dir();
        check_serve_dir(dir.path()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let index = dir.path().join("index.html");
            std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o666)).unwrap();
            let err = check_serve_dir(dir.path()).unwrap_err();
            assert!(err.contains("world-writable"), "{err}");
        }
    }

    #[test]
    fn export_writes_the_baked_console_and_never_overwrites() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("console");
        export(&target, &ADMIN_UI_DIR).unwrap();

        check_serve_dir(&target).unwrap();
        let exported = AdminUiInfo::from_directory(&target, "directory");
        let baked = AdminUiInfo::from_embedded("embedded");
        assert_eq!(exported.index_sha256, baked.index_sha256);
        assert_eq!(exported.file_count, baked.file_count);

        let err = export(&target, &ADMIN_UI_DIR).unwrap_err();
        assert!(err.contains("not empty"), "{err}");
    }

    #[tokio::test]
    async fn exported_member_portal_serves_under_its_own_mount() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("members");
        export(&target, &MEMBER_UI_DIR).unwrap();
        check_serve_dir(&target).unwrap();

        for path in ["/members", "/members/", "/members/profile"] {
            let body = body_of(serve_members_dir(&target, get(path)).await).await;
            assert!(
                body.contains("<title>VTC Members</title>"),
                "{path}: {body}"
            );
        }
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
