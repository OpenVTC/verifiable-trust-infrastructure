//! Admin UX route surface (§12.2, Phase 5 M5.7).
//!
//! Two handlers:
//!
//! - **Catch-all** (`GET /admin/*`) → serves the baked SPA from
//!   [`crate::admin_ui`]. SPA history-mode fallback: paths that
//!   don't match a baked file fall back to `index.html` so
//!   client-side routing works.
//! - **Build-info** (`GET /admin/build-info.json`) → returns the
//!   embedded directory's SHA-256 + file count + mode. Unauth —
//!   the daemon's release metadata is public.

#![cfg(feature = "admin-ui")]

use std::path::{Path as StdPath, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::warn;

use crate::admin_ui::AdminUiInfo;
use crate::server::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    pub version: String,
    pub index_sha256: String,
    pub file_count: u32,
    pub mode: String,
}

/// `GET /admin/build-info.json` — unauth, surfaces what's baked.
pub async fn build_info(State(state): State<AppState>) -> Json<BuildInfo> {
    let mode = state.config.read().await.admin_ui.mode.clone();
    let info = AdminUiInfo::from_embedded(&mode);
    Json(BuildInfo {
        // The admin SPA carries its own internal version, but
        // the embedded build's SHA-256 is what an operator
        // actually pins against.
        version: env!("CARGO_PKG_VERSION").to_string(),
        index_sha256: (*info.index_sha256).clone(),
        file_count: info.file_count,
        mode: (*info.mode).clone(),
    })
}

/// `GET /admin/*` — serve the baked SPA. When
/// `admin_ui.mode = "external"` this handler is skipped at route
/// attach time and `/admin/*` returns 404.
pub async fn serve_spa(req: Request<Body>) -> Response {
    crate::admin_ui::serve(req).await
}

/// Manifest entry the admin SPA's plugin loader iterates over to
/// dynamically `import()` each third-party plugin's entry module.
///
/// Mirrors the shape of `PluginManifest` in the admin SPA's
/// `plugin-api.ts` for the fields a third-party plugin needs to
/// register itself: `id`, `label`, `path`, `entry`, plus optional
/// `icon` + `scopes`. The plugin's entry JS calls
/// `window.VtcPluginApi.registerPlugin({...})` to wire its UI into
/// the shell's router and nav.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifestEntry {
    pub id: String,
    pub label: String,
    pub path: String,
    /// Absolute URL the shell `import()`s. Daemon-served plugins
    /// resolve to `/admin/plugins/<id>/<file>`.
    pub entry: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginsManifestResponse {
    pub plugins: Vec<PluginManifestEntry>,
}

/// Short-TTL cache of plugin-directory scans, keyed by the configured
/// `plugin_dir` so a runtime config change rescans rather than serving
/// a stale set. Keeps the **unauth** `/admin/plugins.json` route from
/// doing a `readdir` + read-every-manifest on every request (a disk-
/// amplification lever). The map holds one entry per distinct
/// `plugin_dir` ever configured (≈1 for a running daemon).
struct PluginScanEntry {
    scanned_at: Instant,
    plugins: Vec<PluginManifestEntry>,
}

static PLUGIN_SCAN_CACHE: LazyLock<RwLock<std::collections::HashMap<PathBuf, PluginScanEntry>>> =
    LazyLock::new(|| RwLock::new(std::collections::HashMap::new()));

const PLUGIN_SCAN_TTL: Duration = Duration::from_secs(30);

/// `GET /admin/plugins.json` — third-party plugin manifest.
///
/// Scans `admin_ui.plugin_dir` (if configured) for subdirectories;
/// each subdirectory whose ID matches `^[a-z][a-z0-9-]*$` and which
/// contains a readable `manifest.json` becomes a plugin in the
/// response. IDs that fail the regex, manifests that fail to parse,
/// or paths that escape the plugin root are dropped silently (with
/// a `warn!`) so one malformed plugin can't take down the manifest
/// surface. The scan result is cached for [`PLUGIN_SCAN_TTL`].
///
/// Unauth on purpose: knowing which plugins are installed is not
/// sensitive, and the shell fetches the manifest before login.
pub async fn plugins_manifest(State(state): State<AppState>) -> Json<PluginsManifestResponse> {
    let plugin_dir = state.config.read().await.admin_ui.plugin_dir.clone();
    let Some(plugin_dir) = plugin_dir else {
        return Json(PluginsManifestResponse { plugins: vec![] });
    };

    Json(PluginsManifestResponse {
        plugins: scan_plugin_dir_cached(&plugin_dir).await,
    })
}

/// [`scan_plugin_dir`] behind the [`PLUGIN_SCAN_CACHE`] TTL.
async fn scan_plugin_dir_cached(plugin_dir: &StdPath) -> Vec<PluginManifestEntry> {
    if let Some(entry) = PLUGIN_SCAN_CACHE.read().await.get(plugin_dir)
        && entry.scanned_at.elapsed() < PLUGIN_SCAN_TTL
    {
        return entry.plugins.clone();
    }
    let plugins = scan_plugin_dir(plugin_dir);
    PLUGIN_SCAN_CACHE.write().await.insert(
        plugin_dir.to_path_buf(),
        PluginScanEntry {
            scanned_at: Instant::now(),
            plugins: plugins.clone(),
        },
    );
    plugins
}

fn scan_plugin_dir(plugin_dir: &StdPath) -> Vec<PluginManifestEntry> {
    let entries = match std::fs::read_dir(plugin_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                path = %plugin_dir.display(),
                error = %e,
                "admin_ui.plugin_dir is set but unreadable — no third-party plugins served"
            );
            return Vec::new();
        }
    };

    let mut plugins = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(id) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !is_valid_plugin_id(id) {
            warn!(id, "skipping plugin: id does not match ^[a-z][a-z0-9-]*$");
            continue;
        }
        let manifest_path = path.join("manifest.json");
        let raw = match std::fs::read_to_string(&manifest_path) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    id,
                    path = %manifest_path.display(),
                    error = %e,
                    "skipping plugin: manifest.json unreadable"
                );
                continue;
            }
        };
        let mut manifest: DiskManifest = match serde_json::from_str(&raw) {
            Ok(m) => m,
            Err(e) => {
                warn!(id, error = %e, "skipping plugin: manifest.json malformed");
                continue;
            }
        };
        // Operators don't have to repeat the id in the manifest;
        // we infer it from the directory name. If they do provide
        // one and it mismatches, take the directory as authoritative.
        if manifest.id.as_deref() != Some(id) {
            manifest.id = Some(id.to_string());
        }

        // Compose the entry URL from the plugin id + the entry
        // file the manifest declared. Refuse anything that tries
        // to escape the plugin's own directory.
        let entry_file = manifest.entry.trim_start_matches('/');
        if entry_file.contains("..") || entry_file.is_empty() {
            warn!(
                id,
                entry = entry_file,
                "skipping plugin: entry path traversal"
            );
            continue;
        }

        plugins.push(PluginManifestEntry {
            id: id.to_string(),
            label: manifest.label,
            path: manifest.path,
            entry: format!("/admin/plugins/{id}/{entry_file}"),
            icon: manifest.icon,
            scopes: manifest.scopes.unwrap_or_default(),
        });
    }
    plugins
}

fn is_valid_plugin_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Shape stored on disk under `<plugin_dir>/<id>/manifest.json`.
/// The `id` field is optional in the file — the directory name is
/// authoritative.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiskManifest {
    #[serde(default)]
    id: Option<String>,
    label: String,
    path: String,
    /// Filename inside the plugin directory the shell `import()`s.
    /// Typically `index.js`. Absolute paths / `..` segments are
    /// rejected at scan time.
    entry: String,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

/// `GET /admin/plugins/{id}/*path` — serves files from
/// `<plugin_dir>/<id>/<path>`. ID + path both validated against
/// directory-traversal before any IO. Falls through to 404 when
/// `plugin_dir` isn't configured.
pub async fn plugin_asset(
    State(state): State<AppState>,
    Path((id, rel_path)): Path<(String, String)>,
) -> Response {
    if !is_valid_plugin_id(&id) {
        return (StatusCode::NOT_FOUND, "plugin id invalid").into_response();
    }
    // Reject any path component that's exactly `..` — `Path` doesn't
    // resolve traversal by itself.
    if rel_path.contains("..") {
        return (StatusCode::NOT_FOUND, "plugin path traversal").into_response();
    }
    let Some(plugin_dir) = state.config.read().await.admin_ui.plugin_dir.clone() else {
        return (StatusCode::NOT_FOUND, "no plugin_dir configured").into_response();
    };

    let absolute: PathBuf = plugin_dir.join(&id).join(&rel_path);
    // Defence in depth: even after the per-component checks above,
    // make sure the canonical path is still under the plugin root.
    let canonical_root = match plugin_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "plugin_dir not resolvable").into_response(),
    };
    let canonical_abs = match absolute.canonicalize() {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "plugin asset not found").into_response(),
    };
    if !canonical_abs.starts_with(&canonical_root) {
        return (StatusCode::NOT_FOUND, "plugin path escapes root").into_response();
    }

    let bytes = match std::fs::read(&canonical_abs) {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "plugin asset not found").into_response(),
    };
    let mime = mime_guess::from_path(&canonical_abs)
        .first_or_octet_stream()
        .to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "public, max-age=300")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "response build").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_plugin(dir: &StdPath, id: &str, entry: &str) {
        let pdir = dir.join(id);
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(
            pdir.join("manifest.json"),
            format!(r#"{{"label":"{id}","path":"/{id}","entry":"{entry}"}}"#),
        )
        .unwrap();
    }

    #[test]
    fn scan_skips_invalid_ids_and_traversal_entries() {
        let dir = tempfile::tempdir().unwrap();
        write_plugin(dir.path(), "good", "index.js");
        write_plugin(dir.path(), "Bad_Id", "index.js"); // invalid id
        write_plugin(dir.path(), "escape", "../../etc/passwd"); // traversal

        let plugins = scan_plugin_dir(dir.path());
        assert_eq!(plugins.len(), 1, "only the valid plugin survives");
        assert_eq!(plugins[0].id, "good");
        assert_eq!(plugins[0].entry, "/admin/plugins/good/index.js");
    }

    #[tokio::test]
    async fn cached_scan_is_not_reread_within_ttl() {
        let dir = tempfile::tempdir().unwrap();
        write_plugin(dir.path(), "alpha", "index.js");

        // First call populates the cache.
        let first = scan_plugin_dir_cached(dir.path()).await;
        assert_eq!(first.len(), 1);

        // Add a second plugin; within the TTL the cached (single)
        // result still stands, proving we don't readdir every request.
        write_plugin(dir.path(), "beta", "index.js");
        let second = scan_plugin_dir_cached(dir.path()).await;
        assert_eq!(second.len(), 1, "scan must be cached within the TTL");

        // A direct (uncached) scan sees both — confirms the cache, not
        // the scanner, is what hid the new plugin.
        assert_eq!(scan_plugin_dir(dir.path()).len(), 2);
    }
}
