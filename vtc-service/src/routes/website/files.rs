//! `/v1/website/files` handlers (Phase 5 M5.5.1 + M5.5.2).
//!
//! - `GET /v1/website/files` — admin paginated listing.
//! - `GET /v1/website/files/{*path}` — admin file read.
//! - `PUT /v1/website/files/{*path}` — admin write with optional
//!   `If-Match` optimistic concurrency.
//! - `DELETE /v1/website/files/{*path}` — admin delete.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use vti_common::audit::{AuditEvent, WebsiteFileDeletedData, WebsiteFileWrittenData};
use vti_common::auth::AdminAuth;

use crate::error::AppError;
use crate::server::AppState;
use crate::website::paths::{PathError, canonical_within_root, canonical_within_root_for_create};

use super::{WebsiteWriteResponse, require_website_config};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub path: String,
    pub size_bytes: u64,
    pub etag: String,
    pub modified_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub items: Vec<FileEntry>,
    pub next_cursor: Option<String>,
}

/// `GET /v1/website/files`
pub async fn list(
    _admin: AdminAuth,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, AppError> {
    let cfg = require_website_config(&state)?;
    let root_dir = cfg.website.root_dir.clone().expect("guarded above");
    let blocklist = cfg.website.executable_blocklist.clone();
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    let serve_root = match deploy_mode.as_str() {
        "managed" => root_dir.join("current"),
        _ => root_dir,
    };

    let limit = query.limit.unwrap_or(50).clamp(1, 200) as usize;
    let cursor = query.cursor.unwrap_or_default();

    // Walk the tree off the async runtime — O(number of files) stats, with NO
    // file reads or hashing. Hashing (a SHA-256 over each file's full contents)
    // is deferred to only the paginated window below, so a large media bundle
    // no longer costs O(total-site-bytes) on every list — and none of the
    // blocking I/O pins a tokio worker (the previous version did both).
    let root_for_walk = serve_root.clone();
    let bl = blocklist.clone();
    let mut metas = tokio::task::spawn_blocking(move || collect_file_meta(&root_for_walk, &bl))
        .await
        .map_err(|e| AppError::Internal(format!("website file walk task panicked: {e}")))??;
    metas.sort_by(|a, b| a.rel.cmp(&b.rel));

    // Cursor is an opaque path string — next page starts at the first entry
    // whose path > cursor. Paginate on cheap metadata; take one extra to compute
    // next_cursor, then hash ONLY the window that is actually returned.
    let start_idx = match metas.binary_search_by(|m| m.rel.as_str().cmp(cursor.as_str())) {
        Ok(i) => i + 1,
        Err(i) => i,
    };
    let mut window: Vec<FileMeta> = metas.into_iter().skip(start_idx).take(limit + 1).collect();
    let next_cursor = if window.len() > limit {
        Some(window[limit - 1].rel.clone())
    } else {
        None
    };
    window.truncate(limit);

    // Read + SHA-256 exactly the returned window, off the runtime.
    let items = tokio::task::spawn_blocking(move || hash_window(window))
        .await
        .map_err(|e| AppError::Internal(format!("website file hash task panicked: {e}")))?;

    Ok(Json(ListResponse { items, next_cursor }))
}

/// Per-file metadata gathered by the (blocking) tree walk — everything a listing
/// needs EXCEPT the etag. The etag is a SHA-256 over the file's full contents, so
/// it is computed only for the paginated window (see [`hash_window`]), never for
/// the whole tree.
struct FileMeta {
    /// Path relative to the serve root, forward-slashed — the listing key.
    rel: String,
    /// Absolute path, for reading the file when its etag is finally computed.
    abs: PathBuf,
    size_bytes: u64,
    modified_at: u64,
}

/// Walk `root` and collect metadata for every servable file. Blocking (one
/// `stat` per entry) but **O(number of files), not O(bytes)** — no file is read
/// here. Call under `spawn_blocking`.
fn collect_file_meta(root: &Path, blocklist: &[String]) -> Result<Vec<FileMeta>, AppError> {
    use std::time::UNIX_EPOCH;

    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let dir_entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in dir_entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Hidden files / dirs (leading `.`) are excluded from
            // listings to match the public handler.
            if name_str.starts_with('.') {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            // Skip files whose extension is in the blocklist — the
            // public handler would refuse to serve them, so the
            // listing shouldn't tease them.
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                let dotted = format!(".{}", ext.to_ascii_lowercase());
                if blocklist.iter().any(|b| b.eq_ignore_ascii_case(&dotted)) {
                    continue;
                }
            }
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let modified_at = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.push(FileMeta {
                rel: rel_str,
                abs: path,
                size_bytes: meta.len(),
                modified_at,
            });
        }
    }
    Ok(out)
}

/// Read + SHA-256 exactly the files in `window`, producing the `FileEntry` rows.
/// Blocking (file reads + hashing); call under `spawn_blocking`. A file that
/// can't be read is dropped from the page — the same skip-on-read-error
/// behaviour the previous single-pass handler had.
fn hash_window(window: Vec<FileMeta>) -> Vec<FileEntry> {
    window
        .into_iter()
        .filter_map(|m| {
            let bytes = std::fs::read(&m.abs).ok()?;
            Some(FileEntry {
                path: m.rel,
                size_bytes: m.size_bytes,
                etag: hex::encode(Sha256::digest(&bytes)),
                modified_at: m.modified_at,
            })
        })
        .collect()
}

/// `GET /v1/website/files/{*path}`
pub async fn show(
    _admin: AdminAuth,
    State(state): State<AppState>,
    AxumPath(path): AxumPath<String>,
) -> Result<axum::response::Response, AppError> {
    let resolved = resolve_or_400(&state, &path).await?;
    let bytes = tokio::fs::read(&resolved)
        .await
        .map_err(|e| AppError::Internal(format!("read {resolved:?}: {e}")))?;
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&bytes)));
    let mime = mime_guess::from_path(&resolved)
        .first_or_octet_stream()
        .to_string();
    let resp = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::ETAG, etag.clone())
        .header("x-website-etag", etag)
        .body(axum::body::Body::from(bytes))
        .map_err(|e| AppError::Internal(format!("build response: {e}")))?;
    Ok(resp)
}

/// `PUT /v1/website/files/{*path}`
pub async fn write(
    _admin: AdminAuth,
    State(state): State<AppState>,
    AxumPath(path): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<WebsiteWriteResponse>), AppError> {
    let cfg = state.config.read().await;
    let max_size = cfg.website.max_file_size_mb.saturating_mul(1024 * 1024);
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let blocklist = cfg.website.executable_blocklist.clone();
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    if (body.len() as u64) > max_size {
        return Err(AppError::Validation(format!(
            "body size {} exceeds max_file_size_mb",
            body.len()
        )));
    }

    // Live mode writes directly into root_dir. Managed mode
    // refuses single-file writes because every change has to land
    // in a new generation; the operator must use POST /deploy.
    if deploy_mode == "managed" {
        return Err(AppError::Validation(
            "single-file writes are not supported in managed deploy mode; use POST /v1/website/deploy".into(),
        ));
    }

    // Path safety FIRST — the target may not exist yet, so run the
    // full safety chain (control/NFC, hidden, blocklist, contained-
    // within-root) via the create-aware validator *before* touching
    // the filesystem. Rejecting first, creating second, is what stops
    // a PUT like `.../../foo/x` from `mkdir`-ing outside the root
    // before the escape check, and stops `.htaccess` / `evil.php` /
    // `.git/config` writes that `deploy` + `serve` already refuse.
    let req_path = format!("/{}", path.trim_start_matches('/'));
    let target = canonical_within_root_for_create(&root_dir, &req_path, &blocklist)
        .map_err(|e| write_path_error(&path, e))?;

    // Only now, after validation passed, create the parent dirs.
    if let Some(parent) = target.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| AppError::Internal(format!("mkdir -p {parent:?}: {e}")))?;
    }

    // Optional If-Match optimistic concurrency.
    if let Some(if_match) = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()) {
        let current = match tokio::fs::read(&target).await {
            Ok(b) => Some(format!("\"{}\"", hex::encode(Sha256::digest(&b)))),
            Err(_) => None,
        };
        let stripped = if_match.trim_matches('"');
        let matches = current
            .as_ref()
            .map(|c| c.trim_matches('"') == stripped)
            .unwrap_or(false);
        if !matches {
            return Err(AppError::Conflict(format!(
                "If-Match {if_match} does not match the current ETag for {path}"
            )));
        }
    }

    // Atomic single-file write: write to a temp file in the same
    // directory, then rename.
    let digest_hex = hex::encode(Sha256::digest(&body));
    let etag = format!("\"{}\"", digest_hex);
    let size_bytes = body.len() as u64;

    let tmp = target.with_extension(format!(
        "{}.tmp.{}",
        target
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("file"),
        rand_suffix(),
    ));
    tokio::fs::write(&tmp, &body)
        .await
        .map_err(|e| AppError::Internal(format!("write tmp {tmp:?}: {e}")))?;
    tokio::fs::rename(&tmp, &target)
        .await
        .map_err(|e| AppError::Internal(format!("rename {tmp:?} -> {target:?}: {e}")))?;

    if let Some(writer) = state.audit_writer.as_ref() {
        let _ = writer
            .write(
                "admin",
                None,
                AuditEvent::WebsiteFileWritten(WebsiteFileWrittenData {
                    path: path.clone(),
                    size_bytes,
                    sha256: digest_hex.clone(),
                }),
            )
            .await;
    }

    Ok((
        StatusCode::OK,
        Json(WebsiteWriteResponse {
            path,
            etag,
            size_bytes,
        }),
    ))
}

/// `DELETE /v1/website/files/{*path}`
pub async fn delete(
    _admin: AdminAuth,
    State(state): State<AppState>,
    AxumPath(path): AxumPath<String>,
) -> Result<StatusCode, AppError> {
    let resolved = resolve_or_400(&state, &path).await?;
    tokio::fs::remove_file(&resolved)
        .await
        .map_err(|e| AppError::Internal(format!("delete {resolved:?}: {e}")))?;

    if let Some(writer) = state.audit_writer.as_ref() {
        let _ = writer
            .write(
                "admin",
                None,
                AuditEvent::WebsiteFileDeleted(WebsiteFileDeletedData { path: path.clone() }),
            )
            .await;
    }
    Ok(StatusCode::OK)
}

/// Map a [`PathError`] from the create-path validator to the HTTP
/// response for `PUT`. Mirrors [`resolve_or_400`]: a blocklisted
/// extension is a 403, a hidden target a 404, everything else a 400.
fn write_path_error(path: &str, err: PathError) -> AppError {
    match err {
        PathError::BlockedExtension(ext) => {
            AppError::Forbidden(format!("extension {ext} is blocklisted"))
        }
        PathError::Hidden => AppError::NotFound(format!("no such file: {path}")),
        _ => AppError::Validation(format!("path rejected by website path-safety: {path}")),
    }
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}

async fn resolve_or_400(state: &AppState, path: &str) -> Result<PathBuf, AppError> {
    let cfg = state.config.read().await;
    let root_dir = cfg
        .website
        .root_dir
        .clone()
        .ok_or_else(|| AppError::Validation("website.root_dir is not configured".into()))?;
    let blocklist = cfg.website.executable_blocklist.clone();
    let deploy_mode = cfg.website.deploy_mode.clone();
    drop(cfg);

    let serve_root = match deploy_mode.as_str() {
        "managed" => root_dir.join("current"),
        _ => root_dir,
    };

    let req_path = format!("/{}", path.trim_start_matches('/'));
    match canonical_within_root(&serve_root, &req_path, &blocklist) {
        Ok(p) => Ok(p),
        Err(PathError::NotFound) | Err(PathError::Hidden) => {
            Err(AppError::NotFound(format!("no such file: {path}")))
        }
        Err(PathError::BlockedExtension(ext)) => Err(AppError::Forbidden(format!(
            "extension {ext} is blocklisted"
        ))),
        Err(_) => Err(AppError::Validation(format!(
            "path rejected by website path-safety: {path}"
        ))),
    }
}

// Suppress unused-import warning for IntoResponse — used through
// `Json::into_response` implicitly via the `?` mapping.
#[allow(dead_code)]
fn _unused(_x: impl IntoResponse) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The D9 fix's core: the tree walk gathers metadata WITHOUT reading/hashing
    /// files (hidden + blocklisted still excluded), and `hash_window` computes the
    /// SHA-256 etag only for the files handed to it — never the whole tree.
    #[test]
    fn walk_gathers_metadata_and_hash_window_hashes_only_the_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(root.join("index.html"), b"<h1>hi</h1>").unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets").join("app.js"), b"console.log(1)").unwrap();
        fs::write(root.join("deploy.sh"), b"#!/bin/sh").unwrap(); // blocklisted
        fs::write(root.join(".hidden"), b"secret").unwrap(); // hidden

        let blocklist = vec![".sh".to_string()];
        let mut metas = collect_file_meta(root, &blocklist).expect("walk");
        metas.sort_by(|a, b| a.rel.cmp(&b.rel));

        // Hidden + blocklisted excluded; rel paths forward-slashed.
        let rels: Vec<&str> = metas.iter().map(|m| m.rel.as_str()).collect();
        assert_eq!(rels, vec!["assets/app.js", "index.html"]);
        assert_eq!(
            metas
                .iter()
                .find(|m| m.rel == "index.html")
                .unwrap()
                .size_bytes,
            11
        );

        // hash_window computes the etag only for what it's given.
        let entries = hash_window(metas);
        assert_eq!(entries.len(), 2);
        let idx = entries.iter().find(|e| e.path == "index.html").unwrap();
        assert_eq!(idx.etag, hex::encode(Sha256::digest(b"<h1>hi</h1>")));
        assert_eq!(idx.size_bytes, 11);
    }
}
