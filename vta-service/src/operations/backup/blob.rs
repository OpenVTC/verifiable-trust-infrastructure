//! Op-layer for the backup-blob byte transport (`GET/POST /backup/blob/{id}`).
//!
//! The token-gated state machine that moves the staged `.vtabak` bytes —
//! GET streams an export bundle (one-shot, delete-before-flip), POST
//! accepts an import upload (size + SHA-256 verified) — lives here. The
//! HTTP route adapters in `routes/backup_blob.rs` handle only transport
//! concerns (path/header parsing, body cap, response framing) and
//! delegate the state machine to these two functions.
//!
//! See `docs/05-design-notes/backup-descriptor-pattern.md` for the full
//! state machine, and §"Auth model" for why the bearer token — not a
//! JWT — is the authenticator.

use std::path::Path;

use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::backup_bundle_store::{self, BundleKind, BundleRecord, BundleState, verify_token};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Download the encrypted bytes of an export bundle. One-shot: on
/// success the record transitions to `ExportDownloaded` (terminal) and
/// the bytes are removed from disk.
///
/// Returns the staged bytes; the route adapter frames them as an
/// `application/octet-stream` attachment.
///
/// Failure modes (the route maps the `AppError` variants to HTTP status):
/// - bundle_id not found → `NotFound`
/// - token doesn't match the stored hash → `Forbidden`
/// - bundle is an import bundle, or already-downloaded / aborted /
///   expired → `NotFound` / `Conflict` (see [`enforce_export_ready`])
/// - bundle expired by clock → `Conflict` (410-style, via [`gone`])
/// - blob bytes missing on disk → `Conflict` (already swept)
pub async fn read_export_blob(
    bundles_ks: &KeyspaceHandle,
    bundle_id: Uuid,
    token: &str,
) -> Result<Vec<u8>, AppError> {
    let mut record = match backup_bundle_store::get_bundle(bundles_ks, &bundle_id).await? {
        Some(r) => r,
        None => {
            warn!(bundle_id = %bundle_id, "GET blob: bundle not found");
            return Err(AppError::NotFound(format!("bundle not found: {bundle_id}")));
        }
    };

    enforce_token(&record, token)?;
    enforce_export_ready(&record)?;
    enforce_not_expired(&record)?;

    let blob_path = record
        .blob_path
        .clone()
        .ok_or_else(|| AppError::Internal(format!("bundle {bundle_id} has no blob path")))?;

    let bytes = match tokio::fs::read(&blob_path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                bundle_id = %bundle_id,
                path = %blob_path.display(),
                "GET blob: file missing on disk; bundle treated as expired"
            );
            return Err(gone(format!("bundle {bundle_id} expired (blob missing)")));
        }
        Err(e) => return Err(AppError::Io(e)),
    };

    // One-shot semantics: bytes are gone after this call. We delete
    // the file BEFORE flipping the state so a crash mid-transition
    // leaves the bytes deleted and the state recoverable on next
    // boot's sweeper pass.
    if let Err(e) = tokio::fs::remove_file(&blob_path).await {
        // Best-effort: failure to delete is not fatal — the sweeper
        // will clean up. But log loud since the file is now
        // operator-visible after the response.
        warn!(
            bundle_id = %bundle_id,
            path = %blob_path.display(),
            error = %e,
            "GET blob: failed to delete blob after read; sweeper will retry"
        );
    }
    record.state = BundleState::ExportDownloaded;
    record.blob_path = None;
    backup_bundle_store::store_bundle(bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, bytes = bytes.len(), "GET blob: served");

    Ok(bytes)
}

/// Accept the encrypted upload for an import bundle. The body's
/// SHA-256 must match the record's `expected_sha256`; the byte count
/// must match `expected_size_bytes`. On success the state moves to
/// `ImportReceived` (no further uploads accepted against this
/// bundle_id).
///
/// Multi-shot until the first successful upload — a failed upload
/// (mismatched hash or interrupted transfer) can be retried without
/// re-running `initiate-import`.
///
/// Failure modes mirror [`read_export_blob`], plus:
/// - body size doesn't match `expected_size_bytes` → `Validation`
/// - body SHA-256 doesn't match `expected_sha256` → `Validation`
/// - I/O error staging to disk → `Io`
pub async fn write_import_blob(
    bundles_ks: &KeyspaceHandle,
    blob_dir: &Path,
    bundle_id: Uuid,
    token: &str,
    bytes: &[u8],
) -> Result<(), AppError> {
    let mut record = match backup_bundle_store::get_bundle(bundles_ks, &bundle_id).await? {
        Some(r) => r,
        None => {
            warn!(bundle_id = %bundle_id, "POST blob: bundle not found");
            return Err(AppError::NotFound(format!("bundle not found: {bundle_id}")));
        }
    };

    enforce_token(&record, token)?;
    enforce_import_pending(&record)?;
    enforce_not_expired(&record)?;

    if bytes.len() as u64 != record.expected_size_bytes {
        return Err(AppError::Validation(format!(
            "upload size mismatch for bundle {bundle_id}: expected {} bytes, got {}",
            record.expected_size_bytes,
            bytes.len()
        )));
    }

    let actual_sha = sha256_hex(bytes);
    if actual_sha != record.expected_sha256 {
        return Err(AppError::Validation(format!(
            "upload integrity check failed for bundle {bundle_id}: \
             expected sha256={}, got {}",
            record.expected_sha256, actual_sha
        )));
    }

    // Stage the bytes on disk. Ensure the blob dir exists; this is
    // the first place that may need to create it (export-side
    // creates at descriptor mint time).
    tokio::fs::create_dir_all(blob_dir)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    set_dir_mode_700(blob_dir).await?;

    let blob_path = blob_dir.join(format!("{bundle_id}.vtabak"));
    tokio::fs::write(&blob_path, bytes)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    set_file_mode_600(&blob_path).await?;

    record.state = BundleState::ImportReceived;
    record.blob_path = Some(blob_path);
    backup_bundle_store::store_bundle(bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, bytes = bytes.len(), "POST blob: accepted");

    Ok(())
}

// ─── State-machine guards ──────────────────────────────────────────────

fn enforce_token(record: &BundleRecord, provided: &str) -> Result<(), AppError> {
    if !verify_token(provided, &record.token_hash) {
        return Err(AppError::Forbidden(format!(
            "token does not match for bundle {}",
            record.bundle_id
        )));
    }
    Ok(())
}

fn enforce_not_expired(record: &BundleRecord) -> Result<(), AppError> {
    if record.expires_at < Utc::now() {
        return Err(gone(format!(
            "bundle {} expired at {}",
            record.bundle_id, record.expires_at
        )));
    }
    Ok(())
}

fn enforce_export_ready(record: &BundleRecord) -> Result<(), AppError> {
    if record.kind != BundleKind::Export {
        // Treat as not-found — the bundle exists but doesn't fit
        // this endpoint's verb. Don't leak the kind.
        return Err(AppError::NotFound(format!(
            "bundle not found: {}",
            record.bundle_id
        )));
    }
    match record.state {
        BundleState::ExportReady => Ok(()),
        BundleState::ExportDownloaded => Err(gone(format!(
            "bundle {} already downloaded (one-shot)",
            record.bundle_id
        ))),
        BundleState::Aborted => Err(gone(format!("bundle {} was aborted", record.bundle_id))),
        BundleState::Expired => Err(gone(format!("bundle {} expired", record.bundle_id))),
        _ => Err(AppError::Conflict(format!(
            "bundle {} is in state {:?}, not ready for download",
            record.bundle_id, record.state
        ))),
    }
}

fn enforce_import_pending(record: &BundleRecord) -> Result<(), AppError> {
    if record.kind != BundleKind::Import {
        return Err(AppError::NotFound(format!(
            "bundle not found: {}",
            record.bundle_id
        )));
    }
    match record.state {
        BundleState::ImportPending => Ok(()),
        BundleState::ImportReceived
        | BundleState::ImportPreviewed
        | BundleState::ImportCommitted => Err(AppError::Conflict(format!(
            "bundle {} upload already accepted",
            record.bundle_id
        ))),
        BundleState::Aborted => Err(gone(format!("bundle {} was aborted", record.bundle_id))),
        BundleState::Expired => Err(gone(format!("bundle {} expired", record.bundle_id))),
        _ => Err(AppError::Conflict(format!(
            "bundle {} is in state {:?}, not ready for upload",
            record.bundle_id, record.state
        ))),
    }
}

fn gone(message: String) -> AppError {
    // `AppError` doesn't have a `Gone` variant. The blob endpoints
    // want 410 specifically so the operator CLI can distinguish
    // "this slot was valid but is now consumed/expired" from
    // "this slot never existed" (404). Map via `Conflict` for now —
    // a follow-on can add a typed variant if the CLI surface
    // requires it.
    AppError::Conflict(message)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(unix)]
async fn set_dir_mode_700(path: &std::path::Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    tokio::fs::set_permissions(path, perms)
        .await
        .map_err(AppError::Io)
}

#[cfg(unix)]
async fn set_file_mode_600(path: &std::path::Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(path, perms)
        .await
        .map_err(AppError::Io)
}
