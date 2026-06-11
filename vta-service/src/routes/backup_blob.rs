//! `GET / POST /backup/blob/{bundle_id}` — token-gated byte transport
//! for the backup-descriptor pattern.
//!
//! See `docs/05-design-notes/backup-descriptor-pattern.md` for the
//! full state machine. Brief recap:
//!
//! - `GET` streams the staged `.vtabak` bytes back to a client that
//!   already initiated the export via the trust-task envelope. The
//!   client presents the bearer token issued in the descriptor;
//!   the bytes are deleted on first successful read (one-shot).
//! - `POST` accepts the encrypted `.vtabak` bytes for a previously
//!   initiated import. The token + bundle_id pair binds this upload
//!   to the descriptor the operator received. Multi-shot until the
//!   first successful upload completes; the state machine then
//!   moves to `ImportReceived`.
//!
//! These routes are deliberately NOT JWT-authenticated. The bearer
//! token IS the auth — it's freshly minted, one-shot for GET, bound
//! to `bundle_id` server-side, short-TTL (5min default), and stored
//! hashed so a leaked DB doesn't leak usable credentials. Justified
//! at length in the design doc §"Auth model".

use std::str::FromStr;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::backup_bundle_store::{self, BundleKind, BundleRecord, BundleState, verify_token};
use crate::error::AppError;
use crate::server::AppState;

/// Header name carrying the bundle's bearer token. Matched
/// case-insensitively by axum's header machinery.
const TOKEN_HEADER: &str = "x-backup-token";

/// `GET /backup/blob/{bundle_id}` — download the encrypted bytes of
/// an export bundle. One-shot: on success, the record transitions to
/// `ExportDownloaded` (terminal) and the bytes are removed from disk.
///
/// Failure modes:
/// - Missing or malformed `X-Backup-Token` header → 401
/// - bundle_id not found → 404
/// - Token doesn't match the stored hash → 403
/// - Bundle expired or in any non-`ExportReady` state → 410 Gone
/// - Bundle is an import bundle → 404 (treat as "not found" so we
///   don't leak the existence of a coexisting import bundle with
///   the same id, which can't actually happen — UUIDs collide
///   effectively never — but the response is consistent regardless)
/// - Blob bytes missing on disk → 410 (already swept)
pub async fn get_blob(
    State(state): State<AppState>,
    Path(bundle_id_str): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let bundle_id = parse_bundle_id(&bundle_id_str)?;
    let token = extract_token(&headers)?;

    let mut record =
        match backup_bundle_store::get_bundle(&state.backup_bundles_ks, &bundle_id).await? {
            Some(r) => r,
            None => {
                warn!(bundle_id = %bundle_id, "GET blob: bundle not found");
                return Err(AppError::NotFound(format!("bundle not found: {bundle_id}")));
            }
        };

    enforce_token(&record, &token)?;
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
    backup_bundle_store::store_bundle(&state.backup_bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, bytes = bytes.len(), "GET blob: served");

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/octet-stream"),
            (
                "content-disposition",
                "attachment; filename=\"backup.vtabak\"",
            ),
        ],
        bytes,
    )
        .into_response())
}

/// `POST /backup/blob/{bundle_id}` — upload encrypted bytes for an
/// import bundle. The body's SHA-256 must match the record's
/// `expected_sha256`; the byte count must match `expected_size_bytes`.
///
/// Multi-shot until the first successful upload — i.e., a failed
/// upload (mismatched hash or interrupted transfer) can be retried
/// without re-running `initiate-import`. Once the upload succeeds
/// the state moves to `ImportReceived` (no further uploads accepted
/// against this bundle_id).
///
/// Failure modes mirror GET, plus:
/// - Body size doesn't match `expected_size_bytes` → 400
/// - Body SHA-256 doesn't match `expected_sha256` → 400
/// - I/O error writing to disk → 500
pub async fn post_blob(
    State(state): State<AppState>,
    Path(bundle_id_str): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, AppError> {
    let bundle_id = parse_bundle_id(&bundle_id_str)?;
    let token = extract_token(&headers)?;

    let mut record =
        match backup_bundle_store::get_bundle(&state.backup_bundles_ks, &bundle_id).await? {
            Some(r) => r,
            None => {
                warn!(bundle_id = %bundle_id, "POST blob: bundle not found");
                return Err(AppError::NotFound(format!("bundle not found: {bundle_id}")));
            }
        };

    enforce_token(&record, &token)?;
    enforce_import_pending(&record)?;
    enforce_not_expired(&record)?;

    // Cap applies at this read; the router-level
    // `DefaultBodyLimit::disable()` lets us bypass the global 1 MB
    // limit, and the cap is enforced HERE so the limit lives in
    // one place. Exceeding it surfaces as a 400 with a clear
    // message rather than axum's 413.
    let bytes = axum::body::to_bytes(body, super::BACKUP_BLOB_BODY_SIZE)
        .await
        .map_err(|e| AppError::Validation(format!("read upload body: {e}")))?;

    if bytes.len() as u64 != record.expected_size_bytes {
        return Err(AppError::Validation(format!(
            "upload size mismatch for bundle {bundle_id}: expected {} bytes, got {}",
            record.expected_size_bytes,
            bytes.len()
        )));
    }

    let actual_sha = sha256_hex(&bytes);
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
    tokio::fs::create_dir_all(&state.backup_blob_dir)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    set_dir_mode_700(&state.backup_blob_dir).await?;

    let blob_path = state.backup_blob_dir.join(format!("{bundle_id}.vtabak"));
    tokio::fs::write(&blob_path, &bytes)
        .await
        .map_err(AppError::Io)?;
    #[cfg(unix)]
    set_file_mode_600(&blob_path).await?;

    record.state = BundleState::ImportReceived;
    record.blob_path = Some(blob_path);
    backup_bundle_store::store_bundle(&state.backup_bundles_ks, &record).await?;

    info!(bundle_id = %bundle_id, bytes = bytes.len(), "POST blob: accepted");

    Ok((StatusCode::ACCEPTED, "").into_response())
}

// ─── Internal helpers ──────────────────────────────────────────────────

fn parse_bundle_id(s: &str) -> Result<Uuid, AppError> {
    Uuid::from_str(s).map_err(|e| AppError::Validation(format!("invalid bundle_id `{s}`: {e}")))
}

fn extract_token(headers: &HeaderMap) -> Result<String, AppError> {
    let raw = headers
        .get(TOKEN_HEADER)
        .ok_or_else(|| AppError::Authentication(format!("missing `{TOKEN_HEADER}` header")))?;
    let s = raw
        .to_str()
        .map_err(|e| AppError::Authentication(format!("malformed `{TOKEN_HEADER}` header: {e}")))?;
    if s.is_empty() {
        return Err(AppError::Authentication(format!(
            "empty `{TOKEN_HEADER}` header"
        )));
    }
    Ok(s.to_string())
}

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

#[cfg(test)]
mod tests {
    //! Integration tests for the blob endpoints. Exercise the full
    //! router (`build_test_app`) so the body-cap layer, the token header
    //! extraction, and the state-machine guards all land at the same level
    //! the real service runs.
    //!
    //! Every request carries an `x-forwarded-for` header: the blob branch
    //! is rate-limited (P0.10) and `tower::oneshot` carries no socket peer
    //! IP, so the governor's key extractor needs an explicit client IP
    //! (production requests always have a peer address or a proxy XFF).

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Duration;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::backup_bundle_store::{self, BundleKind, BundleRecord, BundleState, mint_token};

    fn sha256_hex_local(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// Seed an export bundle (state: ExportReady) with `bytes` staged
    /// on disk. Returns (bundle_id, plaintext_token).
    async fn seed_export(
        ctx: &crate::test_support::TestAppContext,
        bytes: &[u8],
    ) -> (Uuid, String) {
        let bundle_id = Uuid::new_v4();
        let (token, token_hash) = mint_token().expect("mint token");
        tokio::fs::create_dir_all(&ctx.backup_blob_dir)
            .await
            .unwrap();
        let path = ctx.backup_blob_dir.join(format!("{bundle_id}.vtabak"));
        tokio::fs::write(&path, bytes).await.unwrap();
        let record = BundleRecord {
            bundle_id,
            kind: BundleKind::Export,
            state: BundleState::ExportReady,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            created_by: "did:example:admin".into(),
            algorithm: "stream".into(),
            expected_sha256: sha256_hex_local(bytes),
            expected_size_bytes: bytes.len() as u64,
            token_hash,
            blob_path: Some(path),
        };
        backup_bundle_store::store_bundle(&ctx.backup_bundles_ks, &record)
            .await
            .unwrap();
        let plaintext = token.as_str().to_string();
        (bundle_id, plaintext)
    }

    /// Seed an import bundle in ImportPending state. Returns
    /// (bundle_id, plaintext_token, expected_sha256).
    async fn seed_import_pending(
        ctx: &crate::test_support::TestAppContext,
        expected_bytes: &[u8],
    ) -> (Uuid, String, String) {
        let bundle_id = Uuid::new_v4();
        let (token, token_hash) = mint_token().expect("mint token");
        let sha = sha256_hex_local(expected_bytes);
        let record = BundleRecord {
            bundle_id,
            kind: BundleKind::Import,
            state: BundleState::ImportPending,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            created_by: "did:example:admin".into(),
            algorithm: "stream".into(),
            expected_sha256: sha.clone(),
            expected_size_bytes: expected_bytes.len() as u64,
            token_hash,
            blob_path: None,
        };
        backup_bundle_store::store_bundle(&ctx.backup_bundles_ks, &record)
            .await
            .unwrap();
        let plaintext = token.as_str().to_string();
        (bundle_id, plaintext, sha)
    }

    #[tokio::test]
    async fn get_blob_returns_bytes_for_valid_token() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let bytes = b"backup-bytes-here".to_vec();
        let (bundle_id, token) = seed_export(&ctx, &bytes).await;

        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), &bytes[..]);

        // Bundle is now in ExportDownloaded; second GET fails.
        let record = backup_bundle_store::get_bundle(&ctx.backup_bundles_ks, &bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, BundleState::ExportDownloaded);
        assert!(record.blob_path.is_none());
    }

    #[tokio::test]
    async fn get_blob_is_one_shot() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let (bundle_id, token) = seed_export(&ctx, b"once").await;

        // First GET succeeds.
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second GET fails — bundle is ExportDownloaded (terminal).
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // gone() maps to AppError::Conflict → 409
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn get_blob_rejects_missing_token() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let (bundle_id, _token) = seed_export(&ctx, b"x").await;
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_blob_rejects_wrong_token() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let (bundle_id, _token) = seed_export(&ctx, b"x").await;
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, "bogus-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_blob_404_for_unknown_id() {
        let (app, _ctx) = crate::test_support::build_test_app().await;
        let req = Request::builder()
            .uri(format!("/backup/blob/{}", Uuid::new_v4()))
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, "any-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_blob_rejects_import_bundle_as_not_found() {
        // An import bundle exists at the same path but GET refuses
        // (treat as not-found to avoid leaking kind).
        let (app, ctx) = crate::test_support::build_test_app().await;
        let (bundle_id, token, _) = seed_import_pending(&ctx, b"data").await;
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_blob_400_for_malformed_uuid() {
        let (app, _ctx) = crate::test_support::build_test_app().await;
        let req = Request::builder()
            .uri("/backup/blob/not-a-uuid")
            .method("GET")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, "x")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_blob_accepts_matching_upload() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let bytes = b"import-bytes".to_vec();
        let (bundle_id, token, _sha) = seed_import_pending(&ctx, &bytes).await;

        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("POST")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::from(bytes.clone()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let record = backup_bundle_store::get_bundle(&ctx.backup_bundles_ks, &bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, BundleState::ImportReceived);
        let blob_path = record.blob_path.expect("blob path populated");
        assert!(blob_path.exists());
        let on_disk = tokio::fs::read(&blob_path).await.unwrap();
        assert_eq!(on_disk, bytes);
    }

    #[tokio::test]
    async fn post_blob_rejects_size_mismatch() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let expected = b"this is what we expect".to_vec();
        let (bundle_id, token, _) = seed_import_pending(&ctx, &expected).await;

        // Upload a shorter payload — size mismatch should reject.
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("POST")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::from(b"short".to_vec()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_blob_rejects_hash_mismatch_with_same_size() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let expected = b"original-content-here".to_vec();
        let (bundle_id, token, _) = seed_import_pending(&ctx, &expected).await;

        // Same size, different content → SHA mismatch.
        let mut tampered = expected.clone();
        tampered[0] ^= 0xFF;
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("POST")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::from(tampered))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_blob_refuses_second_upload() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let bytes = b"once-upload".to_vec();
        let (bundle_id, token, _) = seed_import_pending(&ctx, &bytes).await;

        // First POST succeeds.
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("POST")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::from(bytes.clone()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Second POST fails — state is now ImportReceived.
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("POST")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .body(Body::from(bytes))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
