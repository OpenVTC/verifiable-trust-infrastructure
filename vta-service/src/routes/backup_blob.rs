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
use uuid::Uuid;

use crate::error::AppError;
use crate::operations::backup::blob;
use crate::server::AppState;

/// Header name carrying the bundle's bearer token. Matched
/// case-insensitively by axum's header machinery.
const TOKEN_HEADER: &str = "x-backup-token";

/// `GET /backup/blob/{bundle_id}` — download the encrypted bytes of
/// an export bundle. Thin transport adapter over
/// [`operations::backup::blob::read_export_blob`]: parse the path +
/// token header, delegate the one-shot state machine, then frame the
/// bytes as a `.vtabak` attachment.
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

    let bytes = blob::read_export_blob(&state.backup_bundles_ks, bundle_id, &token).await?;

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
/// import bundle. Thin transport adapter over
/// [`operations::backup::blob::write_import_blob`]: parse the path +
/// token header, read the (body-capped) upload, delegate the
/// size/SHA-verify + stage-to-disk state machine.
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

    // Cap applies at this read; the router-level
    // `DefaultBodyLimit::max(BACKUP_BLOB_BODY_SIZE)` mirrors it, and
    // the cap is enforced HERE so exceeding it surfaces as a 400 with a
    // clear message rather than axum's 413.
    let bytes = axum::body::to_bytes(body, super::BACKUP_BLOB_BODY_SIZE)
        .await
        .map_err(|e| AppError::Validation(format!("read upload body: {e}")))?;

    blob::write_import_blob(
        &state.backup_bundles_ks,
        &state.backup_blob_dir,
        bundle_id,
        &token,
        &bytes,
    )
    .await?;

    Ok((StatusCode::ACCEPTED, "").into_response())
}

// ─── Transport helpers ─────────────────────────────────────────────────

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
    use chrono::{Duration, Utc};
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
