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

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use uuid::Uuid;

use crate::error::AppError;
use crate::operations::backup::blob;
use crate::server::AppState;

/// Header name carrying the bundle's bearer token. Matched
/// case-insensitively by axum's header machinery.
const TOKEN_HEADER: &str = "x-backup-token";

/// Uploads the VTA reads at once, across every bundle. An upload is read
/// into memory (at most its bundle's declared size, itself at most
/// [`super::BACKUP_BLOB_BODY_SIZE`]), so this bounds what concurrent
/// uploads can hold. Restores are rare, operator-driven events; two is
/// room for a retry overlapping a stalled attempt.
pub(super) const MAX_CONCURRENT_UPLOADS: usize = 2;

/// Longest wait for the next chunk of an upload body. A client that
/// stops sending is dropped after this, rather than holding an upload
/// slot until the router-wide request timeout.
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The uploads in progress, one per bundle and at most
/// [`MAX_CONCURRENT_UPLOADS`] in all. Built once per router and carried
/// to the handler as an extension.
///
/// The mutex guards only the in-memory set; it is never held across an
/// await (R1.3). A slot is claimed after the token check and released
/// when its [`UploadSlot`] drops, whichever way the handler returns.
#[derive(Clone, Debug)]
pub(super) struct UploadSlots {
    in_flight: Arc<Mutex<HashSet<Uuid>>>,
    max: usize,
}

impl UploadSlots {
    pub(super) fn new(max: usize) -> Self {
        Self {
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            max,
        }
    }

    fn claim(&self, bundle_id: Uuid) -> Result<UploadSlot, AppError> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if in_flight.contains(&bundle_id) {
            return Err(AppError::Conflict(format!(
                "an upload for bundle {bundle_id} is already in progress"
            )));
        }
        if in_flight.len() >= self.max {
            return Err(AppError::ResourceExhausted(
                "too many backup uploads in progress; retry shortly".into(),
            ));
        }
        in_flight.insert(bundle_id);
        Ok(UploadSlot {
            slots: self.in_flight.clone(),
            bundle_id,
        })
    }
}

/// One claimed upload slot; dropping it frees the slot.
struct UploadSlot {
    slots: Arc<Mutex<HashSet<Uuid>>>,
    bundle_id: Uuid,
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.bundle_id);
    }
}

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
#[utoipa::path(
    get, path = "/backup/blob/{bundle_id}", tag = "backup",
    params(
        ("bundle_id" = String, Path, description = "Backup bundle id"),
        ("x-backup-token" = String, Header, description = "One-shot backup descriptor token"),
    ),
    responses(
        (status = 200, description = "Encrypted backup bytes (application/octet-stream)"),
        (status = 401, description = "Missing or malformed x-backup-token header"),
        (status = 403, description = "Token does not match"),
        (status = 404, description = "Bundle not found"),
        (status = 410, description = "Bundle expired or already downloaded"),
    ),
)]
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
/// [`operations::backup::blob::admit_import_upload`] and
/// [`operations::backup::blob::stage_import_blob`].
///
/// Order: parse the path and token header, check the bundle, token,
/// state and expiry (no body read yet), check a declared
/// `Content-Length` against the bundle's expected size, claim an upload
/// slot, then read the body, refusing it as soon as it passes the
/// expected size. A request that fails any check before the read never
/// has its body read.
///
/// Failure modes mirror GET, plus:
/// - Body size (declared or actual) doesn't match `expected_size_bytes` → 400
/// - Body SHA-256 doesn't match `expected_sha256` → 400
/// - Another upload for this bundle is in progress → 409
/// - Too many uploads in progress across bundles → 503
/// - The client stops sending for 30 s → 408
/// - I/O error writing to disk → 500
#[utoipa::path(
    post, path = "/backup/blob/{bundle_id}", tag = "backup",
    request_body(content = inline(Vec<u8>), content_type = "application/octet-stream", description = "Encrypted backup bytes"),
    params(
        ("bundle_id" = String, Path, description = "Backup bundle id"),
        ("x-backup-token" = String, Header, description = "One-shot backup descriptor token"),
    ),
    responses(
        (status = 202, description = "Upload accepted and staged"),
        (status = 400, description = "Body size or SHA-256 mismatch"),
        (status = 401, description = "Missing or malformed x-backup-token header"),
        (status = 403, description = "Token does not match"),
        (status = 404, description = "Bundle not found"),
        (status = 408, description = "The upload body stalled"),
        (status = 409, description = "Upload already accepted, or another upload for this bundle is in progress"),
        (status = 410, description = "Bundle expired or aborted"),
        (status = 503, description = "Too many uploads in progress"),
    ),
)]
pub async fn post_blob(
    State(state): State<AppState>,
    Extension(slots): Extension<UploadSlots>,
    Path(bundle_id_str): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, AppError> {
    let bundle_id = parse_bundle_id(&bundle_id_str)?;
    let token = extract_token(&headers)?;

    // Authorise before reading a byte of the body.
    let admitted = blob::admit_import_upload(&state.backup_bundles_ks, bundle_id, &token).await?;

    let expected = usize::try_from(admitted.expected_size_bytes())
        .ok()
        .filter(|n| *n <= super::BACKUP_BLOB_BODY_SIZE)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "bundle {bundle_id} expects {} bytes, over the {} byte upload limit",
                admitted.expected_size_bytes(),
                super::BACKUP_BLOB_BODY_SIZE
            ))
        })?;
    if let Some(declared) = declared_length(&headers)?
        && declared != admitted.expected_size_bytes()
    {
        return Err(AppError::Validation(format!(
            "upload size mismatch for bundle {bundle_id}: expected {expected} bytes, \
             Content-Length says {declared}"
        )));
    }

    let _slot = slots.claim(bundle_id)?;
    let bytes = read_body_capped(body, bundle_id, expected, UPLOAD_IDLE_TIMEOUT).await?;

    blob::stage_import_blob(
        &state.backup_bundles_ks,
        &state.backup_blob_dir,
        admitted,
        &bytes,
    )
    .await?;

    Ok((StatusCode::ACCEPTED, "").into_response())
}

/// Read an upload body of at most `limit` bytes, refusing it as soon as
/// it passes `limit` and dropping a client that sends nothing for
/// `idle_timeout` ([`UPLOAD_IDLE_TIMEOUT`] in service).
async fn read_body_capped(
    body: Body,
    bundle_id: Uuid,
    limit: usize,
    idle_timeout: Duration,
) -> Result<Vec<u8>, AppError> {
    let mut stream = body.into_data_stream();
    // Grow as bytes arrive; never reserve a declared size up front.
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    loop {
        let next = tokio::time::timeout(idle_timeout, stream.next())
            .await
            .map_err(|_| AppError::ServiceError {
                status: StatusCode::REQUEST_TIMEOUT,
                message: format!("upload for bundle {bundle_id} stalled"),
            })?;
        match next {
            None => return Ok(bytes),
            Some(Err(e)) => {
                return Err(AppError::Validation(format!("read upload body: {e}")));
            }
            Some(Ok(chunk)) => {
                if chunk.len() > limit - bytes.len() {
                    return Err(AppError::Validation(format!(
                        "upload size mismatch for bundle {bundle_id}: \
                         body is longer than the expected {limit} bytes"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }
        }
    }
}

/// The request's `Content-Length`, if it sent one.
fn declared_length(headers: &HeaderMap) -> Result<Option<u64>, AppError> {
    let Some(raw) = headers.get(axum::http::header::CONTENT_LENGTH) else {
        return Ok(None);
    };
    raw.to_str()
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Some)
        .ok_or_else(|| AppError::Validation("malformed Content-Length header".into()))
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
        // A consumed single-use slot is 410, not 409 — the status this
        // route's `utoipa` annotation has always declared. `gone()` renders
        // `AppError::Gone`; 409 stays for "wrong bundle kind / wrong state",
        // which a differently-shaped request could still satisfy.
        assert_eq!(resp.status(), StatusCode::GONE);
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

    /// A request body that records whether the server ever polled it,
    /// and yields `chunk` repeatedly without end.
    fn watched_endless_body(
        chunk: &'static [u8],
    ) -> (Body, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let polled = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = polled.clone();
        let stream = futures_util::stream::repeat_with(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(chunk))
        });
        (Body::from_stream(stream), polled)
    }

    async fn post_with(app: axum::Router, bundle_id: Uuid, token: &str, body: Body) -> StatusCode {
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("POST")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, token)
            .body(body)
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), app.oneshot(req))
            .await
            .expect("handler answers without reading an endless body")
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn post_blob_wrong_token_refused_before_the_body_is_read() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let (bundle_id, _token, _) = seed_import_pending(&ctx, b"data").await;
        let (body, polled) = watched_endless_body(&[0u8; 4096]);
        let status = post_with(app, bundle_id, "not-the-token", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn post_blob_unknown_bundle_refused_before_the_body_is_read() {
        let (app, _ctx) = crate::test_support::build_test_app().await;
        let (body, polled) = watched_endless_body(&[0u8; 4096]);
        let status = post_with(app, Uuid::new_v4(), "any-token", body).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn post_blob_stops_reading_once_past_the_expected_size() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let (bundle_id, token, _) = seed_import_pending(&ctx, &[1u8; 10_000]).await;
        let (body, polled) = watched_endless_body(&[1u8; 4096]);
        let status = post_with(app, bundle_id, &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // 10 000 bytes is two 4 KiB chunks and part of a third.
        assert!(polled.load(std::sync::atomic::Ordering::SeqCst) <= 4);

        // The refusal leaves the bundle pending, so a correct retry works.
        let record = backup_bundle_store::get_bundle(&ctx.backup_bundles_ks, &bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, BundleState::ImportPending);
    }

    #[tokio::test]
    async fn post_blob_refuses_a_mismatched_content_length_before_reading() {
        let (app, ctx) = crate::test_support::build_test_app().await;
        let (bundle_id, token, _) = seed_import_pending(&ctx, b"twelve bytes").await;
        let (body, polled) = watched_endless_body(&[0u8; 4096]);
        let req = Request::builder()
            .uri(format!("/backup/blob/{bundle_id}"))
            .method("POST")
            .header("x-forwarded-for", "192.0.2.1")
            .header(TOKEN_HEADER, &token)
            .header("content-length", "104857600")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(polled.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn read_body_capped_drops_a_stalled_upload() {
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let err = read_body_capped(
            body,
            Uuid::new_v4(),
            1024,
            std::time::Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::ServiceError { status, .. } if status == StatusCode::REQUEST_TIMEOUT),
            "{err:?}"
        );
    }

    #[test]
    fn upload_slots_allow_one_upload_per_bundle_and_a_bounded_total() {
        let slots = UploadSlots::new(2);
        let a = Uuid::new_v4();
        let first = slots.claim(a).expect("first upload for a bundle");
        assert!(matches!(slots.claim(a), Err(AppError::Conflict(_))));
        let _second = slots.claim(Uuid::new_v4()).expect("second bundle");
        assert!(matches!(
            slots.claim(Uuid::new_v4()),
            Err(AppError::ResourceExhausted(_))
        ));
        drop(first);
        let _again = slots.claim(a).expect("slot released on drop");
    }

    #[tokio::test]
    async fn staging_rechecks_the_bundle_after_the_body_is_read() {
        let (_app, ctx) = crate::test_support::build_test_app().await;
        let bytes = b"import-bytes".to_vec();
        let (bundle_id, token, _) = seed_import_pending(&ctx, &bytes).await;
        let admitted = blob::admit_import_upload(&ctx.backup_bundles_ks, bundle_id, &token)
            .await
            .expect("admitted");

        // The bundle is aborted while the body is in flight.
        let mut record = backup_bundle_store::get_bundle(&ctx.backup_bundles_ks, &bundle_id)
            .await
            .unwrap()
            .unwrap();
        record.state = BundleState::Aborted;
        backup_bundle_store::store_bundle(&ctx.backup_bundles_ks, &record)
            .await
            .unwrap();

        let err = blob::stage_import_blob(
            &ctx.backup_bundles_ks,
            &ctx.backup_blob_dir,
            admitted,
            &bytes,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Gone(_)), "{err:?}");
        assert!(
            !ctx.backup_blob_dir
                .join(format!("{bundle_id}.vtabak"))
                .exists()
        );
    }
}
