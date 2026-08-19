//! Axum middleware that implements the `Idempotency-Key` cache.
//!
//! Wired in via [`axum::middleware::from_fn_with_state`] using
//! [`IdempotencyLayerState`] for the captured store + class. The
//! middleware buffers both the request body (for hashing) and the
//! response body (for caching), so consumers attaching it to a route
//! MUST ensure the route's expected body fits inside
//! [`MAX_BODY_BYTES`] (1 MB — matches the workspace's global cap,
//! spec §14.4).
//!
//! # Flow
//!
//! 1. Request arrives; pull `Idempotency-Key` header. **Absent →
//!    pass through.** Idempotency keys are optional per the spec
//!    (only retries need them).
//! 2. Derive [`Principal`] from request parts (Auth-token bytes
//!    hashed, else IP, else anonymous).
//! 3. Buffer the request body and hash it.
//! 4. Look up `(principal, key)` in the store:
//!    - Hit, request hash matches → **replay** the cached response.
//!    - Hit, request hash differs → 422 [`AppError::IdempotencyKeyConflict`].
//!    - Miss → forward to inner service.
//! 5. After the inner service responds, buffer + store the response,
//!    then return it unchanged. Storage failures are logged but **do
//!    not** fail the request — a cache miss is always survivable.

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::middleware::Next;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use super::class::IdempotencyClass;
use super::store::{CacheEntry, IdempotencyStore, principal_from_request};
use crate::error::AppError;

/// Canonical `Idempotency-Key` HTTP header name.
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";

/// Hard cap on request + response body sizes the middleware will
/// buffer. Matches the workspace's global 1 MB body cap. Routes whose
/// bodies legitimately exceed this (e.g. website upload) should not
/// attach the idempotency layer.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// State passed to [`idempotency_middleware`] via
/// [`axum::middleware::from_fn_with_state`]. Cheap to clone — the
/// underlying [`IdempotencyStore`] is `Arc`-shared.
#[derive(Clone)]
pub struct IdempotencyLayerState {
    pub store: IdempotencyStore,
    pub class: IdempotencyClass,
}

/// Axum-compatible middleware function. Wire this in via
/// [`axum::middleware::from_fn_with_state`] (the workspace's
/// canonical state-capturing-middleware pattern):
///
/// ```ignore
/// use axum::middleware::from_fn_with_state;
/// use vti_common::idempotency::{
///     idempotency_middleware, IdempotencyLayerState, IdempotencyClass,
/// };
///
/// let state = IdempotencyLayerState {
///     store: store.clone(),
///     class: IdempotencyClass::Destructive,
/// };
/// router.route_with_task(
///     "/v1/members/{did}",
///     delete(remove_handler)
///         .layer(from_fn_with_state(state, idempotency_middleware)),
///     task,
/// )
/// ```
pub async fn idempotency_middleware(
    State(state): State<IdempotencyLayerState>,
    request: Request,
    next: Next,
) -> Result<Response<Body>, AppError> {
    run(state.store, state.class, request, next).await
}

async fn run(
    store: IdempotencyStore,
    class: IdempotencyClass,
    request: Request,
    next: Next,
) -> Result<Response<Body>, AppError> {
    // 1. Header present?
    let idempotency_key = match request
        .headers()
        .get(IDEMPOTENCY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        Some(k) if !k.is_empty() => k,
        // No key, or empty → pass straight through. Optional header.
        _ => return Ok(next.run(request).await),
    };

    // Reject control characters in the key — they would corrupt the
    // storage key (`idem:<hash>:<key>`) and could mask cache entries.
    if idempotency_key
        .chars()
        .any(|c| c.is_control() || c == ':' || c == '\n' || c == '\r')
    {
        return Err(AppError::Validation(format!(
            "Idempotency-Key contains a disallowed character: {:?}",
            idempotency_key
        )));
    }

    // 2. Derive principal.
    let (parts, body) = request.into_parts();
    let principal = principal_from_request(&parts);
    let principal_hash = principal.hash();

    // 3. Buffer + hash the request body.
    let body_bytes = collect_body(body).await?;
    let request_hash = sha256(&body_bytes);

    // 4. Cache lookup.
    if let Some(existing) = store.get(&principal_hash, &idempotency_key).await? {
        if existing.request_hash == request_hash {
            debug!(
                idempotency_key = %idempotency_key,
                "serving cached idempotent response"
            );
            return rebuild_response(&existing);
        }
        warn!(
            idempotency_key = %idempotency_key,
            "Idempotency-Key conflict — same key, different request body"
        );
        return Err(AppError::IdempotencyKeyConflict);
    }

    // 5. Forward to handler.
    let request = Request::from_parts(parts, Body::from(body_bytes));
    let response = next.run(request).await;

    // Cache the response. Storage failures are non-fatal — they just
    // mean a retry will hit the handler again rather than serve from
    // cache. We log and proceed.
    let (resp_parts, resp_body) = response.into_parts();
    let resp_bytes = match collect_body(resp_body).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "could not buffer response for idempotency cache; skipping cache");
            // Re-emit a response with an empty body — the original is
            // gone. The caller still sees the status + headers.
            return Ok(Response::from_parts(resp_parts, Body::empty()));
        }
    };

    let now = Utc::now();
    let entry = CacheEntry {
        // The HTTP path has no claim stage: it caches a response it already
        // has, so the record is complete the moment it is written.
        state: super::EntryState::Completed,
        idempotency_key: idempotency_key.clone(),
        request_hash,
        response_status: resp_parts.status.as_u16(),
        response_headers: capture_headers(&resp_parts.headers),
        response_body: resp_bytes.to_vec(),
        class,
        created_at: now,
        expires_at: now + Duration::seconds(class.ttl_seconds() as i64),
    };
    if let Err(e) = store.put(&principal_hash, &entry).await {
        warn!(error = %e, "idempotency cache write failed; response will not be replayed on retry");
    }

    let mut rebuilt = Response::new(Body::from(resp_bytes));
    *rebuilt.status_mut() = resp_parts.status;
    *rebuilt.headers_mut() = resp_parts.headers;
    Ok(rebuilt)
}

async fn collect_body(body: Body) -> Result<Bytes, AppError> {
    let bytes = http_body_util::Limited::new(body, MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|e| AppError::Validation(format!("body exceeds idempotency buffer limit: {e}")))?
        .to_bytes();
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn capture_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| match v.to_str() {
            Ok(value) => Some((k.as_str().to_string(), value.to_string())),
            Err(_) => {
                // Non-UTF-8 header values (rare) can't round-trip through
                // our cache. Drop them with a warning rather than fail
                // the response.
                warn!(header = %k, "skipping non-UTF-8 response header in idempotency cache");
                None
            }
        })
        .collect()
}

fn rebuild_response(entry: &CacheEntry) -> Result<Response<Body>, AppError> {
    let mut response = Response::new(Body::from(entry.response_body.clone()));
    *response.status_mut() = StatusCode::from_u16(entry.response_status)
        .map_err(|e| AppError::Internal(format!("invalid cached status: {e}")))?;
    for (name, value) in &entry.response_headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| AppError::Internal(format!("invalid cached header name: {e}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|e| AppError::Internal(format!("invalid cached header value: {e}")))?;
        response.headers_mut().insert(name, value);
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;
    use axum::Router;
    use axum::http::Request as HttpRequest;
    use axum::routing::post;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tower::ServiceExt;

    fn temp_store() -> (IdempotencyStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let ks = store.keyspace("idempotency-mw-test").expect("ks");
        (IdempotencyStore::new(ks), dir)
    }

    /// Test handler that counts invocations and echoes the request
    /// body in a JSON response.
    fn counted_router(
        store: IdempotencyStore,
        class: IdempotencyClass,
        counter: Arc<AtomicU32>,
    ) -> Router {
        let state = IdempotencyLayerState { store, class };
        Router::new().route(
            "/",
            post({
                let counter = counter.clone();
                move |body: Bytes| {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Response::builder()
                            .status(StatusCode::CREATED)
                            .header("content-type", "application/json")
                            .body(Body::from(format!(
                                r#"{{"echo":"{}"}}"#,
                                String::from_utf8_lossy(&body)
                            )))
                            .unwrap()
                    }
                }
            })
            .layer(axum::middleware::from_fn_with_state(
                state,
                idempotency_middleware,
            )),
        )
    }

    fn req_with_key(key: Option<&str>, body: &str) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder().method("POST").uri("/");
        if let Some(k) = key {
            builder = builder.header(IDEMPOTENCY_HEADER, k);
        }
        builder
            .header("authorization", "Bearer test-token")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn body_text(resp: Response<Body>) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn no_header_passes_through_and_does_not_cache() {
        let (store, _dir) = temp_store();
        let counter = Arc::new(AtomicU32::new(0));
        let app = counted_router(
            store.clone(),
            IdempotencyClass::NonDestructive,
            counter.clone(),
        );

        // Two requests, neither carries a key: handler called twice.
        for body in ["one", "two"] {
            let resp = app.clone().oneshot(req_with_key(None, body)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn same_key_same_body_replays_cached_response() {
        let (store, _dir) = temp_store();
        let counter = Arc::new(AtomicU32::new(0));
        let app = counted_router(
            store.clone(),
            IdempotencyClass::NonDestructive,
            counter.clone(),
        );

        let first = app
            .clone()
            .oneshot(req_with_key(Some("abc-123"), "payload"))
            .await
            .unwrap();
        let (status1, body1) = body_text(first).await;
        assert_eq!(status1, StatusCode::CREATED);
        assert!(body1.contains("payload"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let second = app
            .clone()
            .oneshot(req_with_key(Some("abc-123"), "payload"))
            .await
            .unwrap();
        let (status2, body2) = body_text(second).await;
        assert_eq!(status2, StatusCode::CREATED);
        assert_eq!(body2, body1, "cached body should match");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "handler should not be re-invoked"
        );
    }

    #[tokio::test]
    async fn same_key_different_body_returns_422() {
        let (store, _dir) = temp_store();
        let counter = Arc::new(AtomicU32::new(0));
        let app = counted_router(
            store.clone(),
            IdempotencyClass::NonDestructive,
            counter.clone(),
        );

        let _first = app
            .clone()
            .oneshot(req_with_key(Some("key-x"), "body-A"))
            .await
            .unwrap();
        let second = app
            .clone()
            .oneshot(req_with_key(Some("key-x"), "body-B"))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let (_, body) = body_text(second).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "IdempotencyKeyConflict");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "second handler call must be rejected pre-handler"
        );
    }

    #[tokio::test]
    async fn destructive_class_caches_for_60s_only() {
        let (store, _dir) = temp_store();
        let counter = Arc::new(AtomicU32::new(0));
        let app = counted_router(
            store.clone(),
            IdempotencyClass::Destructive,
            counter.clone(),
        );

        let resp = app
            .clone()
            .oneshot(req_with_key(Some("d-1"), "del"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Cache entry has the short TTL.
        let principal =
            super::super::store::Principal::AuthToken(b"Bearer test-token".to_vec()).hash();
        let entry = store.get(&principal, "d-1").await.unwrap().unwrap();
        assert_eq!(entry.class, IdempotencyClass::Destructive);
        let ttl = (entry.expires_at - entry.created_at).num_seconds();
        assert!((59..=61).contains(&ttl), "ttl was {ttl}s");
    }

    #[tokio::test]
    async fn different_principals_have_separate_caches() {
        let (store, _dir) = temp_store();
        let counter = Arc::new(AtomicU32::new(0));
        let app = counted_router(
            store.clone(),
            IdempotencyClass::NonDestructive,
            counter.clone(),
        );

        // Alice
        let a = HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header(IDEMPOTENCY_HEADER, "shared-key")
            .header("authorization", "Bearer alice")
            .body(Body::from("a"))
            .unwrap();
        let _ = app.clone().oneshot(a).await.unwrap();

        // Bob using the same idempotency-key but a different bearer
        let b = HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header(IDEMPOTENCY_HEADER, "shared-key")
            .header("authorization", "Bearer bob")
            .body(Body::from("b"))
            .unwrap();
        let resp = app.clone().oneshot(b).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Both reached the handler — same key, different principals
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn idempotency_key_with_control_chars_rejected() {
        let (store, _dir) = temp_store();
        let counter = Arc::new(AtomicU32::new(0));
        let app = counted_router(
            store.clone(),
            IdempotencyClass::NonDestructive,
            counter.clone(),
        );

        let bad = HttpRequest::builder()
            .method("POST")
            .uri("/")
            .header(IDEMPOTENCY_HEADER, "evil:injected")
            .header("authorization", "Bearer test")
            .body(Body::from("x"))
            .unwrap();
        let resp = app.clone().oneshot(bad).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}
