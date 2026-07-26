//! [`TrustTaskRouter`] — Axum `Router` builder that enforces
//! per-route Trust-Task header validation at attach time.
//!
//! ## Why a builder, not a macro
//!
//! Plan decision **D9**: explicit registration via a typed builder.
//! A future reader sees the registered task right next to the handler;
//! no procedural-macro indirection, no string-prefix matching, no
//! version-family heuristics. Exact-match is the only correctness
//! check.
//!
//! ## Usage
//!
//! ```ignore
//! use vti_common::trust_task::{TrustTask, TrustTaskRouter};
//! use axum::routing::{get, post};
//!
//! let install_claim = TrustTask::new("https://trusttasks.org/spec/vtc/install/claim/start/0.1")?;
//!
//! let router = TrustTaskRouter::new()
//!     .route_with_task("/v1/install/claim/start", post(claim_start), install_claim)
//!     .route_exempt("/health", get(health))
//!     .into_router();
//! ```

use std::sync::Arc;

use axum::Router;
use axum::routing::MethodRouter;

use super::TrustTask;

/// Builder that wraps an Axum [`Router`] and enforces Trust-Task
/// header validation on each registered route.
pub struct TrustTaskRouter<S = ()> {
    inner: Router<S>,
}

impl<S> Default for TrustTaskRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> TrustTaskRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Start a new empty builder.
    pub fn new() -> Self {
        Self {
            inner: Router::new(),
        }
    }

    /// Register a route whose incoming `Trust-Task` header must
    /// **exact-match** `task`. Mismatch → 415
    /// [`AppError::TrustTaskMismatch`]; missing → 400
    /// [`AppError::TrustTaskMissing`].
    ///
    /// [`AppError::TrustTaskMismatch`]: crate::error::AppError::TrustTaskMismatch
    /// [`AppError::TrustTaskMissing`]: crate::error::AppError::TrustTaskMissing
    pub fn route_with_task(
        mut self,
        path: &str,
        method_router: MethodRouter<S>,
        task: TrustTask,
    ) -> Self {
        // `Arc` so each invocation of the cloned closure can cheaply
        // hand out a reference to the same task value. The middleware
        // closure must be `Clone + Send + Sync + 'static` per Axum's
        // `from_fn` bound, which `Arc<TrustTask>` satisfies.
        let task = Arc::new(task);
        let layered = method_router.layer(axum::middleware::from_fn(move |request, next| {
            let task = task.clone();
            async move { super::extractor::validate_header(&task, request, next).await }
        }));
        self.inner = self.inner.route(path, layered);
        self
    }

    /// Register a route that bypasses Trust-Task validation. Per spec
    /// §16.2 this is intended **only for `/health`** — operators set
    /// up monitoring against the health endpoint without having to
    /// know about Trust-Task identifiers. Documented as the single
    /// exempt route; if you find yourself reaching for this for a
    /// second endpoint, stop and add a Trust Task instead.
    pub fn route_exempt(mut self, path: &str, method_router: MethodRouter<S>) -> Self {
        self.inner = self.inner.route(path, method_router);
        self
    }

    /// Finalise and yield the underlying [`Router`] ready to be
    /// merged or nested into a parent router.
    pub fn into_router(self) -> Router<S> {
        self.inner
    }
}

impl<S> From<TrustTaskRouter<S>> for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn from(r: TrustTaskRouter<S>) -> Self {
        r.into_router()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn make_router() -> Router {
        let claim = TrustTask::new("https://trusttasks.org/spec/vtc/install/claim/0.1").unwrap();
        TrustTaskRouter::new()
            .route_with_task("/v1/install/claim", post(ok), claim)
            .route_exempt("/health", get(ok))
            .into_router()
    }

    #[tokio::test]
    async fn exact_match_succeeds() {
        let app = make_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/install/claim")
                    .header(
                        HEADER_NAME,
                        "https://trusttasks.org/spec/vtc/install/claim/0.1",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_header_returns_400() {
        let app = make_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/install/claim")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "TrustTaskMissing");
    }

    #[tokio::test]
    async fn mismatched_header_returns_415_with_expected_field() {
        let app = make_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/install/claim")
                    .header(
                        HEADER_NAME,
                        "https://trusttasks.org/spec/vtc/auth/login/0.1",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "TrustTaskMismatch");
        assert_eq!(
            body["expected"],
            "https://trusttasks.org/spec/vtc/install/claim/0.1"
        );
        assert_eq!(
            body["received"],
            "https://trusttasks.org/spec/vtc/auth/login/0.1"
        );
    }

    #[tokio::test]
    async fn exact_match_is_byte_strict_not_prefix() {
        let app = make_router();
        // Same path family, different version — must not match.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/install/claim")
                    .header(
                        HEADER_NAME,
                        "https://trusttasks.org/spec/vtc/install/claim/0.2",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn health_is_exempt() {
        let app = make_router();
        // No header — should still 200.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    use super::super::HEADER_NAME;
}
