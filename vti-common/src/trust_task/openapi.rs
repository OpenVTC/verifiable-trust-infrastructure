//! OpenAPI-aware Trust-Task route layering.
//!
//! [`TrustTaskRouter`](super::TrustTaskRouter) wraps a plain axum `Router` and
//! is opaque to OpenAPI generation. When a service assembles its surface as a
//! utoipa-axum [`OpenApiRouter`](utoipa_axum::router::OpenApiRouter) instead —
//! so the router is the single source of truth for the served `/openapi.json` —
//! these free functions provide the same per-route Trust-Task header
//! validation, layered without dropping the collected OpenAPI path/schema.
//!
//! - [`task_routes`] layers onto a `routes!()` [`UtoipaMethodRouter`], keeping
//!   the operation in the spec — the drift-free replacement for
//!   [`TrustTaskRouter::route_with_task`](super::TrustTaskRouter::route_with_task).
//! - [`task_layer`] layers onto a plain [`MethodRouter`], for routes still on
//!   `OpenApiRouter::route(...)` that haven't been `#[utoipa::path]`-annotated
//!   yet, so wire enforcement is preserved through an incremental migration.
//!
//! The validation is byte-for-byte the same closure `route_with_task` applies.

use std::sync::Arc;

use axum::routing::MethodRouter;
use utoipa_axum::router::{UtoipaMethodRouter, UtoipaMethodRouterExt};

use super::TrustTask;

/// Layer Trust-Task header validation onto a `routes!()`-produced
/// [`UtoipaMethodRouter`], preserving its OpenAPI path + schemas.
///
/// Use in place of [`TrustTaskRouter::route_with_task`] when building an
/// `OpenApiRouter`:
///
/// ```ignore
/// OpenApiRouter::new()
///     .routes(task_routes(routes!(handler), my_task))
/// ```
pub fn task_routes<S>(routes: UtoipaMethodRouter<S>, task: TrustTask) -> UtoipaMethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let task = Arc::new(task);
    routes.layer(axum::middleware::from_fn(move |request, next| {
        let task = task.clone();
        async move { super::extractor::validate_header(&task, request, next).await }
    }))
}

/// Layer Trust-Task header validation onto a plain [`MethodRouter`] — for
/// routes mounted via `OpenApiRouter::route(...)` that are not yet
/// `#[utoipa::path]`-annotated. Keeps the wire enforcement identical while a
/// service is mid-migration from [`TrustTaskRouter`](super::TrustTaskRouter).
pub fn task_layer<S>(method_router: MethodRouter<S>, task: TrustTask) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    let task = Arc::new(task);
    method_router.layer(axum::middleware::from_fn(move |request, next| {
        let task = task.clone();
        async move { super::extractor::validate_header(&task, request, next).await }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_task::HEADER_NAME;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use utoipa_axum::router::OpenApiRouter;
    use utoipa_axum::routes;

    #[utoipa::path(get, path = "/v1/install/claim", responses((status = 200)))]
    async fn ok() -> &'static str {
        "ok"
    }

    fn task() -> TrustTask {
        TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/1.0").unwrap()
    }

    #[test]
    fn task_routes_keeps_the_operation_in_the_spec() {
        let (_router, api): (Router, _) = OpenApiRouter::new()
            .routes(task_routes(routes!(ok), task()))
            .split_for_parts();
        // The layered route still contributes its operation to the document.
        assert!(api.paths.paths.contains_key("/v1/install/claim"));
    }

    async fn app() -> Router {
        OpenApiRouter::new()
            .routes(task_routes(routes!(ok), task()))
            .split_for_parts()
            .0
    }

    #[tokio::test]
    async fn task_routes_enforces_the_header() {
        // Exact match → 200.
        let resp = app()
            .await
            .oneshot(
                Request::builder()
                    .uri("/v1/install/claim")
                    .header(
                        HEADER_NAME,
                        "https://trusttasks.org/openvtc/vtc/install/claim/1.0",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Missing header → 400.
        let resp = app()
            .await
            .oneshot(
                Request::builder()
                    .uri("/v1/install/claim")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Wrong task → 415.
        let resp = app()
            .await
            .oneshot(
                Request::builder()
                    .uri("/v1/install/claim")
                    .header(
                        HEADER_NAME,
                        "https://trusttasks.org/openvtc/vtc/auth/login/1.0",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
