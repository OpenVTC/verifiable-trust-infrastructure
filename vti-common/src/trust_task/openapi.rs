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

    #[utoipa::path(get, path = "/v1/admin/config", responses((status = 200)))]
    async fn cfg_show() -> &'static str {
        "show"
    }

    #[utoipa::path(patch, path = "/v1/admin/config", responses((status = 200)))]
    async fn cfg_patch() -> &'static str {
        "patch"
    }

    const SHOW: &str = "https://trusttasks.org/spec/config/show/0.1";
    const PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";

    /// Two methods on **one path** can carry **different** Trust Tasks.
    ///
    /// `task_routes` layers the method router, and axum merges same-path
    /// method routers per method, so each verb keeps its own layer. This is
    /// what lets a GET/PATCH pair mount as `config/show` + `config/patch`
    /// instead of collapsing onto a single combined task.
    async fn split_app() -> Router {
        OpenApiRouter::new()
            .routes(task_routes(
                routes!(cfg_show),
                TrustTask::new(SHOW).unwrap(),
            ))
            .routes(task_routes(
                routes!(cfg_patch),
                TrustTask::new(PATCH).unwrap(),
            ))
            .split_for_parts()
            .0
    }

    async fn call(method: &str, task: &str) -> StatusCode {
        split_app()
            .await
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/v1/admin/config")
                    .header(HEADER_NAME, task)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    /// The split must not cost us the OpenAPI document: registering the same
    /// path twice has to *merge* the two operations, not overwrite the first.
    #[test]
    fn per_method_split_keeps_both_operations_in_the_spec() {
        let (_router, api): (Router, _) = OpenApiRouter::new()
            .routes(task_routes(
                routes!(cfg_show),
                TrustTask::new(SHOW).unwrap(),
            ))
            .routes(task_routes(
                routes!(cfg_patch),
                TrustTask::new(PATCH).unwrap(),
            ))
            .split_for_parts();
        let item = api
            .paths
            .paths
            .get("/v1/admin/config")
            .expect("path present");
        assert!(item.get.is_some(), "GET operation dropped from the spec");
        assert!(
            item.patch.is_some(),
            "PATCH operation dropped from the spec"
        );
    }

    #[tokio::test]
    async fn per_method_tasks_on_one_path_are_enforced_independently() {
        // Each verb accepts its own task...
        assert_eq!(call("GET", SHOW).await, StatusCode::OK);
        assert_eq!(call("PATCH", PATCH).await, StatusCode::OK);
        // ...and rejects the sibling's (415 = task mismatch), so the two are
        // not interchangeable even though they share a path.
        assert_eq!(call("GET", PATCH).await, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            call("PATCH", SHOW).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
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
