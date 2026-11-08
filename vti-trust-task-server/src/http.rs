//! `POST /v1/trust-tasks` — the HTTPS binding's single document endpoint.
//!
//! The request body is a Trust Task document and the response is a framework
//! `#response` or `trust-task-error` document. The endpoint reads no bearer
//! token: a signed document carries its own authentication (VTI-OPS-020), and
//! the spine refuses one whose specification requires a proof it lacks.
//!
//! A service implements [`TrustTaskService`] — how to build its [`Spine`] for
//! one request — and mounts [`routes`]. A service with transport concerns of
//! its own (per-address admission, cookies, streamed answers) writes its own
//! handler around [`Spine::receive`] instead.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::context::ArrivalCtx;
use crate::spine::Spine;

/// The path the HTTPS binding serves documents on.
pub const TRUST_TASKS_PATH: &str = "/v1/trust-tasks";

/// A service that answers Trust Task documents over HTTPS.
pub trait TrustTaskService: Send + Sync + 'static {
    /// The pipeline for one request.
    fn spine(&self) -> Spine<'_>;

    /// The largest request body buffered, in bytes: the largest document any
    /// served type accepts. The spine's own size gate still holds each type to
    /// its limit.
    fn max_body_bytes(&self) -> usize {
        crate::size::DEFAULT_MAX_DOCUMENT_BYTES
    }
}

/// `POST /v1/trust-tasks`: run the body through the service's spine.
pub async fn handle<S: TrustTaskService>(State(service): State<Arc<S>>, body: Bytes) -> Response {
    service
        .spine()
        .receive(&ArrivalCtx::rest(), &body)
        .await
        .into_response()
}

/// A router serving [`TRUST_TASKS_PATH`] for `service`, with its body limit.
pub fn routes<S: TrustTaskService>(service: Arc<S>) -> Router {
    let limit = service.max_body_bytes();
    Router::new()
        .route(TRUST_TASKS_PATH, post(handle::<S>))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(service)
}
