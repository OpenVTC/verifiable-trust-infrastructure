//! Prometheus metrics for operational observability.
//!
//! Records request count and latency per endpoint. Exposed via
//! `GET /metrics` in Prometheus text format. Requires authentication
//! (any role including Monitor).

use std::time::Instant;

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use metrics::{counter, histogram};
pub use metrics_exporter_prometheus::PrometheusHandle;

/// Install the Prometheus metrics recorder (call once at startup).
///
/// Returns a handle for rendering metrics. The global recorder is installed
/// so all `counter!()` and `histogram!()` calls throughout the codebase
/// are captured.
/// Idempotent: the recorder is process-global and can be installed only once,
/// so a second call (a VTA restarted in the same process, as an embedding
/// application does) returns the handle the first installed.
pub fn install() -> PrometheusHandle {
    static HANDLE: std::sync::OnceLock<PrometheusHandle> = std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install Prometheus recorder")
        })
        .clone()
}

/// Axum middleware that records per-request metrics.
///
/// Metrics emitted:
/// - `http_requests_total` (counter) — labels: method, path, status
/// - `http_request_duration_seconds` (histogram) — labels: method, path
pub async fn track_metrics(req: Request<Body>, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    let start = Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();

    let _ = counter!("http_requests_total", "method" => method.clone(), "path" => path.clone(), "status" => status);
    histogram!("http_request_duration_seconds", "method" => method, "path" => path)
        .record(duration);

    response
}
