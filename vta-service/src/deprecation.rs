//! Deprecation signalling for legacy REST routes that a canonical
//! `/api/trust-tasks` Trust-Task now supersedes.
//!
//! These routes keep working — the deprecation is advisory. We add response
//! headers so clients can detect the deprecation and migrate, and increment a
//! hit counter (`deprecated_route_requests_total`, labelled by route) so that
//! removal can be gated on **observed usage dropping to zero** rather than a
//! guessed calendar date. (No `Sunset` date is emitted for that reason.)
//!
//! The canonical replacement for every route marked here is the same operation
//! dispatched as a Trust-Task via `POST /api/trust-tasks` (reachable over REST,
//! DIDComm, and TSP through the shared `dispatch_trust_task_core` spine).

use axum::http::{HeaderMap, HeaderValue};
use metrics::counter;

/// Build the deprecation response headers for a legacy `route`, pointing at the
/// successor Trust-Task URI, and record a hit for that route.
///
/// Emits `Deprecation: true` and `Link: <successor>; rel="successor-version"`
/// (RFC 8288). Attach the returned [`HeaderMap`] to the handler's response.
pub fn superseded(route: &'static str, successor: &'static str) -> HeaderMap {
    counter!("deprecated_route_requests_total", "route" => route).increment(1);

    let mut headers = HeaderMap::new();
    headers.insert("deprecation", HeaderValue::from_static("true"));
    if let Ok(link) = HeaderValue::from_str(&format!("<{successor}>; rel=\"successor-version\"")) {
        headers.insert("link", link);
    }
    headers
}
