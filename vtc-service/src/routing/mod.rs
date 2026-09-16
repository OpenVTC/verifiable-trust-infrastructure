//! Routing-layer middleware (Phase 5).
//!
//! Holds the cross-cutting layers that wrap the per-surface
//! sub-routers built in [`crate::routes`]:
//!
//! - [`host_dispatch`] — subdomain-mode `Host` header check.
//! - [`rate_limit`] — the response shape every VTC rate-limit refusal
//!   takes (`x-rate-limit-source: vtc`, `Retry-After`, JSON body).
//!
//! Body-cap enforcement + tower-governor rate limiting are layered
//! directly in [`crate::routes::router_with`] at the API nest
//! boundary; they live near the route attach site so per-route
//! overrides (M5.5) can opt out without reaching back into this
//! module.

pub mod csrf;
pub mod host_dispatch;
pub mod rate_limit;
pub mod security_headers;
