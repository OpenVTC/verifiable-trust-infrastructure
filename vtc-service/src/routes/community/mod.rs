//! `/v1/community/*` route handlers.
//!
//! Implements **M0.7.2** of the VTC MVP Phase 0 plan. Handlers
//! consume the [`crate::community`] storage layer; the routing
//! wiring lives in [`crate::routes::router`].

pub mod branding;
pub mod profile;
