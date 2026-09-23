//! `/v1/admin/*` admin-only route handlers.
//!
//! All routes here require `AdminAuth`. The Trust-Task header check
//! happens at the route-table layer (see `crate::routes::router`);
//! reaching a handler implies both the role gate and the task gate
//! have passed.

pub mod bootstrap;
pub mod config;
pub mod console_keys;
pub mod did_register;
pub mod invites;
pub mod passkeys;
