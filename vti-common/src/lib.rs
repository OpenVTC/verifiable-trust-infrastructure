pub mod acl;
pub mod audit;
pub mod auth;
/// Client-side wire helpers for the capability Trust Task families —
/// re-exported from the `trust-tasks-capability-client` crate so both this
/// (the hook producer) and out-of-repo consumers (management UIs) share one
/// contract-tested implementation.
pub use trust_tasks_capability_client as capability_client;
pub mod config;
pub mod consent;
pub mod context_path;
pub mod error;
pub mod idempotency;
pub mod identifier;
pub mod integrity;
pub mod outbox_store;
pub mod pagination;
pub mod secure_file;
pub mod seed_store;
#[cfg(feature = "setup")]
pub mod setup;
pub mod store;
pub mod telemetry;
pub mod trust_task;
pub mod vault;
