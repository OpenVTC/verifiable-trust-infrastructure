//! Rego (OPA policy language) evaluation surface for the VTC.
//!
//! Spec §3-J + §7. The VTC ships an embedded `regorus` interpreter —
//! no external OPA sidecar, no out-of-process IPC. Phase 2 M2.1 lands
//! the **harness only**: compile a Rego source into a [`CompiledPolicy`]
//! and run a query against it. Persistence ([`Policy`] rows backed by
//! a fjall keyspace) lands in M2.2; CRUD endpoints land in M2.3 + M2.4;
//! the default-policy bundle (join / removal / personhood / …) lands
//! in M2.5.
//!
//! ## Lifecycle
//!
//! 1. Operator (or the boot-time default-policy loader) calls
//!    [`engine::compile`] with the Rego source. Failure surfaces as
//!    [`AppError::Validation`] so route handlers map it to 400.
//! 2. The compiled module is wrapped in an `Arc<CompiledPolicy>` and
//!    stored in the live-policy registry (M2.8 / D8). Source +
//!    SHA-256 land in the `policies:<id>` fjall row; the compiled
//!    bytecode is reconstructed on boot.
//! 3. Evaluation goes through [`engine::evaluate`] with a
//!    `serde_json::Value` input. The wrapper clones the underlying
//!    `regorus::Engine` per call so concurrent evaluators don't
//!    serialise on a single mutable engine.
//!
//! ## Why a thin wrapper instead of re-exporting `regorus::Engine`
//!
//! Three reasons:
//! 1. **Error mapping.** Regorus returns `anyhow::Error`; route handlers
//!    speak [`AppError`]. The conversion lives here, not at every call
//!    site.
//! 2. **SHA pinning.** Audit + the trust-task `policies/upload/1.0`
//!    payload need the content hash. Computing it alongside compilation
//!    keeps the two in lockstep — there's no way to ship a compiled
//!    module without its hash.
//! 3. **D8 hot-swap.** The registry needs an `Arc`-shareable handle.
//!    `regorus::Engine` is `Send + Sync` with the `arc` feature (default)
//!    so this works, but we want a single canonical wrapper type so
//!    future changes (e.g. caching `data` alongside the engine) don't
//!    ripple through every consumer.

pub mod default;
pub mod engine;
pub mod extract;
pub mod model;
pub mod storage;

pub use engine::{CompiledPolicy, compile, evaluate};
pub use model::{POLICY_SOURCE_MAX_BYTES, Policy, PolicyPurpose};
pub use storage::{
    clear_active_policy_id, delete_policy, get_active_policy_id, get_policy, list_policies,
    list_policies_paginated, max_version_for, new_policy, set_active_policy_id, store_policy,
};

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Fetch the active policy for `purpose` and compile it.
///
/// Resolves the per-purpose active pointer → the stored `Policy` row →
/// a [`CompiledPolicy`]. The shared loader every ceremony route uses to
/// get the policy `decide()` evaluates. Fails closed: a missing active
/// pointer or row is an [`AppError::Internal`] (the boot-time default
/// loader guarantees one per purpose), not a silent allow.
pub async fn load_active_compiled(
    active_policies_ks: &KeyspaceHandle,
    policies_ks: &KeyspaceHandle,
    purpose: PolicyPurpose,
) -> Result<CompiledPolicy, AppError> {
    let id = get_active_policy_id(active_policies_ks, purpose)
        .await?
        .ok_or_else(|| AppError::Internal(format!("no active {} policy", purpose.as_str())))?;
    let policy = get_policy(policies_ks, id).await?.ok_or_else(|| {
        AppError::Internal(format!(
            "active {} policy {id} points at a missing row",
            purpose.as_str()
        ))
    })?;
    compile(&policy.rego_source, policy.id)
}
