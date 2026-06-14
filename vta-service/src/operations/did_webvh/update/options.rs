//! Caller-supplied request types and result types shared across the
//! `update` submodule.
//!
//! `DerivedWebvhKey` is a phase-1 derive output — produced by
//! [`crate::operations::did_webvh::update::keys::derive_webvh_keys`]
//! before the consuming `didwebvh_rs::update_did` call has produced
//! the new log-entry's `version_id`. The handle is installed via
//! [`crate::operations::did_webvh::update::keys::install_derived_webvh_keys`]
//! once the version-id is known.

use std::time::Duration;

use didwebvh_rs::witness::Witnesses;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Wire types canonically live in vta-sdk per
// `memory::feedback-wire-types-in-sdk`. Re-export from there so
// existing op-layer call sites (and any external `pub use` consumers)
// keep working unchanged.
pub use vta_sdk::protocols::did_management::update::{
    RotateDidWebvhKeysBody as RotateDidWebvhKeysOptions,
    UpdateDidWebvhResultBody as UpdateDidWebvhResult,
};

/// Caller-supplied parameters for
/// [`crate::operations::did_webvh::update::update_did_webvh`].
///
/// This is the **op-layer-internal** representation — `witnesses` is
/// the typed `didwebvh_rs::Witnesses` enum so the update flow can
/// operate on it directly. The wire-format body
/// (`vta_sdk::protocols::did_management::update::UpdateDidWebvhBody`)
/// carries the same shape but with `witnesses: Option<Value>`; route /
/// dispatcher handlers deserialise the SDK body and convert to this
/// struct at intake. Keeping the typed shape internal isolates
/// `didwebvh-rs` as a dependency of the op layer rather than vta-sdk
/// (a leaf crate).
#[derive(Debug, Default, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateDidWebvhOptions {
    /// New DID document. `None` = keep existing. When `Some`, forces a
    /// parallel rotation of `update_keys` + pre-rotation commitments.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub document: Option<Value>,
    /// Override pre-rotation count. `None` = keep current. `Some(0)` =
    /// disable pre-rotation. `Some(n)` = use `n` keys.
    #[serde(default)]
    pub pre_rotation_count: Option<u32>,
    /// New witness configuration. `None` = keep current.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub witnesses: Option<Witnesses>,
    /// New watcher URLs. `None` = keep current. `Some(vec![])` disables.
    #[serde(default)]
    pub watchers: Option<Vec<String>>,
    /// New TTL in seconds. `None` = keep current.
    #[serde(default)]
    pub ttl: Option<u32>,
    /// Operator-facing label for audit. Optional.
    #[serde(default)]
    pub label: Option<String>,
    /// Optimistic-concurrency precondition. When `Some`, the operation
    /// refuses with `Conflict` if the DID's latest log entry no longer
    /// matches this versionId. Lets a `get → edit → save` flow detect
    /// lost updates instead of silently overwriting another operator's
    /// edits with a chain that's structurally valid but content-wise
    /// based on a stale read. `None` (default) preserves prior
    /// behaviour for scripted callers.
    #[serde(default)]
    pub expected_version_id: Option<String>,
}

// `UpdateDidWebvhResult` is now an alias for
// `vta_sdk::...::UpdateDidWebvhResultBody` (re-exported above). The
// types had identical fields; consolidating to a single source of
// truth in vta-sdk. Op-layer call sites continue to work via the
// `pub use ... as UpdateDidWebvhResult` re-export.

/// A freshly-derived webvh key. Not yet persisted — the caller installs
/// it via
/// [`crate::operations::did_webvh::update::keys::install_derived_webvh_keys`]
/// after `didwebvh_rs::update_did` returns with the real new
/// `version_id` (the version-id is part of the storage key, and we
/// can't predict the hash component of it).
///
/// The secret itself isn't stored on the struct — webvh handles are
/// re-derivable from `(seed_id, derivation_path)`, so the caller gets
/// what it needs to persist the handle without holding key material
/// across the async boundary.
pub(in crate::operations::did_webvh) struct DerivedWebvhKey {
    pub public_key: String,
    pub hash: String,
    pub derivation_path: String,
    pub seed_id: u32,
}

/// Hard cap on per-witness DID resolution. Witnesses are typically
/// `did:key` (self-resolving, instant) but the library also accepts
/// `did:web`-style witnesses. 5s is generous for self-resolving keys
/// and short enough that an unresponsive web resolver doesn't hang the
/// admin's update call.
pub(in crate::operations::did_webvh) const WITNESS_RESOLVE_TIMEOUT: Duration =
    Duration::from_secs(5);

// `RotateDidWebvhKeysOptions` is now an alias for
// `vta_sdk::...::RotateDidWebvhKeysBody` (re-exported above). Same
// fields; consolidating to a single source of truth in vta-sdk.
