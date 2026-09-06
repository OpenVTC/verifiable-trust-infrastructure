//! `config/patch/0.1` — change the VTA's runtime configuration.
//!
//! Folded onto the canonical `config/*` family (#840 phase A). The request is
//! a key/value map rather than named typed fields, and the response reports
//! per-key what happened: applied now, stored but pending a restart, or
//! rejected with a reason.
//!
//! # Identity is not patchable
//!
//! `vta_did` is a **readable but immutable** registry key: `config/show`
//! returns it, and a patch naming it lands in `rejected`. This is a change —
//! the pre-fold `config/update` wrote `vta_did` straight into `config.toml`
//! with no guard, so a single mistaken call could re-point the agent's own
//! identity and survive a restart. Every credential the VTA had issued, every
//! ACL grant naming it, and its DID-document linkage would then refer to an
//! identity it no longer claimed.
//!
//! It was super-admin gated, so this was a bricking footgun rather than a
//! privilege escalation — the same class of defect VTC fixed in its P1.1
//! hardening, and for the same reason: a mistaken patch must not strand the
//! daemon auth-dead or re-point the recovery authority.
//!
//! Modelling it as *immutable* rather than *absent from the registry* (VTC's
//! choice) keeps the read path and yields a better error — "identity is set at
//! setup" instead of "unknown key".

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::get_config::GetConfigResultBody;
use serde_json::Value;

/// `config/patch/0.1` request: `key → value`. Keys outside the registry, and
/// keys that are immutable at runtime, come back under `rejected` rather than
/// being silently dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[non_exhaustive]
pub struct UpdateConfigBody {
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub overrides: HashMap<String, serde_json::Value>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

impl UpdateConfigBody {
    /// Build a [`UpdateConfigBody`] from the members the schema requires.
    ///
    /// This type is `#[non_exhaustive]`, so it cannot be built with a struct
    /// literal from outside this crate — a new member added by a later revision
    /// of the schema would break every such literal, which is exactly what
    /// happened when `ext` arrived. The optional members stay public: set them
    /// on the value this returns.
    pub fn new(overrides: HashMap<String, serde_json::Value>) -> Self {
        Self {
            overrides,
            ext: None,
        }
    }
}

/// A key the patch declined to apply, and why — canonical
/// `config/_shared/0.1/config#RejectedKey`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RejectedKey {
    pub key: String,
    /// Why it was rejected — unknown key, immutable at runtime, wrong type.
    pub reason: String,
}

/// `config/patch/0.1` response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateConfigResultBody {
    /// Keys whose new value is in effect now.
    pub applied: Vec<String>,
    /// Keys stored but needing a restart to take effect.
    pub pending_restart: Vec<String>,
    /// Keys not applied, each with a reason.
    pub rejected: Vec<RejectedKey>,
}

/// Retained so callers that want the post-patch view can ask for it without a
/// second round trip shape change; `config/show` is the canonical way to read.
pub type ConfigView = GetConfigResultBody;
