//! `config/show/0.1` — read the VTA's runtime configuration.
//!
//! Folded onto the canonical `config/*` family (#840 phase A). The VTA
//! previously exposed three named, typed fields (`vta_did`, `vta_name`,
//! `public_url`); canonical `config/show` returns a **registry** of keys, each
//! carrying where its effective value came from and whether a restart is
//! needed for a change to take effect. Same information, one shape shared with
//! every other agent.

use serde::{Deserialize, Serialize};

/// `config/show/0.1` request. `keys` narrows the result; omitted returns every
/// registered key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetConfigBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
}

/// One configuration key as the operator currently sees it — canonical
/// `config/_shared/0.1/config#ConfigField`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfigField {
    /// The configuration key, e.g. `vta_name`.
    pub key: String,
    /// The effective value. `null` when the key is unset.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub value: serde_json::Value,
    /// Which layer supplied the effective value — `setup`, `toml`, `default`.
    pub source: String,
    /// True when a change to this key takes effect only after a restart.
    pub requires_restart: bool,
}

/// `config/show/0.1` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetConfigResultBody {
    pub fields: Vec<ConfigField>,
}

impl GetConfigResultBody {
    /// Value of `key`, if the registry carries it and it is set.
    ///
    /// Convenience for callers that want one key out of the registry — most
    /// commonly `vta_did`, which is read far more often than the rest and used
    /// to have a named field of its own.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .map(|f| &f.value)
            .filter(|v| !v.is_null())
    }

    /// `vta_did` as a string, if set. The VTA's own identity is read-only —
    /// see `update_config` for why it cannot be patched.
    pub fn vta_did(&self) -> Option<&str> {
        self.get("vta_did").and_then(|v| v.as_str())
    }
}
