//! DID document templates.
//!
//! A template is a JSON file (or embedded built-in) describing the shape of
//! a DID document with `{TOKEN}` placeholders. Callers render the template
//! by supplying variable values; the renderer returns a concrete
//! `serde_json::Value` ready to hand to a DID-method-specific create
//! operation (e.g. `create_did_webvh`).
//!
//! The format is deliberately declarative — no conditionals, no loops, no
//! includes. Templates that need branching ship as two templates. See the
//! `format` module docs for the full schema.
//!
//! # Scopes
//!
//! Templates live in one of three scopes:
//!
//! - **Built-in** — embedded in this crate at compile time. Always available.
//!   Load via [`builtin::load_embedded`].
//! - **Global** (VTA-stored) — super-admin-managed, visible across all
//!   contexts on a given VTA. Managed via REST routes in Phase 2.
//! - **Context** (VTA-stored) — context-admin-managed, visible only within
//!   one context. Phase 3.
//!
//! Resolution order when a caller names a template without explicit scope:
//! context → global → builtin. Callers can disambiguate with [`Scope`].
//!
//! # Example
//!
//! ```ignore
//! use vta_sdk::did_templates::{DidTemplate, TemplateVars};
//!
//! let tpl = DidTemplate::load_embedded("didcomm-mediator")?;
//! let mut vars = TemplateVars::new();
//! vars.insert_string("DID", "did:webvh:...");
//! vars.insert_string("SIGNING_KEY_MB", "z6Mk...");
//! vars.insert_string("KA_KEY_MB", "z6LS...");
//! vars.insert_string("URL", "https://mediator.example.com");
//! let doc = tpl.render(&vars)?;
//! ```

mod builtin;
mod render;
mod validate;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use builtin::{BUILTIN_NAMES, load_embedded};

/// Minimum supported template `schemaVersion`.
pub const SCHEMA_VERSION_MIN: u32 = 1;
/// Maximum supported template `schemaVersion`.
pub const SCHEMA_VERSION_MAX: u32 = 1;

/// Placeholder names supplied automatically by the renderer. They cannot
/// appear in a template's `requiredVars` or `optionalVars` — callers and
/// templates declare only the things the renderer doesn't already know.
pub const RESERVED_VARS: &[&str] = &[
    "DID",
    "SIGNING_KEY_MB",
    "KA_KEY_MB",
    "VTA_DID",
    "VTA_URL",
    "CONTEXT_ID",
    "CONTEXT_DID",
    "NOW",
];

/// Storage scope for a template. `Builtin` is in-memory only (never written
/// to the VTA); `Global` and `Context` are persisted by the VTA in Phase 2+.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Scope {
    Builtin,
    Global,
    Context {
        #[serde(rename = "contextId")]
        context_id: String,
    },
}

/// A parsed DID template. Serialized shape matches the on-disk JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DidTemplate {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    pub name: String,

    /// Classification hint: `"mediator"`, `"webvh-hosting"`, `"custom"`, …
    /// Not interpreted by the renderer; consumed by UX (icons, default
    /// behaviours in setup wizards).
    pub kind: String,

    #[serde(default)]
    pub description: Option<String>,

    /// DID methods this template is designed for (e.g. `["webvh", "web"]`).
    /// Advisory only — not enforced by the renderer.
    #[serde(default)]
    pub methods: Vec<String>,

    /// Variables the caller MUST supply. Reserved ambient names are not
    /// allowed here (see [`RESERVED_VARS`]).
    #[serde(default, rename = "requiredVars")]
    pub required_vars: Vec<String>,

    /// Variables with default values. Caller-supplied values override.
    #[serde(default, rename = "optionalVars")]
    pub optional_vars: serde_json::Map<String, Value>,

    /// Hints for the CLI / setup wizards (e.g. `preRotationCount`, `portable`).
    /// Not consumed by the renderer itself.
    #[serde(default)]
    pub defaults: serde_json::Map<String, Value>,

    /// The DID document with `{TOKEN}` placeholders.
    pub document: Value,
}

impl DidTemplate {
    /// Parse a template from its JSON representation.
    pub fn from_json(value: Value) -> Result<Self, TemplateError> {
        let tpl: DidTemplate = serde_json::from_value(value)?;
        tpl.validate()?;
        Ok(tpl)
    }

    /// Load and parse a template from a JSON file on disk.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, TemplateError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| TemplateError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let value: Value = serde_json::from_slice(&bytes)?;
        Self::from_json(value)
    }

    /// Render the template with the supplied variables, returning a concrete
    /// DID document ready to hand to a DID-method create operation.
    ///
    /// Ambient variables the renderer knows about are picked up from `vars`
    /// if set (e.g. by the server before handing the vars map to this
    /// function). Missing required vars, unknown placeholders, or reserved
    /// names in the wrong place all produce errors.
    pub fn render(&self, vars: &TemplateVars) -> Result<Value, TemplateError> {
        render::render(self, vars)
    }

    /// Structural + semantic lint. Called automatically by [`Self::from_json`].
    pub fn validate(&self) -> Result<(), TemplateError> {
        validate::validate(self)
    }
}

/// Caller + ambient variables supplied to [`DidTemplate::render`].
///
/// Insertion order is preserved for error messages but not semantically
/// meaningful. Later `insert` calls overwrite earlier ones — this is how
/// caller-supplied values override ambient defaults populated by the server.
#[derive(Debug, Clone, Default)]
pub struct TemplateVars {
    vars: HashMap<String, Value>,
}

impl TemplateVars {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a variable with any JSON-serializable value.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.vars.insert(key.into(), value.into());
        self
    }

    /// Convenience for string variables (the common case from CLI `--var` flags).
    pub fn insert_string(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.vars.insert(key.into(), Value::String(value.into()));
        self
    }

    /// Merge another map into this one; values in `other` override existing.
    pub fn extend(&mut self, other: TemplateVars) {
        self.vars.extend(other.vars);
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.vars.get(key)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.vars.keys()
    }
}

/// A DID template as persisted by the VTA (Phase 2+). The [`DidTemplate`] is
/// the raw authored shape; this wrapper adds provenance metadata the server
/// maintains (scope, timestamps, author DID).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DidTemplateRecord {
    #[serde(flatten)]
    pub template: DidTemplate,
    pub scope: Scope,
    /// UTC unix-epoch seconds. Displayed in the operator's local timezone.
    pub created_at: u64,
    /// UTC unix-epoch seconds. Displayed in the operator's local timezone.
    pub updated_at: u64,
    /// DID of the admin who last wrote this template.
    pub created_by: String,
}

/// Errors from template parsing, validation, and rendering.
#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("failed to read template file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "unsupported schemaVersion {found} (this SDK supports {min}..={max}). Upgrade the SDK or downgrade the template."
    )]
    UnsupportedSchema { found: u32, min: u32, max: u32 },

    #[error("invalid template: {0}")]
    Invalid(String),

    #[error("missing required variable(s): {0}. Supply with --var NAME=VALUE.")]
    MissingVars(String),

    #[error(
        "unresolved placeholder(s) in rendered document: {0}. This is a bug in the template, not a missing --var."
    )]
    Unresolved(String),

    #[error(
        "reserved variable name '{0}' cannot appear in requiredVars/optionalVars — it is supplied automatically by the renderer"
    )]
    ReservedVar(String),

    #[error(
        "builtin template '{0}' not found (available: ai-agent, ai-agent-peer, did-host-didcomm, did-host-http, did-host-http-didcomm, didcomm-mediator, vta-admin, vtc-host)"
    )]
    BuiltinNotFound(String),
}
