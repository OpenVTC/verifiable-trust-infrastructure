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
mod transports;
mod trust_registry;
mod validate;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use builtin::{BUILTIN_NAMES, load_embedded};
pub use transports::{
    DIDCOMM_SERVICE_VAR, TSP_SERVICE_VAR, didcomm_service, tsp_service, tsp_transport_service,
};
pub use trust_registry::{
    TRQP_PROFILE_URI, TRUST_REGISTRY_SERVICE_TYPE, TRUST_REGISTRY_SERVICE_VAR, referral_service,
};

/// Minimum supported template `schemaVersion`.
pub const SCHEMA_VERSION_MIN: u32 = 1;
/// Maximum supported template `schemaVersion`.
///
/// **2** adds the `keys` block — see [`KeySlot`]. A v1 template is exactly a v2
/// template whose `keys` block is the historical default, so raising this
/// changes nothing about how a v1 template renders.
pub const SCHEMA_VERSION_MAX: u32 = 2;

/// The `schemaVersion` at which the `keys` block became expressible.
pub const SCHEMA_VERSION_KEYS_BLOCK: u32 = 2;

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

/// What a declared key slot is *for*, which decides the verification
/// relationships a renderer may put it in.
///
/// Deliberately coarser than DID Core's five relationships: a template says
/// what the key is, and the document body says where it appears. Encoding the
/// relationship here as well would let the two disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum KeyPurpose {
    /// Signs. Authentication, assertion, capability invocation/delegation.
    Signing,
    /// Agrees a shared secret. `keyAgreement` only — a signing algorithm
    /// cannot serve here, which is why the two are separate slots rather than
    /// one key used twice.
    KeyAgreement,
}

/// One declared key in a template: what it is for, and which algorithms are
/// acceptable for it in preference order.
///
/// # Why a list rather than one algorithm
///
/// A fleet does not migrate atomically. `["mldsa44", "ed25519"]` says *mint
/// ML-DSA-44 if this VTA can, otherwise Ed25519* — so one template serves a
/// VTA that has post-quantum support and one that does not, and the same
/// template stops being a fallback the day the fleet finishes upgrading.
///
/// The order is the preference, highest first. An empty list is refused rather
/// than treated as "anything": a template that expresses no preference would
/// silently inherit whatever the implementation happened to default to, which
/// is how a post-quantum deployment quietly mints classical keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KeySlot {
    pub purpose: KeyPurpose,
    /// Acceptable algorithms, most preferred first. Names match
    /// `vta_sdk::keys::KeyType`'s serde spelling (`ed25519`, `x25519`, `p256`,
    /// `mldsa44`, `mldsa65`).
    pub algorithms: Vec<String>,
}

/// The slot name a v1 template's `{SIGNING_KEY_MB}` refers to.
pub const SLOT_SIGNING: &str = "signing";
/// The slot name a v1 template's `{KA_KEY_MB}` refers to.
pub const SLOT_KA: &str = "ka";

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
#[serde(rename_all = "camelCase")]
pub struct DidTemplate {
    #[serde(rename = "schemaVersion", alias = "schema_version")]
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
    #[serde(default, rename = "requiredVars", alias = "required_vars")]
    pub required_vars: Vec<String>,

    /// Variables with default values. Caller-supplied values override.
    #[serde(default, rename = "optionalVars", alias = "optional_vars")]
    pub optional_vars: serde_json::Map<String, Value>,

    /// Hints for the CLI / setup wizards (e.g. `preRotationCount`, `portable`).
    /// Not consumed by the renderer itself.
    #[serde(default)]
    pub defaults: serde_json::Map<String, Value>,

    /// The keys this template needs, by slot name (`schemaVersion` 2+).
    ///
    /// Absent means the historical pair — see [`DidTemplate::key_slots`], which
    /// is what every consumer should read rather than this field, so a v1 and a
    /// v2 template are handled by one code path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<std::collections::BTreeMap<String, KeySlot>>,

    /// The DID document with `{TOKEN}` placeholders.
    pub document: Value,
}

impl DidTemplate {
    /// The keys this template needs, whatever `schemaVersion` it declares.
    ///
    /// **Read this, not the `keys` field.** A v1 template has no `keys` block
    /// and is not thereby key-less: it means the pair this stack has always
    /// minted, an Ed25519 signing key and an X25519 key-agreement key, which is
    /// exactly what its `{SIGNING_KEY_MB}` and `{KA_KEY_MB}` placeholders refer
    /// to. Returning that here is what lets a v1 and a v2 template take one
    /// code path — and is why raising `SCHEMA_VERSION_MAX` cannot change how a
    /// v1 template renders.
    pub fn key_slots(&self) -> std::collections::BTreeMap<String, KeySlot> {
        if let Some(declared) = &self.keys {
            return declared.clone();
        }
        std::collections::BTreeMap::from([
            (
                SLOT_SIGNING.to_string(),
                KeySlot {
                    purpose: KeyPurpose::Signing,
                    algorithms: vec!["ed25519".to_string()],
                },
            ),
            (
                SLOT_KA.to_string(),
                KeySlot {
                    purpose: KeyPurpose::KeyAgreement,
                    algorithms: vec!["x25519".to_string()],
                },
            ),
        ])
    }

    /// The placeholder names this template's key slots occupy.
    ///
    /// A slot's public key is substituted by the minting flow from the key it
    /// actually minted — never by a template author, who has no way to know it.
    /// That makes these names **ambient**, exactly like `{DID}`: usable in the
    /// document without being declared, and not declarable as a variable.
    ///
    /// The two a v1 template uses are in [`RESERVED_VARS`] already, and this is
    /// built from [`Self::key_slots`] rather than from a second fixed list, so
    /// a v2 template declaring a third slot gets the same treatment without its
    /// name having to be added anywhere. That is the whole point: `slot_var`'s
    /// rule is mechanical, and before this existed it was mechanical in only
    /// one direction — a third slot's placeholder was rejected as undeclared,
    /// and declaring it was worse than being rejected (see
    /// `validate::check_slot_vars_not_declared`).
    pub fn slot_vars(&self) -> std::collections::BTreeSet<String> {
        self.key_slots().keys().map(|s| Self::slot_var(s)).collect()
    }

    /// The placeholder a slot's public key is rendered into.
    ///
    /// `signing` -> `SIGNING_KEY_MB`, `ka` -> `KA_KEY_MB`. The rule is
    /// mechanical (`{SLOT_UPPERCASE}_KEY_MB`) and chosen so the two names v1
    /// already uses fall out of it rather than being special-cased — a v2
    /// template declaring `signing` and `ka` renders against exactly the
    /// placeholders a v1 template does.
    pub fn slot_var(slot: &str) -> String {
        format!("{}_KEY_MB", slot.to_ascii_uppercase().replace('-', "_"))
    }

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
        "builtin template '{0}' not found (available: ai-agent, ai-agent-peer, did-host-didcomm, did-host-http, did-host-http-didcomm, did-host-http-tsp, did-host-tsp, didcomm-mediator, vta-admin, vtc-host)"
    )]
    BuiltinNotFound(String),
}
