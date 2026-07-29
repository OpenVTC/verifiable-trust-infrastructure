//! Wire bodies for the `render` op.
//!
//! Render takes a template name + caller-supplied variables and
//! returns the rendered DID document. The VTA injects ambient
//! variables server-side before substitution: `VTA_DID`, `VTA_URL`,
//! `NOW` always; `CONTEXT_ID` and (if set on the context)
//! `CONTEXT_DID` when the request carries a `contextId`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `spec/vta/did-templates/render/2.0` payload — render a template
/// from one scope with caller vars. `context_id` absent: the global
/// scope (any authed caller). `context_id` present: that context's
/// scope, with fall-through to a global template of the same name
/// per the op layer's scope-fallback rule (requires context access).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenderDidTemplateBody {
    /// Scope selector. `None` = global scope; `Some` = that context
    /// (adds ambient `CONTEXT_ID` / `CONTEXT_DID` variables).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub vars: HashMap<String, Value>,
}

/// Result body. `document` is the rendered DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RenderDidTemplateResultBody {
    pub document: Value,
}
