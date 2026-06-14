//! Wire bodies for the `render` op (both scopes).
//!
//! Render takes a template name + caller-supplied variables and
//! returns the rendered DID document. The VTA injects ambient
//! variables (`VTA_DID`, `NOW`, etc.) server-side before
//! substitution.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `spec/vta/did-templates/render/1.0` payload — render a global
/// template with caller vars. Auth: any authed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RenderDidTemplateBody {
    pub name: String,
    #[serde(default)]
    pub vars: HashMap<String, Value>,
}

/// `spec/vta/contexts/did-templates/render/1.0` payload — render a
/// context-scoped template (or fall through to global). Auth: any
/// authed with access to the context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RenderContextDidTemplateBody {
    pub context_id: String,
    pub name: String,
    #[serde(default)]
    pub vars: HashMap<String, Value>,
}

/// Shared result body. `document` is the rendered DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RenderDidTemplateResultBody {
    pub document: Value,
}
