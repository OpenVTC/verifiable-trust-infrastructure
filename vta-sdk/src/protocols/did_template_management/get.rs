//! Wire bodies for the `get` op (both scopes).
//!
//! The result body for both URIs is the persisted
//! [`DidTemplateRecord`].

use serde::{Deserialize, Serialize};

/// `spec/vta/did-templates/get/1.0` payload — fetch one global
/// template by name. Auth: any authed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDidTemplateBody {
    pub name: String,
}

/// `spec/vta/contexts/did-templates/get/1.0` payload — fetch one
/// context-scoped template by name. Auth: any authed with access to
/// the context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct GetContextDidTemplateBody {
    pub context_id: String,
    pub name: String,
}
