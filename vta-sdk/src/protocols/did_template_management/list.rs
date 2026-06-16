//! Wire bodies for the `list` op (both scopes).

use serde::{Deserialize, Serialize};

use crate::did_templates::DidTemplateRecord;

/// `spec/vta/did-templates/list/1.0` payload — list global
/// templates. Empty body; the request has no parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListDidTemplatesBody {}

/// `spec/vta/contexts/did-templates/list/1.0` payload — list
/// templates scoped to a specific context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListContextDidTemplatesBody {
    pub context_id: String,
}

/// Shared result body for both list URIs. Returns the matching
/// templates (global ones for the global URI, context-scoped ones
/// for the context URI).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListDidTemplatesResultBody {
    pub templates: Vec<DidTemplateRecord>,
}
