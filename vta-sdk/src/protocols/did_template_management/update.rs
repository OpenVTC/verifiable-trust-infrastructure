//! Wire bodies for the `update` op (both scopes).
//!
//! "Update" replaces the template at `name` with the new
//! [`DidTemplate`]; the template's own `name` field must match the
//! resource id (legacy REST: `PATCH /did-templates/{name}`).
//!
//! The result body for both URIs is the new persisted
//! [`DidTemplateRecord`].

use serde::{Deserialize, Serialize};

use crate::did_templates::DidTemplate;

/// `spec/vta/did-templates/update/1.0` payload — replace a global
/// template. Auth: super-admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDidTemplateBody {
    /// Resource id (the template's name). The op layer rejects with
    /// `Validation` if `template.name != name`.
    pub name: String,
    pub template: DidTemplate,
}

/// `spec/vta/contexts/did-templates/update/1.0` payload — replace
/// a context-scoped template. Auth: super-admin OR
/// admin-with-context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UpdateContextDidTemplateBody {
    pub context_id: String,
    pub name: String,
    pub template: DidTemplate,
}
