//! Wire bodies for the `delete` op (both scopes).

use serde::{Deserialize, Serialize};

/// `spec/vta/did-templates/delete/1.0` payload — remove a global
/// template by name. Auth: super-admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteDidTemplateBody {
    pub name: String,
}

/// `spec/vta/contexts/did-templates/delete/1.0` payload — remove a
/// context-scoped template. Auth: super-admin OR
/// admin-with-context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteContextDidTemplateBody {
    pub context_id: String,
    pub name: String,
}

/// Shared result body. Echoes the resource id back so callers can
/// log the deletion in audit pipelines that key on the wire
/// payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteDidTemplateResultBody {
    pub name: String,
    pub deleted: bool,
}
