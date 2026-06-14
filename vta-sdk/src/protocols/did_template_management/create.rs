//! Wire bodies for the `create` op (both scopes).
//!
//! The result body for both URIs is the persisted
//! [`DidTemplateRecord`] — same shape as `GET /did-templates/{name}`.

use serde::{Deserialize, Serialize};

use crate::did_templates::DidTemplate;

/// `spec/vta/did-templates/create/1.0` payload — create a global
/// template. Auth: super-admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateDidTemplateBody {
    /// Full template document. The template's `name` field is the
    /// resource id; the VTA refuses duplicates.
    pub template: DidTemplate,
}

/// `spec/vta/contexts/did-templates/create/1.0` payload — create a
/// context-scoped template. Auth: super-admin OR admin-with-context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateContextDidTemplateBody {
    pub context_id: String,
    pub template: DidTemplate,
}
