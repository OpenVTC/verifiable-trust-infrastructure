//! Wire bodies for the `update` op.
//!
//! "Update" replaces the template at `name` with the new
//! [`DidTemplate`]; the template's own `name` field must match the
//! resource id (legacy REST: `PATCH /did-templates/{name}`).
//!
//! The result body is the new persisted [`DidTemplateRecord`].
//!
//! [`DidTemplateRecord`]: crate::did_templates::DidTemplateRecord

use serde::{Deserialize, Serialize};

use crate::did_templates::DidTemplate;

/// `spec/vta/did-templates/update/2.0` payload — replace a template
/// in one scope. `context_id` absent: the global scope (super-admin
/// gated). `context_id` present: that context's scope (context admin
/// OR super-admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UpdateDidTemplateBody {
    /// Scope selector. `None` = global scope; `Some` = that context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Resource id (the template's name). The op layer rejects with
    /// `Validation` if `template.name != name`.
    pub name: String,
    pub template: DidTemplate,
}
