//! Wire bodies for the `create` op.
//!
//! The result body is the persisted [`DidTemplateRecord`] — same
//! shape as `GET /did-templates/{name}`.
//!
//! [`DidTemplateRecord`]: crate::did_templates::DidTemplateRecord

use serde::{Deserialize, Serialize};

use crate::did_templates::DidTemplate;

/// `spec/vta/did-templates/create/2.0` payload — create a template
/// in one scope. `context_id` absent: the global scope (super-admin
/// gated). `context_id` present: that context's scope (context admin
/// OR super-admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateDidTemplateBody {
    /// Scope selector. `None` = global scope; `Some` = that context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Full template document. The template's `name` field is the
    /// resource id within the selected scope; the VTA refuses
    /// duplicates.
    pub template: DidTemplate,
}
