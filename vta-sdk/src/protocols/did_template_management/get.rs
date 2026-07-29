//! Wire bodies for the `get` op.
//!
//! The result body is the persisted [`DidTemplateRecord`].
//!
//! [`DidTemplateRecord`]: crate::did_templates::DidTemplateRecord

use serde::{Deserialize, Serialize};

/// `spec/vta/did-templates/get/2.0` payload — fetch one template by
/// name from one scope. `context_id` absent: the global scope (any
/// authed caller). `context_id` present: that context's scope
/// (requires context access).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct GetDidTemplateBody {
    /// Scope selector. `None` = global scope; `Some` = that context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub name: String,
}
