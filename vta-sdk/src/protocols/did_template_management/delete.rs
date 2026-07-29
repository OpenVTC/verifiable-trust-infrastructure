//! Wire bodies for the `delete` op.

use serde::{Deserialize, Serialize};

/// `spec/vta/did-templates/delete/2.0` payload — remove a template
/// by name from one scope. `context_id` absent: the global scope
/// (super-admin gated). `context_id` present: that context's scope
/// (context admin OR super-admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteDidTemplateBody {
    /// Scope selector. `None` = global scope; `Some` = that context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    pub name: String,
}

/// Result body. Echoes the resource id back so callers can log the
/// deletion in audit pipelines that key on the wire payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteDidTemplateResultBody {
    pub name: String,
    pub deleted: bool,
}
