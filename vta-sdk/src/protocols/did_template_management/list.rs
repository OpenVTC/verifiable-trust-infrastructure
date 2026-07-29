//! Wire bodies for the `list` op.

use serde::{Deserialize, Serialize};

use crate::did_templates::DidTemplateRecord;

/// `spec/vta/did-templates/list/2.0` payload — list the templates in
/// one scope. `context_id` absent: the global templates (any authed
/// caller). `context_id` present: the templates scoped to that
/// context (requires context access).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListDidTemplatesBody {
    /// Scope selector. `None` = global scope; `Some` = that context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

/// Result body. Returns the templates of the selected scope (global
/// ones when the request carried no `contextId`, that context's
/// otherwise).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListDidTemplatesResultBody {
    pub templates: Vec<DidTemplateRecord>,
}
