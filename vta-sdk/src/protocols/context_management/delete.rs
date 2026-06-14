use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteContextBody {
    pub id: String,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteContextResultBody {
    pub id: String,
    pub deleted: bool,
}

/// Summary of resources that will be removed when deleting a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteContextPreviewBody {
    pub id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteContextPreviewResultBody {
    pub id: String,
    pub keys: Vec<String>,
    pub webvh_dids: Vec<String>,
    /// ACL entries that will be deleted (only have this context).
    pub acl_entries_removed: Vec<String>,
    /// ACL entries that will have this context removed from their allowed list.
    pub acl_entries_updated: Vec<String>,
    /// DID templates scoped to this context that will be deleted.
    #[serde(default)]
    pub did_templates: Vec<String>,
}
