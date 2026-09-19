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
#[serde(rename_all = "camelCase")]
pub struct DeleteContextResultBody {
    pub id: String,
    pub deleted: bool,
    /// One entry per `did:webvh` DID in the deleted subtree whose local record
    /// went while its hosting server did not confirm removal of the published
    /// log. **Those DIDs may still resolve.**
    ///
    /// A partial success reported as a success — the subtree-wide form of
    /// `vta/webvh/dids/delete/1.0`'s `daemonCleanupError` — so a consumer
    /// surfaces it rather than treating the deletion as complete. Absent when
    /// every host copy was confirmed gone, which is the ordinary case;
    /// `skip_serializing_if` keeps it off the wire then, because an empty
    /// array reads as a report that was made and came back clean, and that is
    /// a different claim from one that had nothing to report.
    #[serde(
        default,
        alias = "daemon_cleanup_errors",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub daemon_cleanup_errors: Vec<String>,
}

/// Summary of resources that will be removed when deleting a context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteContextPreviewBody {
    pub id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteContextPreviewResultBody {
    pub id: String,
    /// Sub-contexts that would go with this one, as full paths, deepest
    /// first. Every other array here is the union over these and the named
    /// context, because that is what the deletion acts on.
    #[serde(default, alias = "sub_contexts", skip_serializing_if = "Vec::is_empty")]
    pub sub_contexts: Vec<String>,
    pub keys: Vec<String>,
    #[serde(alias = "webvh_dids")]
    pub webvh_dids: Vec<String>,
    /// ACL entries that will be deleted (only have this context).
    #[serde(alias = "acl_entries_removed")]
    pub acl_entries_removed: Vec<String>,
    /// ACL entries that will have this context removed from their allowed list.
    #[serde(alias = "acl_entries_updated")]
    pub acl_entries_updated: Vec<String>,
    /// DID templates scoped to this context that will be deleted.
    #[serde(default, alias = "did_templates")]
    pub did_templates: Vec<String>,
}
