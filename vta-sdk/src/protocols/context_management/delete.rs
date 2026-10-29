use serde::{Deserialize, Serialize};

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

/// One DID whose published log a context deletion could not confirm removed
/// from its hosting server — an entry of the `hostCleanupFailures` array that
/// `vta/contexts/delete:hostCleanupFailed` carries in its error `details`.
///
/// Read from the error rather than a response, so it is a hand-written mirror
/// of the code's `detailsSchema`, which the codegen does not turn into a type.
/// Read leniently: this only decides what an operator is shown before being
/// asked, so an unexpected member must not hide the DIDs it came with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCleanupFailure {
    pub did: String,
    /// The VTA's id for the hosting server, when it records one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Why removal was not confirmed, for a human.
    pub reason: String,
}

impl std::fmt::Display for HostCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.did, self.reason)
    }
}

/// The DIDs a `vta/contexts/delete:hostCleanupFailed` refusal names, or `None`
/// when `err` is any other error.
///
/// The refusal means nothing local was deleted, so the caller can wait for
/// the host and retry, or retry with `abandonHostCopies` — and the
/// specification asks a producer to show these to a human before choosing the
/// second.
pub fn host_cleanup_failures(err: &crate::error::VtaError) -> Option<Vec<HostCleanupFailure>> {
    use trust_tasks_rs::specs::vta::contexts::delete::v1_1::error_codes::HOST_CLEANUP_FAILED;
    let crate::error::VtaError::Rejected { code, details, .. } = err else {
        return None;
    };
    if code != HOST_CLEANUP_FAILED.code {
        return None;
    }
    // A refusal with this code and unreadable details is still this refusal;
    // an empty list keeps the caller on the right branch.
    Some(
        details
            .as_ref()
            .and_then(|d| d.get("hostCleanupFailures"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
    )
}
