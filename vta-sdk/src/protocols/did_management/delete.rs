use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteDidWebvhBody {
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeleteDidWebvhResultBody {
    pub did: String,
    pub deleted: bool,
    /// Outcome of the daemon-side cleanup. `Ok(())` when the
    /// hosting server confirmed deletion (or the DID was
    /// serverless and no daemon call was needed). `Err(reason)`
    /// when the daemon delete failed — local cleanup proceeded
    /// regardless (a stale daemon registration is preferable to a
    /// half-deleted local state) but the operator is responsible
    /// for the orphaned daemon-side entry. The CLI surfaces this
    /// with a corrective hint.
    ///
    /// Skipped on serialise when `Ok(())` to keep the wire format
    /// backwards-compatible with consumers that expect the older
    /// `{did, deleted}` shape — a missing field deserialises as
    /// `None`, treated as "no daemon call needed."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_cleanup_error: Option<String>,
}
