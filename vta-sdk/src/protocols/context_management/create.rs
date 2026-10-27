use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateContextBody {
    /// Leaf segment when `parent` is set (full path = `<parent>/<id>`), else a
    /// top-level segment.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parent context path to nest under, or `None` for a top-level context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateContextResultBody {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parent context id, or `None` for a top-level context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(alias = "base_path")]
    pub base_path: String,
    #[serde(alias = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(alias = "updated_at")]
    pub updated_at: DateTime<Utc>,
    /// Key designated to sign credentials issued as this context's DID.
    /// Absent means this context cannot issue.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "issuer_key_id"
    )]
    pub issuer_key_id: Option<String>,
    /// Keys designated to produce Data-Integrity proofs as this context's DID,
    /// by `proofPurpose`.
    #[serde(
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        alias = "proof_key_ids"
    )]
    pub proof_key_ids: std::collections::BTreeMap<String, String>,
}
