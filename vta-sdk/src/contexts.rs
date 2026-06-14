use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ContextRecord {
    /// The context's materialized path identifier — slash-separated segments
    /// (e.g. `acme/eng/team-a`). A top-level context is a single segment.
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    /// The parent context's id, or `None` for a top-level context. Together
    /// with [`id`](Self::id) this records the tree; absent on legacy (flat)
    /// records, which deserialize as top-level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// BIP-32 derivation base for this context's keys. For a sub-context this
    /// nests under the parent's base (`{parent.base_path}/<child>'`).
    pub base_path: String,
    pub index: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
