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
pub struct CreateContextResultBody {
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    /// Parent context id, or `None` for a top-level context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub base_path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
