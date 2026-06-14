use serde::{Deserialize, Serialize};

use super::create::CreateAclResultBody;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAclBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListAclResultBody {
    pub entries: Vec<CreateAclResultBody>,
}
