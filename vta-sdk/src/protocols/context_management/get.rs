use serde::{Deserialize, Serialize};

use super::create::CreateContextResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetContextBody {
    pub id: String,
}

pub type GetContextResultBody = CreateContextResultBody;
