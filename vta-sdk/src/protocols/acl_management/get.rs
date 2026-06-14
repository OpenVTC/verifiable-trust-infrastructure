use serde::{Deserialize, Serialize};

use super::create::CreateAclResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetAclBody {
    pub did: String,
}

pub type GetAclResultBody = CreateAclResultBody;
