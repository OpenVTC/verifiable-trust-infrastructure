use serde::{Deserialize, Serialize};

use super::create::CreateContextResultBody;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListContextsBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListContextsResultBody {
    pub contexts: Vec<CreateContextResultBody>,
}
