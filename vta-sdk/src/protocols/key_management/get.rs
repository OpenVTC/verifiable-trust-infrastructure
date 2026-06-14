use serde::{Deserialize, Serialize};

use crate::keys::KeyRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetKeyBody {
    pub key_id: String,
}

pub type GetKeyResultBody = KeyRecord;
