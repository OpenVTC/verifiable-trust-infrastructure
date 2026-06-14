use serde::{Deserialize, Serialize};

use crate::webvh::WebvhDidRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDidWebvhBody {
    pub did: String,
}

pub type GetDidWebvhResultBody = WebvhDidRecord;
