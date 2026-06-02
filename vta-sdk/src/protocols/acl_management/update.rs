use serde::{Deserialize, Serialize};

use super::create::CreateAclResultBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAclBody {
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
    /// Set the delegated step-up approver VID. `Some` sets it; `None` leaves
    /// it unchanged (matching the other fields — clearing an existing
    /// approver isn't expressible here, consistent with `label`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_approver: Option<String>,
}

pub type UpdateAclResultBody = CreateAclResultBody;
