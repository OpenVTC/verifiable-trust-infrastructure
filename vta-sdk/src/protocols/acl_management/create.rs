use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAclBody {
    pub did: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    /// Unix-epoch seconds at which the entry auto-expires. `None` = permanent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// VID authorized to ratify a delegated AAL2 step-up for this subject —
    /// the `recipient` an `auth/step-up/approve-request/0.1` is addressed to
    /// (the holder's mobile/browser approver). Stored on the ACL entry as
    /// `step_up_approver`. `None` = no delegated approver configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_approver: Option<String>,
    /// Per-entry step-up override (`"self"` | `"delegated"`) raising the system
    /// floor for this subject. Stored as `step_up_require`. `None` = no override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_require: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAclResultBody {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
    /// Unix-epoch seconds at which the entry auto-expires, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The delegated step-up approver the maintainer now holds for this
    /// subject, if any (echoes the stored `step_up_approver`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_approver: Option<String>,
    /// The per-entry step-up override the maintainer now holds for this subject,
    /// if any (echoes the stored `step_up_require`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_require: Option<String>,
}
