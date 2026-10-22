//! Wire payloads for `spec/vta/contexts/set-issuer-key/0.1`.
//!
//! Designates the key that signs credentials issued **as a context's own DID**
//! (`spec/vta/credentials/issue-in-context/0.1`).
//!
//! Its own task rather than a member on `contexts/update/1.0`: that task has a
//! published schema which forbids additional properties, so a designation sent
//! there is refused on the wire before any handler sees it.

use serde::{Deserialize, Serialize};

use super::create::CreateContextResultBody;

/// `spec/vta/contexts/set-issuer-key/0.1` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SetContextIssuerKeyBody {
    /// The context whose issuer key is being designated.
    pub id: String,
    /// The key to designate, or `None` to clear the designation (after which
    /// the context can no longer issue).
    ///
    /// The key must live in `id`'s context: the designation is what lets a
    /// context-scoped caller issue *without* naming a key, so one pointing
    /// outside the context would hand that caller a key it cannot otherwise
    /// reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

impl SetContextIssuerKeyBody {
    /// Designate `key_id` as `id`'s issuer key.
    pub fn new(id: String, key_id: Option<String>) -> Self {
        Self { id, key_id }
    }
}

/// The updated context record.
pub type SetContextIssuerKeyResultBody = CreateContextResultBody;
