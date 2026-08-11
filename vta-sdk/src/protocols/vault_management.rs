//! Canonical `vault/*` request bodies.
//!
//! Only `delete` is modelled, and deliberately so. The rest of the family takes
//! the whole payload as a caller-supplied `Value` — the SDK is a pass-through
//! there, so there is no emission of *ours* for a body struct to describe, and
//! inventing one would mean modelling a large, still-moving surface and
//! shipping an SDK release for every member the spec adds.
//!
//! Those are guarded instead by the pre-dispatch schema check in
//! [`VtaClient::dispatch_trust_task`](crate::client::VtaClient::dispatch_trust_task),
//! which is the only check a pass-through can have.

use serde::{Deserialize, Serialize};

/// `vault/delete/0.1` — delete an entry, optionally under an
/// optimistic-concurrency precondition.
///
/// Folded because it is the one `vault/*` method with unset optional members
/// built through an inline `json!` — the shape that produced #919. Its
/// siblings take the whole payload as a caller-supplied `Value` and have
/// nothing for a body struct to guard; this one does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDeleteBody {
    pub id: String,
    pub force: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod vault_tests {
    use super::*;

    /// An unset precondition and no reason: absent, not null.
    #[test]
    fn an_unset_delete_member_is_absent() {
        let body = VaultDeleteBody {
            id: "secret-1".into(),
            force: false,
            expected_version: None,
            reason: None,
        };
        assert_eq!(
            serde_json::to_value(&body).expect("serialises"),
            serde_json::json!({ "id": "secret-1", "force": false })
        );
    }
}
