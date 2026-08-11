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

/// `vault/upsert/0.1` — create or update a vault entry.
///
/// The one member of the family worth a type. The rest are pass-throughs whose
/// payloads the SDK does not shape at all; this one is the entry itself — the
/// surface a caller most often gets wrong, and the largest.
///
/// ## Why the escape hatch
///
/// `extra` carries anything this build does not model. Without it, typing the
/// body would mean an SDK release before a caller could use *any* member the
/// spec adds — the real cost of modelling a moving surface, and the reason the
/// rest of `vault/*` stays untyped. With it, a caller gets named members and
/// compile-time help for what exists today, and is never blocked on us for what
/// does not.
///
/// The trade is explicit rather than hidden: modelled members are guarded by
/// the null census, `extra` is not. It is greppable, and a member that lands in
/// it repeatedly is a member that wants promoting into the struct.
///
/// `sealedSecret` is deliberately absent: [`VtaClient::vault_upsert`] inserts
/// it, because sealing needs the client's HPKE context rather than the caller's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultUpsertBody {
    pub context_id: String,
    /// `SiteTarget` union values — `{"kind": "web-origin", "origin": …}` and
    /// friends. Left as `Value` for the same reason `ConsentSubject` is: it is
    /// a union the caller assembles, and modelling it is a separate decision.
    pub targets: Vec<serde_json::Value>,
    pub label: String,
    /// `password` | `passkey` | `oauth-tokens` | `did-self-issued` |
    /// `didcomm-peer` | `bearer-token` | `ssh-key` | `custom`.
    pub secret_kind: String,
    /// Absent on create; present to update a specific entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Optimistic-concurrency precondition, as on `vault/delete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Members this build does not model — see the type's docs.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod upsert_tests {
    use super::*;

    /// A minimal create: the four required members and nothing else. Every
    /// optional is absent, and the escape hatch contributes no member of its own.
    #[test]
    fn a_minimal_upsert_carries_only_what_was_set() {
        let body = VaultUpsertBody {
            context_id: "openvtc".into(),
            targets: vec![
                serde_json::json!({"kind": "web-origin", "origin": "https://example.test"}),
            ],
            label: "example login".into(),
            secret_kind: "password".into(),
            id: None,
            expected_version: None,
            tags: None,
            notes: None,
            expires_at: None,
            extra: serde_json::Map::new(),
        };
        assert_eq!(
            serde_json::to_value(&body).expect("serialises"),
            serde_json::json!({
                "contextId": "openvtc",
                "targets": [{"kind": "web-origin", "origin": "https://example.test"}],
                "label": "example login",
                "secretKind": "password",
            })
        );
    }

    /// The escape hatch flattens beside the modelled members rather than nesting
    /// under a member of its own — which is what makes it forward-compatible
    /// instead of a second, incompatible shape.
    #[test]
    fn unmodelled_members_flatten_alongside() {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "favicon".into(),
            serde_json::json!("data:image/png;base64,AA"),
        );
        let body = VaultUpsertBody {
            context_id: "openvtc".into(),
            targets: vec![
                serde_json::json!({"kind": "web-origin", "origin": "https://example.test"}),
            ],
            label: "example login".into(),
            secret_kind: "password".into(),
            id: None,
            expected_version: None,
            tags: None,
            notes: None,
            expires_at: None,
            extra,
        };
        let v = serde_json::to_value(&body).expect("serialises");
        assert_eq!(
            v.get("favicon").and_then(|f| f.as_str()),
            Some("data:image/png;base64,AA"),
            "an unmodelled member sits beside the modelled ones"
        );
        assert!(
            v.get("extra").is_none(),
            "the hatch itself is never a member"
        );
    }
}
