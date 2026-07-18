use serde::{Deserialize, Serialize};

/// Payload for the `spec/vta/acl/create/1.0` Trust Task.
///
/// **Wire casing is camelCase** (the published Trust-Task spec convention,
/// matching the sibling `acl/swap-key` body). Snake_case is still accepted on
/// input via per-field aliases so existing/legacy senders keep working, and
/// `deny_unknown_fields` makes a misspelled or unrecognized field a *loud*
/// rejection rather than a silent drop.
///
/// This matters for authorization safety: a silently-dropped `allowedContexts`
/// defaults to an empty vec, and an empty `allowed_contexts` on an `Admin`
/// entry is a **super-admin** (`AclEntry::is_super_admin`). Before camelCase
/// was accepted, a spec-conventional caller intending a scoped, expiring grant
/// could have both `allowedContexts` and `expiresAt` dropped and end up
/// minting a permanent, unrestricted admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAclBody {
    pub did: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, alias = "allowed_contexts")]
    pub allowed_contexts: Vec<String>,
    /// Unix-epoch seconds at which the entry auto-expires. `None` = permanent.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "expires_at")]
    pub expires_at: Option<u64>,
    /// VID authorized to ratify a delegated AAL2 step-up for this subject —
    /// the `recipient` an `auth/step-up/approve-request/0.1` is addressed to
    /// (the holder's mobile/browser approver). Stored on the ACL entry as
    /// `step_up_approver`. `None` = no delegated approver configured.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "step_up_approver"
    )]
    pub step_up_approver: Option<String>,
    /// Per-entry step-up override (`"self"` | `"delegated"`) raising the system
    /// floor for this subject. Stored as `step_up_require`. `None` = no override.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "step_up_require"
    )]
    pub step_up_require: Option<String>,
    /// Approve-authority: this DID may **confer** access via an approval
    /// (task-consent delegation / step-up ratification) over any context,
    /// **without** any authority to act. Granting this is super-admin-only.
    /// Takes precedence over `approve_contexts`. Stored as `approve_scope`.
    #[serde(
        default,
        skip_serializing_if = "std::ops::Not::not",
        alias = "approve_all_contexts"
    )]
    pub approve_all_contexts: bool,
    /// Approve-authority scoped to these contexts (and their subtrees): the DID
    /// may confer them via approval but cannot act in them. Ignored when
    /// `approve_all_contexts` is set. Empty = confers nothing (the default).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        alias = "approve_contexts"
    )]
    pub approve_contexts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression: a spec-conventional **camelCase** `acl/create` payload
    /// must populate `allowed_contexts`/`expires_at`, not silently drop them.
    /// A dropped `allowedContexts` on an Admin role is a permanent super-admin.
    #[test]
    fn camelcase_payload_populates_scope_and_expiry() {
        let json = serde_json::json!({
            "did": "did:key:z6MkSubject",
            "role": "admin",
            "allowedContexts": ["ctx-a", "ctx-b"],
            "expiresAt": 1_800_000_000u64,
            "stepUpApprover": "did:key:z6MkApprover",
            "stepUpRequire": "delegated",
        });
        let body: CreateAclBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.allowed_contexts, vec!["ctx-a", "ctx-b"]);
        assert_eq!(body.expires_at, Some(1_800_000_000));
        assert_eq!(
            body.step_up_approver.as_deref(),
            Some("did:key:z6MkApprover")
        );
        assert_eq!(body.step_up_require.as_deref(), Some("delegated"));
    }

    /// Back-compat: legacy/REST snake_case senders still deserialize via aliases.
    #[test]
    fn snakecase_payload_still_accepted_via_alias() {
        let json = serde_json::json!({
            "did": "did:key:z6MkSubject",
            "role": "admin",
            "allowed_contexts": ["ctx-a"],
            "expires_at": 1_800_000_000u64,
            "step_up_approver": "did:key:z6MkApprover",
        });
        let body: CreateAclBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.allowed_contexts, vec!["ctx-a"]);
        assert_eq!(body.expires_at, Some(1_800_000_000));
        assert_eq!(
            body.step_up_approver.as_deref(),
            Some("did:key:z6MkApprover")
        );
    }

    /// A misspelled/unknown scope field is a loud rejection, never a silent
    /// drop that would default the entry to unrestricted super-admin scope.
    #[test]
    fn unknown_field_is_rejected() {
        let json = serde_json::json!({
            "did": "did:key:z6MkSubject",
            "role": "admin",
            "allowedContext": ["ctx-a"], // note: singular typo
        });
        assert!(serde_json::from_value::<CreateAclBody>(json).is_err());
    }

    /// Serialization emits the canonical camelCase wire form.
    #[test]
    fn serializes_as_camelcase() {
        let body = CreateAclBody {
            did: "did:key:z6MkSubject".into(),
            role: "admin".into(),
            label: None,
            allowed_contexts: vec!["ctx-a".into()],
            expires_at: Some(1_800_000_000),
            step_up_approver: None,
            step_up_require: None,
            approve_all_contexts: false,
            approve_contexts: vec![],
        };
        let v = serde_json::to_value(&body).unwrap();
        assert!(v.get("allowedContexts").is_some());
        assert!(v.get("expiresAt").is_some());
        assert!(v.get("allowed_contexts").is_none());
    }

    /// Approve-authority fields round-trip via camelCase, and snake_case aliases
    /// are still accepted; the boolean/list default to off so an omitted scope
    /// confers nothing.
    #[test]
    fn approve_scope_fields_round_trip_and_default_off() {
        let json = serde_json::json!({
            "did": "did:key:z6MkApprover",
            "role": "reader",
            "approveAllContexts": true,
        });
        let body: CreateAclBody = serde_json::from_value(json).unwrap();
        assert!(body.approve_all_contexts);
        assert!(body.approve_contexts.is_empty());

        let json = serde_json::json!({
            "did": "did:key:z6MkApprover",
            "role": "reader",
            "approve_contexts": ["openvtc"],
        });
        let body: CreateAclBody = serde_json::from_value(json).unwrap();
        assert!(!body.approve_all_contexts);
        assert_eq!(body.approve_contexts, vec!["openvtc"]);

        // Absent ⇒ confers nothing.
        let json = serde_json::json!({ "did": "did:key:zX", "role": "reader" });
        let body: CreateAclBody = serde_json::from_value(json).unwrap();
        assert!(!body.approve_all_contexts);
        assert!(body.approve_contexts.is_empty());
    }
}
