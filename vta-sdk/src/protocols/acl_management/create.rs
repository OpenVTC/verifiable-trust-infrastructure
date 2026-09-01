//! `acl/grant/0.1` — add a subject to the ACL.

use serde::{Deserialize, Serialize};

use super::entry::AclEntry;
use serde_json::Value;

/// `acl/grant/0.1` request.
///
/// The entry is **nested** rather than flattened because canonical `acl/*`
/// carries one `AclEntry` shape across every task — grant, show, list, revoke
/// — so a consumer comparing entries between them cannot end up looking at two
/// different spellings of the same thing.
///
/// Note what grant deliberately cannot do. **Changing an existing subject's
/// role** belongs to `acl/change-role`, which takes the current role as a
/// compare-and-swap; **narrowing scopes** belongs to `acl/revoke`. Both are
/// refused here rather than silently applied, so that a reduction in authority
/// always passes through the task that is named and audited as one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAclBody {
    /// The entry the caller wants the maintainer to hold.
    pub entry: AclEntry,
    /// Optional human-readable rationale, recorded with the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than swept up by relaxing
    /// `deny_unknown_fields`: the published payload schemas declare an `ext`
    /// slot, so a conforming producer may send one, and rejecting the whole
    /// document over it would break interop with a peer doing exactly what the
    /// spec allows. Keeping `deny_unknown_fields` alongside it means a *typo*
    /// is still refused rather than silently ignored — which is the guard that
    /// clause was there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `acl/grant/0.1` response — the realized entry the maintainer now holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAclResponseBody {
    pub entry: AclEntry,
}

/// The maintainer's internal view of a stored entry.
///
/// **Not a wire type any more.** It is what `operations::acl` returns, and the
/// handlers convert it to an [`AclEntry`] on the way out
/// ([`AclEntry::from_result`]). Kept in its stored form — epoch seconds, flat
/// approve members — so the storage layer is unaffected by the canonical fold.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateAclResultBody {
    pub did: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(alias = "allowed_contexts")]
    pub allowed_contexts: Vec<String>,
    #[serde(alias = "created_at")]
    pub created_at: u64,
    #[serde(alias = "created_by")]
    pub created_by: String,
    /// Unix-epoch seconds at which the entry auto-expires, if set.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "expires_at")]
    pub expires_at: Option<u64>,
    /// The delegated step-up approver the maintainer now holds for this
    /// subject, if any (echoes the stored `step_up_approver`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "step_up_approver"
    )]
    pub step_up_approver: Option<String>,
    /// The per-entry step-up override the maintainer now holds for this subject,
    /// if any (echoes the stored `step_up_require`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "step_up_require"
    )]
    pub step_up_require: Option<String>,
    /// Approve-authority the entry holds — `true` means it may confer *any*
    /// context via approval (while acting nowhere). Echoes the stored
    /// `approve_scope`; takes precedence over `approve_contexts`.
    #[serde(
        default,
        skip_serializing_if = "std::ops::Not::not",
        alias = "approve_all_contexts"
    )]
    pub approve_all_contexts: bool,
    /// Approve-authority scoped to these contexts (echoes the stored
    /// `approve_scope`). Empty = confers nothing, unless `approve_all_contexts`.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        alias = "approve_contexts"
    )]
    pub approve_contexts: Vec<String>,
    /// The signing-oracle key filter the maintainer now holds for this
    /// subject (#818), echoing the stored `allowed_keys`. `None` = no filter
    /// (every key in the entry's contexts); **`Some([])` = no keys at all** —
    /// the skip is deliberately `Option::is_none`, never emptiness, so the
    /// two cannot collapse.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "allowed_keys"
    )]
    pub allowed_keys: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression the pre-fold body existed to prevent, restated against
    /// the canonical shape: a scoped, expiring grant must not lose its scope.
    ///
    /// A dropped `scopes` on an admin entry is a **permanent super-admin**,
    /// because an empty scope list means "unrestricted" for that role. Nesting
    /// changes where the member lives, not how badly losing it fails.
    #[test]
    fn scoped_expiring_grant_keeps_its_scope_and_expiry() {
        let json = serde_json::json!({
            "entry": {
                "subject": "did:key:z6MkSubject",
                "role": "admin",
                "scopes": ["ctx-a", "ctx-b"],
                "expiresAt": "2027-01-15T08:00:00Z",
                "stepUp": { "approver": "did:key:z6MkApprover", "require": "delegated" }
            }
        });
        let body: CreateAclBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.entry.scopes, vec!["ctx-a", "ctx-b"]);
        assert!(body.entry.expires_at.is_some());
        assert_eq!(
            body.entry.step_up_approver().as_deref(),
            Some("did:key:z6MkApprover")
        );
        assert_eq!(body.entry.step_up_require().as_deref(), Some("delegated"));
    }

    /// A misspelled member is a loud rejection, never a silent drop that would
    /// default the entry to unrestricted scope.
    #[test]
    fn unknown_member_is_rejected() {
        let json = serde_json::json!({
            "entry": { "subject": "did:key:zA", "role": "admin", "scope": ["ctx-a"] }
        });
        assert!(serde_json::from_value::<CreateAclBody>(json).is_err());
    }

    /// The pre-fold flat body must not deserialize — it would arrive with no
    /// scopes at all, which for an admin role is a super-admin.
    #[test]
    fn pre_fold_flat_body_is_rejected() {
        let json = serde_json::json!({
            "did": "did:key:zA", "role": "admin", "allowedContexts": ["ctx-a"]
        });
        assert!(serde_json::from_value::<CreateAclBody>(json).is_err());
    }
}
