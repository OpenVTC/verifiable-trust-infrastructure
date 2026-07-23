//! ACL wire types shared between the VTA and its clients.
//!
//! These live here — rather than in `vti-common` alongside the ACL storage and
//! authorization logic — because the DIDComm and Trust Task bodies in
//! [`crate::protocols::acl_management`] are part of the wire contract and must
//! be constructible by clients that never link the server crates. `vti-common`
//! depends on this crate (never the reverse) and re-exports what it needs, the
//! same arrangement already used for [`crate::context_path`].
//!
//! Authorization over these types stays server-side: `validate_approve_scope_grant`
//! and friends remain in `vti-common`. Only the shape is shared.

use serde::{Deserialize, Serialize};

/// A DID's authority to **confer** access through an approval — task-consent
/// delegation (`compute_delegated_contexts`) and delegated step-up ratification
/// (`delegated_any_approver_covers`) — **without** any authority to act.
///
/// Read only by those two conferral paths; it never feeds `require_admin` or
/// `has_context_access`, so an approver can bless a change in a context while
/// being unable to make one. This is the axis that lets an approver be
/// least-privilege: `role: Reader`, `allowed_contexts: []` (acts nowhere),
/// `approve_scope: All` (may authorize anywhere).
///
/// Default [`ApproveScope::None`]: an entry confers nothing unless explicitly
/// granted this — strictly additive and fail-closed. Pre-existing rows omit the
/// field and deserialise as `None`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case", tag = "kind", content = "contexts")]
pub enum ApproveScope {
    /// Confers nothing (the default).
    #[default]
    None,
    /// May confer any context — a cross-context authorizer. Granting this is
    /// super-admin-only (see `vti_common::acl::validate_approve_scope_grant`).
    All,
    /// May confer these contexts (and their subtrees), and only these.
    Contexts(Vec<String>),
}

impl ApproveScope {
    /// Whether an approval by a holder of this scope may confer `context_id`.
    ///
    /// Segment-aware ancestry, matching `AuthClaims::has_context_access`, so an
    /// approver scoped to a parent context covers its whole subtree.
    pub fn covers(&self, context_id: &str) -> bool {
        match self {
            ApproveScope::None => false,
            ApproveScope::All => true,
            ApproveScope::Contexts(cs) => cs
                .iter()
                .any(|c| crate::context_path::is_ancestor_or_self(c, context_id)),
        }
    }

    /// Whether this scope confers nothing.
    pub fn confers_nothing(&self) -> bool {
        matches!(self, ApproveScope::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire shape is a contract: stored ACL rows and DIDComm bodies both
    /// carry it, so a change here silently reinterprets existing entries.
    #[test]
    fn wire_shape_is_pinned() {
        let cases = [
            (ApproveScope::None, r#"{"kind":"none"}"#),
            (ApproveScope::All, r#"{"kind":"all"}"#),
            (
                ApproveScope::Contexts(vec!["a".into(), "b/c".into()]),
                r#"{"kind":"contexts","contexts":["a","b/c"]}"#,
            ),
        ];
        for (scope, json) in cases {
            assert_eq!(serde_json::to_string(&scope).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<ApproveScope>(json).unwrap(),
                scope,
                "round trip for {json}"
            );
        }
    }

    /// Absent ⇒ `None`, so rows written before the field existed stay
    /// fail-closed rather than deserialising into some conferring shape.
    #[test]
    fn absent_defaults_to_conferring_nothing() {
        assert_eq!(ApproveScope::default(), ApproveScope::None);
        assert!(ApproveScope::default().confers_nothing());
    }

    #[test]
    fn covers_is_subtree_aware() {
        let scope = ApproveScope::Contexts(vec!["acme".into()]);
        assert!(scope.covers("acme"));
        assert!(scope.covers("acme/eng"));
        assert!(!scope.covers("acme-corp"), "sibling must not match");
        assert!(!scope.covers("other"));

        assert!(ApproveScope::All.covers("anything"));
        assert!(!ApproveScope::None.covers("anything"));
    }
}
