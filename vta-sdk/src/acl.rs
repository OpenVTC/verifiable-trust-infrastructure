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

/// A DID's authority to **act** — the contexts in which it may make a change.
/// The sibling axis to [`ApproveScope`], with deliberately identical variants,
/// an identical [`covers`](ActScope::covers) predicate, and the same
/// fail-closed [`None`](ActScope::None) default.
///
/// # Why this exists
///
/// Unlike [`ApproveScope`], this is **not** a stored or wire field. The act
/// axis is stored as `(role, allowed_contexts)`, where an **empty**
/// `allowed_contexts` means opposite things depending on the role: unrestricted
/// for an admin (that *is* how a super-admin is spelled), and *nothing at all*
/// for every other role. Reading the raw field without the role is therefore a
/// bug, and has repeatedly been one — a display that called a least-privilege
/// approver `(unrestricted)`, two `acl list --context` filters that disagreed
/// on whether an empty list matches every context or none, and a vault scope
/// gate that granted cross-context reads to an entry authorized nowhere.
///
/// This type makes the three cases distinguishable so that decode happens in
/// one place instead of at every call site. The decode itself is server-side
/// (`vti_common::acl::act_scope_for`), because it needs `Role`; only the shape
/// and the predicate are shared, exactly as for [`ApproveScope`].
///
/// It lives beside [`ApproveScope`] so the two axes — what a DID may *do* and
/// what it may *confer* — read as one model rather than an enum and a
/// convention.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ActScope {
    /// Authorized in no context at all (the fail-closed default). The shape of
    /// a least-privilege approver: acts nowhere, may still confer via its
    /// [`ApproveScope`].
    #[default]
    None,
    /// Authorized in every context. Combined with the admin role this is a
    /// super-admin.
    All,
    /// Authorized in these contexts and their subtrees, and only these.
    Contexts(Vec<String>),
}

impl ActScope {
    /// Whether a holder of this scope may act in `context_id`.
    ///
    /// Segment-aware ancestry, identical to [`ApproveScope::covers`], so
    /// authority over a parent context covers its whole subtree.
    pub fn covers(&self, context_id: &str) -> bool {
        match self {
            ActScope::None => false,
            ActScope::All => true,
            ActScope::Contexts(cs) => cs
                .iter()
                .any(|c| crate::context_path::is_ancestor_or_self(c, context_id)),
        }
    }

    /// Whether this scope authorizes every context (the super-admin condition
    /// when paired with the admin role).
    pub fn is_unrestricted(&self) -> bool {
        matches!(self, ActScope::All)
    }

    /// Whether this scope authorizes nothing.
    pub fn acts_nowhere(&self) -> bool {
        matches!(self, ActScope::None)
    }

    /// The contexts named by this scope, or an empty slice for
    /// [`None`](ActScope::None) / [`All`](ActScope::All) — neither of which is
    /// expressible as a list.
    pub fn named_contexts(&self) -> &[String] {
        match self {
            ActScope::Contexts(cs) => cs,
            _ => &[],
        }
    }
}

impl std::fmt::Display for ActScope {
    /// Operator-facing rendering. The unrestricted and acts-nowhere cases are
    /// spelled out rather than both collapsing to `(unrestricted)`, which is
    /// what made them indistinguishable on ACL displays. The wording matches
    /// what `vta-cli-common`'s `format_contexts` already prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActScope::None => f.write_str("(none — acts nowhere)"),
            ActScope::All => f.write_str("(unrestricted)"),
            ActScope::Contexts(cs) => f.write_str(&cs.join(", ")),
        }
    }
}

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

    /// The two axes must agree on what a scope covers — same predicate, same
    /// answers — or "act" and "confer" stop being comparable.
    #[test]
    fn act_and_approve_agree_on_coverage() {
        for ctx in ["acme", "acme/eng", "acme-corp", "other"] {
            assert_eq!(
                ActScope::Contexts(vec!["acme".into()]).covers(ctx),
                ApproveScope::Contexts(vec!["acme".into()]).covers(ctx),
                "disagreement on {ctx}"
            );
        }
        assert_eq!(ActScope::All.covers("x"), ApproveScope::All.covers("x"));
        assert_eq!(ActScope::None.covers("x"), ApproveScope::None.covers("x"));
    }

    /// Fail-closed: an unset act scope authorizes nothing, matching
    /// `ApproveScope`'s default.
    #[test]
    fn act_scope_defaults_to_nothing() {
        assert_eq!(ActScope::default(), ActScope::None);
        assert!(ActScope::default().acts_nowhere());
        assert!(!ActScope::default().is_unrestricted());
    }

    /// The display defect this type closes: both empty cases rendered
    /// `(unrestricted)`, so an acts-nowhere entry read as blanket access.
    #[test]
    fn display_distinguishes_nothing_from_everything() {
        assert_eq!(ActScope::All.to_string(), "(unrestricted)");
        assert_eq!(ActScope::None.to_string(), "(none — acts nowhere)");
        assert_ne!(ActScope::None.to_string(), ActScope::All.to_string());
        assert_eq!(
            ActScope::Contexts(vec!["a".into(), "b".into()]).to_string(),
            "a, b"
        );
    }

    #[test]
    fn named_contexts_is_empty_for_the_unlistable_variants() {
        assert!(ActScope::All.named_contexts().is_empty());
        assert!(ActScope::None.named_contexts().is_empty());
        assert_eq!(
            ActScope::Contexts(vec!["a".into()]).named_contexts(),
            ["a".to_string()]
        );
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
