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

    /// Whether this scope names a context **at or beneath** `context_id` — the
    /// mirror of [`covers`](ActScope::covers), with the ancestry test's
    /// arguments swapped.
    ///
    /// [`covers`](ActScope::covers) answers "may this entry act *in* the
    /// context?"; this answers "does this entry hold a grant *inside* the
    /// context's subtree?". They are different questions and a caller sweeping
    /// a subtree — to revoke it, or to audit it — wants this one: a grant at
    /// `acme/eng/team-a` is invisible to `covers("acme/eng")` because it holds
    /// no authority over `acme/eng`, yet it is precisely what the sweep exists
    /// to find.
    ///
    /// Two deliberate edges:
    ///
    /// - [`All`](ActScope::All) is **not** a match. An unrestricted entry names
    ///   no context, so it is not a grant *of* this subtree — it is authority
    ///   everywhere, which [`covers`](ActScope::covers) already reports. A
    ///   subtree sweep that returned it would invite a caller revoking a
    ///   compromised branch to delete its own super-admin. Ask
    ///   [`ContextDirection::Any`] for "everyone whose authority touches this
    ///   subtree", which includes it.
    /// - A [`Contexts`](ActScope::Contexts) scope matches if **any** named
    ///   context is inside the subtree, even when it also names contexts
    ///   outside it. Such an entry does hold a grant in the subtree, so
    ///   omitting it would under-report; whether to delete the entry or narrow
    ///   its scope is then the caller's decision, made with the entry in hand.
    pub fn acts_within(&self, context_id: &str) -> bool {
        match self {
            ActScope::None | ActScope::All => false,
            ActScope::Contexts(cs) => cs
                .iter()
                .any(|c| crate::context_path::is_ancestor_or_self(context_id, c)),
        }
    }

    /// Whether this scope matches `context_id` when read in `direction` — the
    /// single predicate behind every context-filtered ACL listing.
    pub fn matches_context(&self, context_id: &str, direction: ContextDirection) -> bool {
        match direction {
            ContextDirection::ActingIn => self.covers(context_id),
            ContextDirection::Subtree => self.acts_within(context_id),
            ContextDirection::Any => self.covers(context_id) || self.acts_within(context_id),
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

/// Which way a context filter reads along the context hierarchy.
///
/// A context id names a subtree, so "entries relevant to context X" is two
/// questions, not one, and an answer is only meaningful paired with the
/// direction being asked:
///
/// | direction | question | predicate |
/// |---|---|---|
/// | [`ActingIn`](ContextDirection::ActingIn) | who may act **in** X? | scope is X or an ancestor of it |
/// | [`Subtree`](ContextDirection::Subtree) | who holds a grant **beneath** X? | scope is X or a descendant of it |
/// | [`Any`](ContextDirection::Any) | whose authority **touches** X's subtree? | either of the above |
///
/// Only [`ActingIn`](ContextDirection::ActingIn) existed until now, and a
/// caller sweeping a subtree to revoke it got back exactly the entries it was
/// *not* revoking (the ancestors keeping their authority) while every
/// leaf-scoped grant it existed to cut was silently absent — an incomplete
/// answer that looks like a complete one (#822).
///
/// [`ActingIn`](ContextDirection::ActingIn) is the default, so an omitted
/// parameter is today's behaviour exactly. An unparseable value is refused
/// rather than defaulted: guessing which question an operator meant is how the
/// silent-wrong-answer failure returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ContextDirection {
    /// Entries that may act **in** the context: scoped to it or to an ancestor
    /// of it. The historical (and default) behaviour of `?context=`.
    #[default]
    ActingIn,
    /// Entries holding a grant **at or beneath** the context. The revocation-
    /// sweep and delegation-audit direction.
    Subtree,
    /// The union — every entry whose act authority touches the context's
    /// subtree in either direction. The auditor's question.
    Any,
}

impl ContextDirection {
    /// Every direction, in the order the operator-facing help lists them.
    pub const ALL: [ContextDirection; 3] = [
        ContextDirection::ActingIn,
        ContextDirection::Subtree,
        ContextDirection::Any,
    ];

    /// The wire spelling — identical to the serde representation, so the CLI,
    /// the query string, and the Trust Task payload cannot drift apart.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContextDirection::ActingIn => "acting-in",
            ContextDirection::Subtree => "subtree",
            ContextDirection::Any => "any",
        }
    }
}

impl std::fmt::Display for ContextDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ContextDirection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|d| d.as_str() == s)
            .ok_or_else(|| {
                let valid = Self::ALL
                    .iter()
                    .map(|d| d.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("invalid context direction '{s}', expected one of: {valid}")
            })
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

    // ── ContextDirection ────────────────────────────────────────────

    /// The two directions are mirror images: `covers` walks up from the
    /// queried context, `acts_within` walks down. The defect was having only
    /// the first, so the descendant column here was unaskable.
    #[test]
    fn the_two_directions_are_mirrors() {
        let ancestor = ActScope::Contexts(vec!["acme".into()]);
        let exact = ActScope::Contexts(vec!["acme/eng".into()]);
        let descendant = ActScope::Contexts(vec!["acme/eng/team-a".into()]);
        let sibling = ActScope::Contexts(vec!["acme/ops".into()]);
        let q = "acme/eng";

        // covers: ancestor-or-self of the queried context.
        assert!(ancestor.covers(q));
        assert!(exact.covers(q));
        assert!(!descendant.covers(q), "a leaf holds no authority over q");
        assert!(!sibling.covers(q));

        // acts_within: at-or-beneath the queried context.
        assert!(!ancestor.acts_within(q), "a parent grant is not inside q");
        assert!(exact.acts_within(q), "self is inside its own subtree");
        assert!(descendant.acts_within(q), "the sweep's whole point");
        assert!(!sibling.acts_within(q));
    }

    /// Segment-awareness must hold in the new direction too, or `acme/eng`
    /// would "contain" `acme/engineering` and a sweep would revoke a
    /// bystander.
    #[test]
    fn acts_within_is_segment_aware() {
        let scope = ActScope::Contexts(vec!["acme/engineering".into()]);
        assert!(!scope.acts_within("acme/eng"));
        assert!(scope.acts_within("acme"));
    }

    /// An unrestricted entry is authority *everywhere*, not a grant *of* this
    /// subtree. Surfacing it under `subtree` would put the caller's own
    /// super-admin on a revocation list; `any` is where it belongs.
    #[test]
    fn unrestricted_is_reported_by_acting_in_and_any_but_not_subtree() {
        let all = ActScope::All;
        assert!(all.matches_context("acme/eng", ContextDirection::ActingIn));
        assert!(!all.matches_context("acme/eng", ContextDirection::Subtree));
        assert!(all.matches_context("acme/eng", ContextDirection::Any));
    }

    /// Acts-nowhere matches in no direction — the fail-closed edge.
    #[test]
    fn acts_nowhere_matches_no_direction() {
        for d in ContextDirection::ALL {
            assert!(
                !ActScope::None.matches_context("acme", d),
                "acts-nowhere matched {d}"
            );
        }
    }

    /// A scope naming several contexts matches the sweep if *any* of them is
    /// inside it — under-reporting is the failure mode being fixed.
    #[test]
    fn a_partially_inside_scope_is_surfaced() {
        let scope = ActScope::Contexts(vec!["acme/eng/team-a".into(), "other".into()]);
        assert!(scope.acts_within("acme/eng"));
    }

    /// `Any` is exactly the union, and never narrower than either leg.
    #[test]
    fn any_is_the_union_of_both_legs() {
        let scopes = [
            ActScope::None,
            ActScope::All,
            ActScope::Contexts(vec!["acme".into()]),
            ActScope::Contexts(vec!["acme/eng".into()]),
            ActScope::Contexts(vec!["acme/eng/team-a".into()]),
            ActScope::Contexts(vec!["other".into()]),
        ];
        for scope in scopes {
            let acting_in = scope.matches_context("acme/eng", ContextDirection::ActingIn);
            let subtree = scope.matches_context("acme/eng", ContextDirection::Subtree);
            assert_eq!(
                scope.matches_context("acme/eng", ContextDirection::Any),
                acting_in || subtree,
                "union broken for {scope:?}"
            );
        }
    }

    /// Omitting the parameter must be today's behaviour, byte for byte.
    #[test]
    fn default_direction_is_the_historical_one() {
        assert_eq!(ContextDirection::default(), ContextDirection::ActingIn);
        let scope = ActScope::Contexts(vec!["acme".into()]);
        for ctx in ["acme", "acme/eng", "acme-corp", "other"] {
            assert_eq!(
                scope.matches_context(ctx, ContextDirection::default()),
                scope.covers(ctx),
                "default direction diverged from `covers` at {ctx}"
            );
        }
    }

    /// One spelling across the query string, the Trust Task payload, and the
    /// CLI flag — parsed and rendered through the same table.
    #[test]
    fn wire_spelling_is_pinned_and_round_trips() {
        let cases = [
            (ContextDirection::ActingIn, "acting-in"),
            (ContextDirection::Subtree, "subtree"),
            (ContextDirection::Any, "any"),
        ];
        for (direction, wire) in cases {
            assert_eq!(direction.as_str(), wire);
            assert_eq!(direction.to_string(), wire);
            assert_eq!(
                serde_json::to_string(&direction).unwrap(),
                format!("\"{wire}\"")
            );
            assert_eq!(
                serde_json::from_str::<ContextDirection>(&format!("\"{wire}\"")).unwrap(),
                direction
            );
            assert_eq!(wire.parse::<ContextDirection>().unwrap(), direction);
        }
    }

    /// An unknown value is refused, and the error names the valid ones — the
    /// operator-errors-suggest-the-fix rule. Silently defaulting would
    /// reintroduce "wrong question, confident answer".
    #[test]
    fn an_unknown_direction_is_refused_with_the_valid_set() {
        let err = "descendants".parse::<ContextDirection>().unwrap_err();
        assert!(err.contains("descendants"), "{err}");
        for d in ContextDirection::ALL {
            assert!(err.contains(d.as_str()), "{err} omits {d}");
        }
        assert!(serde_json::from_str::<ContextDirection>("\"ActingIn\"").is_err());
    }
}
