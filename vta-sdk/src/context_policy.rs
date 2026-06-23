//! Per-context policy: fine-grained, field-wise constraints on what a
//! context-scoped actor may do, enforced VTA-side. This is the primitive that
//! makes enterprise separation-of-duty expressible beyond coarse capabilities —
//! see `docs/05-design-notes/enterprise-fleet-management.md`.
//!
//! ## Resolution model — field-wise intersection (additive-narrow)
//!
//! A context inherits the constraints of all its ancestors. The *effective*
//! policy for a context is the field-wise intersection of every policy on the
//! path root→leaf ([`ContextPolicy::resolve`]). Each field resolves
//! independently:
//!
//! * **Allow-list fields** (`Option<BTreeSet<String>>`): `None` = inherit (no
//!   constraint at this level); `Some(set)` = only these are allowed.
//!   Intersecting two `Some` sets keeps only members common to both, so a child
//!   can *narrow* an ancestor's allow-list but never widen it — the result is
//!   always a subset of every constraining level.
//! * **`export_allowed`**: logical AND down the chain — once any ancestor
//!   disables export, no descendant can re-enable it.
//! * **`quotas`**: per-operation-class daily ceilings; the effective ceiling is
//!   the minimum across the chain (a level may add a ceiling for a class an
//!   ancestor left unbounded).
//!
//! Widening is therefore *structurally impossible*: enforcement always resolves
//! the full ancestor chain, so a permissive policy written at a child level is
//! clamped by its ancestors regardless of who wrote it. This mirrors the
//! relaxing-override-ignored property of the auth step-up policy, and means the
//! CRUD layer only has to gate *who may write a policy at a level*, not whether
//! a write could escalate — it can't.
//!
//! Every field is "absent = inherit / unrestricted", so a context with no policy
//! (or [`ContextPolicy::unrestricted`]) imposes no constraints — preserving the
//! behaviour of VTAs that predate this type.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Per-context policy. See the module docs for the resolution model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ContextPolicy {
    /// Verifier DIDs an actor in this context may present to. `None` = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_verifiers: Option<BTreeSet<String>>,
    /// Credential `type`s an actor may present. `None` = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentable_types: Option<BTreeSet<String>>,
    /// Key ids the signing oracle may be invoked on. `None` = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signable_keys: Option<BTreeSet<String>>,
    /// Whether sealed-transfer export is permitted. Defaults to `true`
    /// (unrestricted) when absent from the wire.
    #[serde(default = "default_true")]
    pub export_allowed: bool,
    /// Per-operation-class daily ceilings. `None` = no quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<Quotas>,
}

fn default_true() -> bool {
    true
}

/// Per-operation-class daily ceilings (e.g. `"sign" -> 1000`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Quotas {
    /// operation-class -> maximum invocations per day.
    pub per_day: BTreeMap<String, u64>,
}

impl Default for ContextPolicy {
    fn default() -> Self {
        Self::unrestricted()
    }
}

impl ContextPolicy {
    /// A policy that imposes no constraints — the implicit policy of any context
    /// without one, and the identity element for [`intersect`](Self::intersect).
    pub fn unrestricted() -> Self {
        Self {
            trusted_verifiers: None,
            presentable_types: None,
            signable_keys: None,
            export_allowed: true,
            quotas: None,
        }
    }

    /// Field-wise intersection of `self` (ancestor) with `child`. The result is
    /// at least as strict as both inputs; allow-list fields become the set
    /// intersection, `export_allowed` the logical AND, quotas the per-class
    /// minimum.
    #[must_use]
    pub fn intersect(&self, child: &ContextPolicy) -> ContextPolicy {
        ContextPolicy {
            trusted_verifiers: narrow_set(&self.trusted_verifiers, &child.trusted_verifiers),
            presentable_types: narrow_set(&self.presentable_types, &child.presentable_types),
            signable_keys: narrow_set(&self.signable_keys, &child.signable_keys),
            export_allowed: self.export_allowed && child.export_allowed,
            quotas: narrow_quotas(&self.quotas, &child.quotas),
        }
    }

    /// Resolve the effective policy for a context from its ancestor chain,
    /// ordered root→leaf. An empty chain resolves to
    /// [`unrestricted`](Self::unrestricted).
    pub fn resolve<'a, I>(chain: I) -> ContextPolicy
    where
        I: IntoIterator<Item = &'a ContextPolicy>,
    {
        chain
            .into_iter()
            .fold(ContextPolicy::unrestricted(), |acc, p| acc.intersect(p))
    }

    // --- enforcement gates (absent allow-list = allow) ----------------------

    /// Whether a credential may be presented to `verifier_did`.
    pub fn allows_verifier(&self, verifier_did: &str) -> bool {
        self.trusted_verifiers
            .as_ref()
            .is_none_or(|s| s.contains(verifier_did))
    }

    /// Whether a credential of `credential_type` may be presented.
    pub fn allows_presentable_type(&self, credential_type: &str) -> bool {
        self.presentable_types
            .as_ref()
            .is_none_or(|s| s.contains(credential_type))
    }

    /// Whether the signing oracle may be invoked on `key_id`.
    pub fn allows_signing_key(&self, key_id: &str) -> bool {
        self.signable_keys
            .as_ref()
            .is_none_or(|s| s.contains(key_id))
    }

    /// Whether sealed-transfer export is permitted.
    pub fn allows_export(&self) -> bool {
        self.export_allowed
    }

    /// The daily ceiling for `operation_class`, if any.
    pub fn quota_for(&self, operation_class: &str) -> Option<u64> {
        self.quotas
            .as_ref()
            .and_then(|q| q.per_day.get(operation_class).copied())
    }
}

/// Intersect two optional allow-lists. `None` = no constraint at that level, so
/// the other level's constraint (if any) carries through unchanged; two
/// constraints intersect.
fn narrow_set(
    ancestor: &Option<BTreeSet<String>>,
    child: &Option<BTreeSet<String>>,
) -> Option<BTreeSet<String>> {
    match (ancestor, child) {
        (None, None) => None,
        (Some(s), None) | (None, Some(s)) => Some(s.clone()),
        (Some(a), Some(c)) => Some(a.intersection(c).cloned().collect()),
    }
}

/// Merge two optional quota maps: union of operation classes, taking the
/// stricter (minimum) ceiling where both constrain the same class.
fn narrow_quotas(ancestor: &Option<Quotas>, child: &Option<Quotas>) -> Option<Quotas> {
    match (ancestor, child) {
        (None, None) => None,
        (Some(q), None) | (None, Some(q)) => Some(q.clone()),
        (Some(a), Some(c)) => {
            let mut per_day = a.per_day.clone();
            for (op, &limit) in &c.per_day {
                per_day
                    .entry(op.clone())
                    .and_modify(|existing| *existing = (*existing).min(limit))
                    .or_insert(limit);
            }
            Some(Quotas { per_day })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unrestricted_allows_everything() {
        let p = ContextPolicy::unrestricted();
        assert!(p.allows_verifier("did:key:anything"));
        assert!(p.allows_presentable_type("AnyCredential"));
        assert!(p.allows_signing_key("key-1"));
        assert!(p.allows_export());
        assert_eq!(p.quota_for("sign"), None);
    }

    #[test]
    fn allow_list_present_is_membership() {
        let p = ContextPolicy {
            trusted_verifiers: Some(set(&["did:key:trusted"])),
            ..ContextPolicy::unrestricted()
        };
        assert!(p.allows_verifier("did:key:trusted"));
        assert!(!p.allows_verifier("did:key:other"));
    }

    #[test]
    fn intersect_inherits_when_child_unset() {
        let parent = ContextPolicy {
            signable_keys: Some(set(&["k1", "k2"])),
            ..ContextPolicy::unrestricted()
        };
        let eff = parent.intersect(&ContextPolicy::unrestricted());
        assert_eq!(eff.signable_keys, Some(set(&["k1", "k2"])));
    }

    #[test]
    fn intersect_adds_child_constraint() {
        let child = ContextPolicy {
            signable_keys: Some(set(&["k1"])),
            ..ContextPolicy::unrestricted()
        };
        let eff = ContextPolicy::unrestricted().intersect(&child);
        assert_eq!(eff.signable_keys, Some(set(&["k1"])));
    }

    #[test]
    fn intersect_drops_unauthorized_and_cannot_widen() {
        let parent = ContextPolicy {
            signable_keys: Some(set(&["k1", "k2"])),
            ..ContextPolicy::unrestricted()
        };
        // Child tries to allow k3 (never granted by the parent) plus k2.
        let child = ContextPolicy {
            signable_keys: Some(set(&["k2", "k3"])),
            ..ContextPolicy::unrestricted()
        };
        let eff = parent.intersect(&child);
        assert_eq!(eff.signable_keys, Some(set(&["k2"])));
        assert!(!eff.allows_signing_key("k3")); // widening dropped
        assert!(eff.allows_signing_key("k2"));
        assert!(!eff.allows_signing_key("k1")); // child narrowed it away
    }

    #[test]
    fn export_is_logical_and_and_cannot_be_re_enabled() {
        let on = ContextPolicy::unrestricted();
        let off = ContextPolicy {
            export_allowed: false,
            ..ContextPolicy::unrestricted()
        };
        assert!(on.intersect(&on).allows_export());
        assert!(!on.intersect(&off).allows_export());
        assert!(!off.intersect(&on).allows_export()); // descendant cannot re-enable
    }

    #[test]
    fn quotas_take_min_and_union() {
        let parent = ContextPolicy {
            quotas: Some(Quotas {
                per_day: [("sign".to_string(), 1000), ("release".to_string(), 10)].into(),
            }),
            ..ContextPolicy::unrestricted()
        };
        let child = ContextPolicy {
            quotas: Some(Quotas {
                per_day: [("sign".to_string(), 50), ("proxy".to_string(), 5)].into(),
            }),
            ..ContextPolicy::unrestricted()
        };
        let eff = parent.intersect(&child);
        assert_eq!(eff.quota_for("sign"), Some(50)); // min of 1000, 50
        assert_eq!(eff.quota_for("release"), Some(10)); // inherited from parent
        assert_eq!(eff.quota_for("proxy"), Some(5)); // added by child
    }

    #[test]
    fn resolve_empty_chain_is_unrestricted() {
        assert_eq!(
            ContextPolicy::resolve(std::iter::empty()),
            ContextPolicy::unrestricted()
        );
    }

    #[test]
    fn resolve_chain_narrows_monotonically() {
        let root = ContextPolicy {
            presentable_types: Some(set(&["A", "B", "C"])),
            ..ContextPolicy::unrestricted()
        };
        let mid = ContextPolicy {
            presentable_types: Some(set(&["B", "C"])),
            export_allowed: false,
            ..ContextPolicy::unrestricted()
        };
        let leaf = ContextPolicy {
            presentable_types: Some(set(&["C", "D"])),
            ..ContextPolicy::unrestricted()
        };
        let eff = ContextPolicy::resolve([&root, &mid, &leaf]);
        assert_eq!(eff.presentable_types, Some(set(&["C"]))); // D never authorized upstream
        assert!(!eff.allows_export()); // mid disabled; leaf can't re-enable
    }

    #[test]
    fn intersect_is_subset_of_each_input() {
        let a = ContextPolicy {
            signable_keys: Some(set(&["k1", "k2", "k3"])),
            ..ContextPolicy::unrestricted()
        };
        let b = ContextPolicy {
            signable_keys: Some(set(&["k2", "k3", "k4"])),
            ..ContextPolicy::unrestricted()
        };
        let r = a.intersect(&b).signable_keys.unwrap();
        assert!(r.is_subset(&set(&["k1", "k2", "k3"])));
        assert!(r.is_subset(&set(&["k2", "k3", "k4"])));
    }

    #[test]
    fn serde_empty_is_unrestricted_and_roundtrips() {
        // Backward-compat: an empty object (no policy fields) = unrestricted.
        let p: ContextPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, ContextPolicy::unrestricted());

        let full = ContextPolicy {
            trusted_verifiers: Some(set(&["did:key:v"])),
            presentable_types: None,
            signable_keys: Some(set(&["k1"])),
            export_allowed: false,
            quotas: Some(Quotas {
                per_day: [("sign".to_string(), 10)].into(),
            }),
        };
        let back: ContextPolicy =
            serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
        assert_eq!(full, back);
    }
}
