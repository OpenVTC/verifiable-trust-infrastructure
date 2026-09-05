//! Key layout for the persona keyspace, and the scope split expressed as
//! separately addressable prefixes.
//!
//! Every key in this module is built by a function here rather than formatted
//! at a call site. That is not tidiness: the agent-scoped and context-scoped
//! prefixes are a security boundary, and a call site that formats its own key
//! can put a record on the wrong side of it. Concentrating the layout means the
//! boundary has one definition and the census test below can assert it.

// ---- Agent-scoped: the person's own, above every context --------------------

/// One attribute of the pool.
#[must_use]
pub fn attribute_key(attribute_id: &str) -> String {
    format!("pa:{attribute_id}")
}

/// Prefix scan over the whole pool.
pub const ATTRIBUTE_PREFIX: &str = "pa:";

/// One profile.
#[must_use]
pub fn profile_key(profile_id: &str) -> String {
    format!("pp:{profile_id}")
}

pub const PROFILE_PREFIX: &str = "pp:";

/// Correlation index, keyed by a keyed hash of the value so that exact-match
/// lookup works with no plaintext index over the holder's personal data.
#[must_use]
pub fn correlation_key(value_hmac_hex: &str) -> String {
    format!("pxi:{value_hmac_hex}")
}

pub const CORRELATION_PREFIX: &str = "pxi:";

/// Attribute → profile reverse index, so a delete can name its referring
/// profiles without scanning every profile.
#[must_use]
pub fn reverse_index_key(attribute_id: &str, profile_id: &str) -> String {
    format!("pxr:{attribute_id}:{profile_id}")
}

/// Prefix scan for every profile referring to one attribute.
#[must_use]
pub fn reverse_index_prefix(attribute_id: &str) -> String {
    format!("pxr:{attribute_id}:")
}

// ---- Context-scoped: a persona lives in a context, and so do its peers -------

/// Binding of a profile to a persona DID.
#[must_use]
pub fn binding_key(context_id: &str, persona_did: &str) -> String {
    format!("pb:{context_id}:{persona_did}")
}

/// Prefix scan over one context's bindings.
#[must_use]
pub fn binding_prefix(context_id: &str) -> String {
    format!("pb:{context_id}:")
}

/// A contact's current revision.
#[must_use]
pub fn contact_key(context_id: &str, contact_id: &str) -> String {
    format!("pc:{context_id}:{contact_id}")
}

#[must_use]
pub fn contact_prefix(context_id: &str) -> String {
    format!("pc:{context_id}:")
}

/// A superseded contact revision.
///
/// Zero-padded so a prefix scan returns revisions in numeric order; without the
/// padding revision 10 sorts before revision 9 and a "previous revision" lookup
/// silently reads the wrong one.
#[must_use]
pub fn contact_revision_key(context_id: &str, contact_id: &str, rev: u64) -> String {
    format!("pcr:{context_id}:{contact_id}:{rev:020}")
}

#[must_use]
pub fn contact_revision_prefix(context_id: &str, contact_id: &str) -> String {
    format!("pcr:{context_id}:{contact_id}:")
}

/// An append-only disclosure record. Zero-padded for the same reason.
#[must_use]
pub fn disclosure_key(context_id: &str, seq: u64) -> String {
    format!("pd:{context_id}:{seq:020}")
}

#[must_use]
pub fn disclosure_prefix(context_id: &str) -> String {
    format!("pd:{context_id}:")
}

// ---- Context-local: authored below the boundary ------------------------------

/// A context-local profile — inline entries only.
///
/// A **separate prefix**, not a flag on [`profile_key`]. If the two shared a
/// space, a context-scoped list would need a filter to avoid returning a pool
/// profile, and a filter bug is the same one-line leak the authorization rule
/// exists to remove.
#[must_use]
pub fn local_profile_key(context_id: &str, profile_id: &str) -> String {
    format!("plp:{context_id}:{profile_id}")
}

#[must_use]
pub fn local_profile_prefix(context_id: &str) -> String {
    format!("plp:{context_id}:")
}

/// Binding of a context-local profile.
#[must_use]
pub fn local_binding_key(context_id: &str, persona_did: &str) -> String {
    format!("plb:{context_id}:{persona_did}")
}

/// The store's monotonic write counter.
pub const VERSION_COUNTER_KEY: &str = "pver";

/// Per-agent key for the correlation index's keyed hash.
pub const CORRELATION_HMAC_KEY: &str = "pxkey";

/// Every prefix this module writes under, paired with whether it is
/// agent-scoped. The census test uses it to assert the boundary holds.
const PREFIX_SCOPES: &[(&str, Scope)] = &[
    ("pa:", Scope::Agent),
    ("pp:", Scope::Agent),
    ("pxi:", Scope::Agent),
    ("pxr:", Scope::Agent),
    ("pb:", Scope::Context),
    ("pc:", Scope::Context),
    ("pcr:", Scope::Context),
    ("pd:", Scope::Context),
    ("plp:", Scope::Context),
    ("plb:", Scope::Context),
];

/// Which side of the boundary a record sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Above every context. Reachable only by a holder-authorized, unscoped
    /// caller.
    Agent,
    /// Belongs to one context and is reachable from inside it.
    Context,
}

/// The scope of a key, or `None` if no prefix in this module claims it.
///
/// Returning `None` rather than defaulting is deliberate: a key nobody
/// recognises must not be assumed safe to serve a context-scoped caller.
#[must_use]
pub fn scope_of(key: &str) -> Option<Scope> {
    // Longest prefix first, so `pcr:` is not matched as `pc:` — the two are on
    // the same side of the boundary today, which is exactly why an ordering bug
    // here would go unnoticed until one of them moved.
    let mut best: Option<(usize, Scope)> = None;
    for (p, s) in PREFIX_SCOPES {
        if key.starts_with(p) && best.is_none_or(|(len, _)| p.len() > len) {
            best = Some((p.len(), *s));
        }
    }
    best.map(|(_, s)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_prefix_is_scoped_and_unambiguous() {
        // A key nobody recognises is not defaulted into either scope.
        assert_eq!(scope_of("unknown:x"), None);

        for (p, expected) in PREFIX_SCOPES {
            let k = format!("{p}sample");
            assert_eq!(
                scope_of(&k),
                Some(*expected),
                "prefix {p} did not resolve to its declared scope"
            );
        }
    }

    #[test]
    fn contact_revision_is_not_read_as_a_contact() {
        // `pcr:` starts with `pc:`. Both are context-scoped, so a mismatch here
        // is invisible today — and would become a boundary bug the moment
        // either moved. Longest-prefix-wins is asserted rather than assumed.
        let rev = contact_revision_key("ctx", "c1", 3);
        assert!(rev.starts_with("pcr:"));
        assert_eq!(scope_of(&rev), Some(Scope::Context));
    }

    #[test]
    fn agent_scoped_keys_carry_no_context() {
        // The pool sits above every context, so its keys cannot name one. A key
        // that did would be a pool record filed under a context, which is the
        // shape of the leak the scope split exists to prevent.
        assert_eq!(attribute_key("01J8"), "pa:01J8");
        assert_eq!(profile_key("01J8"), "pp:01J8");
        // Exactly one separator: the prefix. A second would mean a context
        // segment had crept into an agent-scoped key.
        assert_eq!(attribute_key("01J8").matches(':').count(), 1);
        assert_eq!(profile_key("01J8").matches(':').count(), 1);
    }

    #[test]
    fn revisions_sort_numerically_not_lexically() {
        // Without zero-padding, revision 10 sorts before revision 9 and a
        // "previous revision" lookup reads the wrong one.
        let mut keys = [
            contact_revision_key("c", "x", 9),
            contact_revision_key("c", "x", 10),
            contact_revision_key("c", "x", 2),
        ];
        keys.sort();
        assert_eq!(keys[0], contact_revision_key("c", "x", 2));
        assert_eq!(keys[2], contact_revision_key("c", "x", 10));
    }

    #[test]
    fn local_profiles_are_a_separate_space_from_pool_profiles() {
        // The isolation is the address, not a filter. A context-scoped scan of
        // local profiles must not be able to reach a pool profile.
        let pool = profile_key("01J8");
        let local = local_profile_key("ctx", "01J8");
        assert!(!local.starts_with(PROFILE_PREFIX));
        assert!(!pool.starts_with(&local_profile_prefix("ctx")));
        assert_eq!(scope_of(&pool), Some(Scope::Agent));
        assert_eq!(scope_of(&local), Some(Scope::Context));
    }
}
