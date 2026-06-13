//! Server-side re-export of the canonical context-path validators.
//!
//! Hierarchical trust-context paths are the security foundation for
//! folder/sub-folder contexts (`docs/05-design-notes/hierarchical-contexts.md`).
//! A context identifier **is** its materialized path: slash-separated segments,
//! e.g. `acme/eng/team-a`. The authorization gate ([`crate::auth`]'s
//! `has_context_access`) decides "admin of a parent → access to descendants"
//! with [`is_ancestor_or_self`] — a **pure, store-free** segment comparison
//! over data already in the verified JWT.
//!
//! ## Why this lives in the SDK now
//! The pure construction/validation rules moved down into
//! [`vta_sdk::context_path`] so **clients** can derive sub-context ids under
//! the *same* rules the VTA enforces, without depending on this server-only
//! crate (see issue #392). This module re-exports the pure helpers verbatim and
//! wraps the two fallible constructors so they keep returning [`AppError`] for
//! the server's `?`-ergonomics; the [`ValidationError`](vta_sdk::identifier::ValidationError)
//! message is preserved verbatim.
//!
//! ## The one footgun, handled
//! A raw `str::starts_with` is **wrong**: `acme` would "contain" `acme-evil`.
//! Ancestry here is **segment-aware**, and `/` is the *only* separator — it
//! cannot appear inside a segment (each segment is a
//! [`validate_identifier`](crate::identifier::validate_identifier) value), so
//! there is no `..` / slash-injection / empty-segment aliasing.

use crate::error::AppError;

// Pure helpers re-exported unchanged — clients make no authz decisions, but the
// server's ACL gate and callers consume these by their existing paths.
pub use vta_sdk::context_path::{
    MAX_CONTEXT_DEPTH, SEPARATOR, depth, is_ancestor_or_self, parent_path,
};

/// Validate a context path: non-empty, ≤ [`MAX_CONTEXT_DEPTH`] segments, every
/// segment a valid identifier, and no empty / leading / trailing / doubled
/// separators.
///
/// Thin wrapper over [`vta_sdk::context_path::validate_context_path`] mapping
/// the SDK error onto [`AppError::Validation`] (message preserved verbatim).
pub fn validate_context_path(value: &str) -> Result<(), AppError> {
    vta_sdk::context_path::validate_context_path(value).map_err(|e| AppError::Validation(e.0))
}

/// Build a child path under `parent` by appending a single `segment`. The
/// `segment` must be one valid identifier — it cannot itself contain a separator
/// (else it would silently add *several* levels) — and the resulting path must
/// validate (depth included).
///
/// Thin wrapper over [`vta_sdk::context_path::child_path`] mapping the SDK error
/// onto [`AppError::Validation`] (message preserved verbatim).
pub fn child_path(parent: &str, segment: &str) -> Result<String, AppError> {
    vta_sdk::context_path::child_path(parent, segment).map_err(|e| AppError::Validation(e.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_good_paths() {
        for p in ["acme", "acme/eng", "acme/eng/team-a", "a.b_c/d-e", "x/y/z"] {
            assert!(validate_context_path(p).is_ok(), "{p} should be valid");
        }
    }

    #[test]
    fn rejects_malformed_paths() {
        assert!(validate_context_path("").is_err()); // empty
        assert!(validate_context_path("/acme").is_err()); // leading separator
        assert!(validate_context_path("acme/").is_err()); // trailing separator
        assert!(validate_context_path("acme//eng").is_err()); // doubled separator
        assert!(validate_context_path("acme/ev il").is_err()); // space in a segment
        // `..` is a *legal* segment name (only alnum/`.`/`_`/`-`), but it can't
        // escape anything: `/` is the sole separator and can't appear in a
        // segment, so `..` is just a literal child named "..". The dangerous
        // forms (slash / empty-segment injection) above are all rejected.
        assert!(validate_context_path("acme/..").is_ok());
    }

    #[test]
    fn enforces_max_depth() {
        let deep = (0..=MAX_CONTEXT_DEPTH)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(
            validate_context_path(&deep).is_err(),
            "{deep} exceeds max depth"
        );
        let ok = (0..MAX_CONTEXT_DEPTH)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(validate_context_path(&ok).is_ok());
    }

    #[test]
    fn ancestry_is_segment_aware_not_string_prefix() {
        // Self.
        assert!(is_ancestor_or_self("acme", "acme"));
        assert!(is_ancestor_or_self("acme/eng", "acme/eng"));
        // True ancestry.
        assert!(is_ancestor_or_self("acme", "acme/eng"));
        assert!(is_ancestor_or_self("acme", "acme/eng/team-a"));
        assert!(is_ancestor_or_self("acme/eng", "acme/eng/team-a"));
        // The prefix-confusion attack: string-prefix but NOT a segment ancestor.
        assert!(!is_ancestor_or_self("acme", "acme-evil"));
        assert!(!is_ancestor_or_self("acme/eng", "acme/engineering"));
        assert!(!is_ancestor_or_self("ac", "acme"));
        // Descendant is shorter / a sibling.
        assert!(!is_ancestor_or_self("acme/eng", "acme"));
        assert!(!is_ancestor_or_self("acme/eng", "acme/ops"));
        // Empty never matches.
        assert!(!is_ancestor_or_self("", "acme"));
        assert!(!is_ancestor_or_self("acme", ""));
    }

    #[test]
    fn parent_and_depth() {
        assert_eq!(parent_path("acme"), None);
        assert_eq!(parent_path("acme/eng"), Some("acme"));
        assert_eq!(parent_path("acme/eng/team-a"), Some("acme/eng"));
        assert_eq!(depth("acme"), 1);
        assert_eq!(depth("acme/eng/team-a"), 3);
        assert_eq!(depth(""), 0);
    }

    #[test]
    fn child_path_builds_and_validates() {
        assert_eq!(child_path("acme", "eng").unwrap(), "acme/eng");
        assert!(child_path("acme", "ev/il").is_err()); // separator in the new segment
        assert!(child_path("acme", "").is_err()); // empty segment
    }
}
