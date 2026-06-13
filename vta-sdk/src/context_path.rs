//! Hierarchical trust-context paths — the security foundation for
//! folder/sub-folder contexts.
//!
//! A context identifier **is** its materialized path: slash-separated segments,
//! e.g. `acme/eng/team-a`. The server's authorization gate decides "admin of a
//! parent → access to descendants" with [`is_ancestor_or_self`] — a **pure,
//! store-free** segment comparison over data already in the verified JWT.
//!
//! ## Why this lives in the SDK
//! Path construction (`child_path`) and validation (`validate_context_path`)
//! are the canonical rules for what a context path may contain. A **client**
//! that derives a sub-context id (e.g. a community's `<top>/<slug>`) must apply
//! the *same* rules so it only ever sends paths the VTA will accept. Keeping
//! them here lets clients share the one source of truth instead of mirroring it
//! and drifting on security-relevant logic. The server re-exports these through
//! `vti_common::context_path`.
//!
//! ## The one footgun, handled
//! A raw `str::starts_with` is **wrong**: `acme` would "contain" `acme-evil`.
//! Ancestry here is **segment-aware**, and `/` is the *only* separator — it
//! cannot appear inside a segment (each segment is a
//! [`validate_identifier`](crate::identifier::validate_identifier) value), so
//! there is no `..` / slash-injection / empty-segment aliasing.

use crate::identifier::{ValidationError, validate_identifier};

/// Maximum nesting depth (number of path segments). Bounds derivation depth and
/// keeps ancestry checks cheap; deep trees are an anti-pattern, not a need.
pub const MAX_CONTEXT_DEPTH: usize = 8;

/// The path separator. A context identifier is segments joined by this; it never
/// appears inside a segment.
pub const SEPARATOR: char = '/';

/// Validate a context path: non-empty, ≤ [`MAX_CONTEXT_DEPTH`] segments, every
/// segment a valid identifier, and no empty / leading / trailing / doubled
/// separators.
pub fn validate_context_path(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError("context path must not be empty".into()));
    }
    if value.starts_with(SEPARATOR) || value.ends_with(SEPARATOR) {
        return Err(ValidationError(format!(
            "context path must not start or end with '{SEPARATOR}'"
        )));
    }

    let segments: Vec<&str> = value.split(SEPARATOR).collect();
    if segments.len() > MAX_CONTEXT_DEPTH {
        return Err(ValidationError(format!(
            "context path is {} levels deep; maximum is {MAX_CONTEXT_DEPTH}",
            segments.len()
        )));
    }
    for segment in &segments {
        // An empty segment means a leading/trailing/doubled separator — `split`
        // yields `""` for each. (The leading/trailing case is caught above; this
        // catches `a//b`.)
        if segment.is_empty() {
            return Err(ValidationError(
                "context path must not contain an empty segment ('//')".into(),
            ));
        }
        validate_identifier("context path segment", segment)?;
    }
    Ok(())
}

/// Split a path into its segments. The path is assumed
/// [validated](validate_context_path); for an arbitrary string this still
/// returns the slash-split parts.
fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split(SEPARATOR)
}

/// Whether `ancestor` is `descendant` itself or an ancestor of it — the test the
/// ACL gate uses for "admin of a parent context covers the subtree".
///
/// **Segment-aware:** `descendant`'s segments must *begin with* `ancestor`'s
/// segments, segment-for-segment. So `acme` is an ancestor of `acme/eng` but
/// **not** of `acme-evil`, and `acme/eng` is not an ancestor of `acme/engineering`.
///
/// Inputs are compared as-is; callers gate creation through
/// [`validate_context_path`], so malformed paths simply fail to match.
pub fn is_ancestor_or_self(ancestor: &str, descendant: &str) -> bool {
    // Empty strings never participate (an empty `allowed_contexts` entry must
    // not grant access; super-admin is handled separately by the gate).
    if ancestor.is_empty() || descendant.is_empty() {
        return false;
    }
    let mut anc = segments(ancestor);
    let mut desc = segments(descendant);
    loop {
        match anc.next() {
            // Ancestor exhausted: descendant began with all of it → ancestor-or-self.
            None => return true,
            Some(a) => match desc.next() {
                // Descendant ran out first, or a segment differs → not an ancestor.
                None => return false,
                Some(d) if a != d => return false,
                Some(_) => continue,
            },
        }
    }
}

/// The parent path (one segment shorter), or `None` for a top-level (single
/// segment) path.
pub fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once(SEPARATOR).map(|(parent, _)| parent)
}

/// The depth (segment count) of a path. A top-level context is depth 1.
pub fn depth(path: &str) -> usize {
    if path.is_empty() {
        return 0;
    }
    path.split(SEPARATOR).count()
}

/// Build a child path under `parent` by appending a single `segment`. The
/// `segment` must be one valid identifier — it cannot itself contain a separator
/// (else it would silently add *several* levels) — and the resulting path must
/// validate (depth included).
pub fn child_path(parent: &str, segment: &str) -> Result<String, ValidationError> {
    // Reject a `segment` that is empty or contains the separator: `child_path`
    // adds exactly one level.
    validate_identifier("context path segment", segment)?;
    let candidate = format!("{parent}{SEPARATOR}{segment}");
    validate_context_path(&candidate)?;
    Ok(candidate)
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
