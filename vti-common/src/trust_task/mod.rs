//! Trust-Task primitive — every wire op in the workspace binds to a
//! versioned Trust Task identifier published on
//! [`trusttasks.org`](https://trusttasks.org). See spec §3-L and §16 of
//! `docs/05-design-notes/vtc-mvp.md` for the full design rationale.
//!
//! This module ships the workspace-wide foundation:
//!
//! - [`TrustTask`] — a validated newtype around the Trust-Task
//!   identifier (a URL the workspace treats as opaque).
//! - [`HEADER_NAME`] — the canonical HTTP header name (`Trust-Task`).
//! - [`extractor::TrustTaskHeader`] — Axum extractor for handlers that
//!   want to read the header value directly.
//! - [`router::TrustTaskRouter`] — builder that wraps Axum `Router`
//!   and enforces exact-match Trust-Task header validation **at route
//!   attach time** (no string-prefix tricks, no version-family
//!   matching — see spec §9.4).
//!
//! ## Design call
//!
//! The router builder is explicit and macro-free per the M0.1.1 plan
//! decision **D9**. A future-reader sees the registered task right
//! next to the handler in source, and `cargo doc` surfaces it on the
//! route without any procedural-macro indirection.

pub mod extractor;
#[cfg(feature = "openapi")]
pub mod openapi;
pub mod router;

pub use extractor::TrustTaskHeader;
#[cfg(feature = "openapi")]
pub use openapi::{task_layer, task_routes};
pub use router::TrustTaskRouter;

use crate::error::AppError;

/// Canonical HTTP header name carrying the Trust-Task identifier on
/// REST requests. The workspace pins this literal so a future audit
/// can grep for header consumers without ambiguity.
pub const HEADER_NAME: &str = "Trust-Task";

/// A validated Trust-Task identifier.
///
/// The workspace treats Trust-Task URLs as opaque — we don't enforce
/// the full `https://trusttasks.org/{org}/{path}/{maj}.{min}` shape
/// because the registry's canonical format is still evolving (spec
/// §17 Q10). What we **do** enforce:
///
/// - non-empty
/// - starts with `https://`
/// - no CR/LF characters (prevents header-injection attacks via a
///   round-tripped Trust-Task value)
///
/// Exact-match against a handler's registered task is the only
/// correctness check at request time — see
/// [`TrustTaskRouter::route_with_task`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustTask(String);

impl TrustTask {
    /// Parse and validate a Trust-Task identifier. Returns
    /// [`AppError::TrustTaskMalformed`] for empty, non-HTTPS, or
    /// control-character-containing values.
    pub fn new(s: impl Into<String>) -> Result<Self, AppError> {
        let s = s.into();
        if s.is_empty() {
            return Err(AppError::TrustTaskMalformed("<empty>".into()));
        }
        if !s.starts_with("https://") {
            return Err(AppError::TrustTaskMalformed(s));
        }
        if s.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err(AppError::TrustTaskMalformed(s));
        }
        Ok(Self(s))
    }

    /// The validated identifier as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TrustTask {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TrustTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_https_url() {
        let t = TrustTask::new("https://trusttasks.org/openvtc/vtc/install/claim/1.0").unwrap();
        assert_eq!(
            t.as_str(),
            "https://trusttasks.org/openvtc/vtc/install/claim/1.0"
        );
    }

    #[test]
    fn rejects_empty_string() {
        let err = TrustTask::new("").expect_err("empty");
        assert!(matches!(err, AppError::TrustTaskMalformed(_)));
    }

    #[test]
    fn rejects_non_https() {
        for s in [
            "http://trusttasks.org/openvtc/vtc/install/claim/1.0",
            "urn:openvtc:vtc:install:claim:1.0",
            "trusttasks.org/openvtc/vtc/install/claim/1.0",
        ] {
            let err = TrustTask::new(s).expect_err("non-https");
            assert!(
                matches!(err, AppError::TrustTaskMalformed(_)),
                "{s} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_header_injection_attempts() {
        for s in [
            "https://trusttasks.org/x\r\nInjected: yes",
            "https://trusttasks.org/x\nInjected: yes",
            "https://trusttasks.org/x\0",
        ] {
            let err = TrustTask::new(s).expect_err("control chars");
            assert!(
                matches!(err, AppError::TrustTaskMalformed(_)),
                "{s:?} should be rejected"
            );
        }
    }

    #[test]
    fn display_returns_full_url() {
        let t = TrustTask::new("https://trusttasks.org/x/1.0").unwrap();
        assert_eq!(format!("{t}"), "https://trusttasks.org/x/1.0");
    }
}
