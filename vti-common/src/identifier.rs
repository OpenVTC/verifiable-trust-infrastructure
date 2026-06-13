//! Server-side re-export of the canonical identifier validator.
//!
//! The pure rules now live in [`vta_sdk::identifier`] so **clients** can apply
//! the same security-relevant gate without depending on this server-only crate
//! (see issue #392). This module is a thin wrapper that maps the SDK's
//! dependency-light [`ValidationError`](vta_sdk::identifier::ValidationError)
//! onto the server's [`AppError`] for `?`-ergonomics at the route handlers.
//!
//! See [`vta_sdk::identifier`] for the rationale behind the narrow
//! `[A-Za-z0-9._-]` character class and 64-byte cap.

use crate::error::AppError;

pub use vta_sdk::identifier::MAX_IDENTIFIER_LEN;

/// Validate a caller-supplied identifier (context ID, template name, slug).
///
/// Thin wrapper over [`vta_sdk::identifier::validate_identifier`] that converts
/// the SDK [`ValidationError`](vta_sdk::identifier::ValidationError) into an
/// [`AppError::Validation`]; the message is preserved verbatim. See the SDK
/// function for the accepted character class and the injection shapes it
/// rejects.
pub fn validate_identifier(label: &str, value: &str) -> Result<(), AppError> {
    vta_sdk::identifier::validate_identifier(label, value).map_err(|e| AppError::Validation(e.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_identifier_shapes() {
        for ok in [
            "myapp",
            "My-App_1",
            "context.v2",
            "a",
            "0",
            "didcomm-mediator",
            "_private",
            "CamelCase",
        ] {
            validate_identifier("id", ok).unwrap_or_else(|e| panic!("{ok:?} rejected: {e:?}"));
        }
    }

    #[test]
    fn rejects_empty() {
        let err = validate_identifier("id", "").expect_err("empty must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn rejects_separator_injection() {
        // These are the concrete attack shapes: a caller who can inject
        // `:` can collide with or escape adjacent store namespaces.
        for bad in [
            "global:evil",     // collides with tpl:global: prefix
            "../../etc",       // path traversal shape
            "a:b:c",           // keyspace separator
            "my/ctx",          // path separator
            "with space",      // whitespace
            "tab\there",       // control chars
            "with\nnewline",   // newline injection
            "null\0byte",      // null byte
            "unicode:§§",      // non-ASCII
            "quote\"injected", // quote shape
        ] {
            validate_identifier("id", bad).expect_err(&format!("{bad:?} must be rejected"));
        }
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        let err = validate_identifier("id", &long).expect_err("overlong must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn accepts_exactly_at_limit() {
        let edge = "a".repeat(MAX_IDENTIFIER_LEN);
        validate_identifier("id", &edge).expect("exactly-at-limit must pass");
    }

    #[test]
    fn error_message_names_the_field() {
        let err = validate_identifier("context_id", "bad:id").expect_err("rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("context_id"),
            "error must name the field it is validating — got {msg}"
        );
    }
}
