//! The largest document each Trust Task type may be, checked before the
//! document is parsed.
//!
//! One cap for every type is either too small for the few tasks whose payload
//! is legitimately large (a Rego module, a DID's whole log) or far too large
//! for the many whose payload is a handful of identifiers. The body is
//! attacker-supplied and arrives unauthenticated, so the cap is what bounds the
//! parsing, schema validation and proof verification the spine does before it
//! knows who is asking.
//!
//! So each type declares its own maximum in [`DECLARED`], and every other type
//! takes [`DEFAULT_MAX_DOCUMENT_BYTES`]. A value is raised above the default
//! only where the task's specification needs it, and each says why.
//!
//! # Before the parse
//!
//! A body no larger than the default is admitted without looking at it: every
//! type accepts that much. A larger body has only its top-level `type` read —
//! a scan that keeps no other member — and is refused unless that type
//! declares a maximum it fits. Nothing else in it is parsed, validated or
//! verified. The refusal is a framework `trust-task-error` with the standard
//! `malformedRequest` code and the limit under `details.maxBytes`.
//!
//! The check sits in the spine, so it is the same on every transport. The
//! HTTPS door additionally caps its request body at [`LARGEST_MAX_DOCUMENT_BYTES`],
//! so no body larger than any type accepts is ever buffered.

use trust_tasks_rs::{ErrorPayload, Payload, RejectReason};

use super::helpers::{TrustTaskOutcome, unrouted_error_response};

/// Every type not in [`DECLARED`] accepts a document of at most 64 KiB —
/// generous for a document of identifiers, a credential or a presentation,
/// and small enough that an unauthenticated flood of them is cheap to refuse.
pub(crate) const DEFAULT_MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// `policy/upsert/0.2`: 192 KiB.
///
/// The payload's `module` is a Rego source of up to
/// [`crate::policy::POLICY_SOURCE_MAX_BYTES`] (64 KiB). JSON escaping of
/// ordinary source (quotes, backslashes, newlines) at most doubles it, and the
/// rest — `name`, `ext`, the envelope and the proof — is well under a further
/// 64 KiB.
pub(crate) const POLICY_UPSERT_MAX_DOCUMENT_BYTES: usize =
    2 * crate::policy::POLICY_SOURCE_MAX_BYTES + 64 * 1024;

/// `did-management/did/register/0.1`: 1 MiB.
///
/// `didData` is the DID's complete `did:webvh` log — every entry it has ever
/// had, each a signed DID document — so it grows with the DID's age and cannot
/// be bounded by its shape. 1 MiB is what the HTTPS route for the same task
/// accepts today ([`crate::routes::MAX_BODY_SIZE`]); a lower limit here would
/// refuse a long-lived DID's log that the route admits.
pub(crate) const DID_REGISTER_MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The types that accept more than [`DEFAULT_MAX_DOCUMENT_BYTES`], and how
/// much. Keyed by the full Type URI, so a new version of a task takes the
/// default until it declares its own.
pub(crate) const DECLARED: &[(&str, usize)] = &[
    (
        <trust_tasks_rs::specs::policy::upsert::v0_2::Payload as Payload>::TYPE_URI,
        POLICY_UPSERT_MAX_DOCUMENT_BYTES,
    ),
    (
        <trust_tasks_rs::specs::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI,
        DID_REGISTER_MAX_DOCUMENT_BYTES,
    ),
];

/// The largest document any type accepts: the HTTPS door's body cap.
pub(crate) const LARGEST_MAX_DOCUMENT_BYTES: usize = {
    let mut max = DEFAULT_MAX_DOCUMENT_BYTES;
    let mut i = 0;
    while i < DECLARED.len() {
        if DECLARED[i].1 > max {
            max = DECLARED[i].1;
        }
        i += 1;
    }
    max
};

/// The `details` member naming the limit a refused document exceeded.
pub(crate) const DETAILS_MAX_BYTES: &str = "maxBytes";

/// The largest document `type_uri` accepts, in bytes.
pub(crate) fn max_document_bytes(type_uri: &str) -> usize {
    DECLARED
        .iter()
        .find(|(uri, _)| *uri == type_uri)
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, |(_, max)| *max)
}

/// Admit `body`, or refuse it for its size before it is parsed.
pub(crate) fn check(body: &[u8]) -> Result<(), TrustTaskOutcome> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(());
    }
    let type_uri = peek_type(body);
    let max = type_uri
        .as_deref()
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, max_document_bytes);
    if body.len() <= max {
        return Ok(());
    }
    let named = type_uri
        .as_deref()
        .unwrap_or("a document of no readable type");
    let payload: ErrorPayload = RejectReason::MalformedRequest {
        reason: format!(
            "the document is {} bytes; {named} accepts at most {max}",
            body.len()
        ),
    }
    .into();
    Err(unrouted_error_response(payload.with_details(
        serde_json::json!({ DETAILS_MAX_BYTES: max }),
    )))
}

/// The document's top-level `type`, read without keeping anything else.
///
/// `None` for a body that is not a JSON object with a string `type` — which
/// then takes the default limit, as a type that declares nothing does.
fn peek_type(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TypeOnly {
        #[serde(rename = "type")]
        type_uri: String,
    }
    serde_json::from_slice::<TypeOnly>(body)
        .ok()
        .map(|t| t.type_uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_UPSERT: &str =
        <trust_tasks_rs::specs::policy::upsert::v0_2::Payload as Payload>::TYPE_URI;
    const MEMBERS_UPDATE: &str =
        <trust_tasks_rs::specs::vtc::members::update::v0_1::Payload as Payload>::TYPE_URI;

    /// A document of `type_uri` padded to exactly `len` bytes.
    fn document_of(type_uri: &str, len: usize) -> Vec<u8> {
        let head = format!(r#"{{"type":"{type_uri}","payload":{{"pad":""#);
        let tail = r#""}}"#;
        let pad = len - head.len() - tail.len();
        let body = format!("{head}{}{tail}", "x".repeat(pad));
        assert_eq!(body.len(), len);
        body.into_bytes()
    }

    fn refusal(outcome: TrustTaskOutcome) -> serde_json::Value {
        assert_eq!(outcome.status, axum::http::StatusCode::BAD_REQUEST);
        let doc: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        doc["payload"].clone()
    }

    #[test]
    fn every_declared_type_is_a_published_specification_raised_above_the_default() {
        for (uri, max) in DECLARED {
            assert!(
                trust_tasks_rs::schema_index::schema_for(uri).is_some(),
                "{uri} names no published specification"
            );
            assert!(
                *max > DEFAULT_MAX_DOCUMENT_BYTES,
                "{uri} declares {max}, which is not above the default; drop it"
            );
        }
        let mut uris: Vec<&str> = DECLARED.iter().map(|(u, _)| *u).collect();
        uris.sort_unstable();
        uris.dedup();
        assert_eq!(uris.len(), DECLARED.len(), "a type is declared twice");
    }

    #[test]
    fn an_undeclared_type_takes_the_default() {
        assert_eq!(
            max_document_bytes(MEMBERS_UPDATE),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(
            max_document_bytes(POLICY_UPSERT),
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(LARGEST_MAX_DOCUMENT_BYTES, DID_REGISTER_MAX_DOCUMENT_BYTES);
    }

    #[test]
    fn a_document_at_its_types_limit_is_admitted() {
        assert!(check(&document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES)).is_ok());
        assert!(
            check(&document_of(
                POLICY_UPSERT,
                POLICY_UPSERT_MAX_DOCUMENT_BYTES
            ))
            .is_ok()
        );
    }

    #[test]
    fn a_document_over_the_default_is_refused_for_a_type_that_declares_nothing() {
        let payload = refusal(
            check(&document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES + 1)).unwrap_err(),
        );
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    #[test]
    fn a_document_over_its_raised_limit_is_refused() {
        let payload = refusal(
            check(&document_of(
                POLICY_UPSERT,
                POLICY_UPSERT_MAX_DOCUMENT_BYTES + 1,
            ))
            .unwrap_err(),
        );
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
    }

    /// An oversized body with no readable `type` cannot claim a raised limit:
    /// it is held to the default, and refused without being parsed further.
    #[test]
    fn an_oversized_body_with_no_readable_type_takes_the_default() {
        let junk = vec![b'['; DEFAULT_MAX_DOCUMENT_BYTES + 1];
        let payload = refusal(check(&junk).unwrap_err());
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }
}
