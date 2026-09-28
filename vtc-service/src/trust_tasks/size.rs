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
//! A declared maximum is **in force only while this node serves the type**
//! ([`super::DISPATCHED_URIS`]). The spine verifies a document's proof —
//! canonicalising the whole document and resolving its signer's DID — before
//! it refuses a type it does not route, so a raised limit on a type nobody
//! serves would buy an unauthenticated caller that much more work for nothing.
//! Until a declared type is dispatched it takes the default like any other.
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
//! HTTPS door additionally caps its request body at
//! [`largest_max_document_bytes`], so no body larger than any served type
//! accepts is ever buffered.

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

/// The largest document any **served** type accepts: the HTTPS door's body
/// cap. The default while no type in [`DECLARED`] is dispatched.
pub(crate) fn largest_max_document_bytes() -> usize {
    largest_in(DECLARED, super::DISPATCHED_URIS)
}

fn largest_in(declared: &[(&str, usize)], served: &[&str]) -> usize {
    declared
        .iter()
        .filter(|(uri, _)| served.contains(uri))
        .map(|(_, max)| *max)
        .fold(DEFAULT_MAX_DOCUMENT_BYTES, usize::max)
}

/// The `details` member naming the limit a refused document exceeded.
pub(crate) const DETAILS_MAX_BYTES: &str = "maxBytes";

/// The largest document `type_uri` accepts, in bytes.
pub(crate) fn max_document_bytes(type_uri: &str) -> usize {
    max_in(type_uri, DECLARED, super::DISPATCHED_URIS)
}

fn max_in(type_uri: &str, declared: &[(&str, usize)], served: &[&str]) -> usize {
    declared
        .iter()
        .find(|(uri, _)| *uri == type_uri && served.contains(uri))
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, |(_, max)| *max)
}

/// Admit `body`, or refuse it for its size before it is parsed.
pub(crate) fn check(body: &[u8]) -> Result<(), TrustTaskOutcome> {
    check_with(body, max_document_bytes)
}

/// The longest `type` a refusal names. A caller's own `type` is echoed back
/// only when it is short enough to be a Type URI; anything longer is not one,
/// and repeating it would turn the refusal into an echo of the caller's body.
const MAX_NAMED_TYPE_CHARS: usize = 256;

fn check_with(body: &[u8], limit: impl Fn(&str) -> usize) -> Result<(), TrustTaskOutcome> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(());
    }
    let type_uri = peek_type(body);
    let max = type_uri
        .as_deref()
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, &limit);
    if body.len() <= max {
        return Ok(());
    }
    let named = match type_uri.as_deref() {
        Some(t) if t.chars().count() <= MAX_NAMED_TYPE_CHARS => t,
        Some(_) => "its type",
        None => "a document of no readable type",
    };
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

    /// `policy/upsert` as though this node served it.
    fn served_upsert(type_uri: &str) -> usize {
        max_in(type_uri, DECLARED, &[POLICY_UPSERT])
    }

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
        assert_eq!(served_upsert(MEMBERS_UPDATE), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            served_upsert(POLICY_UPSERT),
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
    }

    /// A raised limit on a type this node does not route would only let an
    /// unauthenticated caller make the spine canonicalise and verify a larger
    /// document before refusing it as unrouted.
    #[test]
    fn a_declared_type_that_is_not_served_takes_the_default() {
        assert_eq!(
            max_in(POLICY_UPSERT, DECLARED, &[]),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(largest_in(DECLARED, &[]), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            largest_in(DECLARED, &[POLICY_UPSERT]),
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
        // And on this build, the live table agrees with what the spine routes.
        for (uri, max) in DECLARED {
            let served = super::super::DISPATCHED_URIS.contains(uri);
            assert_eq!(
                max_document_bytes(uri),
                if served {
                    *max
                } else {
                    DEFAULT_MAX_DOCUMENT_BYTES
                },
                "{uri}"
            );
        }
        assert!(largest_max_document_bytes() >= DEFAULT_MAX_DOCUMENT_BYTES);
    }

    #[test]
    fn a_document_at_its_types_limit_is_admitted() {
        assert!(check(&document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES)).is_ok());
        assert!(
            check_with(
                &document_of(POLICY_UPSERT, POLICY_UPSERT_MAX_DOCUMENT_BYTES),
                served_upsert
            )
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
            check_with(
                &document_of(POLICY_UPSERT, POLICY_UPSERT_MAX_DOCUMENT_BYTES + 1),
                served_upsert,
            )
            .unwrap_err(),
        );
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
    }

    /// The `type` is read wherever it sits: one placed after a large member is
    /// still the one the limit is looked up by, and a nested `type` is not it.
    #[test]
    fn the_type_is_the_top_level_one_wherever_it_sits() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let late = format!(
            r#"{{"payload":{{"type":"{MEMBERS_UPDATE}","pad":"{pad}"}},"type":"{POLICY_UPSERT}"}}"#
        );
        assert!(check_with(late.as_bytes(), served_upsert).is_ok());
        let nested_only = format!(r#"{{"payload":{{"type":"{POLICY_UPSERT}","pad":"{pad}"}}}}"#);
        assert_eq!(
            refusal(check_with(nested_only.as_bytes(), served_upsert).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// Two top-level `type`s cannot claim the larger limit: the body reads as
    /// no type at all, and takes the default.
    #[test]
    fn a_duplicated_type_takes_the_default() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let body =
            format!(r#"{{"type":"{MEMBERS_UPDATE}","type":"{POLICY_UPSERT}","pad":"{pad}"}}"#);
        assert_eq!(
            refusal(check_with(body.as_bytes(), served_upsert).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// The refusal repeats a caller's `type` only when it could be a Type URI.
    #[test]
    fn a_refusal_does_not_echo_an_oversized_type() {
        let huge = "t".repeat(DEFAULT_MAX_DOCUMENT_BYTES + 1);
        let body = format!(r#"{{"type":"{huge}"}}"#);
        let payload = refusal(check(body.as_bytes()).unwrap_err());
        let text = payload.to_string();
        assert!(
            text.len() < 1024,
            "the refusal echoes the body: {} bytes",
            text.len()
        );
        assert_eq!(
            payload["details"],
            serde_json::json!({ DETAILS_MAX_BYTES: DEFAULT_MAX_DOCUMENT_BYTES })
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

    /// The gate is the spine's, so a transport that is not HTTPS — which has
    /// no body cap of its own here — meets the same refusal.
    #[tokio::test]
    async fn every_transport_meets_the_same_refusal() {
        use crate::join::JoinTransport;
        let vtc = crate::test_support::TestVtc::builder().build().await;
        let body = document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES + 1);
        for transport in [
            JoinTransport::Rest,
            JoinTransport::DIDComm,
            JoinTransport::Tsp,
        ] {
            let ctx = match transport {
                JoinTransport::Rest => super::super::JoinAuthCtx::rest(),
                _ => super::super::JoinAuthCtx {
                    transport,
                    sender_did: Some("did:key:z6MkSizeSender".into()),
                    verified_signer: None,
                },
            };
            let out = super::super::dispatch_trust_task_core(&vtc.state, &ctx, &body).await;
            let payload = refusal(out);
            assert_eq!(payload["code"], "malformedRequest", "{transport:?}");
            assert_eq!(
                payload["details"][DETAILS_MAX_BYTES], DEFAULT_MAX_DOCUMENT_BYTES,
                "{transport:?}"
            );
        }
    }
}
