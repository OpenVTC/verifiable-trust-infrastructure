//! The largest document each Trust Task type may be, checked before the
//! document is parsed.
//!
//! One cap for every type is either too small for the few tasks whose payload
//! is legitimately large (a Rego module, a DID's whole log, a chunk of a
//! website) or far too large for the many whose payload is a handful of
//! identifiers. The body is attacker-supplied and arrives unauthenticated, so
//! the cap is what bounds the parsing, schema validation and proof verification
//! the spine does before it knows who is asking.
//!
//! # Where a limit comes from
//!
//! From the task's own specification: its front matter's `maxDocumentBytes`,
//! which the codegen emits as `Payload::MAX_DOCUMENT_BYTES` and answers by Type
//! URI through [`trust_tasks_rs::schema_index::max_document_bytes_for`]. Every
//! type that declares nothing takes [`DEFAULT_MAX_DOCUMENT_BYTES`]. This module
//! keeps no table of its own, except [`AWAITING_DECLARATION`]: the two served
//! tasks that need more than the default and whose specifications do not yet
//! say so. Each entry is removed when its specification declares a limit, and
//! a test fails the build once one does.
//!
//! # Three rules on top of the number
//!
//! - **Served types only.** A limit is in force only while this node serves the
//!   type ([`super::DISPATCHED_URIS`]). The spine verifies a document's proof —
//!   canonicalising the whole document and resolving its signer's DID — before
//!   it refuses a type it does not route, so a raised limit on a type nobody
//!   serves would buy an unauthenticated caller that much more work for
//!   nothing.
//! - **Known issuers only.** A document above the default is admitted at its
//!   type's raised limit only when its claimed `issuer` holds a live ACL entry
//!   here, or is a signing key an active delegation names for such an entry
//!   ([`check`]). The lookup is one keyspace read, made before any signature is
//!   verified; a claimed issuer that then fails verification is refused as
//!   usual. Nobody without standing could be authorised for a raised task, so a
//!   stranger's large document is held to the default.
//! - **No echo.** A refusal names the caller's `type` only when it is short
//!   enough to be a Type URI.
//!
//! # Before the parse
//!
//! A body no larger than the default is admitted without looking at it: every
//! type accepts that much. A larger body has only its top-level `type` and
//! `issuer` read — a scan that keeps no other member — and is refused unless
//! that type's limit admits it and the issuer is known. Nothing else in it is
//! parsed, validated or verified. The refusal is a framework `trust-task-error`
//! with the standard `malformedRequest` code and the limit that applied under
//! `details.maxBytes`.
//!
//! The check sits in the spine, so it is the same on every transport. The
//! HTTPS door additionally caps its request body at
//! [`largest_max_document_bytes`], so no body larger than any served type
//! accepts is ever buffered.

use trust_tasks_rs::{ErrorPayload, Payload, RejectReason};

use super::helpers::{TrustTaskOutcome, unrouted_error_response};
use crate::server::AppState;

/// Every type that declares nothing accepts a document of at most 64 KiB —
/// generous for a document of identifiers, a credential or a presentation, and
/// small enough that an unauthenticated flood of them is cheap to refuse.
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
/// accepts ([`crate::routes::MAX_BODY_SIZE`]), and what the DID hosting
/// service's control plane accepts for it.
pub(crate) const DID_REGISTER_MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Served types that need more than the default and whose specification does
/// not declare `maxDocumentBytes` yet. Keyed by the full Type URI, so a new
/// version of a task takes its own declaration. An entry goes when the
/// specification declares a limit
/// (`every_awaiting_entry_is_still_undeclared_upstream`).
pub(crate) const AWAITING_DECLARATION: &[(&str, usize)] = &[
    (
        <trust_tasks_rs::specs::policy::upsert::v0_2::Payload as Payload>::TYPE_URI,
        POLICY_UPSERT_MAX_DOCUMENT_BYTES,
    ),
    (
        <trust_tasks_rs::specs::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI,
        DID_REGISTER_MAX_DOCUMENT_BYTES,
    ),
];

/// What `type_uri`'s specification declares, or its [`AWAITING_DECLARATION`]
/// entry.
fn declared(type_uri: &str) -> Option<usize> {
    trust_tasks_rs::schema_index::max_document_bytes_for(type_uri).or_else(|| {
        AWAITING_DECLARATION
            .iter()
            .find(|(uri, _)| *uri == type_uri)
            .map(|(_, max)| *max)
    })
}

/// The largest document any **served** type accepts: the HTTPS door's body
/// cap.
pub(crate) fn largest_max_document_bytes() -> usize {
    largest_in(super::DISPATCHED_URIS, declared)
}

fn largest_in(served: &[&str], declared: impl Fn(&str) -> Option<usize>) -> usize {
    served
        .iter()
        .filter_map(|uri| declared(uri))
        .fold(DEFAULT_MAX_DOCUMENT_BYTES, usize::max)
}

/// The `details` member naming the limit a refused document exceeded.
pub(crate) const DETAILS_MAX_BYTES: &str = "maxBytes";

/// The largest document `type_uri` accepts, in bytes, from a known issuer.
pub(crate) fn max_document_bytes(type_uri: &str) -> usize {
    max_in(type_uri, super::DISPATCHED_URIS, declared)
}

fn max_in(type_uri: &str, served: &[&str], declared: impl Fn(&str) -> Option<usize>) -> usize {
    if served.contains(&type_uri) {
        declared(type_uri).unwrap_or(DEFAULT_MAX_DOCUMENT_BYTES)
    } else {
        DEFAULT_MAX_DOCUMENT_BYTES
    }
}

/// Admit `body`, or refuse it for its size before it is parsed.
///
/// A document above the default is held to its type's limit only when its
/// claimed `issuer` is known here ([`is_known_issuer`]); a stranger's is held to
/// the default.
pub(crate) async fn check(state: &AppState, body: &[u8]) -> Result<(), TrustTaskOutcome> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(());
    }
    let known = match peek_issuer(body) {
        Some(issuer) => is_known_issuer(state, &issuer).await,
        None => false,
    };
    if known {
        check_with(body, max_document_bytes)
    } else {
        check_with(body, |_| DEFAULT_MAX_DOCUMENT_BYTES)
    }
}

/// Whether `issuer` holds standing here: a live ACL entry of its own, or an
/// active signing-key delegation to an identity that holds one.
///
/// A failed read counts as unknown, so a store error costs the caller the
/// raised limit rather than admitting an unbounded body.
async fn is_known_issuer(state: &AppState, issuer: &str) -> bool {
    let now = crate::auth::session::now_epoch();
    let live = |entry: Option<crate::acl::VtcAclEntry>| entry.is_some_and(|e| !e.is_expired(now));
    let did = issuer.split('#').next().unwrap_or(issuer);
    if live(
        crate::acl::get_acl_entry(&state.acl_ks, did)
            .await
            .ok()
            .flatten(),
    ) {
        return true;
    }
    match crate::acl::console_key::resolve_delegated_admin(&state.console_keys_ks, did).await {
        Ok(Some(delegation)) => live(
            crate::acl::get_acl_entry(&state.acl_ks, &delegation.admin_did)
                .await
                .ok()
                .flatten(),
        ),
        _ => false,
    }
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

/// The document's top-level `issuer`, read the same way as [`peek_type`]: a
/// duplicated or non-string one reads as none, and the body is held to the
/// default.
fn peek_issuer(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct IssuerOnly {
        issuer: String,
    }
    serde_json::from_slice::<IssuerOnly>(body)
        .ok()
        .map(|t| t.issuer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_UPSERT: &str =
        <trust_tasks_rs::specs::policy::upsert::v0_2::Payload as Payload>::TYPE_URI;
    const MEMBERS_UPDATE: &str =
        <trust_tasks_rs::specs::vtc::members::update::v0_1::Payload as Payload>::TYPE_URI;
    const WEBSITE_CHUNK: &str =
        <trust_tasks_rs::specs::vtc::website::upload::chunk::v0_1::Payload as Payload>::TYPE_URI;

    /// `policy/upsert` as though this node served it.
    fn served_upsert(type_uri: &str) -> usize {
        max_in(type_uri, &[POLICY_UPSERT], declared)
    }

    /// A document of `type_uri` from `issuer`, padded to exactly `len` bytes.
    fn document_from(issuer: &str, type_uri: &str, len: usize) -> Vec<u8> {
        let head = format!(r#"{{"type":"{type_uri}","issuer":"{issuer}","payload":{{"pad":""#);
        let tail = r#""}}"#;
        let pad = len - head.len() - tail.len();
        let body = format!("{head}{}{tail}", "x".repeat(pad));
        assert_eq!(body.len(), len);
        body.into_bytes()
    }

    fn document_of(type_uri: &str, len: usize) -> Vec<u8> {
        document_from("did:key:z6MkSizeSender", type_uri, len)
    }

    fn refusal(outcome: TrustTaskOutcome) -> serde_json::Value {
        assert_eq!(outcome.status, axum::http::StatusCode::BAD_REQUEST);
        let doc: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        doc["payload"].clone()
    }

    /// An interim entry is for a specification that declares nothing; once it
    /// declares a limit, the declaration is the one in force and the entry goes.
    #[test]
    fn every_awaiting_entry_is_still_undeclared_upstream() {
        for (uri, max) in AWAITING_DECLARATION {
            assert!(
                trust_tasks_rs::schema_index::schema_for(uri).is_some(),
                "{uri} names no published specification"
            );
            assert!(
                trust_tasks_rs::schema_index::max_document_bytes_for(uri).is_none(),
                "{uri} now declares maxDocumentBytes; drop its AWAITING_DECLARATION entry"
            );
            assert!(
                *max > DEFAULT_MAX_DOCUMENT_BYTES,
                "{uri} awaits {max}, which is not above the default; drop it"
            );
        }
    }

    /// The codegen's declaration is the limit: the website chunk declares
    /// 352 KiB, and a type that declares nothing takes the default.
    #[test]
    fn a_declared_limit_is_the_specifications_own() {
        let chunk = trust_tasks_rs::schema_index::max_document_bytes_for(WEBSITE_CHUNK)
            .expect("the chunk declares a limit");
        assert_eq!(max_in(WEBSITE_CHUNK, &[WEBSITE_CHUNK], declared), chunk);
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
            max_in(POLICY_UPSERT, &[], declared),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(largest_in(&[], declared), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            largest_in(&[POLICY_UPSERT, MEMBERS_UPDATE], declared),
            POLICY_UPSERT_MAX_DOCUMENT_BYTES
        );
        // And on this build, every served limit is at most the door's cap.
        for uri in super::super::DISPATCHED_URIS {
            assert!(
                max_document_bytes(uri) <= largest_max_document_bytes(),
                "{uri}"
            );
        }
    }

    #[test]
    fn a_document_at_its_types_limit_is_admitted() {
        assert!(
            check_with(
                &document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES),
                max_document_bytes
            )
            .is_ok()
        );
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
            check_with(
                &document_of(MEMBERS_UPDATE, DEFAULT_MAX_DOCUMENT_BYTES + 1),
                max_document_bytes,
            )
            .unwrap_err(),
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
        let payload = refusal(check_with(body.as_bytes(), max_document_bytes).unwrap_err());
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
        let payload = refusal(check_with(&junk, max_document_bytes).unwrap_err());
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// A raised limit is for a known issuer: a stranger's large document, and
    /// one naming no issuer, are held to the default; an administrator's, and
    /// a signing key's delegated by one, are admitted at the type's limit.
    #[tokio::test]
    async fn a_raised_limit_needs_an_issuer_with_standing() {
        use crate::acl::{VtcAclEntry, VtcRole, store_acl_entry};
        let vtc = crate::test_support::TestVtc::builder().build().await;
        let admin = "did:key:z6MkSizeKnownAdmin";
        store_acl_entry(
            &vtc.state.acl_ks,
            &VtcAclEntry {
                did: admin.into(),
                role: VtcRole::Admin,
                label: None,
                allowed_contexts: vec![],
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
        let key = "did:key:z6MkSizeDelegatedKey";
        crate::acl::console_key::enrol_delegation(
            &vtc.state.console_keys_ks,
            &vtc.state.acl_ks,
            key,
            admin,
            None,
            None,
        )
        .await
        .unwrap();

        let len = DEFAULT_MAX_DOCUMENT_BYTES + 1;
        assert!(served_upsert(POLICY_UPSERT) >= len);
        let limit_for = |issuer: &str| document_from(issuer, POLICY_UPSERT, len);
        // `policy/upsert` is served on this build.
        assert!(super::super::DISPATCHED_URIS.contains(&POLICY_UPSERT));
        for issuer in [admin, key] {
            assert!(
                check(&vtc.state, &limit_for(issuer)).await.is_ok(),
                "{issuer}"
            );
        }
        let stranger = refusal(
            check(&vtc.state, &limit_for("did:key:z6MkSizeStranger"))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            stranger["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let anonymous = format!(r#"{{"type":"{POLICY_UPSERT}","payload":{{"pad":"{pad}"}}}}"#);
        assert!(check(&vtc.state, anonymous.as_bytes()).await.is_err());
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
