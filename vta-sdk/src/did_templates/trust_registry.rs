//! The `TrustRegistry` referral a community publishes in its DID document.
//!
//! TRQP v2.0 recommends that a trust registry be machine-discoverable *via the
//! `authority_id`* — that is, from the DID document of the authority whose
//! records it holds:
//!
//! > "It is RECOMMENDED that the TRQP service endpoint(s) for any authoritative
//! > trust registry be machine-discoverable via the `authority_id`. An example
//! > would be to publish either of the following in the DID document for the
//! > `authority_id`: 1. The authoritative TRQP service endpoint URL(s).
//! > 2. The DID(s) identifying authoritative trust registries."
//!
//! A VTC *is* the `authority_id` in every trust tuple evaluated under it, so
//! this entry belongs in the VTC's document and names the registry by DID —
//! form 2. A client that holds only the community's DID can then resolve one
//! hop to the registry rather than being configured with both.
//!
//! ## Referral, not endpoint
//!
//! The same `TrustRegistry` service type means two different things depending
//! on whose document carries it, and the endpoint's shape is what distinguishes
//! them: in a *registry's own* document the `uri` is that registry's TRQP URL
//! (an **endpoint**); in a *community's* document the `uri` is the registry's
//! **DID** (a **referral**). Consumers test the `uri` for a `did:` prefix —
//! `trql_client::registry_referral` is the reference implementation — so a
//! referral whose `uri` is an https URL would be silently misread as this
//! community claiming to serve TRQP itself. [`referral_service`] refuses a
//! non-DID `uri` for that reason.
//!
//! ## A referral asserts nothing about authority
//!
//! Publishing this entry is a self-assertion: anyone may name any registry in
//! their own document. Authority flows registry → subject, never the reverse,
//! so a client that follows the referral must confirm the registry answers
//! *for* the community that referred it before believing the answer. That
//! check lives client-side (`TrqlClient::referred_by`), not here — emitting
//! the entry establishes where to ask and nothing more.

use serde_json::{Value, json};

use super::TemplateError;

/// DID-document service `type` for a Trust Registry, per the
/// [ToIP Trust Registry Service Profile][profile].
///
/// TRQP v2.0 blesses the indirection but names no service type, so this one
/// comes from the Service Profile spec instead. That spec is Pre-Draft 0.0.1
/// and self-described as non-binding — the value is pinned here so the whole
/// stack moves together if it changes.
///
/// [profile]: https://github.com/trustoverip/tswg-trust-registry-service-profile/blob/main/spec.md
pub const TRUST_REGISTRY_SERVICE_TYPE: &str = "TrustRegistry";

/// Profile URI stamped on the referral's service endpoint.
///
/// The ToIP Service Profile example says `.../profiles/trp/v2`, left over from
/// when the protocol was still called TRP. Neither URI resolves today, so
/// nothing depends on the choice; we name the protocol as it is now called,
/// matching `trust-registry`'s own `TRQP_PROFILE_URI`. A consumer that starts
/// matching on `profile` would need to accept both spellings.
pub const TRQP_PROFILE_URI: &str = "https://trustoverip.org/profiles/trqp/v2";

/// Template variable carrying the whole referral entry.
///
/// The `vtc-host` template declares this in `optionalVars` with a `null`
/// default and places it as a bare array member, so a community provisioned
/// without a registry simply has the element pruned (see the array arm of
/// `render::substitute_value`). That null-pruning slot is the only conditional
/// mechanism the template format has, and it is why the entry is built here in
/// Rust rather than spelled out in the template JSON: the template cannot own
/// a constant it can also omit.
pub const TRUST_REGISTRY_SERVICE_VAR: &str = "SERVICE_TRUST_REGISTRY";

/// Fragment appended to the community's DID to id the referral entry.
const SERVICE_ID_FRAGMENT: &str = "#trust-registry";

/// Build the `TrustRegistry` referral entry naming `registry_did` as the
/// registry authoritative for this community.
///
/// Pass the result as [`TRUST_REGISTRY_SERVICE_VAR`] in a template's vars map.
/// The `id` carries the literal `{DID}` sentinel: caller-supplied variable
/// values are not re-substituted by the renderer, but `didwebvh-rs` resolves
/// `{DID}` across every leaf string after the SCID is computed, so the entry
/// lands with the community's minted DID.
///
/// # Errors
///
/// [`TemplateError::Invalid`] if `registry_did` is not a DID. An https URL
/// here would render an entry that reads as an *endpoint* — this community
/// advertising a TRQP surface it does not serve — rather than a referral.
pub fn referral_service(registry_did: &str) -> Result<Value, TemplateError> {
    let registry_did = registry_did.trim();
    if !registry_did.starts_with("did:") {
        return Err(TemplateError::Invalid(format!(
            "trust-registry referral must name the registry by DID, got '{registry_did}'. \
             A referral's `uri` is tested for a `did:` prefix by consumers; an https URL \
             would be read as this community serving TRQP itself."
        )));
    }

    Ok(json!({
        "id": format!("{{DID}}{SERVICE_ID_FRAGMENT}"),
        "type": TRUST_REGISTRY_SERVICE_TYPE,
        "serviceEndpoint": {
            "uri": registry_did,
            "profile": TRQP_PROFILE_URI,
        }
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn builds_the_referral_shape_the_profile_spec_defines() {
        let entry = referral_service("did:webvh:abc:registry.example.com").unwrap();
        assert_eq!(entry["id"], "{DID}#trust-registry");
        assert_eq!(entry["type"], TRUST_REGISTRY_SERVICE_TYPE);
        assert_eq!(
            entry["serviceEndpoint"]["uri"],
            "did:webvh:abc:registry.example.com"
        );
        assert_eq!(entry["serviceEndpoint"]["profile"], TRQP_PROFILE_URI);
    }

    /// The endpoint is a `{uri, profile}` struct, never a bare string — the
    /// Service Profile spec's own text rules out an array of structs, and a
    /// bare string would lose the profile.
    #[test]
    fn endpoint_is_a_struct_not_a_string() {
        let entry = referral_service("did:key:z6Mk").unwrap();
        assert!(entry["serviceEndpoint"].is_object());
    }

    #[test]
    fn an_https_uri_is_refused_because_it_would_read_as_an_endpoint() {
        let err = referral_service("https://registry.example.com").unwrap_err();
        assert!(
            matches!(err, TemplateError::Invalid(ref m) if m.contains("did:")),
            "got: {err}"
        );
    }

    #[test]
    fn surrounding_whitespace_does_not_defeat_the_did_check() {
        let entry = referral_service("  did:webvh:abc:registry.example.com  ").unwrap();
        assert_eq!(
            entry["serviceEndpoint"]["uri"], "did:webvh:abc:registry.example.com",
            "the trimmed DID is what lands in the document"
        );
    }

    #[test]
    fn an_empty_registry_did_is_refused() {
        assert!(referral_service("").is_err());
    }
}
