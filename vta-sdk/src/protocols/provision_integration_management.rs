//! DIDComm protocol for `provision-integration`.
//!
//! Carries a VP-framed [`crate::provision_integration::BootstrapRequest`]
//! to the VTA in an authcrypt'd DIDComm message; receives the sealed
//! `TemplateBootstrap` bundle back in an authcrypt'd reply.
//!
//! Auth model: DIDComm authcrypt is the auth — the VTA reads `from`
//! as the authenticated sender DID and ACL-checks it (must hold admin
//! role in the target context). The VP's `DataIntegrityProof` is the
//! second proof; both must agree (`from == VP holder`) for the
//! handler to proceed.
//!
//! Both parties exchange the same on-the-wire shapes the REST endpoint
//! at `POST /bootstrap/provision-integration` does — wire format is
//! transport-neutral. See
//! [`crate::provision_integration::http::ProvisionIntegrationRequest`]
//! and [`crate::provision_integration::http::ProvisionIntegrationResponse`].
//!
//! Two URI shapes are accepted on the wire, both routed to the same
//! handler:
//!
//! * The legacy FPN-private URI ([`PROVISION_INTEGRATION`]) — what every
//!   existing client targets today.
//! * The canonical Trust Task URI
//!   ([`CANONICAL_PROVISION_INTEGRATION`]) — landed in
//!   `dtgwg-trust-tasks-tf` PR #51 as
//!   `https://trusttasks.org/spec/provision/integration/0.1`. Clients
//!   migrating to the canonical registry target this URI.
//!
//! The handler emits the response under whichever URI the request came
//! in with — a caller using the canonical URI receives a canonical
//! response (`#response` fragment), a caller using the FPN URI receives
//! the legacy `…-result` URI. That keeps both clients working without
//! either having to know about the other.

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/provision-integration/1.0";

/// Inbound VP + provisioning options. Legacy FPN-private URI.
pub const PROVISION_INTEGRATION: &str =
    "https://firstperson.network/protocols/provision-integration/1.0/provision-integration";

/// Outbound sealed bundle + summary. Legacy FPN-private URI.
pub const PROVISION_INTEGRATION_RESULT: &str =
    "https://firstperson.network/protocols/provision-integration/1.0/provision-integration-result";

/// Inbound VP + provisioning options — canonical Trust Task URI. Same
/// wire body as [`PROVISION_INTEGRATION`]; accepting both is the spec
/// migration step #51 of `dtgwg-trust-tasks-tf` set up.
pub const CANONICAL_PROVISION_INTEGRATION: &str =
    "https://trusttasks.org/spec/provision/integration/0.1";

/// Outbound sealed bundle + summary — canonical Trust Task URI.
/// Per SPEC.md §4.4.1 of `dtgwg-trust-tasks-tf`, success responses are
/// emitted under the request URI with a `#response` fragment.
pub const CANONICAL_PROVISION_INTEGRATION_RESULT: &str =
    "https://trusttasks.org/spec/provision/integration/0.1#response";

/// Match the result URI to whichever request URI the caller used.
/// Centralised here so the routing decision lives next to the URI
/// constants — handlers downstream just call this and don't need to
/// know which URIs are alias-equivalent.
pub fn result_uri_for(request_uri: &str) -> &'static str {
    if request_uri == CANONICAL_PROVISION_INTEGRATION {
        CANONICAL_PROVISION_INTEGRATION_RESULT
    } else {
        // Default to the legacy URI for any URI that's not the canonical
        // one. Today the only other accepted shape is the FPN-private
        // URI; future additions widen this match.
        PROVISION_INTEGRATION_RESULT
    }
}

pub mod request {
    //! Body shape for the inbound DIDComm message.
    //!
    //! Equivalent to [`crate::provision_integration::http::ProvisionIntegrationRequest`]
    //! — same field semantics, same JSON layout.
    pub use crate::provision_integration::http::{AssertionMode, ProvisionIntegrationRequest};
}

pub mod result {
    //! Body shape for the reply DIDComm message.
    //!
    //! Equivalent to [`crate::provision_integration::http::ProvisionIntegrationResponse`].
    pub use crate::provision_integration::http::{ProvisionIntegrationResponse, ProvisionSummary};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_uri_for_canonical_request_emits_canonical_response() {
        assert_eq!(
            result_uri_for(CANONICAL_PROVISION_INTEGRATION),
            CANONICAL_PROVISION_INTEGRATION_RESULT
        );
    }

    #[test]
    fn result_uri_for_legacy_request_emits_legacy_response() {
        assert_eq!(
            result_uri_for(PROVISION_INTEGRATION),
            PROVISION_INTEGRATION_RESULT
        );
    }

    /// Unknown / future URIs default to the legacy result URI.  The router
    /// only advertises the two URIs we know about, so this branch is
    /// unreachable in production — but exercising it pins the fallback so
    /// a future widening doesn't silently change the default response
    /// shape for an already-deployed client.
    #[test]
    fn result_uri_for_unknown_request_defaults_to_legacy() {
        assert_eq!(
            result_uri_for("https://example.invalid/something-else"),
            PROVISION_INTEGRATION_RESULT
        );
    }

    /// The canonical Trust Task URI MUST be exactly the value declared in
    /// `dtgwg-trust-tasks-tf` PR #51's `payload.schema.json` `$id`. Pin
    /// the string so a refactor here can't drift away from the registry.
    #[test]
    fn canonical_uri_matches_registry() {
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION,
            "https://trusttasks.org/spec/provision/integration/0.1"
        );
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION_RESULT,
            "https://trusttasks.org/spec/provision/integration/0.1#response"
        );
    }
}
