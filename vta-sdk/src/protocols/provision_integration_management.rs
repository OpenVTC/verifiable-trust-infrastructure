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
//! Two canonical Trust Task URI versions are accepted on the wire, both
//! routed to the same handler:
//!
//! * [`CANONICAL_PROVISION_INTEGRATION`] — `provision/integration/0.1`,
//!   landed in `dtgwg-trust-tasks-tf` PR #51.
//! * [`CANONICAL_PROVISION_INTEGRATION_0_2`] —
//!   `provision/integration/0.2`. Same VP/bundle wire body; the 0.2 delta
//!   is camelCase enum casing (e.g. the VP's `ask.type`), which the typed
//!   verifier accommodates by checking the proof over the bytes as
//!   received — see
//!   [`crate::provision_integration::BootstrapRequest::verify_value`].
//!
//! The handler emits the response under whichever version the request
//! came in with — a 0.1 request gets the `0.1#response` URI, a 0.2 request
//! the `0.2#response` URI — so both clients work without either knowing
//! about the other.
//!
//! The legacy `firstperson.network` provision-integration URI was retired
//! once consumers (the browser plugin, the Rust CLIs) moved to the
//! canonical registry. The other `firstperson.network` management
//! protocols are unaffected.

/// Inbound VP + provisioning options — canonical Trust Task URI, v0.1.
pub const CANONICAL_PROVISION_INTEGRATION: &str =
    "https://trusttasks.org/spec/provision/integration/0.1";

/// Outbound sealed bundle + summary — canonical Trust Task URI, v0.1.
/// Per SPEC.md §4.4.1 of `dtgwg-trust-tasks-tf`, success responses are
/// emitted under the request URI with a `#response` fragment.
pub const CANONICAL_PROVISION_INTEGRATION_RESULT: &str =
    "https://trusttasks.org/spec/provision/integration/0.1#response";

/// Inbound VP + provisioning options — canonical Trust Task URI, v0.2.
/// Same wire body as v0.1; the 0.2 spec uses camelCase enum casing
/// (notably the signed VP's `ask.type`). Verification runs over the
/// as-received bytes so the holder's casing survives.
pub const CANONICAL_PROVISION_INTEGRATION_0_2: &str =
    "https://trusttasks.org/spec/provision/integration/0.2";

/// Outbound sealed bundle + summary — canonical Trust Task URI, v0.2.
pub const CANONICAL_PROVISION_INTEGRATION_0_2_RESULT: &str =
    "https://trusttasks.org/spec/provision/integration/0.2#response";

/// Match the result URI to whichever request URI the caller used.
/// Centralised here so the routing decision lives next to the URI
/// constants — handlers downstream just call this. The 0.2 request URI
/// maps to the 0.2 `#response`; the 0.1 request URI (the only other shape
/// the router advertises) maps to the 0.1 `#response`.
pub fn result_uri_for(request_uri: &str) -> &'static str {
    if request_uri == CANONICAL_PROVISION_INTEGRATION_0_2 {
        CANONICAL_PROVISION_INTEGRATION_0_2_RESULT
    } else {
        CANONICAL_PROVISION_INTEGRATION_RESULT
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
    fn result_uri_for_v0_1_request_emits_v0_1_response() {
        assert_eq!(
            result_uri_for(CANONICAL_PROVISION_INTEGRATION),
            CANONICAL_PROVISION_INTEGRATION_RESULT
        );
    }

    #[test]
    fn result_uri_for_v0_2_request_emits_v0_2_response() {
        assert_eq!(
            result_uri_for(CANONICAL_PROVISION_INTEGRATION_0_2),
            CANONICAL_PROVISION_INTEGRATION_0_2_RESULT
        );
    }

    /// Unknown / future URIs default to the 0.1 result URI. The router
    /// only advertises the 0.1 and 0.2 URIs, so this branch is unreachable
    /// in production — but exercising it pins the fallback so a future
    /// widening doesn't silently change the default response shape.
    #[test]
    fn result_uri_for_unknown_request_defaults_to_v0_1() {
        assert_eq!(
            result_uri_for("https://example.invalid/something-else"),
            CANONICAL_PROVISION_INTEGRATION_RESULT
        );
    }

    /// The canonical Trust Task URIs MUST be exactly the values declared
    /// in `dtgwg-trust-tasks-tf`'s `payload.schema.json` `$id`. Pin the
    /// strings so a refactor here can't drift away from the registry.
    #[test]
    fn canonical_uris_match_registry() {
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION,
            "https://trusttasks.org/spec/provision/integration/0.1"
        );
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION_RESULT,
            "https://trusttasks.org/spec/provision/integration/0.1#response"
        );
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION_0_2,
            "https://trusttasks.org/spec/provision/integration/0.2"
        );
        assert_eq!(
            CANONICAL_PROVISION_INTEGRATION_0_2_RESULT,
            "https://trusttasks.org/spec/provision/integration/0.2#response"
        );
    }
}
