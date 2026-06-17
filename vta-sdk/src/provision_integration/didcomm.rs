//! DIDComm transport for `provision-integration`.
//!
//! Holder side. Sends a VP-framed [`super::BootstrapRequest`] over an
//! authcrypt'd DIDComm session and receives the sealed
//! `TemplateBootstrap` bundle in the reply. Wire shapes are
//! transport-neutral — the payload that arrives is the same armored
//! bundle the REST endpoint returns.
//!
//! Use this when the holder already has a DIDComm session open to the
//! VTA (e.g., the integration's setup wizard). For file-based offline
//! bootstrap, use the `vta bootstrap provision-integration` CLI on the
//! VTA host.
//!
//! Auth model — layered like an onion. The DIDComm authcrypt
//! sender authenticates the *relayer* and is gated by the VTA's
//! ACL (sender must be admin in the target context). Inside the
//! body, the VP's `DataIntegrityProof` authenticates the *holder*
//! — the bundle is HPKE-sealed to the holder's X25519 derivation,
//! so only the holder can open it. Sender and holder may legitimately
//! differ; the air-gap onboarding flow relies on this:
//!
//!   1. Third-party integration (air-gapped) signs a BootstrapRequest
//!      with its own ephemeral did:key.
//!   2. Request is transferred to the operator's host.
//!   3. Operator's PNM relays the request over its DIDComm session.
//!   4. VTA issues the bundle, sealed to the integration.
//!   5. Operator carries the (encrypted) bundle back across the
//!      air-gap; only the integration can decrypt.

use crate::didcomm_session::DIDCommSession;
use crate::error::VtaError;
use crate::protocols::provision_integration_management::{
    ProvisionSpecVersion, request_body_for_version, result_uri_for,
};

use super::BootstrapRequest;
use super::http::{AssertionMode, ProvisionIntegrationRequest, ProvisionIntegrationResponse};

/// Default DIDComm round-trip timeout (seconds). Generous so the VTA
/// has time to mint keys, render templates, build the webvh log, and
/// seal the bundle — all of which happen synchronously inside the
/// shared library function before the reply lands.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Send a `provision-integration` request over an existing DIDComm
/// session.
///
/// The holder must have an authcrypt'd DIDComm session open to the
/// VTA — see [`DIDCommSession::connect`]. The session's `client_did`
/// must already hold admin role in the target context's ACL; the VTA
/// rejects with `Forbidden` (mapped to [`VtaError::Auth`]) otherwise.
///
/// Returns the same shape the REST endpoint produces: armored sealed
/// bundle + sha256 digest + summary (including `admin_did` /
/// `admin_rolled_over` when the VP requested rollover via
/// `adminTemplate`).
///
/// `assertion` defaults to [`AssertionMode::DidSigned`] when `None`.
///
/// `create_context` opts into super-admin context creation when the
/// target context isn't yet registered — same semantics as the REST
/// path. Default is `false` (caller must have created the context
/// out-of-band).
///
/// `context` is `Option<String>`. Pass `Some(name)` for the
/// integration-class pattern (caller knows which bucket to provision
/// into); pass `None` to let the VTA infer per the canonical Trust
/// Task spec's three rules — typical for wallet-class callers that
/// don't track the maintainer's context layout. See
/// [`crate::provision_integration::http::ProvisionIntegrationRequest::context`]
/// for the full inference rules + error semantics.
///
/// `spec_version` selects the Trust Task wire version. [`ProvisionSpecVersion::V0_1`]
/// emits the legacy snake_case option fields + kebab `assertion` under the
/// `provision/integration/0.1` URI; [`ProvisionSpecVersion::V0_2`] emits
/// lowerCamelCase (`vcValiditySeconds` / `createContext` / `didSigned`) under
/// the `0.2` URI. The signed VP carried in `request` is left byte-identical
/// either way — its casing is the holder's, and the VTA dual-accepts both.
pub async fn provision_integration_didcomm(
    session: &DIDCommSession,
    request: BootstrapRequest,
    context: Option<String>,
    assertion: Option<AssertionMode>,
    vc_validity_seconds: Option<i64>,
    create_context: bool,
    spec_version: ProvisionSpecVersion,
) -> Result<ProvisionIntegrationResponse, VtaError> {
    // No "session DID must equal VP holder" pre-check. The flow is
    // intentionally layered (outer authcrypt = relayer, inner VP =
    // holder); see the module-level docs for the air-gap rationale.
    let body_struct = ProvisionIntegrationRequest {
        request,
        context,
        assertion,
        vc_validity_seconds,
        create_context,
    };
    let request_uri = spec_version.request_uri();
    let body = request_body_for_version(&body_struct, request_uri).map_err(VtaError::from)?;

    session
        .send_and_wait::<ProvisionIntegrationResponse>(
            request_uri,
            body,
            result_uri_for(request_uri),
            DEFAULT_TIMEOUT_SECS,
        )
        .await
}
