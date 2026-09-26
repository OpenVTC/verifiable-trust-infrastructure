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
//! Auth model — layered like an onion. The request is a Trust Task
//! document carried in the DIDComm binding envelope and signed by the
//! *relayer* (the session's DID): that Data Integrity proof, bound to the
//! document's `issuer` and the DIDComm sender, authenticates the relayer,
//! and the VTA's ACL gates it (relayer must be admin in the target
//! context). The DIDComm sender alone authenticates nobody. Inside the
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
    ProvisionSpecVersion, request_body_for_version,
};

use serde_json::Value;

use super::http::{
    AdminScope, AssertionMode, ProvisionIntegrationRequest, ProvisionIntegrationResponse,
};

/// Default DIDComm round-trip timeout (seconds). Generous so the VTA
/// has time to mint keys, render templates, build the webvh log, and
/// seal the bundle — all of which happen synchronously inside the
/// shared library function before the reply lands.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// The DIDComm binding envelope — the only DIDComm carriage for a Trust Task.
const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

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
/// `spec_version` selects the Trust Task wire version, and a caller in this
/// workspace passes [`ProvisionSpecVersion::CURRENT`] — the VTA serves exactly
/// one version of this operation at a time. The older variants remain callable
/// because they still describe wire forms this crate can *render*, which is
/// what makes them testable: [`ProvisionSpecVersion::V0_1`] emits the legacy
/// snake_case option fields + kebab `assertion` under the
/// `provision/integration/0.1` URI, and [`ProvisionSpecVersion::V0_2`] emits
/// lowerCamelCase (`vcValiditySeconds` / `createContext` / `didSigned`) under
/// the `0.2` URI. Neither is dispatchable against a current VTA — both were
/// removed rather than deprecated, so they come back `unsupportedType`.
/// The signed VP carried in `request` is left byte-identical
/// either way — its casing is the holder's, and the VTA dual-accepts both.
/// That is why `request` is a raw [`Value`] and not a typed
/// [`BootstrapRequest`](super::BootstrapRequest): the claim above was
/// false while this took the
/// struct, because serialising it re-rendered the holder's document in
/// this crate's casing.
pub async fn provision_integration_didcomm(
    session: &DIDCommSession,
    relayer_key: &crate::trust_task_sign::HolderKey,
    request: Value,
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
        // Always the default. This helper drives *integration-class*
        // provisioning — a mediator, a DID-hosting control plane — which acts
        // in the context it was provisioned into and nowhere else. The
        // unrestricted scope exists for an operator console, which reaches
        // this task over the Trust-Task spine rather than through this
        // client; if that ever changes, this becomes a parameter, not a
        // default someone flipped.
        admin_scope: AdminScope::default(),
    };
    let request_uri = spec_version.request_uri();
    let body = request_body_for_version(&body_struct, request_uri).map_err(VtaError::from)?;

    send_signed_task(
        session,
        relayer_key,
        request_uri,
        body,
        DEFAULT_TIMEOUT_SECS,
    )
    .await
}

/// Send one Trust Task over a raw [`DIDCommSession`]: the document is issued by
/// the session's DID, addressed to its VTA, signed with `key`, carried in the
/// DIDComm binding envelope, and the reply's `payload` is decoded as `T`.
///
/// The signature is what identifies the caller: the VTA refuses any document
/// over DIDComm whose proof, `issuer` and sender are not one DID.
pub(crate) async fn send_signed_task<T: serde::de::DeserializeOwned>(
    session: &DIDCommSession,
    key: &crate::trust_task_sign::HolderKey,
    type_uri: &str,
    payload: Value,
    timeout_secs: u64,
) -> Result<T, VtaError> {
    let mut doc = crate::trust_task_sign::build_unsigned(
        type_uri,
        payload,
        session.client_did(),
        &session.vta_did,
    )
    .map_err(|e| VtaError::Protocol(format!("could not build `{type_uri}`: {e}")))?;
    crate::trust_task_sign::sign_in_place_with(&mut doc, key)
        .await
        .map_err(|e| VtaError::Protocol(format!("could not sign `{type_uri}`: {e}")))?;
    let doc = serde_json::to_value(&doc).map_err(VtaError::from)?;
    let reply: Value = session
        .send_and_wait(
            TRUST_TASK_ENVELOPE_TYPE,
            doc,
            TRUST_TASK_ENVELOPE_TYPE,
            timeout_secs,
        )
        .await?;
    let payload = crate::client::VtaClient::extract_trust_task_payload(reply)?;
    serde_json::from_value(payload)
        .map_err(|e| VtaError::Protocol(format!("`{type_uri}` response decode: {e}")))
}
