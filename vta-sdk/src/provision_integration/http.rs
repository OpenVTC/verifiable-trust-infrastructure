//! Wire types for `POST /bootstrap/provision-integration`.
//!
//! Mirrors the shape of
//! `vta-service::routes::bootstrap::provision::*` on the client side,
//! so `VtaClient::provision_integration` consumers don't need to
//! depend on vta-service.

use serde::{Deserialize, Serialize};

use super::BootstrapRequest;

/// Request body. Used by both transports — REST clients serialize and
/// the DIDComm provision-integration handler (`vta-service`) deserializes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionIntegrationRequest {
    /// The integration's VP-framed bootstrap request (signed by its
    /// ephemeral `client_did`). The caller sends it unverified — the
    /// server verifies on intake.
    pub request: BootstrapRequest,
    /// VTA context to provision into.
    ///
    /// **Optional** per the canonical Trust Task spec
    /// (`https://trusttasks.org/spec/provision/integration/0.1`). When
    /// absent, the maintainer infers the target context using these
    /// rules in order:
    ///
    /// 1. If the relayer's ACL grant scopes to exactly one context →
    ///    use that context.
    /// 2. If the relayer is a super-admin (Admin role with empty
    ///    `allowed_contexts`) AND the maintainer has exactly one
    ///    context registered → use it.
    /// 3. Otherwise the maintainer refuses with
    ///    `provision/integration:context_required` and `details.
    ///    candidates: Vec<String>` listing the plausible contexts.
    ///
    /// Wallet-class consumers SHOULD omit; integration-class consumers
    /// SHOULD send explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Optional — default `did-signed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<AssertionMode>,
    /// Optional override for the VC's validity window (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vc_validity_seconds: Option<i64>,
    /// Create the target context as part of provisioning if it
    /// doesn't already exist. Requires **super-admin** on the VTA;
    /// context-admin callers get `Forbidden` against a missing
    /// context. Idempotent when the context already exists.
    /// Defaults to `false` for compatibility with older clients.
    #[serde(default, skip_serializing_if = "is_false")]
    pub create_context: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Producer assertion mode on the returned sealed bundle. Mirrors the
/// server's `AssertionMode`.
///
/// Serialises kebab-case (`did-signed` / `pinned-only`, the 0.1 wire
/// form). The camelCase aliases accept the `provision/integration/0.2`
/// wire form (`didSigned` / `pinnedOnly`) on the way in. This field is
/// outside the signed VP, so an alias is sufficient — no as-received
/// verification needed.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssertionMode {
    #[default]
    #[serde(alias = "didSigned")]
    DidSigned,
    #[serde(alias = "pinnedOnly")]
    PinnedOnly,
}

/// Response body. Used by both transports — REST handlers serialize
/// and the DIDComm provision-integration client (`vta-sdk`)
/// deserializes the result message body.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionIntegrationResponse {
    /// Armored sealed bundle.
    pub bundle: String,
    /// SHA-256 digest of the sealed ciphertext (lowercase hex).
    pub digest: String,
    pub summary: ProvisionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProvisionSummary {
    /// Ephemeral DID that signed the VP and opens the sealed bundle.
    pub client_did: String,
    /// Long-term admin DID — equals `client_did` when no rollover, or
    /// the VTA-minted DID when the request carried an `adminTemplate`
    /// (or used `AdminRotation`). Older VTAs that pre-date admin
    /// rollover omit this field on the wire; we default it to
    /// `client_did` for backward compat.
    #[serde(default)]
    pub admin_did: String,
    /// True when the VTA minted a fresh long-term admin DID for this
    /// provisioning. Defaults to `false` for backward compatibility
    /// with VTAs that pre-date admin rollover.
    #[serde(default)]
    pub admin_rolled_over: bool,
    /// Integration DID rendered from the integration template. `None`
    /// for the `AdminRotation` ask — that flow only mints an admin
    /// DID and does not produce an integration DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_did: Option<String>,
    /// Name of the integration template that was rendered. `None` for
    /// the `AdminRotation` ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_name: Option<String>,
    /// `kind` field of the integration template. `None` for the
    /// `AdminRotation` ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_kind: Option<String>,
    /// Name of the admin template, when one was used (i.e. the
    /// request used `adminTemplate` rollover *or* the `AdminRotation`
    /// ask).
    #[serde(default)]
    pub admin_template_name: Option<String>,
    pub bundle_id_hex: String,
    pub secret_count: usize,
    pub output_count: usize,
    /// Resolved id of the registered webvh hosting server the VTA
    /// published the integration's `did.jsonl` to. `None` (default)
    /// means self-hosted at the URL — i.e. no `WEBVH_SERVER` template
    /// var was set, or it was explicitly null. Older VTAs that
    /// pre-date this field omit it on the wire; deserialize as `None`.
    #[serde(default)]
    pub webvh_server_id: Option<String>,
    /// `true` when the target context didn't exist before this call
    /// and was created inline because the caller passed
    /// `create_context: true`. `false` when the context already
    /// existed (or `create_context` was `false`). Lets operators
    /// see whether `--create-context` actually did something.
    /// Defaults to `false` on the wire for backward compatibility.
    #[serde(default)]
    pub context_created: bool,
}
