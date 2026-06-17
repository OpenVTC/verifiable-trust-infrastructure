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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    ///
    /// Emitted snake_case (0.1 wire form); the `vcValiditySeconds` alias
    /// accepts the `provision/integration/0.2` camelCase wire form on intake.
    /// Dual-accept keeps a spec-0.2 producer working without a breaking
    /// emission change (issue #517).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "vcValiditySeconds"
    )]
    pub vc_validity_seconds: Option<i64>,
    /// Create the target context as part of provisioning if it
    /// doesn't already exist. Requires **super-admin** on the VTA;
    /// context-admin callers get `Forbidden` against a missing
    /// context. Idempotent when the context already exists.
    /// Defaults to `false` for compatibility with older clients.
    ///
    /// Emitted snake_case; the `createContext` alias accepts the
    /// `provision/integration/0.2` camelCase form on intake (issue #517).
    #[serde(default, skip_serializing_if = "is_false", alias = "createContext")]
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionIntegrationResponse {
    /// Armored sealed bundle.
    pub bundle: String,
    /// SHA-256 digest of the sealed ciphertext (lowercase hex).
    pub digest: String,
    pub summary: ProvisionSummary,
}

/// Emitted snake_case (0.1 wire form). Each field also carries a camelCase
/// `alias` so a `provision/integration/0.2` (lowerCamelCase) producer's
/// summary deserializes too — backwards-compatible dual-accept; emission is
/// unchanged so existing snake_case consumers are unaffected (issue #517).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionSummary {
    /// Ephemeral DID that signed the VP and opens the sealed bundle.
    #[serde(alias = "clientDid")]
    pub client_did: String,
    /// Long-term admin DID — equals `client_did` when no rollover, or
    /// the VTA-minted DID when the request carried an `adminTemplate`
    /// (or used `AdminRotation`). Older VTAs that pre-date admin
    /// rollover omit this field on the wire; we default it to
    /// `client_did` for backward compat.
    #[serde(default, alias = "adminDid")]
    pub admin_did: String,
    /// True when the VTA minted a fresh long-term admin DID for this
    /// provisioning. Defaults to `false` for backward compatibility
    /// with VTAs that pre-date admin rollover.
    #[serde(default, alias = "adminRolledOver")]
    pub admin_rolled_over: bool,
    /// Integration DID rendered from the integration template. `None`
    /// for the `AdminRotation` ask — that flow only mints an admin
    /// DID and does not produce an integration DID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "integrationDid"
    )]
    pub integration_did: Option<String>,
    /// Name of the integration template that was rendered. `None` for
    /// the `AdminRotation` ask.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "templateName"
    )]
    pub template_name: Option<String>,
    /// `kind` field of the integration template. `None` for the
    /// `AdminRotation` ask.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "templateKind"
    )]
    pub template_kind: Option<String>,
    /// Name of the admin template, when one was used (i.e. the
    /// request used `adminTemplate` rollover *or* the `AdminRotation`
    /// ask).
    #[serde(default, alias = "adminTemplateName")]
    pub admin_template_name: Option<String>,
    #[serde(alias = "bundleIdHex")]
    pub bundle_id_hex: String,
    #[serde(alias = "secretCount")]
    pub secret_count: usize,
    #[serde(alias = "outputCount")]
    pub output_count: usize,
    /// Resolved id of the registered webvh hosting server the VTA
    /// published the integration's `did.jsonl` to. `None` (default)
    /// means self-hosted at the URL — i.e. no `WEBVH_SERVER` template
    /// var was set, or it was explicitly null. Older VTAs that
    /// pre-date this field omit it on the wire; deserialize as `None`.
    #[serde(default, alias = "webvhServerId")]
    pub webvh_server_id: Option<String>,
    /// `true` when the target context didn't exist before this call
    /// and was created inline because the caller passed
    /// `create_context: true`. `false` when the context already
    /// existed (or `create_context` was `false`). Lets operators
    /// see whether `--create-context` actually did something.
    /// Defaults to `false` on the wire for backward compatibility.
    #[serde(default, alias = "contextCreated")]
    pub context_created: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #517: a `provision/integration/0.2` producer sends lowerCamelCase
    /// field + assertion values. The shared request struct must accept both
    /// the legacy snake_case (0.1) and the camelCase (0.2) forms; emission
    /// stays snake_case so existing servers/clients are unaffected.
    ///
    /// Builds a real VP-framed [`BootstrapRequest`] (the `request` field has
    /// `deny_unknown_fields`), then wraps it with the two option-field casings.
    #[tokio::test]
    async fn request_accepts_both_camel_and_snake_case() {
        use crate::provision_integration::ProvisionRequestBuilder;

        let (seed, pub_bytes) = crate::sealed_transfer::generate_ed25519_keypair();
        let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        let vp = ProvisionRequestBuilder::new("didcomm-mediator")
            .sign_with(&seed, &client_did)
            .await
            .expect("sign VP");
        let request_json = serde_json::to_value(&vp).expect("serialize VP");

        // camelCase (0.2) option fields + assertion.
        let camel = serde_json::json!({
            "request": request_json,
            "assertion": "pinnedOnly",
            "vcValiditySeconds": 3600,
            "createContext": true,
        });
        let req: ProvisionIntegrationRequest = serde_json::from_value(camel).expect("camelCase");
        assert!(matches!(req.assertion, Some(AssertionMode::PinnedOnly)));
        assert_eq!(req.vc_validity_seconds, Some(3600));
        assert!(req.create_context);

        // snake_case (0.1) option fields + assertion.
        let snake = serde_json::json!({
            "request": request_json,
            "assertion": "did-signed",
            "vc_validity_seconds": 60,
            "create_context": false,
        });
        let req: ProvisionIntegrationRequest = serde_json::from_value(snake).expect("snake_case");
        assert!(matches!(req.assertion, Some(AssertionMode::DidSigned)));
        assert_eq!(req.vc_validity_seconds, Some(60));
        assert!(!req.create_context);

        // Emission stays snake_case (conservative).
        let out = serde_json::to_value(&req).unwrap();
        assert!(out.get("vc_validity_seconds").is_some());
        assert!(out.get("vcValiditySeconds").is_none());
    }

    /// The summary deserializes from a camelCase (0.2) producer too, while
    /// still emitting snake_case for existing consumers.
    #[test]
    fn summary_accepts_camel_case() {
        let camel = r#"{
            "clientDid": "did:key:zClient",
            "adminDid": "did:key:zAdmin",
            "adminRolledOver": true,
            "integrationDid": "did:webvh:x",
            "templateName": "did-host-http",
            "templateKind": "did-hosting-server",
            "bundleIdHex": "deadbeef",
            "secretCount": 2,
            "outputCount": 1,
            "webvhServerId": "srv-1",
            "contextCreated": true
        }"#;
        let s: ProvisionSummary = serde_json::from_str(camel).expect("camelCase summary");
        assert_eq!(s.client_did, "did:key:zClient");
        assert_eq!(s.admin_did, "did:key:zAdmin");
        assert!(s.admin_rolled_over);
        assert_eq!(s.integration_did.as_deref(), Some("did:webvh:x"));
        assert_eq!(s.secret_count, 2);
        assert!(s.context_created);

        let out = serde_json::to_value(&s).unwrap();
        assert!(out.get("client_did").is_some());
        assert!(out.get("clientDid").is_none());
    }
}
