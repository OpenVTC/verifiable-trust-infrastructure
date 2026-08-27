//! Wire types for `POST /bootstrap/provision-integration`.
//!
//! Mirrors the shape of
//! `vta-service::routes::bootstrap::provision::*` on the client side,
//! so `VtaClient::provision_integration` consumers don't need to
//! depend on vta-service.

use serde::{Deserialize, Serialize};

/// Request body. Used by both transports — REST clients serialize and
/// the DIDComm provision-integration handler (`vta-service`) deserializes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionIntegrationRequest {
    /// The integration's VP-framed bootstrap request (signed by its
    /// ephemeral `client_did`). The caller sends it unverified — the
    /// server verifies on intake.
    ///
    /// Raw JSON, **not** a typed [`BootstrapRequest`](super::BootstrapRequest).
    /// A relayer is
    /// usually not the holder — the air-gap flow exists precisely so it
    /// isn't — so this field routinely carries a document some other
    /// process signed. Holding it typed meant serialising this struct
    /// re-rendered that document with this crate's casing, and the
    /// maintainer verified bytes the holder never signed. Build it from
    /// [`to_signed_wire_value`](super::BootstrapRequest::to_signed_wire_value)
    /// when this process did
    /// the signing, or pass the received JSON through untouched when it
    /// didn't.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub request: serde_json::Value,
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
    ///    `provision/integration:contextRequired` and `details.
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
    /// Emitted camelCase — the canonical `provision/integration/0.2` wire
    /// form, which is the only URI the dispatcher still binds (#857). The
    /// snake_case alias keeps accepting the legacy 0.1 spelling on intake
    /// (dual-accept per #517, direction reversed).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "vcValiditySeconds",
        alias = "vc_validity_seconds"
    )]
    pub vc_validity_seconds: Option<i64>,
    /// Create the target context as part of provisioning if it
    /// doesn't already exist. Requires **super-admin** on the VTA;
    /// context-admin callers get `Forbidden` against a missing
    /// context. Idempotent when the context already exists.
    /// Defaults to `false` for compatibility with older clients.
    ///
    /// Emitted camelCase (the canonical 0.2 wire form, #857); the
    /// snake_case alias accepts the legacy 0.1 spelling on intake (#517).
    #[serde(
        default,
        skip_serializing_if = "is_false",
        rename = "createContext",
        alias = "create_context"
    )]
    pub create_context: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Producer assertion mode on the returned sealed bundle. Mirrors the
/// server's `AssertionMode`.
///
/// Serialises camelCase (`didSigned` / `pinnedOnly`) — the canonical
/// `provision/integration/0.2` enum vocabulary, which is the only URI the
/// dispatcher still binds (#857). The kebab-case aliases keep accepting the
/// legacy 0.1 wire form (`did-signed` / `pinned-only`) on the way in. This
/// field is outside the signed VP, so an alias is sufficient — no
/// as-received verification needed.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum AssertionMode {
    #[default]
    #[serde(alias = "did-signed")]
    DidSigned,
    #[serde(alias = "pinned-only")]
    PinnedOnly,
}

/// Response body. Used by both transports — REST handlers serialize
/// and the DIDComm provision-integration client (`vta-sdk`)
/// deserializes the result message body.
/// `rename_all` is on the struct rather than on the one field that needs it.
/// Every member was a single word until `digestMultibase`, so nothing here had
/// ever exercised the casing — and the first multi-word field went out as
/// `digest_multibase`, which `additionalProperties: false` rejects. Naming the
/// rule once means the next multi-word member cannot repeat that.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionIntegrationResponse {
    /// Armored sealed bundle.
    pub bundle: String,
    /// Digest over the armored ciphertext, for a holder that pins the bundle
    /// out-of-band.
    ///
    /// A multibase multihash as of `provision/integration/0.3`, where it
    /// replaced the bare-hex `digest`: multihash names its own algorithm, so
    /// moving off SHA-256 is a change of value rather than of schema. OPTIONAL
    /// — a holder that does not pin does not need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_multibase: Option<String>,
    pub summary: ProvisionSummary,
}

/// Emitted lowerCamelCase — the canonical `provision/integration/0.2` wire
/// form (`additionalProperties: false`, so the schema rejects any other
/// spelling; #857). Each field carries a snake_case `alias` so a legacy 0.1
/// producer's summary still deserializes (dual-accept per #517, direction
/// reversed now that 0.2 is the only URI the dispatcher binds).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionSummary {
    /// Ephemeral DID that signed the VP and opens the sealed bundle.
    #[serde(alias = "client_did")]
    pub client_did: String,
    /// Long-term admin DID — equals `client_did` when no rollover, or
    /// the VTA-minted DID when the request carried an `adminTemplate`
    /// (or used `AdminRotation`). Older VTAs that pre-date admin
    /// rollover omit this field on the wire; we default it to
    /// `client_did` for backward compat.
    #[serde(default, alias = "admin_did")]
    pub admin_did: String,
    /// True when the VTA minted a fresh long-term admin DID for this
    /// provisioning. Defaults to `false` for backward compatibility
    /// with VTAs that pre-date admin rollover.
    #[serde(default, alias = "admin_rolled_over")]
    pub admin_rolled_over: bool,
    /// Integration DID rendered from the integration template. `None`
    /// for the `AdminRotation` ask — that flow only mints an admin
    /// DID and does not produce an integration DID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "integration_did"
    )]
    pub integration_did: Option<String>,
    /// Name of the integration template that was rendered. `None` for
    /// the `AdminRotation` ask.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "template_name"
    )]
    pub template_name: Option<String>,
    /// `kind` field of the integration template. `None` for the
    /// `AdminRotation` ask.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "template_kind"
    )]
    pub template_kind: Option<String>,
    /// Name of the admin template, when one was used (i.e. the
    /// request used `adminTemplate` rollover *or* the `AdminRotation`
    /// ask).
    ///
    /// Omitted rather than sent as `null`: the schema types it `string`, and
    /// its three `Option<String>` siblings above already skip. It was the odd
    /// one out, which is why `provision/integration/0.2` could not satisfy its
    /// own response schema.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "admin_template_name"
    )]
    pub admin_template_name: Option<String>,
    #[serde(alias = "bundle_id_hex")]
    pub bundle_id_hex: String,
    #[serde(alias = "secret_count")]
    pub secret_count: usize,
    #[serde(alias = "output_count")]
    pub output_count: usize,
    /// Resolved id of the registered webvh hosting server the VTA
    /// published the integration's `did.jsonl` to. `None` (default)
    /// means self-hosted at the URL — i.e. no `WEBVH_SERVER` template
    /// var was set, or it was explicitly null. Older VTAs that
    /// pre-date this field omit it on the wire; deserialize as `None`.
    /// Omitted rather than sent as `null`, for the same reason as
    /// `admin_template_name`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "webvh_server_id"
    )]
    pub webvh_server_id: Option<String>,
    /// `true` when the target context didn't exist before this call
    /// and was created inline because the caller passed
    /// `create_context: true`. `false` when the context already
    /// existed (or `create_context` was `false`). Lets operators
    /// see whether `--create-context` actually did something.
    /// Defaults to `false` on the wire for backward compatibility.
    #[serde(default, alias = "context_created")]
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

        // Emission is the canonical 0.2 camelCase wire form (#857).
        let out = serde_json::to_value(&req).unwrap();
        assert!(out.get("vcValiditySeconds").is_some());
        assert!(out.get("vc_validity_seconds").is_none());

        // A `false` create_context is omitted; re-serialize the camel parse
        // (create_context: true) to check the member name.
        let camel_again = serde_json::json!({
            "request": request_json,
            "createContext": true,
        });
        let req: ProvisionIntegrationRequest =
            serde_json::from_value(camel_again).expect("camelCase");
        let out = serde_json::to_value(&req).unwrap();
        assert!(out.get("createContext").is_some());
        assert!(out.get("create_context").is_none());
    }

    /// The summary deserializes from a legacy snake_case (0.1) producer too,
    /// while emitting the canonical camelCase (0.2) wire form.
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
        assert!(out.get("clientDid").is_some());
        assert!(out.get("client_did").is_none());

        // Legacy snake_case (0.1) still parses via the aliases.
        let snake = r#"{
            "client_did": "did:key:zClient",
            "bundle_id_hex": "deadbeef",
            "secret_count": 2,
            "output_count": 1
        }"#;
        let s: ProvisionSummary = serde_json::from_str(snake).expect("snake_case summary");
        assert_eq!(s.client_did, "did:key:zClient");
        assert_eq!(s.bundle_id_hex, "deadbeef");
    }

    /// What this crate sends must satisfy the schema of the URI it sends under.
    ///
    /// The client submits `provision/integration/0.2`
    /// ([`crate::trust_tasks::TASK_PROVISION_INTEGRATION_0_2`]) but serialised
    /// the 0.1 PascalCase `ask.type` tags. The two schemas differ in exactly
    /// that constant, so the VTA's payload-schema gate rejected every request:
    ///
    /// ```text
    /// malformed request: payload does not conform to
    /// https://trusttasks.org/spec/provision/integration/0.2:
    /// {...,"type":"AdminRotation"} is not valid under any of the schemas
    /// listed in the 'oneOf' keyword
    /// ```
    ///
    /// Latent since the client moved to the 0.2 URI, fatal once the gate
    /// landed. The unit tests on `BootstrapAsk` pin the tag itself; this pins
    /// the property that actually matters — the whole payload validating
    /// against the real published schema, through the same
    /// `trust_tasks_rs::validate` call the VTA runs.
    #[tokio::test]
    async fn the_request_payload_conforms_to_the_0_2_schema() {
        use crate::provision_integration::{
            AdminRotationAsk, BootstrapAsk, BootstrapRequest, DidTemplateRef,
        };
        use chrono::Duration;

        let schema = trust_tasks_rs::schema_index::schema_for(
            crate::trust_tasks::TASK_PROVISION_INTEGRATION_0_3,
        )
        .expect("the 0.3 schema is published and indexed");

        let (seed, pub_bytes) = crate::sealed_transfer::generate_ed25519_keypair();
        let client_did = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);

        // The AdminRotation shape from the failing report: an OpenVTC setup
        // rotating its ephemeral setup key to a VTA-minted admin identity.
        let vp = BootstrapRequest::sign(
            &seed,
            &client_did,
            [0x5Au8; 16],
            Duration::hours(1),
            Some("openvtc".into()),
            BootstrapAsk::AdminRotation(AdminRotationAsk {
                context_hint: Some("openvtc".into()),
                admin_template: DidTemplateRef {
                    name: "vta-admin".into(),
                    vars: Default::default(),
                },
                note: Some("openvtc".into()),
            }),
        )
        .await
        .expect("sign the VP");

        let payload = serde_json::json!({
            "request": serde_json::to_value(&vp).expect("serialize VP"),
        });

        trust_tasks_rs::validate::against_schema(schema, &payload).unwrap_or_else(|e| {
            panic!("the payload this crate sends must satisfy the 0.2 schema: {e}\n{payload:#}")
        });
    }
}
