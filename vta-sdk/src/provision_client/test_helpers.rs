//! Test fixtures shared between in-crate tests and downstream consumers.
//!
//! Gated by `#[cfg(any(test, feature = "test-support"))]`. Downstream
//! crates running their own integration tests against `provision_client`
//! enable both `provision-client` and `test-support` to access these
//! helpers.

use std::collections::BTreeMap;

use serde_json::json;

use crate::provision_integration::http::{AdminScope, ProvisionSummary};
use crate::provision_integration::payload::{
    DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
    VtaTrustBundle,
};

use super::intent::AdminCredentialReply;
use super::result::ProvisionResult;

/// Build a synthetic [`ProvisionResult`] for tests that need a fully-
/// populated Connected event without standing up a VTA. `rolled_over`
/// picks between the admin-rollover path (admin DID != client DID) and
/// the legacy no-rollover path.
pub fn sample_provision_result(rolled_over: bool) -> ProvisionResult {
    let admin_did = if rolled_over {
        "did:key:z6MkAdmin"
    } else {
        "did:key:z6MkSetup"
    };
    let integration_did = "did:webvh:integration.example.com";
    let mut secrets = BTreeMap::new();
    secrets.insert(
        integration_did.to_string(),
        DidKeyMaterial {
            did: integration_did.into(),
            signing_key: KeyPair {
                key_id: format!("{integration_did}#key-0"),
                public_key_multibase: "z6MkSample".into(),
                private_key_multibase: "zPrivateSample".into(),
            },
            ka_key: KeyPair {
                key_id: format!("{integration_did}#key-1"),
                public_key_multibase: "z6LSSample".into(),
                private_key_multibase: "zKaPrivate".into(),
            },
        },
    );
    if rolled_over {
        secrets.insert(
            admin_did.to_string(),
            DidKeyMaterial {
                did: admin_did.into(),
                signing_key: KeyPair {
                    key_id: format!("{admin_did}#key-0"),
                    public_key_multibase: "z6MkAdminSigning".into(),
                    private_key_multibase: "zAdminSigningPrivate".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{admin_did}#key-1"),
                    public_key_multibase: "z6LSAdminKa".into(),
                    private_key_multibase: "zAdminKaPrivate".into(),
                },
            },
        );
    }
    let payload = TemplateBootstrapPayload {
        authorization: json!({ "type": ["VerifiableCredential", "VtaAuthorizationCredential"] }),
        secrets,
        config: TemplateBootstrapConfig {
            template_name: "didcomm-mediator".into(),
            template_kind: "mediator".into(),
            did_document: json!({ "id": integration_did }),
            outputs: vec![TemplateOutput::WebvhLog {
                did: integration_did.into(),
                log: "{\"versionId\":\"1-abc\"}\n".into(),
            }],
            vta_url: Some("https://vta.example.com".into()),
            vta_trust: VtaTrustBundle {
                vta_did: "did:webvh:vta.example.com".into(),
                vta_did_document: json!({ "id": "did:webvh:vta.example.com" }),
                vta_did_log: None,
            },
        },
    };
    ProvisionResult {
        bundle_id_hex: "00112233445566778899aabbccddeeff".into(),
        digest: "deadbeef".into(),
        summary: ProvisionSummary {
            client_did: "did:key:z6MkSetup".into(),
            admin_did: admin_did.into(),
            admin_rolled_over: rolled_over,
            integration_did: Some(integration_did.into()),
            template_name: Some("didcomm-mediator".into()),
            template_kind: Some("mediator".into()),
            admin_template_name: if rolled_over {
                Some("vta-admin".into())
            } else {
                None
            },
            bundle_id_hex: "00112233445566778899aabbccddeeff".into(),
            secret_count: if rolled_over { 2 } else { 1 },
            output_count: 1,
            webvh_server_id: None,
            context_created: false,
            context: Some("ctx-1".into()),
            admin_scope: Some(AdminScope::Context),
        },
        payload,
    }
}

/// Build a synthetic [`AdminCredentialReply`] for tests that mock the
/// [`super::intent::VtaIntent::AdminRotated`] path's terminal reply
/// shape — admin DID + rotated private key.
pub fn sample_admin_rotation_reply() -> AdminCredentialReply {
    AdminCredentialReply {
        admin_did: "did:key:z6MkRotatedAdmin".into(),
        admin_private_key_mb: "zRotatedAdminPrivate".into(),
    }
}
