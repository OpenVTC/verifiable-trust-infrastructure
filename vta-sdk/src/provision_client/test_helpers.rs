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
use super::result::{ProvisionResult, ProvisionResultV2};

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

/// [`sample_provision_result`] in the shape [`super::intent::VtaReply::Full`]
/// now carries.
///
/// Lifts the V1 fixture rather than duplicating it, so the two cannot drift and
/// a test written against either sees the same DIDs, digest and summary. Its
/// keys use real multicodec-prefixed multibase — the lift reads each key's
/// algorithm from that prefix, so a fixture with placeholder strings would not
/// lift at all.
///
/// `pq` adds a post-quantum signing key to the integration DID, for a test that
/// needs the hybrid shape.
pub fn sample_provision_result_v2(rolled_over: bool, pq: bool) -> ProvisionResultV2 {
    use crate::keys::KeyType;
    use crate::sealed_transfer::template_bootstrap::SlotKeyPair;

    let v1 = sample_provision_result(rolled_over);
    let mb = |codec: &[u8], fill: u8| {
        multibase::encode(
            multibase::Base::Base58Btc,
            [codec, &[fill; 32][..]].concat(),
        )
    };

    let mut secrets = BTreeMap::new();
    for (did, material) in &v1.payload.secrets {
        secrets.insert(
            did.clone(),
            crate::sealed_transfer::template_bootstrap::DidKeyMaterialV2 {
                did: material.did.clone(),
                signing_key: SlotKeyPair {
                    slot: crate::did_templates::SLOT_SIGNING.into(),
                    key_type: KeyType::Ed25519,
                    key_id: material.signing_key.key_id.clone(),
                    public_key_multibase: mb(KeyType::Ed25519.multicodec_public(), 0x11),
                    private_key_multibase: material.signing_key.private_key_multibase.clone(),
                },
                ka_key: SlotKeyPair {
                    slot: crate::did_templates::SLOT_KA.into(),
                    key_type: KeyType::X25519,
                    key_id: material.ka_key.key_id.clone(),
                    public_key_multibase: mb(KeyType::X25519.multicodec_public(), 0x22),
                    private_key_multibase: material.ka_key.private_key_multibase.clone(),
                },
                additional_signing_keys: if pq && Some(did.as_str()) == v1.integration_did() {
                    vec![SlotKeyPair {
                        slot: "pq-signing".into(),
                        key_type: KeyType::MlDsa44,
                        key_id: format!("{did}#key-2"),
                        public_key_multibase: mb(KeyType::MlDsa44.multicodec_public(), 0x33),
                        private_key_multibase: mb(KeyType::MlDsa44.multicodec_private(), 0x44),
                    }]
                } else {
                    Vec::new()
                },
            },
        );
    }

    ProvisionResultV2 {
        bundle_id_hex: v1.bundle_id_hex,
        digest: v1.digest,
        summary: v1.summary,
        payload: crate::sealed_transfer::template_bootstrap::TemplateBootstrapPayloadV2 {
            authorization: v1.payload.authorization,
            secrets,
            config: v1.payload.config,
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The V2 fixture must actually be usable as one: its keys carry real
    /// multicodec prefixes, because the V1 lift reads each key's algorithm from
    /// that prefix and a placeholder string does not lift at all. A fixture
    /// that could not survive the path it stands in for is worse than none.
    #[test]
    fn the_v2_fixture_carries_real_multicodec_keys() {
        let r = sample_provision_result_v2(true, true);
        let integration = r.integration_key().expect("integration key");
        assert_eq!(
            integration.signing_key.key_type,
            crate::keys::KeyType::Ed25519
        );
        assert_eq!(
            crate::keys::KeyType::from_public_multibase(
                &integration.signing_key.public_key_multibase
            ),
            Some(crate::keys::KeyType::Ed25519),
            "the fixture's public key must decode to the type it declares"
        );
        assert_eq!(integration.additional_signing_keys.len(), 1);
        assert_eq!(
            integration.additional_signing_keys[0].key_type,
            crate::keys::KeyType::MlDsa44
        );

        // The admin DID gets no post-quantum key: admin authentication is not
        // issuance, and nothing has asked it for one.
        let admin = r.admin_key().expect("admin key");
        assert!(admin.additional_signing_keys.is_empty());
    }

    /// Without `pq`, the fixture is the classical shape — the case every
    /// existing consumer is in.
    #[test]
    fn the_v2_fixture_without_pq_holds_only_the_pair() {
        let r = sample_provision_result_v2(false, false);
        let integration = r.integration_key().expect("integration key");
        assert!(integration.additional_signing_keys.is_empty());
        assert_eq!(r.admin_did(), "did:key:z6MkSetup");
    }
}
