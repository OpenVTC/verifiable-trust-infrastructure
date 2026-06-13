//! Mock-based end-to-end smoke test for the online provisioning workflow.
//!
//! Drives the SDK's REST entry point (`provision_via_rest`) against a
//! wiremock-backed fake VTA. The fake decodes the VP nonce from the
//! incoming `ProvisionIntegrationRequest`, seals a synthetic
//! `TemplateBootstrapPayload` to the test's setup-key X25519 pubkey, and
//! returns the armored bundle + matching digest. This exercises the
//! HPKE seal/open + response_to_result chain that the per-runner unit
//! tests can't validate in the success direction (because they don't
//! have a way to mock a valid sealed bundle response).
//!
//! Out of scope for this file: real VTA-side template rendering, ACL
//! state-machine, DID resolution (we feed `provision_via_rest`
//! directly, bypassing `resolve_vta`).

#![cfg(all(feature = "provision-client", feature = "test-support"))]

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use vta_sdk::did_key::decode_private_key_multibase;
use vta_sdk::provision_client::ask::ProvisionAsk;
use vta_sdk::provision_client::provision_via_rest;
use vta_sdk::provision_client::result::ProvisionResult;
use vta_sdk::provision_client::setup_key::EphemeralSetupKey;
use vta_sdk::provision_integration::http::{
    ProvisionIntegrationRequest, ProvisionIntegrationResponse, ProvisionSummary,
};
use vta_sdk::provision_integration::payload::{
    DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
    VtaTrustBundle,
};
use vta_sdk::sealed_transfer::{
    AssertionProof, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
    seal_payload,
};

/// Fake VTA bootstrap responder. On every POST, decodes the request VP
/// nonce, seals a synthetic `TemplateBootstrapPayload` to the test's
/// setup-key X25519 pubkey, returns the armored bundle + matching digest.
struct SealResponder {
    /// X25519 public key the bundle is sealed *to*. Derived from the
    /// test's setup `did:key` seed before the test runs.
    recipient_x_pub: [u8; 32],
    /// What the synthetic VTA "rendered" — drives the assertions in the
    /// test bodies.
    integration_did: String,
    admin_did: String,
    template_name: String,
    template_kind: String,
    /// Fixed VTA producer DID for the assertion. PinnedOnly is the
    /// simplest assertion shape; the OOB digest is the integrity anchor.
    producer_did: String,
}

impl Respond for SealResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let req: ProvisionIntegrationRequest =
            serde_json::from_slice(&request.body).expect("decode ProvisionIntegrationRequest body");

        // VP nonce is a base64url-no-pad 16-byte string.
        let nonce: [u8; 16] = {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
            let raw = B64URL.decode(&req.request.nonce).expect("nonce b64");
            raw.try_into().expect("nonce 16 bytes")
        };

        // Synthetic rendered payload — keys are placeholders; only field
        // shape matters for the open + accessor path.
        let mut secrets = BTreeMap::new();
        secrets.insert(
            self.integration_did.clone(),
            DidKeyMaterial {
                did: self.integration_did.clone(),
                signing_key: KeyPair {
                    key_id: format!("{}#key-0", self.integration_did),
                    public_key_multibase: "z6MkSyntheticIntegrationSig".into(),
                    private_key_multibase: "zSyntheticIntegrationSigPriv".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{}#key-1", self.integration_did),
                    public_key_multibase: "z6LSSyntheticIntegrationKa".into(),
                    private_key_multibase: "zSyntheticIntegrationKaPriv".into(),
                },
            },
        );
        secrets.insert(
            self.admin_did.clone(),
            DidKeyMaterial {
                did: self.admin_did.clone(),
                signing_key: KeyPair {
                    key_id: format!("{}#key-0", self.admin_did),
                    public_key_multibase: "z6MkSyntheticAdminSig".into(),
                    private_key_multibase: "zSyntheticAdminSigPriv".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{}#key-1", self.admin_did),
                    public_key_multibase: "z6LSSyntheticAdminKa".into(),
                    private_key_multibase: "zSyntheticAdminKaPriv".into(),
                },
            },
        );

        let template_payload = TemplateBootstrapPayload {
            authorization: json!({
                "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
                "credentialSubject": { "id": self.admin_did }
            }),
            secrets,
            config: TemplateBootstrapConfig {
                template_name: self.template_name.clone(),
                template_kind: self.template_kind.clone(),
                did_document: json!({ "id": self.integration_did }),
                outputs: vec![TemplateOutput::WebvhLog {
                    did: self.integration_did.clone(),
                    log: "{\"versionId\":\"1-fake\"}\n".into(),
                }],
                vta_url: Some("https://vta.example.com".into()),
                vta_trust: VtaTrustBundle {
                    vta_did: self.producer_did.clone(),
                    vta_did_document: json!({ "id": self.producer_did }),
                    vta_did_log: None,
                },
            },
        };
        let sealed_payload = SealedPayloadV1::TemplateBootstrap(Box::new(template_payload));

        let producer = ProducerAssertion {
            producer_did: self.producer_did.clone(),
            proof: AssertionProof::PinnedOnly,
        };

        // seal_payload is async (NonceStore.check_and_record awaits).
        // wiremock's Respond is sync and runs from a context where the
        // current runtime's blocking helpers aren't available, so we
        // cross to a fresh thread + runtime.
        let recipient_x_pub = self.recipient_x_pub;
        let bundle = std::thread::scope(|s| {
            s.spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build runtime")
                    .block_on(seal_payload(
                        &recipient_x_pub,
                        nonce,
                        producer,
                        &sealed_payload,
                        &InMemoryNonceStore::new(),
                    ))
            })
            .join()
            .expect("seal thread join")
        })
        .expect("seal payload");

        let armored = armor::encode(&bundle);
        let digest = bundle_digest(&bundle);

        let response = ProvisionIntegrationResponse {
            bundle: armored,
            digest,
            summary: ProvisionSummary {
                client_did: req.request.holder.clone(),
                admin_did: self.admin_did.clone(),
                admin_rolled_over: req.request.holder != self.admin_did,
                integration_did: Some(self.integration_did.clone()),
                template_name: Some(self.template_name.clone()),
                template_kind: Some(self.template_kind.clone()),
                admin_template_name: Some("vta-admin".into()),
                bundle_id_hex: hex_lower(&nonce),
                secret_count: 2,
                output_count: 1,
                webvh_server_id: None,
                context_created: false,
            },
        };

        ResponseTemplate::new(200).set_body_json(response)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

/// Derive the X25519 pubkey for HPKE seal/open from the setup key's
/// Ed25519 seed. Mirrors what `ed25519_seed_to_x25519_secret` does on
/// the open side; `seal_payload` needs the corresponding pubkey.
fn x25519_pub_from_setup_seed(seed: &[u8; 32]) -> [u8; 32] {
    let sk = SigningKey::from_bytes(seed);
    let ed_pub = sk.verifying_key().to_bytes();
    affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes(&ed_pub)
        .expect("ed25519 → x25519 pubkey conversion")
}

async fn mount_auth_mocks(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "challenge": "test-challenge",
            "sessionId": "test-session",
            "expiresAt": "2099-12-31T23:59:59Z"
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "test-session",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "test-access-token",
                "tokenType": "Bearer",
                "expiresIn": 9999999999_u64
            }
        })))
        .mount(server)
        .await;
}

/// `did:key` is self-resolving — the auth flow extracts the recipient
/// X25519 from the identifier itself, so no network roundtrip happens.
fn test_vta_did_key() -> String {
    EphemeralSetupKey::generate().unwrap().did
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_via_rest_didcomm_mediator_round_trip() {
    let server = MockServer::start().await;
    mount_auth_mocks(&server).await;

    let key = EphemeralSetupKey::generate().unwrap();
    let seed: [u8; 32] = decode_private_key_multibase(key.private_key_multibase()).unwrap();
    let recipient_x_pub = x25519_pub_from_setup_seed(&seed);

    let integration_did = "did:webvh:mediator.example.com".to_string();
    let admin_did = "did:key:z6MkAdminMediator".to_string();
    Mock::given(method("POST"))
        .and(path("/bootstrap/provision-integration"))
        .respond_with(SealResponder {
            recipient_x_pub,
            integration_did: integration_did.clone(),
            admin_did: admin_did.clone(),
            template_name: "didcomm-mediator".into(),
            template_kind: "mediator".into(),
            producer_did: "did:webvh:vta.example.com".into(),
        })
        .mount(&server)
        .await;

    let ask = ProvisionAsk::didcomm_mediator("prod-mediator", "https://m.example.com");

    let result: ProvisionResult = provision_via_rest(
        &server.uri(),
        &test_vta_did_key(),
        key.did.clone(),
        key.private_key_multibase().to_string(),
        ask,
    )
    .await
    .expect("REST round-trip succeeds");

    assert_eq!(result.integration_did(), Some(integration_did.as_str()));
    assert_eq!(result.admin_did(), admin_did);
    assert_eq!(
        result.summary.template_name.as_deref(),
        Some("didcomm-mediator")
    );
    assert_eq!(result.summary.template_kind.as_deref(), Some("mediator"));
    assert!(result.summary.admin_rolled_over);
    assert!(result.integration_key().is_some());
    assert!(result.admin_key().is_some());
    assert!(result.webvh_log().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_via_rest_webvh_server_round_trip() {
    let server = MockServer::start().await;
    mount_auth_mocks(&server).await;

    let key = EphemeralSetupKey::generate().unwrap();
    let seed: [u8; 32] = decode_private_key_multibase(key.private_key_multibase()).unwrap();
    let recipient_x_pub = x25519_pub_from_setup_seed(&seed);

    let integration_did = "did:webvh:service.example.com".to_string();
    let admin_did = "did:key:z6MkAdminWebvhSvc".to_string();
    Mock::given(method("POST"))
        .and(path("/bootstrap/provision-integration"))
        .respond_with(SealResponder {
            recipient_x_pub,
            integration_did: integration_did.clone(),
            admin_did: admin_did.clone(),
            template_name: "did-host-didcomm".into(),
            template_kind: "did-host-didcomm".into(),
            producer_did: "did:webvh:vta.example.com".into(),
        })
        .mount(&server)
        .await;

    let ask = ProvisionAsk::did_host_didcomm("prod-webvh", "did:webvh:m.example.com");

    let result: ProvisionResult = provision_via_rest(
        &server.uri(),
        &test_vta_did_key(),
        key.did.clone(),
        key.private_key_multibase().to_string(),
        ask,
    )
    .await
    .expect("REST round-trip succeeds");

    assert_eq!(result.integration_did(), Some(integration_did.as_str()));
    assert_eq!(result.admin_did(), admin_did);
    assert_eq!(
        result.summary.template_name.as_deref(),
        Some("did-host-didcomm")
    );
    assert_eq!(
        result.summary.template_kind.as_deref(),
        Some("did-host-didcomm")
    );
}

// ── AdminRotated path ────────────────────────────────────────────────

/// Fake VTA responder for the [`vta_sdk::provision_client::VtaIntent::AdminRotated`]
/// flow. Mirrors [`SealResponder`] but seals an
/// [`SealedPayloadV1::AdminRotation`] payload — the new admin DID +
/// keys, no integration material — and reports `integration_did = None`
/// in the wire summary.
struct AdminRotationResponder {
    recipient_x_pub: [u8; 32],
    /// What the synthetic VTA "rotated to" — drives the assertions in
    /// the test bodies.
    admin_did: String,
    admin_private_key_mb: String,
    producer_did: String,
}

impl Respond for AdminRotationResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let req: ProvisionIntegrationRequest =
            serde_json::from_slice(&request.body).expect("decode ProvisionIntegrationRequest body");

        let nonce: [u8; 16] = {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
            let raw = B64URL.decode(&req.request.nonce).expect("nonce b64");
            raw.try_into().expect("nonce 16 bytes")
        };

        let payload = vta_sdk::sealed_transfer::AdminRotationPayload {
            authorization: json!({
                "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
                "credentialSubject": { "id": self.admin_did }
            }),
            admin: DidKeyMaterial {
                did: self.admin_did.clone(),
                signing_key: KeyPair {
                    key_id: format!("{}#{}", self.admin_did, "key-0"),
                    public_key_multibase: "z6MkSyntheticAdminSig".into(),
                    private_key_multibase: self.admin_private_key_mb.clone(),
                },
                ka_key: KeyPair {
                    key_id: format!("{}#{}", self.admin_did, "key-1"),
                    public_key_multibase: "z6LSSyntheticAdminKa".into(),
                    private_key_multibase: "zSyntheticAdminKaPriv".into(),
                },
            },
            vta_url: Some("https://vta.example.com".into()),
            vta_trust: VtaTrustBundle {
                vta_did: self.producer_did.clone(),
                vta_did_document: json!({ "id": self.producer_did }),
                vta_did_log: None,
            },
        };

        let producer_assertion = ProducerAssertion {
            producer_did: self.producer_did.clone(),
            proof: AssertionProof::PinnedOnly,
        };

        // seal_payload is async; wiremock's Respond is sync and runs
        // from a context where the current runtime's blocking helpers
        // aren't available — same pattern as SealResponder.
        let recipient_x_pub = self.recipient_x_pub;
        let sealed = SealedPayloadV1::AdminRotation(Box::new(payload));
        let bundle = std::thread::scope(|s| {
            s.spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build runtime")
                    .block_on(seal_payload(
                        &recipient_x_pub,
                        nonce,
                        producer_assertion,
                        &sealed,
                        &InMemoryNonceStore::new(),
                    ))
            })
            .join()
            .expect("seal thread join")
        })
        .expect("seal AdminRotation payload");

        let armored = armor::encode(&bundle);
        let digest = bundle_digest(&bundle);

        let response = ProvisionIntegrationResponse {
            bundle: armored,
            digest,
            summary: ProvisionSummary {
                client_did: req.request.holder.clone(),
                admin_did: self.admin_did.clone(),
                admin_rolled_over: true,
                integration_did: None,
                template_name: None,
                template_kind: None,
                admin_template_name: Some("vta-admin".into()),
                bundle_id_hex: hex_lower(&nonce),
                secret_count: 1,
                output_count: 0,
                webvh_server_id: None,
                context_created: false,
            },
        };

        ResponseTemplate::new(200).set_body_json(response)
    }
}

/// REST AdminRotated round-trip: send a `BootstrapAsk::AdminRotation`
/// VP through the public `VtaClient::provision_integration` entry
/// point against a wiremock that returns a sealed `AdminRotation`
/// payload, then decode it via `admin_rotation_response_to_reply`.
///
/// Pins three contract guarantees:
/// 1. `admin_did` in the reply is the rotated DID — *not* the setup
///    key's DID (no rotation = no point).
/// 2. `admin_private_key_mb` is the freshly-minted private key
///    (rotated DID's signing key), not the setup key.
/// 3. The wire summary's `integration_did` is `None` (AdminRotation
///    payloads carry only admin material).
///
/// Bypasses `run_connection_test` because that path resolves the VTA
/// DID first and a `did:key` advertises no transports. The
/// orchestrator is exercised separately via the unit tests in
/// `runner_rest.rs`; this e2e covers the wire shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_rotated_via_rest_round_trip() {
    use vta_sdk::client::VtaClient;
    use vta_sdk::provision_client::admin_rotation_response_to_reply;
    use vta_sdk::provision_integration::ProvisionRequestBuilder;
    use vta_sdk::provision_integration::http::ProvisionIntegrationRequest;

    let server = MockServer::start().await;
    mount_auth_mocks(&server).await;

    let key = EphemeralSetupKey::generate().unwrap();
    let seed: [u8; 32] = decode_private_key_multibase(key.private_key_multibase()).unwrap();
    let recipient_x_pub = x25519_pub_from_setup_seed(&seed);

    let rotated_admin_did = "did:key:z6MkRotatedAdminFresh".to_string();
    let rotated_admin_private_key_mb = "zRotatedAdminFreshPriv".to_string();
    Mock::given(method("POST"))
        .and(path("/bootstrap/provision-integration"))
        .respond_with(AdminRotationResponder {
            recipient_x_pub,
            admin_did: rotated_admin_did.clone(),
            admin_private_key_mb: rotated_admin_private_key_mb.clone(),
            producer_did: "did:webvh:vta.example.com".into(),
        })
        .mount(&server)
        .await;

    let signed = ProvisionRequestBuilder::for_admin_rotation("vta-admin")
        .context_hint("ctx-1")
        .sign_with(&seed, &key.did)
        .await
        .expect("sign VP for admin rotation");

    let nonce = {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let raw = B64URL.decode(&signed.nonce).unwrap();
        let arr: [u8; 16] = raw.try_into().unwrap();
        arr
    };

    let token = vta_sdk::session::challenge_response(
        &server.uri(),
        &key.did,
        key.private_key_multibase(),
        &test_vta_did_key(),
    )
    .await
    .expect("auth handshake");

    let client = VtaClient::new(&server.uri());
    client.set_token_async(token.access_token).await;

    let req = ProvisionIntegrationRequest {
        request: signed,
        context: Some("ctx-1".into()),
        assertion: None,
        vc_validity_seconds: None,
        create_context: false,
    };
    let response = client
        .provision_integration(req)
        .await
        .expect("provision_integration round-trip");

    // Wire summary contract: AdminRotation must omit integration_did.
    assert!(
        response.summary.integration_did.is_none(),
        "AdminRotation summary must omit integration_did, got {:?}",
        response.summary.integration_did
    );
    assert!(response.summary.admin_rolled_over);

    // Decode + reply contract: rotated DID + key, not the setup pair.
    let reply = admin_rotation_response_to_reply(&seed, nonce, response)
        .expect("decode AdminRotation response");
    assert_eq!(reply.admin_did, rotated_admin_did);
    assert_ne!(reply.admin_did, key.did, "must not be the setup DID");
    assert_eq!(reply.admin_private_key_mb, rotated_admin_private_key_mb);
    assert_ne!(
        reply.admin_private_key_mb,
        key.private_key_multibase(),
        "rotated key must not equal the setup key"
    );
}

/// The public URL-direct AdminRotated entry point
/// (`provision_admin_rotated_via_rest`, issue #406): one call drives auth +
/// the `BootstrapAsk::AdminRotation` round-trip against an explicit `rest_url`,
/// never re-resolving the VTA DID — the seam that lets the OpenVTC e2e drive a
/// loopback `MockVta`. Mirrors [`admin_rotated_via_rest_round_trip`] but through
/// the one public function instead of the hand-assembled auth + client + decode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_admin_rotated_via_rest_public_entry_round_trip() {
    use vta_sdk::provision_client::provision_admin_rotated_via_rest;

    let server = MockServer::start().await;
    mount_auth_mocks(&server).await;

    let key = EphemeralSetupKey::generate().unwrap();
    let seed: [u8; 32] = decode_private_key_multibase(key.private_key_multibase()).unwrap();
    let recipient_x_pub = x25519_pub_from_setup_seed(&seed);

    let rotated_admin_did = "did:key:z6MkRotatedAdminPublicEntry".to_string();
    let rotated_admin_private_key_mb = "zRotatedAdminPublicEntryPriv".to_string();
    Mock::given(method("POST"))
        .and(path("/bootstrap/provision-integration"))
        .respond_with(AdminRotationResponder {
            recipient_x_pub,
            admin_did: rotated_admin_did.clone(),
            admin_private_key_mb: rotated_admin_private_key_mb.clone(),
            producer_did: "did:webvh:vta.example.com".into(),
        })
        .mount(&server)
        .await;

    // One call: auth handshake + VP build + provision-integration POST + bundle
    // open, all against the explicit `rest_url` — no DID→URL resolution.
    let reply = provision_admin_rotated_via_rest(
        &server.uri(),
        &test_vta_did_key(),
        key.did.clone(),
        key.private_key_multibase().to_string(),
        ProvisionAsk::vta_admin_rotated("ctx-1"),
    )
    .await
    .expect("URL-direct admin rotation round-trip");

    assert_eq!(reply.admin_did, rotated_admin_did);
    assert_ne!(
        reply.admin_did, key.did,
        "must return the rotated DID, not the setup DID"
    );
    assert_eq!(reply.admin_private_key_mb, rotated_admin_private_key_mb);
}

/// DIDComm transport for the AdminRotated path — unit-test the
/// `provision_admin_rotation_via_didcomm` decoder against a synthetic
/// `ProvisionIntegrationResponse`. We don't have a wiremock for
/// DIDComm in this suite, so we exercise the response decoder directly
/// (the same code path the live DIDComm runner takes after receiving
/// the result message body from the mediator).
#[tokio::test]
async fn admin_rotated_didcomm_response_decoder_extracts_rotated_credentials() {
    use vta_sdk::provision_client::admin_rotation_response_to_reply;

    let key = EphemeralSetupKey::generate().unwrap();
    let seed: [u8; 32] = decode_private_key_multibase(key.private_key_multibase()).unwrap();
    let recipient_x_pub = x25519_pub_from_setup_seed(&seed);

    let rotated_admin_did = "did:key:z6MkAdminRotatedDIDComm".to_string();
    let rotated_admin_private_key_mb = "zAdminRotatedDIDCommPriv".to_string();

    // Build a synthetic AdminRotation bundle exactly like the server
    // would emit. The decoder must surface the rotated DID + key
    // material verbatim.
    let mut nonce = [0u8; 16];
    nonce[0] = 0xAA;
    let payload = vta_sdk::sealed_transfer::AdminRotationPayload {
        authorization: json!({
            "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
            "credentialSubject": { "id": rotated_admin_did }
        }),
        admin: DidKeyMaterial {
            did: rotated_admin_did.clone(),
            signing_key: KeyPair {
                key_id: format!("{rotated_admin_did}#key-0"),
                public_key_multibase: "z6MkAdminPub".into(),
                private_key_multibase: rotated_admin_private_key_mb.clone(),
            },
            ka_key: KeyPair {
                key_id: format!("{rotated_admin_did}#key-1"),
                public_key_multibase: "z6LSAdminKaPub".into(),
                private_key_multibase: "zAdminKaPriv".into(),
            },
        },
        vta_url: None,
        vta_trust: VtaTrustBundle {
            vta_did: "did:webvh:vta.example.com".into(),
            vta_did_document: json!({ "id": "did:webvh:vta.example.com" }),
            vta_did_log: None,
        },
    };

    let producer_assertion = ProducerAssertion {
        producer_did: "did:webvh:vta.example.com".into(),
        proof: AssertionProof::PinnedOnly,
    };
    let nonce_store = InMemoryNonceStore::default();
    let bundle = seal_payload(
        &recipient_x_pub,
        nonce,
        producer_assertion,
        &SealedPayloadV1::AdminRotation(Box::new(payload)),
        &nonce_store,
    )
    .await
    .expect("seal AdminRotation");

    let response = ProvisionIntegrationResponse {
        bundle: armor::encode(&bundle),
        digest: bundle_digest(&bundle),
        summary: ProvisionSummary {
            client_did: key.did.clone(),
            admin_did: rotated_admin_did.clone(),
            admin_rolled_over: true,
            integration_did: None,
            template_name: None,
            template_kind: None,
            admin_template_name: Some("vta-admin".into()),
            bundle_id_hex: hex_lower(&nonce),
            secret_count: 1,
            output_count: 0,
            webvh_server_id: None,
            context_created: false,
        },
    };

    let reply = admin_rotation_response_to_reply(&seed, nonce, response).expect("decode");
    assert_eq!(reply.admin_did, rotated_admin_did);
    assert_ne!(reply.admin_did, key.did);
    assert_eq!(reply.admin_private_key_mb, rotated_admin_private_key_mb);
}
