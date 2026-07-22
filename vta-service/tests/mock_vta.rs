//! The `MockVta` test-harness helper: a real, listening VTA on a random
//! loopback port that any HTTP client can drive — verified here by hitting the
//! unauthenticated `GET /health` over the wire (raw TCP, no client dep).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vta_service::test_support::MockVta;

/// Minimal HTTP/1.1 GET over a fresh TCP connection; returns the raw response.
async fn http_get(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect to mock VTA");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn mock_vta_serves_health_over_http() {
    let mock = MockVta::start().await;
    let addr = mock
        .base_url()
        .strip_prefix("http://")
        .expect("base_url is http://")
        .to_string();

    let response = http_get(&addr, "/health").await;

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200 from /health, got:\n{response}"
    );
    // The health handler returns a JSON status body.
    assert!(
        response.contains("status"),
        "expected a status body, got:\n{response}"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn mock_vta_gates_authenticated_routes() {
    let mock = MockVta::start().await;
    let addr = mock.base_url().strip_prefix("http://").unwrap().to_string();

    // An authenticated route without a token must not be served as 200 — the
    // mock is a real VTA, auth gates and all.
    let response = http_get(&addr, "/keys").await;
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "an unauthenticated /keys must not return 200, got:\n{}",
        response.lines().next().unwrap_or("")
    );

    mock.shutdown().await;
}

// ── Provisionable MockVta: the OpenVTC bootstrap→join e2e seams (issue #406) ──

/// `start_provisionable` must serve a real, self-resolving `did:key` VTA DID —
/// not the non-resolvable `z6MkTestVTA` sentinel the cheap app uses. This is the
/// VTA-identity half of Gap 1: only a real `did:key` lets the VTA sign the
/// authorization VC and seal the provision bundle. A harness drives provisioning
/// URL-direct with [`MockVta::base_url`] + [`MockVta::vta_did`] (no DID→URL
/// resolution); the SDK's URL-direct entry is
/// `vta_sdk::provision_client::provision_admin_rotated_via_rest` (covered by a
/// wiremock round-trip in `vta-sdk`'s `provision_client_e2e`).
#[tokio::test]
async fn provisionable_mock_exposes_a_real_vta_did() {
    let mock = MockVta::start_provisionable().await;
    let did = mock.vta_did();
    assert!(
        did.starts_with("did:key:z6Mk"),
        "expected a real ed25519 did:key, got {did}"
    );
    assert_ne!(
        did, "did:key:z6MkTestVTA",
        "provisionable mock must not use the non-resolvable sentinel DID"
    );
    mock.shutdown().await;
}

/// Gap 3: a seeded webvh hosting server shows up in the real
/// `GET /webvh/servers` catalogue, so a DID-mint / join flow finds a server to
/// publish to. Auth uses [`TestAppContext::mint_token`] — the REST-only mock has
/// no ATM for the DIDComm-packed live handshake.
#[tokio::test]
async fn seeded_webvh_server_is_listed_over_http() {
    let mock = MockVta::start_provisionable().await;
    mock.seed_webvh_server("prod", "did:webvh:host.example.com")
        .await;

    let token = mock
        .ctx
        .mint_token("did:key:z6MkTestAdmin", "admin", vec![])
        .await;
    let client = vta_sdk::client::VtaClient::new(mock.base_url());
    client.set_token_async(token).await;

    let result = client
        .list_webvh_servers()
        .await
        .expect("list webvh servers");
    assert!(
        result
            .servers
            .iter()
            .any(|s| s.id == "prod" && s.did == "did:webvh:host.example.com"),
        "seeded server must appear in the catalogue, got {:?}",
        result.servers
    );

    mock.shutdown().await;
}

/// Full URL-direct provision against a **REST-only** MockVta, end to end:
/// `provision_admin_rotated_via_rest` authenticates via the DI-signed
/// `auth/authenticate/0.1` Trust Task (no DIDComm / ATM — the mock has none),
/// the VTA mints a fresh admin DID + issues the authorization VC + seals the
/// rotation bundle, and the client opens it. This is the round-trip that
/// failed with "ATM not configured" before the DI-signed REST auth path
/// existed; it ties together the #406 seams + the DI-auth fix.
#[tokio::test]
async fn url_direct_admin_rotation_round_trips_against_rest_only_mock() {
    use vta_sdk::provision_client::ProvisionAsk;
    use vta_sdk::provision_client::provision_admin_rotated_via_rest;
    use vta_sdk::provision_client::setup_key::EphemeralSetupKey;

    let mock = MockVta::start_provisionable().await;

    // Cold-start: authorize the setup did:key as super-admin so the relayer is
    // authorized and the holder VP passes the provision gate.
    let setup = EphemeralSetupKey::generate().expect("generate setup key");
    mock.grant_super_admin(&setup.did).await;

    let reply = provision_admin_rotated_via_rest(
        mock.base_url(),
        mock.vta_did(),
        setup.did.clone(),
        setup.private_key_multibase().to_string(),
        ProvisionAsk::vta_admin_rotated("ctx1"),
    )
    .await
    .expect("URL-direct admin rotation should round-trip against the REST-only mock");

    assert!(
        reply.admin_did.starts_with("did:key:"),
        "rotated admin must be a did:key, got {}",
        reply.admin_did
    );
    assert_ne!(
        reply.admin_did, setup.did,
        "rotation must mint a fresh admin DID, not echo the setup DID"
    );
    assert!(
        !reply.admin_private_key_mb.is_empty(),
        "rotated admin must carry its private key"
    );

    mock.shutdown().await;
}

/// Full server-managed `create_did_webvh` round-trip against a REST-only mock
/// with an in-process stub hosting backend (#431): the VTA resolves the seeded
/// `did:webvh` server DID to the loopback stub, reserves a path, mints the
/// persona `did:webvh` via `didwebvh-rs`, and publishes the signed log to the
/// stub. Mirrors `url_direct_admin_rotation_round_trips_against_rest_only_mock`
/// for the persona-mint layer.
#[tokio::test]
async fn create_did_webvh_round_trips_against_stub_host() {
    use vta_sdk::client::{CreateDidWebvhRequest, VtaClient};
    use vta_sdk::protocols::did_management::create::WebvhPathMode;

    let mock = MockVta::start_with_webvh_host().await;

    // Authenticate as a super-admin (mint-token shortcut — no live handshake).
    let token = mock
        .ctx
        .mint_token("did:key:z6MkWebvhAdmin", "admin", vec![])
        .await;
    let client = VtaClient::new(mock.base_url());
    client.set_token_async(token).await;

    let req = CreateDidWebvhRequest {
        context_id: "ctx1".into(),
        server_id: Some(MockVta::WEBVH_SERVER_ID.into()),
        url: None,
        path: None,
        path_mode: Some(WebvhPathMode::AutoAssign),
        domain: None,
        label: None,
        portable: false,
        add_mediator_service: false,
        additional_services: None,
        pre_rotation_count: 0,
        did_document: None,
        did_log: None,
        set_primary: false,
        signing_key_id: None,
        ka_key_id: None,
        template: None,
        template_context: None,
        template_vars: Default::default(),
    };

    let res = client
        .create_did_webvh(req)
        .await
        .expect("create_did_webvh round-trip against the stub host");

    assert!(
        res.did.starts_with("did:webvh:"),
        "expected a minted did:webvh, got {}",
        res.did
    );
    assert_eq!(
        res.server_id.as_deref(),
        Some(MockVta::WEBVH_SERVER_ID),
        "result must record the server it was minted against"
    );
    assert!(
        res.mnemonic.is_some(),
        "a server-managed mint must return the server-assigned mnemonic"
    );
    assert!(!res.scid.is_empty(), "minted DID must carry an SCID");

    mock.shutdown().await;
}

/// Self-recovery from a failed publish (the DTTE / update path).
///
/// A webvh update commits local state before it can confirm the host received
/// the new version, so a publish that fails leaves the local head ahead of the
/// host. This must not wedge the DID: the confirmed-published marker must not
/// advance on a failed publish, and the next update must reconcile (re-publish
/// the pending log) and succeed. Before the reconcile guard, a failed publish
/// advanced the key counter and the DID looped forever.
#[cfg(feature = "webvh")]
#[tokio::test]
async fn a_failed_publish_does_not_wedge_the_did_and_the_next_update_recovers() {
    use vta_sdk::client::{CreateDidWebvhRequest, VtaClient};
    use vta_sdk::protocols::did_management::create::WebvhPathMode;
    use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

    let mock = MockVta::start_with_webvh_host().await;
    let token = mock
        .ctx
        .mint_token("did:key:z6MkWebvhAdmin", "admin", vec![])
        .await;
    let client = VtaClient::new(mock.base_url());
    client.set_token_async(token).await;

    let create = client
        .create_did_webvh(CreateDidWebvhRequest {
            context_id: "ctx1".into(),
            server_id: Some(MockVta::WEBVH_SERVER_ID.into()),
            url: None,
            path: None,
            path_mode: Some(WebvhPathMode::AutoAssign),
            domain: None,
            label: None,
            portable: false,
            add_mediator_service: false,
            additional_services: None,
            pre_rotation_count: 0,
            did_document: None,
            did_log: None,
            set_primary: false,
            signing_key_id: None,
            ka_key_id: None,
            template: None,
            template_context: None,
            template_vars: Default::default(),
        })
        .await
        .expect("create server-managed DID against the stub host");
    let did = create.did;
    let scid = create.scid;

    let confirmed = |did: &str| {
        let did = did.to_string();
        let ks = mock.ctx.webvh_ks.clone();
        async move {
            vta_service::webvh_store::get_published_version(&ks, &did)
                .await
                .unwrap()
        }
    };
    // Drive *document* updates (the "Edit DID" case), which rotate the update
    // key — the exact path that burned a key index on every failed publish.
    let update = |label: &str| {
        let scid = scid.clone();
        let did = did.clone();
        let client = &client;
        let body = UpdateDidWebvhBody {
            document: Some(serde_json::json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "verificationMethod": [{
                    "id": format!("{did}#key-0"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": "z6MkExternalPubForTest",
                }],
            })),
            label: Some(label.into()),
            ..Default::default()
        };
        async move { client.update_did_webvh("ctx1", &scid, body).await }
    };

    // A first update lands normally and confirms a published version.
    update("u1").await.expect("first update succeeds");
    let after_u1 = confirmed(&did).await;
    assert!(
        after_u1.is_some(),
        "a successful update records a confirmed-published version"
    );

    // Fail the next publish. The update builds a new version locally, but the
    // host rejects it — so the confirmed marker must NOT advance.
    mock.fail_next_publishes(1);
    assert!(
        update("u2-fails").await.is_err(),
        "a publish failure surfaces as an error, not a silent success"
    );
    assert_eq!(
        confirmed(&did).await,
        after_u1,
        "a failed publish must not advance the confirmed-published marker \
         (that divergence is what the reconcile heals)"
    );

    // The DID is diverged (local ahead of host) but not wedged: the next update
    // reconciles the pending publish and succeeds, advancing the marker.
    update("u3-recovers")
        .await
        .expect("the next update self-recovers instead of looping");
    assert_ne!(
        confirmed(&did).await,
        after_u1,
        "recovery re-publishes the pending log and advances past the pre-failure version"
    );

    mock.shutdown().await;
}
