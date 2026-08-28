//! The `MockVta` test-harness helper: a real, listening VTA on a random
//! loopback port that any HTTP client can drive — verified here by hitting the
//! unauthenticated `GET /health` over the wire (raw TCP, no client dep).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vta_sdk::client::VtaClient;
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

/// A client that can produce documents a conforming VTA accepts.
///
/// `mint_token` alone stopped being enough when the spine started enforcing
/// SPEC §7.2: every dispatched spec declares `recipient` REQUIRED (item 5b) and
/// 72 of them declare `proof` REQUIRED (item 7a), so a client needs the key
/// behind the DID its token names — not just the token. `seed` picks the
/// identity, so a test wanting two callers asks for two seeds.
async fn signing_client(mock: &MockVta, seed: u8, role: &str, contexts: Vec<String>) -> VtaClient {
    let vta_did = mock.vta_did().to_string();
    let (identity, token) = mock
        .ctx
        .mint_signing_identity(seed, role, contexts, &vta_did)
        .await;
    let client = VtaClient::new(mock.base_url()).with_identity(identity);
    client.set_token_async(token).await;
    client
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

    let client = signing_client(&mock, 0x10, "admin", vec![]).await;

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
    use vta_sdk::client::CreateDidWebvhRequest;
    use vta_sdk::protocols::did_management::create::WebvhPathMode;

    let mock = MockVta::start_with_webvh_host().await;

    // Authenticate as a super-admin (mint-token shortcut — no live handshake).
    let client = signing_client(&mock, 0x11, "admin", vec![]).await;

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
        add_tsp_service: false,
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
#[allow(deprecated)] // pins the legacy (context_id, scid) route until it is removed
async fn a_failed_publish_does_not_wedge_the_did_and_the_next_update_recovers() {
    use vta_sdk::client::CreateDidWebvhRequest;
    use vta_sdk::protocols::did_management::create::WebvhPathMode;
    use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

    let mock = MockVta::start_with_webvh_host().await;
    let client = signing_client(&mock, 0x11, "admin", vec![]).await;

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
            add_tsp_service: false,
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

/// The same self-recovery, but for a caller that sends `expectedVersionId`.
///
/// The test above passes `None`, which is why the wedge it is meant to prevent
/// survived anyway. A real client — the webvh admin UI — reads the DID from the
/// **host** and pins that version as its optimistic-concurrency precondition. A
/// failed publish leaves the local head ahead, so the caller's expectation no
/// longer matches the local head even though it matches the host exactly.
///
/// Comparing the two naively makes the caller wrong for reading the only thing
/// it can see, and refuses before step 4b can reconcile — so the DID wedges
/// permanently, every retry failing identically. Worse through the consent
/// flow: the refusal comes from the Plan dry-run, and 4b is Execute-only, so
/// the task can never reach the code that would heal it.
///
/// The precondition still has to work. `a_stale_caller_still_conflicts` below
/// pins the other side.
#[cfg(feature = "webvh")]
#[tokio::test]
#[allow(deprecated)] // pins the legacy (context_id, scid) route until it is removed
async fn a_caller_pinned_to_the_host_version_recovers_a_failed_publish() {
    use vta_sdk::client::CreateDidWebvhRequest;
    use vta_sdk::protocols::did_management::create::WebvhPathMode;
    use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

    let mock = MockVta::start_with_webvh_host().await;
    let client = signing_client(&mock, 0x11, "admin", vec![]).await;

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
            add_tsp_service: false,
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
    let update = |label: &str, expected: Option<String>| {
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
            expected_version_id: expected,
            ..Default::default()
        };
        async move { client.update_did_webvh("ctx1", &scid, body).await }
    };

    update("u1", None).await.expect("first update succeeds");
    let host_version = confirmed(&did).await.expect("a landed update confirms");

    // The publish fails: local head advances, the host stays on `host_version`.
    mock.fail_next_publishes(1);
    assert!(
        update("u2-fails", Some(host_version.clone()))
            .await
            .is_err(),
        "a publish failure surfaces as an error"
    );
    assert_eq!(
        confirmed(&did).await.as_deref(),
        Some(host_version.as_str()),
        "a failed publish must not advance the confirmed-published marker"
    );

    // What the admin UI does next: re-read the host (still `host_version`,
    // since the failed publish never landed) and submit pinned to it. This is
    // the call that used to fail forever with `concurrent update`.
    update("u3-recovers", Some(host_version.clone()))
        .await
        .expect("a caller in step with the host must not be refused as stale");
    assert_ne!(
        confirmed(&did).await.as_deref(),
        Some(host_version.as_str()),
        "recovery re-publishes the pending log and advances the host past the failure"
    );

    mock.shutdown().await;
}

/// The precondition still refuses a genuinely stale caller.
///
/// The relaxation above keys on the caller matching the last *confirmed*
/// publish. A caller pinned to a version the host has already moved past
/// matches neither the local head nor the confirmed marker, so it is still a
/// lost update and must still be refused — otherwise the fix for the wedge
/// would have quietly deleted the optimistic-concurrency guarantee.
#[cfg(feature = "webvh")]
#[tokio::test]
#[allow(deprecated)] // pins the legacy (context_id, scid) route until it is removed
async fn a_stale_caller_still_conflicts() {
    use vta_sdk::client::CreateDidWebvhRequest;
    use vta_sdk::protocols::did_management::create::WebvhPathMode;
    use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

    let mock = MockVta::start_with_webvh_host().await;
    let client = signing_client(&mock, 0x11, "admin", vec![]).await;

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
            add_tsp_service: false,
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
    let update = |label: &str, expected: Option<String>| {
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
            expected_version_id: expected,
            ..Default::default()
        };
        async move { client.update_did_webvh("ctx1", &scid, body).await }
    };

    update("u1", None).await.expect("first update succeeds");
    let stale = confirmed(&did).await.expect("a landed update confirms");

    // Somebody else updates the DID; both the host and the local head move on,
    // so `stale` is now genuinely behind rather than merely unpublished.
    update("u2-by-someone-else", None)
        .await
        .expect("second update succeeds");
    assert_ne!(
        confirmed(&did).await.as_deref(),
        Some(stale.as_str()),
        "the host really did move past the version our caller is pinned to"
    );

    let err = update("u3-stale", Some(stale.clone()))
        .await
        .expect_err("a caller pinned behind the host must still conflict");
    let msg = format!("{err:?}");
    assert!(
        msg.contains(&stale),
        "the refusal should name the stale version the caller sent: {msg}"
    );

    mock.shutdown().await;
}

/// Backward-recovery: a DID whose signing-key handle was superseded out of the
/// active prefix (the state a pre-#730 failed-publish loop left) still updates,
/// because the resolver re-derives the committed key from the seed.
///
/// Without the recovery fallback this is the permanent wedge: the key the
/// current entry requires is invisible to `find_handle_by_hash`, so every
/// update fails at signing and loops.
#[cfg(feature = "webvh")]
#[tokio::test]
#[allow(deprecated)] // pins the legacy (context_id, scid) route until it is removed
async fn a_superseded_signing_key_is_recovered_from_the_seed() {
    use vta_sdk::client::CreateDidWebvhRequest;
    use vta_sdk::protocols::did_management::create::WebvhPathMode;
    use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

    let mock = MockVta::start_with_webvh_host().await;
    let client = signing_client(&mock, 0x11, "admin", vec![]).await;

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
            add_tsp_service: false,
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
        .expect("create server-managed DID");
    let did = create.did.clone();
    let scid = create.scid.clone();

    let doc_update = |label: &str| {
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

    // v2: a document update rotates the update key; v2's handle is now active.
    let v2 = doc_update("v2")
        .await
        .expect("first document update succeeds");

    // Corrupt: move v2's key handles to `superseded:` — the exact state a
    // failed-publish loop leaves the key the next update must sign with.
    mock.corrupt_supersede_keys(&scid, &v2.new_version_id).await;

    // The next update must still succeed: the resolver can't find v2's handle
    // in the active prefix, so it re-derives the key from the seed.
    doc_update("v3-after-corruption")
        .await
        .expect("update recovers by re-deriving the superseded signing key from the seed");

    mock.shutdown().await;
}

/// Response-conformance coverage for the webvh family, against the stub host.
///
/// These tasks are not covered by the lib-level `response_coverage` module for
/// a reason worth stating: **every one of them either reaches a hosting server
/// or requires a DID that is already hosted.** `agent-name/*` looks local — the
/// names are local records — but each refuses a serverless DID ("agent names
/// require a hosted DID"), and a DID seeded straight into the keyspace *is*
/// serverless. So the whole family needs a real mint against a host, which is
/// exactly what `MockVta::start_with_webvh_host` provides.
///
/// The assertions here are deliberately thin. The response-conformance layer
/// validates every response these provoke against its published schema, so a
/// drift shows up as a `500` and fails the call, not as a weak assertion here.
#[cfg(feature = "webvh")]
#[tokio::test]
async fn webvh_family_response_shapes() {
    use vta_sdk::client::CreateDidWebvhRequest;
    use vta_sdk::protocols::did_management::create::WebvhPathMode;

    let mock = MockVta::start_with_webvh_host().await;
    let client = signing_client(&mock, 0x12, "admin", vec![]).await;

    // A real mint: everything below needs a *hosted* DID, not a seeded record.
    let minted = client
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
            add_tsp_service: false,
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
        .expect("mint against the stub host");
    let did = minted.did;

    // ── server surface ────────────────────────────────────────────────────
    client.list_webvh_servers().await.expect("servers/list");
    client
        .list_webvh_server_domains(MockVta::WEBVH_SERVER_ID)
        .await
        .expect("servers/domains");
    client
        .reconcile_webvh_server_dids(MockVta::WEBVH_SERVER_ID)
        .await
        .expect("servers/reconcile");

    // ── agent names ───────────────────────────────────────────────────────
    // Ordered as an operator would: claim, read back, disable, re-enable, drop.
    client
        .set_agent_name(&did, "coverage-agent")
        .await
        .expect("agent-name/set");
    client
        .check_agent_name(&did, "coverage-agent")
        .await
        .expect("agent-name/check");
    client
        .list_agent_names(&did)
        .await
        .expect("agent-name/list");
    client
        .disable_agent_name(&did, "coverage-agent")
        .await
        .expect("agent-name/disable");
    client
        .enable_agent_name(&did, "coverage-agent")
        .await
        .expect("agent-name/enable");
    client
        .remove_agent_name(&did, "coverage-agent")
        .await
        .expect("agent-name/remove");

    // ── passkey verification methods ──────────────────────────────────────
    // Same constraint as agent names, for a different reason: these refuse a
    // DID that is not **VTA-managed**, so the fixture's own `did:key` signing
    // identity does not qualify and a minted one does. Dispatched raw because
    // `VtaClient` exposes no method for this family.
    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_LIST_0_1,
            serde_json::json!({ "did": did }),
            30,
        )
        .await
        .expect("passkey-vms/list");
    // `enroll-challenge` needs `public_url`, not a WebAuthn relying party as
    // first assumed: the RP is *derived* from the VTA's public origin
    // (`require_public_url` → `build_webauthn`), and this fixture leaves it
    // unset, so the task answers `unavailable`. Setting the origin is the whole
    // prerequisite.
    {
        let mut cfg = mock.ctx.config.write().await;
        cfg.public_url = Some("https://vta.test".into());
    }
    let challenge = client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
            serde_json::json!({ "did": did, "label": "coverage-key" }),
            30,
        )
        .await
        .expect("passkey-vms/enroll-challenge");

    // `enroll-submit` runs full WebAuthn verification, so the attestation has
    // to be real — `SoftAuthenticator` is an authenticator in software rather
    // than a hand-written fixture, and the challenge, RP-ID hash, flags and
    // credential key all have to line up or `finish_passkey_registration`
    // refuses. The RP id is the `public_url`'s domain and the origin is the URL
    // itself, which is what `build_webauthn` derives.
    let authenticator = vta_service::test_support::SoftAuthenticator::new(0x60);
    let registration = authenticator.register(
        "vta.test",
        "https://vta.test",
        challenge["challenge"].as_str().expect("a challenge"),
    );
    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1,
            serde_json::json!({
                "did": did,
                "ceremonyId": challenge["ceremonyId"].as_str().expect("a ceremony id"),
                "credentialId": registration.credential_id,
                "publicKeyMultibase": registration.public_key_multibase,
                "coseAlgorithm": registration.cose_algorithm,
                "attestationObject": registration.attestation_object,
                "clientDataJson": registration.client_data_json,
                "authenticatorData": registration.authenticator_data,
            }),
            30,
        )
        .await
        .expect("passkey-vms/enroll-submit");

    // And now `revoke` has something to remove. It refuses a fragment the
    // document does not carry (`fragmentNotFound`), so this is only reachable
    // once a VM has really been enrolled — the fragment is derived from the
    // credential id the same way the enrolment derived it.
    let fragment = {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use sha2::{Digest, Sha256};
        let cred = B64URL
            .decode(&registration.credential_id)
            .expect("the credential id round-trips");
        format!("passkey-{}", B64URL.encode(Sha256::digest(&cred)))
    };
    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1,
            serde_json::json!({ "did": did, "fragment": fragment }),
            30,
        )
        .await
        .expect("passkey-vms/revoke");

    // ── server slot maintenance ───────────────────────────────────────────
    // A slot the host holds with no local record behind it. `reconcile` above
    // reports these; `retire-orphan` is how an operator clears one, so covering
    // them together follows the operator's actual sequence.
    client
        .retire_orphan_slot(
            &vta_sdk::protocols::did_management::servers::RetireOrphanSlotBody {
                server_id: MockVta::WEBVH_SERVER_ID.into(),
                // A slot this VTA has no record of — which is what "orphan"
                // means. The minted DID's own slot is deliberately not used:
                // the task refuses it, and correctly, pointing the caller at
                // `webvh/dids/delete` for a slot it still controls.
                slot_id: "cov-orphan-slot".into(),
                // `None`: the caller retires the slot on the strength of the
                // reconcile report alone. Setting it asserts "I believe this
                // slot serves <did>", which turns a stale report into a
                // refusal rather than a surprise — a guard worth its own test,
                // not worth spending the happy path on.
                expected_did: None,
                reason: Some("coverage".into()),
            },
        )
        .await
        .expect("servers/retire-orphan");

    // ── promoting a serverless DID ────────────────────────────────────────
    // `dids/register-with-server` is the one webvh path that cannot be reached
    // from the DID above: it refuses anything already server-managed, so it
    // needs a *second* DID minted the other way — `url` set, `server_id`
    // unset, which is what puts `"serverless"` on the record. That mint also
    // writes the local `did.jsonl` the register pushes; a hand-seeded record
    // would satisfy the serverless check and then fail at `LogMissing`, which
    // is the reject arm, not the shape this is here for.
    let serverless = client
        .create_did_webvh(CreateDidWebvhRequest {
            context_id: "ctx1".into(),
            server_id: None,
            url: Some(vta_service::test_support::STUB_WEBVH_DID_URL.into()),
            path: None,
            path_mode: None,
            domain: None,
            label: None,
            portable: false,
            add_mediator_service: false,
            add_tsp_service: false,
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
        .expect("mint a serverless DID");
    let promoted = client
        .register_did_with_server(&serverless.did, MockVta::WEBVH_SERVER_ID, false, None)
        .await
        .expect("dids/register-with-server");
    assert_eq!(promoted.server_id, MockVta::WEBVH_SERVER_ID);

    // ── the DID itself ────────────────────────────────────────────────────
    // Rotate before delete: a rotation on a deleted DID has nothing to rotate,
    // and delete is terminal.
    client
        .rotate_did_webvh_keys_by_did(&did, Default::default())
        .await
        .expect("dids/rotate-keys");
    client.delete_did_webvh(&did).await.expect("dids/delete");

    // Last: removing the server registration invalidates every path above it,
    // so an operator does this once nothing depends on it.
    client
        .remove_webvh_server(MockVta::WEBVH_SERVER_ID)
        .await
        .expect("servers/remove");

    mock.shutdown().await;
}

/// The `consent/*` family, driven as the ceremony it is: bind an approver, ask,
/// decide, read back, withdraw.
///
/// The order is the point. `consent/request` is default-deny and resolves an
/// approver for the (platform, context) before it will mint anything, so
/// `approver-set` is not setup for this test — it is the step that makes the
/// rest of the family reachable at all. Running the six in isolation would
/// prove six shapes; running them in sequence proves the gate.
#[tokio::test]
async fn consent_family_response_shapes() {
    use vta_sdk::protocols::consent_management::ConsentRequestBody;

    const PLATFORM: &str = "signal";
    const CONTEXT: &str = "ctx1";
    // base64url, ≥128 bits per the schema's `minLength` 16.
    const CHALLENGE: &str = "Y29uc2VudC1jb3ZlcmFnZS0xMjhi";

    let mock = MockVta::start().await;
    // One context, not the unrestricted admin: `consent/request` falls back to
    // `default_context()` when the caller sends no `contextHint`, and that
    // returns `Some` only for a caller with *exactly* one allowed context. An
    // admin minted with `vec![]` has unrestricted access and no default, so the
    // fallback this test exercises would be dead.
    let client = signing_client(&mock, 0x20, "admin", vec![CONTEXT.to_string()]).await;
    // The operator is the caller: `consent/decision` treats the requester and
    // the approver as one when they are the same DID (bridge-attested), and the
    // caller's DID is now derived from its signing seed rather than named.
    let operator = mock
        .ctx
        .mint_signing_identity(0x20, "admin", vec![CONTEXT.to_string()], mock.vta_did())
        .await
        .0
        .client_did;
    let operator = operator.as_str();

    let subject = serde_json::json!({
        "platform": PLATFORM,
        "conversationRef": "sig-cov-1a2b3c4d",
        "kind": "group",
        "agent": "did:key:z6MkConsentAgent",
    });

    // ── the approver must exist before anything can be asked ──────────────
    client
        .consent_approver_set(PLATFORM, CONTEXT, operator, Some("bridge-relay"), None)
        .await
        .expect("consent/approver-set");
    let listed = client
        .consent_approver_list(Some(PLATFORM), Some(CONTEXT))
        .await
        .expect("consent/approver-list");
    assert_eq!(
        listed["approvers"].as_array().map(Vec::len),
        Some(1),
        "the binding just written must come back through the filter that names it"
    );

    // ── ask ───────────────────────────────────────────────────────────────
    // No `contextHint`: the approver resolves through `default_context()`.
    let asked = client
        .consent_request(&ConsentRequestBody {
            subject: subject.clone(),
            scope: "converse".into(),
            challenge: CHALLENGE.into(),
            display_hint: Some("Signal group 'Coverage'".into()),
            first_message_digest: None,
            context_hint: None,
        })
        .await
        .expect("consent/request");
    assert_eq!(asked["status"], "accepted");
    assert_eq!(
        asked["requestId"], CHALLENGE,
        "the request id a bridge correlates on is the challenge it sent"
    );

    // ── decide ────────────────────────────────────────────────────────────
    let decided = client
        .consent_decision(
            subject.clone(),
            "allow",
            Some("converse"),
            Some(CHALLENGE),
            None,
        )
        .await
        .expect("consent/decision");
    assert_eq!(decided["status"], "recorded");

    // Asking again now short-circuits on the live grant rather than minting a
    // second pending consent — the branch that stops a bridge re-prompting an
    // operator who has already answered.
    let again = client
        .consent_request(&ConsentRequestBody {
            subject: subject.clone(),
            scope: "converse".into(),
            challenge: "Y29uc2VudC1jb3ZlcmFnZS1hZ2Fpbg".into(),
            display_hint: None,
            first_message_digest: None,
            context_hint: None,
        })
        .await
        .expect("consent/request (already decided)");
    assert_eq!(again["requestId"], "existing-grant");

    // ── read back ─────────────────────────────────────────────────────────
    let grants = client
        .consent_list(None, Some(PLATFORM), None)
        .await
        .expect("consent/list");
    assert_eq!(grants["grants"].as_array().map(Vec::len), Some(1));

    // ── withdraw, and prove it took ───────────────────────────────────────
    client
        .consent_revoke(subject.clone(), Some("coverage"))
        .await
        .expect("consent/revoke");
    let after = client
        .consent_list(None, Some(PLATFORM), None)
        .await
        .expect("consent/list after revoke");
    assert_eq!(
        after["grants"].as_array().map(Vec::len),
        Some(0),
        "revoke must return the subject to default-deny, not merely report success"
    );

    // Revoking again is `notFound` as a *status*, not a reject: the published
    // response schema declares the value, and the post-condition the caller
    // asked for already holds.
    let twice = client
        .consent_revoke(subject, None)
        .await
        .expect("consent/revoke is idempotent");
    assert_eq!(twice["status"], "notFound");

    mock.shutdown().await;
}

/// The `services/*` write paths, against a VTA whose own DID is hosted.
///
/// These were the last uncovered block with a shared cause. `services/enable`
/// and its siblings publish a new WebVH LogEntry for the VTA's *own* DID, so
/// `load_vta_doc_state` needs a record and a log for it — and the ordinary test
/// fixture's `vta_did` is a self-resolving `did:key`, which has neither. No
/// amount of test-writing reaches them from there; the fixture is the blocker.
///
/// Minting one against the stub host and pointing `vta_did` at it is what
/// unlocks the whole family, which is why this is one test rather than five.
#[tokio::test]
async fn services_write_paths_against_a_hosted_vta_did() {
    use vta_sdk::client::{CreateDidWebvhRequest, VtaClient};
    use vta_sdk::protocols::did_management::create::WebvhPathMode;

    let mock = MockVta::start_with_webvh_host().await;
    let client: VtaClient = mock.signing_client(0x40, "admin", vec![]).await;

    // A real hosted DID, with the record and log the preconditions read.
    let minted = client
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
            add_tsp_service: false,
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
        .expect("mint a hosted DID for the VTA itself");
    let did = minted.did.clone();

    // Point the VTA at it. `services/*` mutate *this* DID's document, so the
    // one under test has to be the one the VTA calls its own.
    {
        let mut cfg = mock.ctx.config.write().await;
        cfg.vta_did = Some(did.clone());
    }

    // And re-address the client. The VTA's identity just changed, and a
    // document's `recipient` has to name the consumer it is sent to — SPEC §7.2
    // item 5 rejects one that does not. Reusing the old client would fail on
    // `wrongRecipient` before reaching anything this test is about.
    let (identity, token) = mock
        .ctx
        .mint_signing_identity(0x40, "admin", vec![], &did)
        .await;
    let client = VtaClient::new(mock.base_url()).with_identity(identity);
    client.set_token_async(token).await;

    // REST throughout: it is the transport with no live handshake, so these
    // exercise the publish path rather than a service-liveness probe.
    //
    // `enable` first, and it is doing real work: the freshly minted DID's
    // document advertises no REST service, while the fixture's config says REST
    // is on. Reconciling that disagreement is what enable is for — and until
    // this change it refused to, leaving the state unmanageable.
    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_SERVICES_ENABLE_1_0,
            serde_json::json!({ "service": "rest", "config": { "url": "https://vta.test" } }),
            30,
        )
        .await
        .expect("services/enable");

    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_SERVICES_UPDATE_1_0,
            serde_json::json!({ "service": "rest", "config": { "url": "https://vta.test/moved" } }),
            30,
        )
        .await
        .expect("services/update");

    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_SERVICES_DISABLE_1_0,
            serde_json::json!({ "service": "rest" }),
            30,
        )
        .await
        .expect("services/disable");

    client
        .dispatch_trust_task(
            vta_sdk::trust_tasks::TASK_SERVICES_ROLLBACK_1_0,
            serde_json::json!({ "service": "rest" }),
            30,
        )
        .await
        .expect("services/rollback");

    // `passkey-vms/revoke` is *not* here, and the reason is worth recording:
    // it refuses a fragment that is not on the document
    // (`vta/passkey-vms/revoke:fragmentNotFound`), so covering it needs a VM
    // that was really enrolled — which needs a real authenticator attestation
    // over `enroll-challenge`'s nonce. That is a soft-authenticator harness,
    // not a fixture tweak, and it is the same blocker as `enroll-submit`.

    mock.shutdown().await;
}
