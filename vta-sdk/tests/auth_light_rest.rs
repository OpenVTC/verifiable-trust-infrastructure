//! Coverage harness for `vta_sdk::auth_light` and the auth-touching
//! paths in `vta_sdk::client::VtaClient` (`from_credential`,
//! `ensure_token_valid` refresh-on-expiry, full re-auth fallback).
//!
//! All tests run against a `wiremock` server. Where a real `did:key` is
//! required for DIDComm anoncrypt packing, we derive one from a fixed
//! seed via `ed25519_dalek` + the SDK's own multibase helpers — no
//! private key material leaves the test process.

#![cfg(feature = "client")]

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde_json::json;
use vta_sdk::auth_light::{
    authenticate_with_credential, challenge_response_light, refresh_token_light,
};
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::error::VtaError;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Test fixtures ───────────────────────────────────────────────────

/// Build a deterministic `did:key` + matching multibase private-key
/// string from a seed byte. Both client and VTA DIDs need to be valid
/// `did:key`s because `auth_light` calls `pack_auth_message`, which
/// derives X25519 keys from the embedded Ed25519 multibase.
fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
    // Multicodec Ed25519 private-key prefix (0x1300 → varint 0x80 0x26)
    // followed by the 32-byte seed, base58btc multibase encoded.
    let mut buf = vec![0x80, 0x26];
    buf.extend_from_slice(&seed);
    let priv_mb = multibase::encode(multibase::Base::Base58Btc, &buf);
    (did, priv_mb)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn mount_challenge(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "challenge": "c-nonce-123",
            "sessionId": "sess-test",
            "expiresAt": "2026-12-31T23:59:59Z"
        })))
        .mount(server)
        .await;
}

/// Mount the canonical `authenticate` response shape. The `expires_at`
/// argument is the absolute Unix-second value the client should
/// observe after parsing. We anchor `issuedAt` at the Unix epoch so
/// `issuedAt + expiresIn == expires_at` arithmetic falls out
/// trivially without parsing nuance.
async fn mount_authenticate(server: &MockServer, expires_at: u64) {
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess-test",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "access-jwt",
                "tokenType": "Bearer",
                "expiresIn": expires_at,
                "refreshToken": "refresh-tok",
                "refreshExpiresIn": expires_at + 3600
            }
        })))
        .mount(server)
        .await;
}

// ── challenge_response_light ────────────────────────────────────────

#[tokio::test]
async fn challenge_response_success_returns_tokens() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    mount_authenticate(&server, 1_700_001_000).await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let http = reqwest::Client::new();

    let result =
        challenge_response_light(&http, &server.uri(), &client_did, &client_priv, &vta_did)
            .await
            .unwrap();

    assert_eq!(result.access_token, "access-jwt");
    assert_eq!(result.access_expires_at, 1_700_001_000);
    assert_eq!(result.refresh_token.as_deref(), Some("refresh-tok"));
    assert_eq!(result.refresh_expires_at, Some(1_700_001_000 + 3600));
}

#[tokio::test]
async fn challenge_endpoint_401_maps_to_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(401).set_body_string("not authorized"))
        .mount(&server)
        .await;
    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let http = reqwest::Client::new();
    let err = challenge_response_light(&http, &server.uri(), &client_did, &client_priv, &vta_did)
        .await
        .unwrap_err();
    assert!(matches!(err, VtaError::Auth(_)), "got {err:?}");
}

#[tokio::test]
async fn challenge_endpoint_500_maps_to_server() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let http = reqwest::Client::new();
    let err = challenge_response_light(&http, &server.uri(), &client_did, &client_priv, &vta_did)
        .await
        .unwrap_err();
    match err {
        VtaError::Server { status, .. } => assert_eq!(status, 500),
        other => panic!("expected Server, got {other:?}"),
    }
}

#[tokio::test]
async fn authenticate_endpoint_401_maps_to_auth() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(401).set_body_string("bad challenge"))
        .mount(&server)
        .await;
    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let http = reqwest::Client::new();
    let err = challenge_response_light(&http, &server.uri(), &client_did, &client_priv, &vta_did)
        .await
        .unwrap_err();
    assert!(matches!(err, VtaError::Auth(_)), "got {err:?}");
}

#[tokio::test]
async fn pack_failure_with_invalid_vta_did_maps_to_validation() {
    // `pack_auth_message` resolves the VTA's keyAgreement via
    // `resolve_vta_keyagreement`, which supports `did:key` and
    // `did:webvh` only. A `did:web` VTA produces an "unsupported DID
    // method" error that `auth_light` wraps into `VtaError::Validation`.
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    let (client_did, client_priv) = did_key_from_seed(0x11);
    let http = reqwest::Client::new();
    let err = challenge_response_light(
        &http,
        &server.uri(),
        &client_did,
        &client_priv,
        "did:web:not-a-key",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, VtaError::Validation(_)), "got {err:?}");
}

// ── refresh_token_light ─────────────────────────────────────────────

#[tokio::test]
async fn refresh_token_success_rotates_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess-test",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "new-access",
                "tokenType": "Bearer",
                "expiresIn": 2_000_000_000_u64,
                "refreshToken": "new-refresh",
                "refreshExpiresIn": 2_000_003_600_u64
            }
        })))
        .mount(&server)
        .await;

    let (client_did, _) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let http = reqwest::Client::new();
    let result = refresh_token_light(&http, &server.uri(), &client_did, &vta_did, "old-refresh")
        .await
        .unwrap();
    assert_eq!(result.access_token, "new-access");
    assert_eq!(result.refresh_token.as_deref(), Some("new-refresh"));
}

#[tokio::test]
async fn refresh_token_401_maps_to_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/refresh"))
        .respond_with(ResponseTemplate::new(401).set_body_string("refresh token not found"))
        .mount(&server)
        .await;
    let (client_did, _) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let http = reqwest::Client::new();
    let err = refresh_token_light(&http, &server.uri(), &client_did, &vta_did, "old")
        .await
        .unwrap_err();
    assert!(matches!(err, VtaError::Auth(_)));
}

#[tokio::test]
async fn refresh_token_pack_failure_with_invalid_did() {
    let server = MockServer::start().await;
    let (client_did, _) = did_key_from_seed(0x11);
    let http = reqwest::Client::new();
    let err = refresh_token_light(
        &http,
        &server.uri(),
        &client_did,
        "did:web:not-a-key",
        "old",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, VtaError::Validation(_)), "got {err:?}");
}

// ── authenticate_with_credential ────────────────────────────────────

#[tokio::test]
async fn authenticate_with_credential_uses_url_override() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    mount_authenticate(&server, 1_700_001_000).await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    // Bundle has no URL — override drives the call.
    let cred = CredentialBundle::new(client_did, client_priv, vta_did);
    let (result, returned_cred, _http) = authenticate_with_credential(&cred, Some(&server.uri()))
        .await
        .unwrap();
    assert_eq!(result.access_token, "access-jwt");
    // Bundle echoed back unchanged.
    assert_eq!(returned_cred.did, cred.did);
}

#[tokio::test]
async fn authenticate_with_credential_uses_bundle_url() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    mount_authenticate(&server, 1_700_001_000).await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let cred = CredentialBundle::new(client_did, client_priv, vta_did).vta_url(server.uri());
    let (result, _, _) = authenticate_with_credential(&cred, None).await.unwrap();
    assert_eq!(result.access_token, "access-jwt");
}

#[tokio::test]
async fn authenticate_with_credential_no_url_anywhere_fails() {
    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let cred = CredentialBundle::new(client_did, client_priv, vta_did);
    let err = authenticate_with_credential(&cred, None).await.unwrap_err();
    match err {
        VtaError::Validation(msg) => assert!(msg.contains("no VTA URL")),
        other => panic!("expected Validation, got {other:?}"),
    }
}

// ── VtaClient::from_credential + token-refresh integration ──────────

#[tokio::test]
async fn from_credential_authenticates_and_exposes_token() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    mount_authenticate(&server, 1_700_001_000).await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let cred = CredentialBundle::new(client_did, client_priv, vta_did).vta_url(server.uri());

    let client = VtaClient::from_credential(&cred, None).await.unwrap();
    assert_eq!(client.token_expires_at().await, Some(1_700_001_000));
    assert_eq!(client.rest_url(), Some(server.uri().trim_end_matches('/')));
}

#[tokio::test]
async fn from_credential_url_override_wins_over_bundle() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    mount_authenticate(&server, 1_700_001_000).await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let cred = CredentialBundle::new(client_did, client_priv, vta_did)
        .vta_url("https://stale.example.com");
    let client = VtaClient::from_credential(&cred, Some(&server.uri()))
        .await
        .unwrap();
    assert_eq!(client.rest_url(), Some(server.uri().trim_end_matches('/')));
}

/// Exercise `client::ensure_token_valid`'s refresh-on-expiry path:
/// the initial auth returns an already-expired access token plus a
/// still-valid refresh token. The next authenticated call must hit
/// `/auth/refresh` first, then proceed with the new access token.
#[tokio::test]
async fn ensure_token_valid_refreshes_expired_access_token() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;

    // Initial auth: access already expired, refresh still good.
    // `issuedAt: 1970-01-01T00:00:00Z` makes expiresIn = absolute epoch.
    let future = now_secs() + 3600;
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "expired-access",
                "tokenType": "Bearer",
                "expiresIn": 100_u64,
                "refreshToken": "live-refresh",
                "refreshExpiresIn": future
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Refresh: returns a fresh access token (future expiry).
    Mock::given(method("POST"))
        .and(path("/auth/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "fresh-access",
                "tokenType": "Bearer",
                "expiresIn": future,
                "refreshToken": "newer-refresh",
                "refreshExpiresIn": future + 3600
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Downstream call must carry the *refreshed* token, not the expired one.
    Mock::given(method("GET"))
        .and(path("/config"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer fresh-access",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vta_did": null, "vta_name": null, "public_url": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let cred = CredentialBundle::new(client_did, client_priv, vta_did).vta_url(server.uri());
    let client = VtaClient::from_credential(&cred, None).await.unwrap();

    // Trigger an authenticated call → ensure_token_valid sees expired
    // access, calls refresh, then proceeds. wiremock's expect counters
    // verify the order of calls.
    client.get_config().await.unwrap();
    assert_eq!(client.token_expires_at().await, Some(future));
}

/// When the refresh token is itself expired, `ensure_token_valid` falls
/// through to a full re-authentication via `challenge_response_light`.
#[tokio::test]
async fn ensure_token_valid_full_reauth_when_refresh_expired() {
    let server = MockServer::start().await;

    // Two sequential challenge calls expected (initial + re-auth).
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "challenge": "c",
            "sessionId": "sess",
            "expiresAt": "2099-12-31T23:59:59Z"
        })))
        .expect(2)
        .mount(&server)
        .await;

    let future = now_secs() + 3600;
    // wiremock matches mocks in registration order until each
    // `up_to_n_times` budget is exhausted. So the first /auth/ call
    // hits the "stale tokens" mock; the second hits the "reauth" mock.
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "stale-access",
                "tokenType": "Bearer",
                "expiresIn": 100_u64,
                "refreshToken": "stale-refresh",
                "refreshExpiresIn": 100_u64
            }
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "reauth-access",
                "tokenType": "Bearer",
                "expiresIn": future,
                "refreshToken": "reauth-refresh",
                "refreshExpiresIn": future + 3600
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/config"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer reauth-access",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vta_did": null, "vta_name": null, "public_url": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let cred = CredentialBundle::new(client_did, client_priv, vta_did).vta_url(server.uri());
    let client = VtaClient::from_credential(&cred, None).await.unwrap();
    client.get_config().await.unwrap();
}

/// If the refresh endpoint itself fails, `ensure_token_valid` must fall
/// through to a full re-auth instead of bubbling the refresh error.
#[tokio::test]
async fn ensure_token_valid_falls_through_when_refresh_fails() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "challenge": "c",
            "sessionId": "sess",
            "expiresAt": "2099-12-31T23:59:59Z"
        })))
        .expect(2)
        .mount(&server)
        .await;

    let future = now_secs() + 3600;
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "expired",
                "tokenType": "Bearer",
                "expiresIn": 100_u64,
                "refreshToken": "live-but-server-rejects",
                "refreshExpiresIn": future
            }
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "session": {
                "id": "sess",
                "subject": "did:example:caller",
                "issuedAt": "1970-01-01T00:00:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "amr": ["did"],
                "acr": "aal1"
            },
            "tokens": {
                "accessToken": "fallback-access",
                "tokenType": "Bearer",
                "expiresIn": future,
                "refreshToken": "fallback-refresh",
                "refreshExpiresIn": future + 3600
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Refresh returns 401: invalid → should be tolerated, full re-auth runs.
    Mock::given(method("POST"))
        .and(path("/auth/refresh"))
        .respond_with(ResponseTemplate::new(401).set_body_string("token reuse detected"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/config"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer fallback-access",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vta_did": null, "vta_name": null, "public_url": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (client_did, client_priv) = did_key_from_seed(0x11);
    let (vta_did, _) = did_key_from_seed(0x22);
    let cred = CredentialBundle::new(client_did, client_priv, vta_did).vta_url(server.uri());
    let client = VtaClient::from_credential(&cred, None).await.unwrap();
    client.get_config().await.unwrap();
}
