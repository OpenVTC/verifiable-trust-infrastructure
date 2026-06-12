//! Coverage for `vta_sdk::session::SessionStore` and its backends.
//!
//! Three test layers:
//!   1. **Backend ops** — pure storage round-trips with the in-memory
//!      backend (`store_direct`, `store_pending_rotation`,
//!      `loaded_session`, `session_status`, `logout`).
//!   2. **`FileBackend`** — exercise the on-disk plaintext fallback by
//!      constructing `SessionStore::new(...)` against a tempdir, where
//!      the SDK's feature-gate cascade lands on `FileBackend`.
//!   3. **Network paths** — `login` / `ensure_authenticated` /
//!      `rotate_key` against a `wiremock` server, using `did:key` DIDs
//!      so TDK's resolver doesn't need outbound DNS.

#![cfg(all(feature = "session", feature = "test-support"))]

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde_json::json;
#[cfg(not(any(feature = "keyring", feature = "azure-secrets")))]
use tempfile::tempdir;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_key::ed25519_multibase_pubkey;
use vta_sdk::session::testing::InMemorySessionBackend;
use vta_sdk::session::{
    SessionStore, TokenStatus, VtaEndpoint, resolve_vta_endpoint, resolve_vta_url,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Test fixtures ───────────────────────────────────────────────────

fn store() -> SessionStore {
    SessionStore::with_backend(Box::new(InMemorySessionBackend::new()))
}

fn did_key_from_seed(seed_byte: u8) -> (String, String) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&pk));
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

// ── Backend round-trips (no network) ────────────────────────────────

#[test]
fn store_direct_round_trips_through_loaded_session() {
    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    s.store_direct("k", &did, &pk, &vta_did).unwrap();

    assert!(s.has_session("k"));
    let info = s.loaded_session("k").unwrap();
    assert_eq!(info.client_did, did);
    assert_eq!(info.vta_did.as_deref(), Some(vta_did.as_str()));
    assert_eq!(info.private_key_multibase, pk);
}

#[test]
fn store_pending_rotation_marks_needs_rotation() {
    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    s.store_pending_rotation("k", &did, &pk, &vta_did).unwrap();

    // The needs_rotation flag isn't directly visible via SessionInfo,
    // but `session_status` returns TokenStatus::None (no token yet).
    let status = s.session_status("k").unwrap();
    assert_eq!(status.client_did, did);
    assert!(matches!(status.token_status, TokenStatus::None));
}

#[test]
fn logout_clears_entry() {
    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    s.store_direct("k", &did, &pk, &vta_did).unwrap();
    assert!(s.has_session("k"));
    s.logout("k");
    assert!(!s.has_session("k"));
    assert!(s.loaded_session("k").is_none());
    assert!(s.session_status("k").is_none());
}

#[test]
fn has_session_false_for_missing_entry() {
    let s = store();
    assert!(!s.has_session("never-stored"));
    assert!(s.loaded_session("never-stored").is_none());
}

#[test]
fn session_status_none_when_no_token_cached() {
    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    s.store_direct("k", &did, &pk, &vta_did).unwrap();
    let status = s.session_status("k").unwrap();
    assert!(matches!(status.token_status, TokenStatus::None));
}

// ── FileBackend (on-disk plaintext fallback) ────────────────────────
//
// Only exercised when no other session backend is compiled in. Under
// workspace cov runs the `keyring` feature is unified on (pnm-cli /
// cnm-cli enable it), and `default_backend` returns `KeyringBackend`
// instead — so these tests would no-op against a different code path.
// Running `cargo test -p vta-sdk --test session_store --features
// "session test-support"` exercises this path.

#[cfg(not(any(feature = "keyring", feature = "azure-secrets")))]
#[test]
fn file_backend_round_trips_via_session_store_new() {
    // SessionStore::new() with no keyring/azure features compiled
    // (the default for these tests) lands on FileBackend with
    // warn=true. Save → load → clear must round-trip through
    // `<sessions_dir>/sessions.json`.
    let dir = tempdir().unwrap();
    let store = SessionStore::new("test-svc", dir.path().to_path_buf());

    let (did, pk) = did_key_from_seed(0x30);
    let (vta_did, _) = did_key_from_seed(0x40);
    store.store_direct("file-k", &did, &pk, &vta_did).unwrap();

    // The on-disk file is created.
    let sessions_file = dir.path().join("sessions.json");
    assert!(
        sessions_file.exists(),
        "FileBackend should create sessions.json"
    );

    // Round-trip via a fresh store instance pointing at the same dir.
    let store2 = SessionStore::new("test-svc", dir.path().to_path_buf());
    let info = store2.loaded_session("file-k").unwrap();
    assert_eq!(info.client_did, did);
    assert_eq!(info.vta_did.as_deref(), Some(vta_did.as_str()));

    store2.logout("file-k");
    assert!(!store2.has_session("file-k"));
    // A subsequent load on a fresh store sees the cleared state.
    let store3 = SessionStore::new("test-svc", dir.path().to_path_buf());
    assert!(store3.loaded_session("file-k").is_none());
}

#[cfg(not(any(feature = "keyring", feature = "azure-secrets")))]
#[test]
fn file_backend_load_on_missing_dir_returns_none() {
    // Pointing at a non-existent path must not panic; load returns None.
    let store = SessionStore::new(
        "test-svc",
        std::path::PathBuf::from("/tmp/never-created-vta-sdk-tests-xyz"),
    );
    assert!(!store.has_session("missing"));
    assert!(store.loaded_session("missing").is_none());
}

// ── Network paths via wiremock ──────────────────────────────────────

async fn mount_challenge(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "challenge": "c-nonce",
            "sessionId": "sess",
            "expiresAt": "2099-12-31T23:59:59Z"
        })))
        .mount(server)
        .await;
}

/// Mount the canonical authenticate response. `issuedAt: 1970-01-01`
/// anchors the absolute access-expiry epoch at `expiresIn` so test
/// assertions on `access_expires_at` see exactly `expires_at`.
async fn mount_authenticate(server: &MockServer, expires_at: u64) {
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
                "accessToken": "access-jwt",
                "tokenType": "Bearer",
                "expiresIn": expires_at
            }
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn login_authenticates_and_persists_token() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    let future = now_secs() + 3600;
    mount_authenticate(&server, future).await;

    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    let bundle = CredentialBundle::new(&did, &pk, &vta_did);

    let result = s.login(&bundle, &server.uri(), "k").await.unwrap();
    assert_eq!(result.client_did, did);
    assert_eq!(result.vta_did.as_deref(), Some(vta_did.as_str()));

    let status = s.session_status("k").unwrap();
    match status.token_status {
        TokenStatus::Valid { expires_in_secs } => assert!(expires_in_secs > 3000),
        other => panic!("expected Valid token, got {other:?}"),
    }
}

#[tokio::test]
async fn login_propagates_challenge_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/challenge"))
        .respond_with(ResponseTemplate::new(401).set_body_string("nope"))
        .mount(&server)
        .await;

    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    let bundle = CredentialBundle::new(&did, &pk, &vta_did);
    let err = s.login(&bundle, &server.uri(), "k").await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("challenge request failed") || msg.contains("401"),
        "expected challenge-failure surface, got: {msg}"
    );
}

#[tokio::test]
async fn ensure_authenticated_returns_cached_token_if_valid() {
    // Pre-populate a session with a token expiring far in the future.
    // ensure_authenticated should NOT touch the network — wiremock has
    // no /auth mocks mounted, so any HTTP attempt would fail.
    let server = MockServer::start().await;
    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);

    // Use login to populate a valid token via wiremock, then call
    // ensure_authenticated against a *different* (un-mocked) URL — the
    // cache should make that a no-op.
    mount_challenge(&server).await;
    let future = now_secs() + 3600;
    mount_authenticate(&server, future).await;
    let bundle = CredentialBundle::new(&did, &pk, &vta_did);
    s.login(&bundle, &server.uri(), "k").await.unwrap();

    // Different URL — would 404 if hit. Cached token means it isn't.
    let token = s
        .ensure_authenticated("http://127.0.0.1:1", "k")
        .await
        .unwrap();
    assert_eq!(token, "access-jwt");
}

#[tokio::test]
async fn ensure_authenticated_re_authenticates_when_token_expired() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    // Two sequential responses: first auth gives an expired token, second
    // gives a fresh one. wiremock matches in registration order with
    // up_to_n_times.
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
                "expiresIn": 100_u64
            }
        })))
        .up_to_n_times(1)
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
                "accessToken": "fresh",
                "tokenType": "Bearer",
                "expiresIn": future
            }
        })))
        .mount(&server)
        .await;

    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    let bundle = CredentialBundle::new(&did, &pk, &vta_did);
    s.login(&bundle, &server.uri(), "k").await.unwrap();

    // Cached token is expired → ensure_authenticated runs a new
    // challenge-response and returns the fresh token.
    let token = s.ensure_authenticated(&server.uri(), "k").await.unwrap();
    assert_eq!(token, "fresh");
}

#[tokio::test]
async fn ensure_authenticated_errors_when_no_session() {
    let s = store();
    let err = s
        .ensure_authenticated("http://localhost", "missing")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Not authenticated"),
        "expected 'Not authenticated' guidance, got: {msg}"
    );
}

#[tokio::test]
async fn ensure_authenticated_errors_when_pending_vta_binding() {
    // store_pending_vta_binding leaves vta_did = None. require_vta_did
    // (gated on entry to ensure_authenticated) must reject this state
    // with operator-actionable guidance.
    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    s.store_pending_vta_binding("k", &did, &pk).unwrap();
    let err = s
        .ensure_authenticated("http://localhost", "k")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("setup continue") || msg.contains("VTA"),
        "expected pending-binding guidance, got: {msg}"
    );
}

#[tokio::test]
async fn ensure_authenticated_runs_full_rotation_flow() {
    // Pending-rotation session: first auth as the temp DID succeeds,
    // then ensure_authenticated fetches the temp DID's ACL entry, mints
    // a fresh did:key, creates a new ACL entry, runs a *second*
    // challenge-response as the new DID, and best-effort deletes the
    // temp ACL entry.
    let server = MockServer::start().await;
    mount_challenge(&server).await;

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
                "accessToken": "temp-token",
                "tokenType": "Bearer",
                "expiresIn": future
            }
        })))
        .up_to_n_times(1)
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
                "accessToken": "rotated-token",
                "tokenType": "Bearer",
                "expiresIn": future
            }
        })))
        .mount(&server)
        .await;

    let (temp_did, temp_pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);

    // GET /acl/{temp_did} — return the entry the admin granted.
    Mock::given(method("GET"))
        .and(path(format!("/acl/{temp_did}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": temp_did,
            "role": "admin",
            "label": "ops",
            "allowed_contexts": ["primary"],
            "created_at": 1_700_000_000_u64,
            "created_by": "did:web:vta",
        })))
        .expect(1)
        .mount(&server)
        .await;

    // POST /acl — create entry for new DID. We don't know the new DID
    // ahead of time (it's randomly generated), so don't assert path
    // beyond /acl + method.
    Mock::given(method("POST"))
        .and(path("/acl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": "did:key:zNew",
            "role": "admin",
            "label": "ops",
            "allowed_contexts": ["primary"],
            "created_at": 1_700_000_000_u64,
            "created_by": "did:web:vta",
        })))
        .expect(1)
        .mount(&server)
        .await;

    // DELETE /acl/{temp_did} — best-effort cleanup of the temp DID.
    Mock::given(method("DELETE"))
        .and(path(format!("/acl/{temp_did}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let s = store();
    s.store_pending_rotation("k", &temp_did, &temp_pk, &vta_did)
        .unwrap();

    let token = s.ensure_authenticated(&server.uri(), "k").await.unwrap();
    assert_eq!(token, "rotated-token");

    // After rotation, the session reflects the *new* DID, not the temp.
    let info = s.loaded_session("k").unwrap();
    assert_ne!(info.client_did, temp_did, "rotation must replace temp DID");
    assert!(info.client_did.starts_with("did:key:"));
}

#[tokio::test]
async fn ensure_authenticated_rotation_fails_when_acl_read_fails() {
    // If the GET /acl/{temp_did} call fails, the rotation must bail
    // BEFORE deleting the temp ACL entry — so the temp DID stays
    // authoritative and the caller can retry.
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    let future = now_secs() + 3600;
    mount_authenticate(&server, future).await;

    let (temp_did, temp_pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);

    Mock::given(method("GET"))
        .and(path(format!("/acl/{temp_did}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("no entry yet"))
        .mount(&server)
        .await;

    // Important: NO /acl POST mock — if rotation tries to create a new
    // entry without a successful read, the test fails on the unmatched
    // request.

    let s = store();
    s.store_pending_rotation("k", &temp_did, &temp_pk, &vta_did)
        .unwrap();

    let err = s
        .ensure_authenticated(&server.uri(), "k")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("temp DID's ACL"),
        "expected ACL-read failure guidance, got: {msg}"
    );

    // Session is still the temp DID after a failed rotation.
    let info = s.loaded_session("k").unwrap();
    assert_eq!(info.client_did, temp_did);
}

// ── connect() with URL override (REST path) ─────────────────────────

#[tokio::test]
async fn connect_with_url_override_uses_rest_and_attaches_token() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
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
                "accessToken": "connect-token",
                "tokenType": "Bearer",
                "expiresIn": future
            }
        })))
        .mount(&server)
        .await;
    // Authenticated request after connect() returns: should carry the
    // token established during the auth round-trip.
    Mock::given(method("GET"))
        .and(path("/config"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer connect-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vta_did": null, "vta_name": null, "public_url": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);
    s.store_direct("k", &did, &pk, &vta_did).unwrap();

    let client = s.connect("k", Some(&server.uri()), None).await.unwrap();
    // Round-trip an authenticated call to prove the token was attached.
    client.get_config().await.unwrap();
}

// ── resolve_vta_url / resolve_vta_endpoint URL-fallback paths ───────
//
// These exercise the cache-resolver-fails → `url_from_did` fallback
// that runs against unreachable / unresolvable DIDs (the `did:web:`
// path looks up nothing on the network in test).

#[tokio::test]
async fn resolve_vta_url_falls_back_to_did_web_parse() {
    // The cache resolver tries to fetch `did:web:nonexistent.invalid`
    // and fails, so `resolve_vta_url` falls through to `url_from_did`,
    // which strips `did:web:` and produces `https://<host>`.
    let url = resolve_vta_url("did:web:vta.example.invalid")
        .await
        .unwrap();
    assert_eq!(url, "https://vta.example.invalid");
}

#[tokio::test]
async fn resolve_vta_url_falls_back_to_did_webvh_parse() {
    let url = resolve_vta_url("did:webvh:Qabc:vta.example.invalid:primary")
        .await
        .unwrap();
    assert_eq!(url, "https://vta.example.invalid");
}

#[tokio::test]
async fn resolve_vta_url_decodes_percent_encoded_port() {
    // `:` in the host segment is percent-encoded as `%3A`. The
    // fallback parser must decode it so the URL is usable.
    let url = resolve_vta_url("did:web:vta.example.invalid%3A8100")
        .await
        .unwrap();
    assert_eq!(url, "https://vta.example.invalid:8100");
}

#[tokio::test]
async fn resolve_vta_url_unparseable_did_errors() {
    // `did:key:` doesn't have a host segment — `url_from_did` returns
    // None, so `resolve_vta_url` errors with operator-actionable
    // guidance.
    let err = resolve_vta_url("did:key:z6Mkpub").await.unwrap_err();
    assert!(err.to_string().contains("Could not determine VTA URL"));
}

#[tokio::test]
async fn resolve_vta_endpoint_falls_back_to_rest_for_did_web() {
    let endpoint = resolve_vta_endpoint("did:web:vta.example.invalid")
        .await
        .unwrap();
    match endpoint {
        VtaEndpoint::Rest { url } => assert_eq!(url, "https://vta.example.invalid"),
        VtaEndpoint::DIDComm { .. } => panic!("expected Rest fallback, got DIDComm"),
    }
}

#[tokio::test]
async fn resolve_vta_endpoint_unparseable_did_errors() {
    let err = match resolve_vta_endpoint("did:key:z6Mkpub").await {
        Ok(_) => panic!("expected unparseable did:key to fail resolution"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("Could not determine VTA URL"));
}

#[tokio::test]
async fn connect_url_override_falls_back_to_rest() {
    // A session bound to an unresolvable did:key VTA still connects over
    // REST when the operator passes `--url`. Resolution (priority 2) yields
    // nothing usable for a did:key, and the authenticated DIDComm-status
    // discovery (priority 3) finds no live mediator (the status endpoint
    // isn't mounted → errors → None), so connect falls back to REST-only.
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    mount_authenticate(&server, now_secs() + 3600).await;

    let s = store();
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20); // did:key, no service entry
    s.store_direct("k", &did, &pk, &vta_did).unwrap();

    // Round-trip an authenticated call to prove the client is wired.
    Mock::given(method("GET"))
        .and(path("/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vta_did": null, "vta_name": null, "public_url": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = s
        .connect("k", Some(&server.uri()), None)
        .await
        .expect("connect with url override");
    client.get_config().await.unwrap();
}

// ── connect() ───────────────────────────────────────────────────────

#[tokio::test]
async fn connect_errors_when_no_session() {
    let s = store();
    let err = match s.connect("missing", Some("http://localhost"), None).await {
        Ok(_) => panic!("expected connect to fail with no session"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("auth login") || err.to_string().contains("Not authenticated")
    );
}
