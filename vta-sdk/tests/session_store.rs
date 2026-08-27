//! Coverage for `vta_sdk::session::SessionStore` and its backends.
//!
//! Three test layers:
//!   1. **Backend ops** — pure storage round-trips with the in-memory
//!      backend (`store_direct`, `store_pending_rotation`,
//!      `loaded_session`, `session_status`, `logout`).
//!   2. **Backend selection** — what `SessionStore::new(...)` resolves to when
//!      no backend feature is compiled in. There is no longer a silent
//!      plaintext fallback (#1027), so this asserts a refusal. `FileBackend`'s
//!      own round-trip and file-mode coverage lives in unit tests beside it in
//!      `session/backends/file.rs`, where it runs under the workspace's
//!      unified feature set instead of being cfg'd out of every CI run.
//!   3. **Network paths** — `login` / `ensure_authenticated` /
//!      `rotate_key` against a `wiremock` server, using `did:key` DIDs
//!      so TDK's resolver doesn't need outbound DNS.
//!
//! The layer-3 stubs serve `POST /trust-tasks` — the Trust-Task HTTPS binding —
//! and answer with a `#response` document whose `payload` is what the client
//! returns. They used to serve bespoke REST routes (`GET /config`,
//! `GET|POST|DELETE /acl…`), which the SDK no longer calls. Nothing caught the
//! drift because nothing compiled this file: it is gated on `session` +
//! `test-support`, and no CI step built that pair until one was added for
//! exactly this class of rot.

#![cfg(all(feature = "session", feature = "test-support"))]

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde_json::json;
#[cfg(not(any(
    feature = "keyring",
    feature = "azure-secrets",
    feature = "config-session"
)))]
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

// ── Backend selection ───────────────────────────────────────────────
//
// Under a workspace test run the `keyring` feature is unified on (pnm-cli /
// cnm-cli enable it), so `default_backend` returns `KeyringBackend` and the
// tests below are cfg'd out. That was already true of the `FileBackend` tests
// that used to live here — which is why their round-trip and file-mode coverage
// moved into unit tests beside the backend, where the workspace's unified
// feature set actually runs them. What remains here is only the selection
// contract, which cannot be observed from inside the module.

/// With no backend feature compiled in, a session store must refuse rather than
/// invent somewhere to put a private key.
///
/// This replaces `file_backend_round_trips_via_session_store_new`, which
/// asserted the opposite: that the feature cascade silently landed on
/// `FileBackend` and wrote `sessions.json` at the process umask. That fallback
/// is gone — a store holding an admin key is now always an explicit choice.
#[cfg(not(any(
    feature = "keyring",
    feature = "azure-secrets",
    feature = "config-session"
)))]
#[test]
fn no_compiled_backend_refuses_to_store_a_session() {
    let dir = tempdir().unwrap();
    let store = SessionStore::new("test-svc", dir.path().to_path_buf());

    let (did, pk) = did_key_from_seed(0x30);
    let (vta_did, _) = did_key_from_seed(0x40);

    let err = store
        .store_direct("file-k", &did, &pk, &vta_did)
        .expect_err("a build with no session store must not persist a private key");
    let msg = err.to_string();
    assert!(
        msg.contains("VTI_SECURE_STORE"),
        "the refusal must name the deliberate opt-out, got: {msg}"
    );

    assert!(
        !dir.path().join("sessions.json").exists(),
        "refusing to store must not leave a plaintext file behind"
    );
}

/// Pointing at a non-existent path must not panic; load returns None.
#[cfg(not(any(
    feature = "keyring",
    feature = "azure-secrets",
    feature = "config-session"
)))]
#[test]
fn load_on_missing_dir_returns_none() {
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

    // `POST /acl/swap` — one atomic operation, and the reason this stub is a
    // single mock where it used to be three. Rotation was read-the-entry,
    // create-under-the-new-DID, delete-the-temp; `acl/swap-key` moves the
    // entry's role and contexts onto the new DID in one step, so there is no
    // window in which both DIDs are privileged. The new DID is minted inside
    // `rotate_key` and unknown here, which is exactly why the swap carries a
    // VP-JWT proving control of it rather than the caller naming it.
    Mock::given(method("POST"))
        .and(path("/acl/swap"))
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
async fn ensure_authenticated_rotation_leaves_the_temp_did_authoritative_on_failure() {
    // This used to assert that a failed `GET /acl/{temp_did}` bailed *before*
    // the delete, so the temp entry survived. That hazard is gone: rotation is
    // one atomic `acl/swap-key`, not read-create-delete, so there is no
    // half-applied state to protect against.
    //
    // What still matters is the caller-visible half — a refused swap must leave
    // the stored session on the temp DID, so the operator can fix the ACL and
    // retry with the credential they still hold.
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    let future = now_secs() + 3600;
    mount_authenticate(&server, future).await;

    let (temp_did, temp_pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);

    Mock::given(method("POST"))
        .and(path("/acl/swap"))
        .respond_with(ResponseTemplate::new(403).set_body_string("no entry for the temp DID"))
        .mount(&server)
        .await;

    let s = store();
    s.store_pending_rotation("k", &temp_did, &temp_pk, &vta_did)
        .unwrap();

    let err = s
        .ensure_authenticated(&server.uri(), "k")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("acl/swap-key failed"),
        "the error must name the operation that refused, got: {msg}"
    );
    assert!(
        msg.contains("import-did"),
        "and the remedy an operator can act on, got: {msg}"
    );

    // The session is still the temp DID, so the retry has a credential to use.
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
    // `get_config()` dispatches `config/show/0.1`; the bearer assertion is the
    // point of the call, so it stays on the binding endpoint.
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(wiremock::matchers::body_partial_json(json!({
            "type": "https://trusttasks.org/spec/config/show/0.1"
        })))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer connect-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "urn:uuid:stub-response",
            "type": "https://trusttasks.org/spec/config/show/0.1#response",
            "issuedAt": "2026-01-01T00:00:00Z",
            "payload": { "fields": [] },
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
        // `VtaEndpoint` is `#[non_exhaustive]`; any non-Rest transport is a
        // failure here, so catch the rest in one arm.
        _ => panic!("expected Rest fallback, got a non-Rest transport"),
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
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(wiremock::matchers::body_partial_json(json!({
            "type": "https://trusttasks.org/spec/config/show/0.1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "urn:uuid:stub-response",
            "type": "https://trusttasks.org/spec/config/show/0.1#response",
            "issuedAt": "2026-01-01T00:00:00Z",
            "payload": { "fields": [] },
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

// ── VtaClient::connect_auto ─────────────────────────────────────────
//
// The DIDComm arm needs a live mediator round-trip, so only the REST
// arm and the transport-selection guards are exercised here. The
// `rest_fallback = (!vta_url.is_empty()).then(...)` derivation on the
// DIDComm arm is unit-trivial and shared with `connect_didcomm`.

#[tokio::test]
async fn connect_auto_rest_authenticates_and_returns_token() {
    let server = MockServer::start().await;
    mount_challenge(&server).await;
    let future = now_secs() + 3600;
    mount_authenticate(&server, future).await;
    // An authenticated call must carry the token established at connect.
    Mock::given(method("POST"))
        .and(path("/trust-tasks"))
        .and(wiremock::matchers::body_partial_json(json!({
            "type": "https://trusttasks.org/spec/config/show/0.1"
        })))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer access-jwt",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "urn:uuid:stub-response",
            "type": "https://trusttasks.org/spec/config/show/0.1#response",
            "issuedAt": "2026-01-01T00:00:00Z",
            "payload": { "fields": [] },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);

    let connected = vta_sdk::client::VtaClient::connect_auto(vta_sdk::client::AutoConnect {
        vta_url: &server.uri(),
        vta_did: &vta_did,
        credential_did: &did,
        private_key_multibase: &pk,
        mediator_did: None,
    })
    .await
    .expect("REST connect_auto");

    // REST path surfaces the issued token so callers can cache it.
    let token = connected.rest_token.expect("rest path returns a token");
    assert_eq!(token.access_token, "access-jwt");
    // ...and the same token is attached to the client.
    connected.client.get_config().await.unwrap();
}

#[tokio::test]
async fn connect_auto_rest_requires_non_empty_url() {
    let (did, pk) = did_key_from_seed(0x10);
    let (vta_did, _) = did_key_from_seed(0x20);

    let result = vta_sdk::client::VtaClient::connect_auto(vta_sdk::client::AutoConnect {
        vta_url: "",
        vta_did: &vta_did,
        credential_did: &did,
        private_key_multibase: &pk,
        mediator_did: None,
    })
    .await;

    match result {
        Err(vta_sdk::error::VtaError::Validation(_)) => {}
        Ok(_) => panic!("empty url on the REST path must error"),
        Err(other) => panic!("expected Validation error, got {other:?}"),
    }
}
