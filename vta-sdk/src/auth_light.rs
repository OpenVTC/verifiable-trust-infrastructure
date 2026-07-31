//! Lightweight challenge-response authentication for VTA REST clients.
//!
//! Same challenge-response flow as `session::challenge_response()`, but with no
//! ATM/TDK runtime and no mediator: the request is a DI-signed
//! `auth/authenticate/0.1` Trust Task (see [`crate::auth_di`]), the canonical
//! REST transport the VTA tries before its DIDComm-envelope path.
//!
//! **This module used to pack an anoncrypt DIDComm envelope** via
//! `didcomm_light` and throw the caller's private key away — the sender was
//! merely *asserted* in a plaintext `from` header. VTI #771 hardened `/auth/*`
//! to require an authenticated (authcrypt) envelope, which rejected every
//! anoncrypt message outright ("authenticate message must be an authenticated
//! (authcrypt) DIDComm envelope") and broke this whole tier: the VTC setup
//! wizard's did-hosting picker, `VtaClient`'s REST re-auth and refresh, and
//! `vtc-client`. Signing with the holder key both fixes that and is what the
//! server actually prefers.
//!
//! Consequence of the switch: the VTA verifies the proof with a `did:key`-only
//! resolver, so [`challenge_response_light`] requires a `did:key` holder and
//! returns [`VtaError::Validation`] for anything else. Callers holding another
//! DID method need `session::challenge_response` (DIDComm authcrypt), which
//! `integration::auth::try_rest` already falls back to.
//!
//! Feature gate: `client` (not `session`).

use crate::auth_di;
use crate::credentials::CredentialBundle;
use crate::error::VtaError;
use crate::protocols::auth::{ChallengeRequest, ChallengeResponse};
use reqwest::Client;

/// The per-request Trust-Task URL header.
///
/// The **VTC gates every route on it** (`vtc-service/src/routes/mod.rs`, the
/// `tt(...)` wrapper) and answers 400 without it; the VTA does not read it. So
/// omitting it made this client VTC-incompatible at the *transport* layer,
/// independently of the body — `vtc-client::connect` could not even reach the
/// authenticate handler. Sending it on every call is what lets one auth client
/// speak to both services.
///
/// Not sent on the VTC's `/wallet/auth/*` aliases, which are deliberately
/// header-exempt for the browser extension; those aren't this client's paths.
const TRUST_TASK_HEADER: &str = "Trust-Task";

/// Result of a successful authentication.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<u64>,
}

/// Perform challenge-response authentication without ATM/TDK runtime.
///
/// The lightweight equivalent of `session::challenge_response()`: the
/// challenge is answered with a DI-signed `auth/authenticate/0.1` Trust Task,
/// so the holder key proves the sender and no mediator is involved.
///
/// `client_did` must be a `did:key` — see the module docs.
pub async fn challenge_response_light(
    http: &Client,
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<AuthResult, crate::error::VtaError> {
    // Step 1: Request challenge
    let challenge_url = format!("{base_url}/auth/challenge");
    let challenge_resp = http
        .post(&challenge_url)
        .header(
            TRUST_TASK_HEADER,
            crate::trust_tasks::TASK_AUTH_CHALLENGE_0_1,
        )
        .json(&ChallengeRequest {
            did: client_did.to_string(),
        })
        .send()
        .await?;

    if !challenge_resp.status().is_success() {
        let status = challenge_resp.status();
        let body = challenge_resp.text().await.unwrap_or_default();
        return Err(VtaError::from_http(status, body));
    }

    let challenge: ChallengeResponse = challenge_resp.json().await?;

    // Step 2: Build + sign the authenticate Trust Task. Signing is local
    // (no DID resolution, no I/O): the holder's key is right here, and the
    // VTA resolves the proof's `did:key` verification method itself.
    let body = auth_di::sign_authenticate_doc(
        client_did,
        private_key_multibase,
        vta_did,
        &challenge.challenge,
        &challenge.session_id,
    )
    .await
    .map_err(|e| VtaError::Validation(e.to_string()))?;

    // Step 3: Send the signed document
    let auth_url = format!("{base_url}/auth/");
    let auth_resp = http
        .post(&auth_url)
        .header("content-type", "application/json")
        .header(
            TRUST_TASK_HEADER,
            crate::trust_tasks::TASK_AUTH_AUTHENTICATE_0_1,
        )
        .body(body)
        .send()
        .await?;

    if !auth_resp.status().is_success() {
        let status = auth_resp.status();
        let body = auth_resp.text().await.unwrap_or_default();
        return Err(VtaError::from_http(status, body));
    }

    let auth_data = auth_di::parse_auth_response(&auth_resp.text().await?)
        .map_err(|e| VtaError::Validation(e.to_string()))?;

    let access_expires_at = auth_data.access_expires_at_epoch().ok_or_else(|| {
        VtaError::Validation(format!(
            "VTA returned unparseable session.issuedAt: '{}'",
            auth_data.session.issued_at
        ))
    })?;
    let refresh_expires_at = auth_data.refresh_expires_at_epoch();
    Ok(AuthResult {
        access_token: auth_data.tokens.access_token,
        access_expires_at,
        refresh_token: auth_data.tokens.refresh_token,
        refresh_expires_at,
    })
}

/// Refresh an access token using the refresh token endpoint.
///
/// Returns a new `AuthResult` carrying a fresh access token **and a fresh
/// refresh token** — the VTA implements RFC 6749 §10.4 refresh-token
/// rotation, so the presented refresh token is single-use. Callers MUST
/// persist `result.refresh_token` and `result.refresh_expires_at` from
/// the returned value before the next refresh; replaying the original
/// token after a successful refresh fails with `Auth("refresh token not
/// found")`. The `VtaClient` handles this automatically (see
/// `client.rs::ensure_token_valid`).
///
/// Unlike [`challenge_response_light`] this carries no proof and works for a
/// holder of any DID method: the opaque refresh token *is* the credential
/// (RFC 6749 §10.4), so the VTA's Trust-Task refresh path verifies the token,
/// not a signer.
pub async fn refresh_token_light(
    http: &Client,
    base_url: &str,
    client_did: &str,
    vta_did: &str,
    refresh_token: &str,
) -> Result<AuthResult, crate::error::VtaError> {
    let body = auth_di::build_refresh_doc(client_did, vta_did, refresh_token)
        .map_err(|e| VtaError::Validation(e.to_string()))?;

    let refresh_url = format!("{base_url}/auth/refresh");
    let resp = http
        .post(&refresh_url)
        .header("content-type", "application/json")
        .header(TRUST_TASK_HEADER, crate::trust_tasks::TASK_AUTH_REFRESH_0_1)
        .body(body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(VtaError::from_http(status, body));
    }

    let auth_data = auth_di::parse_auth_response(&resp.text().await?)
        .map_err(|e| VtaError::Validation(e.to_string()))?;

    let access_expires_at = auth_data.access_expires_at_epoch().ok_or_else(|| {
        VtaError::Validation(format!(
            "VTA returned unparseable session.issuedAt: '{}'",
            auth_data.session.issued_at
        ))
    })?;
    let refresh_expires_at = auth_data.refresh_expires_at_epoch();
    Ok(AuthResult {
        access_token: auth_data.tokens.access_token,
        access_expires_at,
        refresh_token: auth_data.tokens.refresh_token,
        refresh_expires_at,
    })
}

/// Authenticate using an already-decoded credential bundle, returning an
/// `AuthResult`.
///
/// The second tuple element is a clone of the input bundle, echoed back for
/// callers that want a single expression yielding auth state + identity.
pub async fn authenticate_with_credential(
    credential: &CredentialBundle,
    url_override: Option<&str>,
) -> Result<(AuthResult, CredentialBundle, Client), crate::error::VtaError> {
    let url = url_override
        .or(credential.vta_url.as_deref())
        .ok_or_else(|| {
            VtaError::Validation("no VTA URL in credential and no override provided".into())
        })?;

    let http = Client::new();
    let result = challenge_response_light(
        &http,
        url,
        &credential.did,
        &credential.private_key_multibase,
        &credential.vta_did,
    )
    .await?;

    Ok((result, credential.clone(), http))
}
