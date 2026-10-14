//! DI-signed (`eddsa-jcs-2022`) REST authentication for the provision-client.
//!
//! This is the *canonical* auth transport the VTA serves: a
//! pre-session, family-owned dispatch on `POST /trust-tasks`
//! (`vta-service::trust_tasks::auth::owns`/`dispatch_pre_session`) whose
//! `auth/authenticate/0.2` document's holder `eddsa-jcs-2022` Data-Integrity
//! proof **is** the authentication — no DIDComm packing, no mediator. It
//! mirrors `vta-mobile-core::build_authenticate`, but signs in-process with
//! the holder key (which the provision-client owns) via the same
//! [`DataIntegrityProof::sign`] primitive the VP signer uses
//! ([`crate::provision_integration::request`]).
//!
//! It works against *any* VTA — REST-only or DIDComm/TSP-enabled — since the
//! document's own proof is checked identically on every transport.
//!
//! The document building / signing / response parsing lives in
//! [`crate::auth_di`], shared with [`crate::auth_light`] (the REST client
//! tier). This module is the provision-client's entry point onto it.

use crate::auth_di;
use crate::session::TokenResult;

/// Authenticate over plain REST using a DI-signed `auth/authenticate/0.2`
/// Trust Task, returning the same [`TokenResult`] as
/// [`crate::session::challenge_response`].
///
/// `client_did` must be a `did:key` whose private seed is
/// `private_key_multibase` (the holder/setup key); `vta_did` is the VTA the
/// document is addressed to. No DIDComm / mediator is involved.
///
/// This is the cryptographically-sound REST auth (the key signs the request),
/// suitable for any client that *holds* a key — e.g. a fleet manager
/// authenticating as a per-VTA super-admin. Re-exported as
/// [`crate::provision_client::challenge_response_di`].
pub async fn challenge_response_di(
    base_url: &str,
    client_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult, Box<dyn std::error::Error>> {
    let http = crate::http::rest_client();
    let trust_tasks_url = format!("{base_url}/trust-tasks");

    // Step 1 — request a challenge: a Trust-Task document POSTed to
    // `/trust-tasks`, not the flat `{ subject }` shape the retired
    // `/auth/challenge` REST route once accepted.
    let challenge_body = auth_di::build_challenge_doc(client_did, vta_did, client_did)?;
    let challenge_resp = http
        .post(&trust_tasks_url)
        .header("content-type", "application/json")
        // Trust-Task URL header: required by the VTC, ignored by the VTA. See
        // `crate::auth_light::TRUST_TASK_HEADER`.
        .header("Trust-Task", crate::trust_tasks::TASK_AUTH_CHALLENGE_0_1)
        .body(challenge_body)
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {trust_tasks_url}: {e}"))?;
    if !challenge_resp.status().is_success() {
        let status = challenge_resp.status();
        let headers = challenge_resp.headers().clone();
        let body = challenge_resp.text().await.unwrap_or_default();
        // A rate limit stays typed: as a string it reads as an auth failure.
        if let Some(e) = crate::error::VtaError::rate_limited_from_http(
            status,
            &headers,
            &body,
            &trust_tasks_url,
        ) {
            return Err(e.into());
        }
        return Err(format!("challenge request failed ({status}): {body}").into());
    }
    let server_date = crate::auth_light::response_date(challenge_resp.headers());
    let challenge_text = challenge_resp
        .text()
        .await
        .map_err(|e| format!("failed to read challenge response from VTA: {e}"))?;
    let challenge = auth_di::parse_challenge_response(&challenge_text).map_err(|e| {
        format!("unexpected challenge response from VTA at {trust_tasks_url} (is this a VTA?): {e}")
    })?;

    // Steps 2–3 — sign the `auth/authenticate/0.2` Trust Task with the holder
    // key (payload `{ challenge, sessionId }`, `eddsa-jcs-2022` proof over the
    // proof-less document) and POST it. A rate-limited authenticate is retried
    // with this same challenge while it is valid, never by starting over —
    // see `auth_light::redeem_challenge`. A rate limit that outlasts it stays
    // typed: as a string it reads as an auth failure.
    let deadline = crate::auth_light::authenticate_deadline(
        &challenge.expires_at,
        server_date.as_deref(),
        chrono::Utc::now(),
    );
    let auth_text = crate::auth_light::redeem_challenge(
        &http,
        &trust_tasks_url,
        client_did,
        private_key_multibase,
        vta_did,
        &challenge,
        deadline,
    )
    .await?;
    // A Trust-Task request yields a TT `#response` document whose payload is the
    // `{ session, tokens }` body; some clients/mocks return that body flat.
    let auth_data = auth_di::parse_auth_response(&auth_text)
        .map_err(|e| format!("{e} (VTA at {trust_tasks_url})"))?;
    let access_expires_at = auth_data.access_expires_at_epoch().ok_or_else(|| {
        format!(
            "VTA returned unparseable session.issuedAt: '{}'",
            auth_data.session.issued_at
        )
    })?;

    Ok(TokenResult {
        access_token: auth_data.tokens.access_token,
        access_expires_at,
    })
}
