//! DI-signed (`eddsa-jcs-2022`) REST authentication for the provision-client.
//!
//! The provision REST legs previously authenticated via
//! [`crate::session::challenge_response`], which packs a **DIDComm** envelope
//! the VTA unpacks with its ATM. A REST-only VTA (no mediator / ATM) rejects
//! that with `ATM not configured`, so provisioning over plain REST against
//! such a VTA was impossible — see issue #406's MockVta e2e.
//!
//! This module implements the *canonical* REST auth the VTA tries first
//! (`vta-service/src/routes/auth.rs::try_authenticate_trust_task`): a plain
//! `auth/authenticate/0.1` Trust Task whose holder `eddsa-jcs-2022`
//! Data-Integrity proof **is** the authentication — no DIDComm packing, no
//! mediator. It mirrors `vta-mobile-core::build_authenticate`, but signs
//! in-process with the holder key (which the provision-client owns) via the
//! same [`DataIntegrityProof::sign`] primitive the VP signer uses
//! ([`crate::provision_integration::request`]).
//!
//! It works against *any* VTA — REST-only or DIDComm-enabled — because the
//! server attempts the DI path before the DIDComm-envelope path.
//!
//! The document building / signing / response parsing lives in
//! [`crate::auth_di`], shared with [`crate::auth_light`] (the REST client tier,
//! which moved onto this same transport once the VTA started requiring an
//! authenticated sender on `/auth/*`). This module is the provision-client's
//! entry point onto it.

use crate::auth_di;
use crate::protocols::auth::{ChallengeRequest, ChallengeResponse};
use crate::session::TokenResult;

/// Authenticate over plain REST using a DI-signed `auth/authenticate/0.1`
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

    // Step 1 — request a challenge. Flat `{ subject }` request → canonical
    // `{ challenge, sessionId, expiresAt }` response.
    let challenge_url = format!("{base_url}/auth/challenge");
    let challenge_resp = http
        .post(&challenge_url)
        .json(&ChallengeRequest {
            did: client_did.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {challenge_url}: {e}"))?;
    if !challenge_resp.status().is_success() {
        let status = challenge_resp.status();
        let body = challenge_resp.text().await.unwrap_or_default();
        return Err(format!("challenge request failed ({status}): {body}").into());
    }
    let challenge: ChallengeResponse = challenge_resp.json().await.map_err(|e| {
        format!("unexpected challenge response from VTA at {challenge_url} (is this a VTA?): {e}")
    })?;

    // Step 2 — build + sign the `auth/authenticate/0.1` Trust Task with the
    // holder key (payload `{ challenge, sessionId }`, `eddsa-jcs-2022` proof
    // over the proof-less document).
    let body = auth_di::sign_authenticate_doc(
        client_did,
        private_key_multibase,
        vta_did,
        &challenge.challenge,
        &challenge.session_id,
    )
    .await?;

    // Step 3 — POST the signed document. A Trust Task request yields a TT
    // `#response` document whose payload is the `{ session, tokens }`
    // `AuthenticateResponse`.
    let auth_url = format!("{base_url}/auth/");
    let auth_resp = http
        .post(&auth_url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("could not connect to VTA at {auth_url}: {e}"))?;
    let status = auth_resp.status();
    if !status.is_success() {
        let body = auth_resp.text().await.unwrap_or_default();
        return Err(format!("authentication failed ({status}): {body}").into());
    }
    let auth_text = auth_resp
        .text()
        .await
        .map_err(|e| format!("failed to read auth response from VTA: {e}"))?;
    // A Trust-Task request yields a TT `#response` document whose payload is the
    // `{ session, tokens }` body; some clients/mocks return that body flat.
    let auth_data =
        auth_di::parse_auth_response(&auth_text).map_err(|e| format!("{e} (VTA at {auth_url})"))?;
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
