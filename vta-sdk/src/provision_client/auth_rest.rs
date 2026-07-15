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

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::{Proof, TrustTask};

use crate::did_key::decode_private_key_multibase;
use crate::protocols::auth::{AuthenticateResponse, ChallengeRequest, ChallengeResponse};
use crate::session::TokenResult;
use crate::trust_tasks::TASK_AUTH_AUTHENTICATE_0_1;

/// The `did:key:zXxx#zXxx` verification-method id the Data-Integrity resolver
/// recognises for a `did:key` holder.
fn did_key_to_vm(did: &str) -> Option<String> {
    let mb = did.strip_prefix("did:key:")?;
    Some(format!("{did}#{mb}"))
}

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

    // Step 2 — build the `auth/authenticate/0.1` Trust Task. The payload is a
    // `Value` matching the spec `authenticate::Payload` shape
    // (`{ challenge, sessionId }`); the server deserializes it into the typed
    // payload after verifying the proof.
    let type_uri = TASK_AUTH_AUTHENTICATE_0_1
        .parse()
        .map_err(|e| format!("authenticate type URI parse: {e}"))?;
    let mut doc: TrustTask<Value> = TrustTask::new(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri,
        json!({
            "challenge": challenge.challenge,
            "sessionId": challenge.session_id,
        }),
    );
    doc.issuer = Some(client_did.to_string());
    doc.recipient = Some(vta_did.to_string());
    doc.issued_at = Some(Utc::now());

    // Step 3 — attach the holder's `eddsa-jcs-2022` Data-Integrity proof. Build
    // a `Secret` whose id is the `did:key:zXxx#zXxx` verification method, sign
    // the proof-less document (JCS is presence-sensitive — the server verifies
    // against the same shape with `proof` stripped), then graft the proof on.
    let vm_id = did_key_to_vm(client_did).ok_or_else(|| {
        format!("the DI-signed auth path requires a did:key holder; got {client_did}")
    })?;
    let seed = decode_private_key_multibase(private_key_multibase)?;
    let mut signer = Secret::generate_ed25519(Some(&vm_id), Some(&seed));
    signer.id = vm_id.clone();

    let sign_options = SignOptions::new()
        .with_proof_purpose("assertionMethod")
        .with_created(Utc::now());

    let mut signing_doc =
        serde_json::to_value(&doc).map_err(|e| format!("serialize authenticate document: {e}"))?;
    if let Some(obj) = signing_doc.as_object_mut() {
        obj.remove("proof");
    }
    let di_proof = DataIntegrityProof::sign(&signing_doc, &signer, sign_options)
        .await
        .map_err(|e| format!("sign authenticate Trust Task: {e}"))?;
    let proof_json =
        serde_json::to_value(&di_proof).map_err(|e| format!("serialize proof: {e}"))?;
    doc.proof =
        Some(serde_json::from_value::<Proof>(proof_json).map_err(|e| format!("proof shape: {e}"))?);

    // Step 4 — POST the signed document. A Trust Task request yields a TT
    // `#response` document whose payload is the `{ session, tokens }`
    // `AuthenticateResponse`.
    let auth_url = format!("{base_url}/auth/");
    let body =
        serde_json::to_string(&doc).map_err(|e| format!("serialize signed document: {e}"))?;
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
    // Accept either: try flat first, then unwrap the Trust-Task envelope.
    let auth_data: AuthenticateResponse = match serde_json::from_str(&auth_text) {
        Ok(flat) => flat,
        Err(_) => {
            let response_doc: TrustTask<Value> = serde_json::from_str(&auth_text).map_err(|e| {
                format!("unexpected auth response from VTA at {auth_url} (is this a VTA?): {e}")
            })?;
            serde_json::from_value(response_doc.payload)
                .map_err(|e| format!("auth response payload is not an AuthenticateResponse: {e}"))?
        }
    };
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
