//! Deliver issued credentials to a holder's wallet over DIDComm.
//!
//! When the VTC issues a credential to a member — at join auto-admit, at
//! admin-approve, or when a role change re-mints the role VEC — the holder needs
//! to actually *receive* it. The REST surfaces return the credential inline in
//! their response (for out-of-band hand-off), but a holder that interacted over
//! DIDComm, or one that's offline at approval/role-change time, has no inline
//! channel. This module pushes each credential to the holder over DIDComm.
//!
//! Each credential is wrapped in a `credential-exchange/issue` message — the same
//! one-way-deposit shape the holder's VTA receives via its
//! `handle_credential_issue` handler — packed authcrypt **to the proven holder**
//! (never the relayer) and forwarded via the holder's own mediator (resolved from
//! its DID document, falling back to the VTC's mediator for the shared-mediator
//! deployment). Sending is **best-effort**: the credential is already issued and
//! persisted, so the caller logs a delivery failure rather than unwinding the
//! decision.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_openid4vci::issuer::create_credential_response;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_vc::VerifiableCredential;
use serde_json::Value as JsonValue;
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::{ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody};
use vti_common::error::AppError;

use crate::ceremony::AdmitOutcome;
use crate::server::AppState;

/// Deliver the credentials a holder earned by being admitted — the
/// MembershipCredential and role EndorsementCredential of an [`AdmitOutcome`] —
/// into the holder's wallet over DIDComm. See [`deliver_credentials`].
pub(crate) async fn deliver_membership_credentials(
    state: &AppState,
    holder_did: &str,
    admit: &AdmitOutcome,
) -> Result<(), AppError> {
    deliver_credentials(state, holder_did, &[&admit.vmc, &admit.role_vec]).await
}

/// Deliver each of `credentials` to `holder_did` over DIDComm, one
/// `credential-exchange/issue` message apiece.
///
/// Packed authcrypt **to the proven holder** (not a relayer) and forwarded via
/// the holder's own mediator. Best-effort by nature (mediator delivery is
/// end-to-end): the first failure is returned so the caller can log it, but the
/// credentials are already issued and persisted — a failure must not unwind the
/// decision that issued them.
pub(crate) async fn deliver_credentials(
    state: &AppState,
    holder_did: &str,
    credentials: &[&VerifiableCredential],
) -> Result<(), AppError> {
    for credential in credentials {
        let credential_json = serde_json::to_value(credential)
            .map_err(|e| AppError::Internal(format!("issued credential serialise: {e}")))?;
        let body = issue_message_body(credential_json)?;
        // A fresh thread per delivered credential — `issue` is a one-way deposit,
        // not a request/response, so it needs no correlation to a prior thread.
        let msg_id = Uuid::new_v4().to_string();
        push_to_holder(state, holder_did, &msg_id, CREDENTIAL_ISSUE_TYPE, body).await?;
    }
    Ok(())
}

/// Wrap an issued credential JSON value in a `credential-exchange/issue` body —
/// the exact shape the holder's VTA extracts in its `handle_credential_issue` →
/// `store_issued_credential` path (`credential_response.credential`, here a W3C
/// Data-Integrity VC object). `sealed` is `None`: the holder is a proven,
/// resolvable DID, so the message is authcrypt-encrypted to it rather than
/// HPKE-sealed (sealing is the unknown-holder / invite case).
fn issue_message_body(credential_json: JsonValue) -> Result<JsonValue, AppError> {
    let issue = IssueBody {
        credential_response: Some(create_credential_response(credential_json, None, None)),
        sealed: None,
    };
    serde_json::to_value(&issue)
        .map_err(|e| AppError::Internal(format!("issue body serialise: {e}")))
}

/// Pack `body` as a DIDComm message (`msg_id` / `msg_type`) authcrypt to
/// `holder_did`, wrap it in a mediator forward, and send it.
///
/// The forward is addressed to the **holder's own mediator** (resolved from the
/// holder's DID document) and sent through the **VTC's own mediator** — the
/// mediator the VTC has a connection to. The VTC's mediator routes the forward
/// onward to the holder's mediator, which delivers it. When the holder advertises
/// no mediator, the VTC's own mediator is used as the forward target (the
/// shared-mediator deployment). Shared by the credential-query push and the
/// issued-credential delivery.
pub(crate) async fn push_to_holder(
    state: &AppState,
    holder_did: &str,
    msg_id: &str,
    msg_type: &str,
    body: JsonValue,
) -> Result<(), AppError> {
    let atm = state
        .atm
        .as_ref()
        .ok_or_else(|| AppError::Internal("messaging (ATM) not configured".into()))?;

    let (vtc_did, mediator_did) = {
        let config = state.config.read().await;
        let vtc_did = config
            .vtc_did
            .clone()
            .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;
        let mediator_did = config
            .messaging
            .as_ref()
            .map(|m| m.mediator_did.clone())
            .ok_or_else(|| AppError::Internal("no mediator configured for messaging".into()))?;
        (vtc_did, mediator_did)
    };

    // Resolve the holder's own mediator from its DID document; fall back to the
    // VTC's mediator (shared-mediator deployment) when the holder has none.
    let target_mediator = resolve_holder_mediator(state, holder_did)
        .await
        .unwrap_or_else(|| mediator_did.clone());

    // The VTC sends through its OWN mediator (the profile's connection); the
    // forward, addressed to the holder's mediator, is routed onward from there.
    let profile = Arc::new(
        ATMProfile::new(atm, None, vtc_did.clone(), Some(mediator_did.clone()))
            .await
            .map_err(|e| AppError::Internal(format!("ATM profile setup failed: {e}")))?,
    );

    let msg = Message::build(msg_id.to_string(), msg_type.to_string(), body)
        .from(vtc_did.clone())
        .to(holder_did.to_string())
        .finalize();

    // Send with a bounded retry. A transient mediator WebSocket failure (e.g.
    // "Connection reset by peer" / a disconnected socket) right around the
    // forward must not permanently drop an already-issued credential — nothing
    // re-pushes it, so the member would be stuck "Pending" forever. Each attempt
    // re-enables the websocket (the previous connection may be gone) and re-packs
    // the message; on the final attempt the error is returned so the caller can
    // log the best-effort failure.
    send_with_retry(
        atm,
        &profile,
        &msg,
        msg_id,
        holder_did,
        &vtc_did,
        &target_mediator,
    )
    .await
}

/// Backoff between credential-delivery send attempts. The schedule is the wait
/// *before* attempts 2, 3, and 4 — total of four attempts. Kept short and
/// in-request (this runs on the approve/admit path), so it rides out a transient
/// mediator WebSocket blip without holding the caller for long.
const DELIVERY_RETRY_BACKOFF: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

/// Enable the websocket, pack the message authcrypt to the holder, and forward
/// it through the VTC's mediator — retrying the whole send on failure with the
/// [`DELIVERY_RETRY_BACKOFF`] schedule.
///
/// Mediator delivery over a websocket is exactly where a transient reset
/// (`ConnectionReset` / a dropped/`Disconnected` socket) shows up, and any of the
/// three steps can surface it, so each attempt re-runs all three: re-enabling the
/// websocket reconnects a socket the previous attempt may have lost, and the pack
/// is cheap to redo. On success it returns immediately; once the attempts are
/// exhausted it returns the last error (the caller logs it best-effort).
async fn send_with_retry(
    atm: &affinidi_tdk::messaging::ATM,
    profile: &Arc<ATMProfile>,
    msg: &Message,
    msg_id: &str,
    holder_did: &str,
    vtc_did: &str,
    target_mediator: &str,
) -> Result<(), AppError> {
    let mut attempt = 0usize;
    loop {
        let result: Result<(), AppError> = async {
            atm.profile_enable_websocket(profile)
                .await
                .map_err(|e| AppError::Internal(format!("mediator websocket failed: {e}")))?;

            let (jwe, _meta) = atm
                .pack_encrypted(msg, holder_did, Some(vtc_did), None)
                .await
                .map_err(|e| AppError::Internal(format!("pack_encrypted failed: {e}")))?;

            atm.forward_and_send_message(
                profile,
                false,
                &jwe,
                Some(msg_id),
                target_mediator,
                holder_did,
                None,
                None,
                false,
            )
            .await
            .map_err(|e| AppError::Internal(format!("mediator forward failed: {e}")))?;

            Ok(())
        }
        .await;

        match result {
            Ok(()) => return Ok(()),
            Err(e) => match DELIVERY_RETRY_BACKOFF.get(attempt) {
                Some(delay) => {
                    tracing::warn!(
                        holder_did,
                        msg_id,
                        attempt = attempt + 1,
                        error = %e,
                        "credential delivery send failed; retrying after backoff"
                    );
                    tokio::time::sleep(*delay).await;
                    attempt += 1;
                }
                // Backoff schedule exhausted (all attempts used) — surface the
                // last error for the caller's best-effort log.
                None => return Err(e),
            },
        }
    }
}

/// Resolve the holder's own DIDComm mediator from its DID document — the `did:`
/// `uri` of its `DIDCommMessaging` service. Returns `None` when the holder
/// advertises no mediator (so the caller routes through its own).
async fn resolve_holder_mediator(state: &AppState, holder_did: &str) -> Option<String> {
    let resolver = state.did_resolver.as_ref()?;
    let resolved = resolver.resolve(holder_did).await.ok()?;
    for svc in &resolved.doc.service {
        if svc.type_.iter().any(|t| t == "DIDCommMessaging")
            && let Some(mediator) = svc
                .service_endpoint
                .get_uris()
                .into_iter()
                .map(|u| u.trim_matches('"').to_string())
                .find(|u| u.starts_with("did:"))
        {
            return Some(mediator);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn issue_message_body_matches_the_vta_receive_shape() {
        // A W3C-DI MembershipCredential as the VTC issues it.
        let vmc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:vtc.example",
            "credentialSubject": { "id": "did:key:zHolder", "community": "acme" },
            "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022" },
        });

        let body = issue_message_body(vmc.clone()).expect("wrap issue body");

        // The holder's VTA parses exactly this with IssueBody, then reads
        // `credential_response.credential` (a DI VC object) in store_issued_credential.
        let issue: IssueBody = serde_json::from_value(body).expect("parse as IssueBody");
        assert!(
            issue.sealed.is_none(),
            "a proven holder gets authcrypt, not a seal"
        );
        let credential = issue
            .credential_response
            .expect("credential_response present")
            .credential
            .expect("credential present");
        assert_eq!(
            credential, vmc,
            "the delivered credential round-trips intact"
        );
    }
}
