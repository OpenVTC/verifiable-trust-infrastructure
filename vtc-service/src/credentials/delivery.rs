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

use affinidi_messaging_didcomm::Message;
use affinidi_openid4vci::issuer::create_credential_response;
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

/// Pack `body` as a DIDComm message (`msg_id` / `msg_type`) from the VTC to
/// `holder_did` and send it over the VTC's **shared inbound mediator
/// connection** via [`AppState::send_to_member`].
///
/// This is the single outbound funnel — credential-query push, issued-credential
/// delivery, and the member-VMC request all go through it. Routing the send
/// through the running listener's connection is deliberate: the mediator allows
/// one websocket per DID, so an outbound path must reuse that connection rather
/// than open its own (a second one made the mediator terminate connections with
/// `w.websocket.duplicate-channel`, and the auto-reconnecting sockets then
/// duelled). The listener packs authcrypt and forwards through the VTC's
/// mediator — the same path inbound replies already take to reach members.
pub(crate) async fn push_to_holder(
    state: &AppState,
    holder_did: &str,
    msg_id: &str,
    msg_type: &str,
    body: JsonValue,
) -> Result<(), AppError> {
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;

    let message = Message::build(msg_id.to_string(), msg_type.to_string(), body)
        .from(vtc_did)
        .to(holder_did.to_string())
        .finalize();

    state.send_to_member(holder_did, message).await
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
