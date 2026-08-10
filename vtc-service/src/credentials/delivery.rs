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
/// end-to-end): failures are reported so the caller can log them, but the
/// credentials are already issued and persisted — a failure must not unwind the
/// decision that issued them.
///
/// # Every credential is attempted
///
/// This loop used to be `push_to_holder(..).await?`, which abandoned every
/// *remaining* credential the moment one failed. Admission delivers two — the
/// VMC and the role VEC — so a transient failure packing the second (holder DID
/// resolution, say) meant the member got their membership credential, never got
/// their role credential, and never would: the enqueue that makes delivery
/// durable is the very step that was skipped, so there was nothing to retry.
/// The caller only `warn!`s, so the member's wallet was simply missing a
/// credential with nothing but a log line to say why.
///
/// Independent one-way deposits have no reason to share a fate. Each is now
/// attempted regardless of what happened to the others, and the error names
/// every one that failed — a caller that logs it can say *which* credential to
/// re-deliver, which the previous first-failure-wins error could not.
pub(crate) async fn deliver_credentials(
    state: &AppState,
    holder_did: &str,
    credentials: &[&VerifiableCredential],
) -> Result<(), AppError> {
    let mut failures: Vec<String> = Vec::new();

    for (index, credential) in credentials.iter().enumerate() {
        // `push_of` is fallible at three points (serialise, wrap, send); running
        // it as one unit keeps a failure at any of them from skipping the rest.
        let push = async {
            let credential_json = serde_json::to_value(credential)
                .map_err(|e| AppError::Internal(format!("issued credential serialise: {e}")))?;
            let body = issue_message_body(credential_json)?;
            // A fresh thread per delivered credential — `issue` is a one-way
            // deposit, not a request/response, so it needs no correlation to a
            // prior thread.
            let msg_id = Uuid::new_v4().to_string();
            push_to_holder(state, holder_did, &msg_id, CREDENTIAL_ISSUE_TYPE, body).await
        };

        if let Err(e) = push.await {
            // Name the credential by type, not just position: "the role VEC did
            // not go" is actionable where "credential 2 of 2" is a puzzle.
            let kind = credential_kind(credential);
            tracing::warn!(
                holder = %holder_did,
                credential = %kind,
                error = %e,
                "credential delivery failed; continuing with the rest"
            );
            failures.push(format!("{kind} (#{}): {e}", index + 1));
        }
    }

    if failures.is_empty() {
        return Ok(());
    }
    Err(AppError::Internal(format!(
        "{} of {} credential(s) failed to deliver to {holder_did}: {}",
        failures.len(),
        credentials.len(),
        failures.join("; ")
    )))
}

/// The most specific `type` on a VC, for diagnostics — `MembershipCredential`
/// rather than the `VerifiableCredential` every one of them carries.
fn credential_kind(credential: &VerifiableCredential) -> String {
    serde_json::to_value(credential)
        .ok()
        .and_then(|v| {
            v.get("type").and_then(|t| t.as_array()).and_then(|types| {
                types
                    .iter()
                    .filter_map(|t| t.as_str())
                    .find(|t| *t != "VerifiableCredential")
                    .map(str::to_string)
            })
        })
        .unwrap_or_else(|| "credential".to_string())
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

    /// The most specific type is what names the credential in a failure.
    #[test]
    fn credential_kind_names_the_specific_type() {
        let vmc: VerifiableCredential = serde_json::from_value(json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:vtc.example",
            "credentialSubject": { "id": "did:key:zHolder" },
        }))
        .expect("parse VMC");
        assert_eq!(credential_kind(&vmc), "MembershipCredential");
    }

    /// One credential failing must not abandon the others.
    ///
    /// The loop was `push_to_holder(..).await?`, so the first failure returned
    /// and every remaining credential was silently dropped. Admission delivers
    /// two — the VMC and the role VEC — so a transient failure on the second
    /// left the member holding one credential, with no retry possible: the
    /// enqueue that makes delivery durable is the step that was skipped. The
    /// caller only `warn!`s, so nothing surfaced but a log line.
    ///
    /// Driven with messaging deliberately **not** running, which makes every
    /// push fail identically. That is the point: if delivery still short-
    /// circuited, the error would name one credential. It must name both,
    /// because both must have been attempted.
    #[tokio::test]
    async fn a_failed_credential_does_not_abandon_the_rest() {
        let tv = crate::test_support::build_test_vtc().await;

        let vmc: VerifiableCredential = serde_json::from_value(json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:web:vtc.example",
            "credentialSubject": { "id": "did:key:zHolder" },
        }))
        .expect("parse VMC");
        let vec_: VerifiableCredential = serde_json::from_value(json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "EndorsementCredential"],
            "issuer": "did:web:vtc.example",
            "credentialSubject": { "id": "did:key:zHolder" },
        }))
        .expect("parse VEC");

        let err = deliver_credentials(&tv.state, "did:key:zHolder", &[&vmc, &vec_])
            .await
            .expect_err("messaging is not running, so both pushes fail");
        let msg = err.to_string();

        assert!(
            msg.contains("MembershipCredential"),
            "the first credential must be named: {msg}"
        );
        assert!(
            msg.contains("EndorsementCredential"),
            "the second must be attempted too — naming only the first is the \
             short-circuit this test exists to catch: {msg}"
        );
        assert!(
            msg.contains("2 of 2"),
            "the summary should say how many of how many failed: {msg}"
        );
    }
}
