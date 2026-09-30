//! Push credential-exchange steps, and other VTC-originated Trust Tasks, to a
//! holder — over whichever transport the holder speaks.
//!
//! When the VTC issues a credential to a member — at join auto-admit, at
//! admin-approve, or when a role change re-mints the role VAC — the holder needs
//! to actually *receive* it. The REST surfaces return the credential inline in
//! their response (for out-of-band hand-off), but a holder that interacted over
//! messaging, or one that's offline at approval/role-change time, has no inline
//! channel. This module pushes each credential to the holder.
//!
//! Every step is a **signed Trust Task document** (`credential-exchange/issue`,
//! `query`, `offer`, `vtc/members/request-vmc`, `join-requests/submit-receipt`)
//! pushed through [`crate::member_push`]: TSP > DIDComm > REST by what the holder
//! advertises, durable on the delivery outbox, escalating when a transport yields
//! no evidence of delivery. None of these tasks defines a response document —
//! the counterparty's answer, when there is one, arrives later as the next task
//! in the thread. A step used to be a bare DIDComm message typed as its task URI,
//! which `bindings/didcomm/0.2` §2 requires a consumer to refuse, and which no
//! other transport can carry at all.
//!
//! Sending is **best-effort** for delivered credentials: the credential is
//! already issued and persisted, so the caller logs a delivery failure rather
//! than unwinding the decision.

use affinidi_openid4vci::issuer::create_credential_response;
use affinidi_vc::VerifiableCredential;
use serde_json::Value as JsonValue;
use vta_sdk::protocols::credential_exchange::{ISSUE as CREDENTIAL_ISSUE_TYPE, IssueBody};
use vti_common::capability_client::build_document;
use vti_common::error::AppError;

use crate::ceremony::AdmitOutcome;
use crate::server::AppState;

/// Deliver the credentials a holder earned by being admitted — the
/// MembershipCredential and role AuthorityCredential of an [`AdmitOutcome`] —
/// into the holder's wallet. See [`deliver_credentials`].
pub(crate) async fn deliver_membership_credentials(
    state: &AppState,
    holder_did: &str,
    admit: &AdmitOutcome,
) -> Result<(), AppError> {
    deliver_credentials(state, holder_did, &[&admit.vmc, &admit.role_vac]).await
}

/// Deliver each of `credentials` to `holder_did`, one signed
/// `credential-exchange/issue` document apiece, addressed **to the proven
/// holder** (not a relayer).
///
/// Failures are reported so the caller can log them, but the credentials are
/// already issued and persisted — a failure must not unwind the decision that
/// issued them.
///
/// # Every credential is attempted
///
/// This loop used to be `push_to_holder(..).await?`, which abandoned every
/// *remaining* credential the moment one failed. Admission delivers two — the
/// VMC and the role VAC — so a transient failure packing the second (holder DID
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
            // No thread: an unprompted delivery answers nothing, so it starts
            // its own.
            push_document(state, holder_did, CREDENTIAL_ISSUE_TYPE, body, Thread::New)
                .await
                .map(|_| ())
        };

        if let Err(e) = push.await {
            // Name the credential by type, not just position: "the role VAC did
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

/// Where a pushed step sits in its exchange.
pub(crate) enum Thread<'a> {
    /// Starts nothing and answers nothing — its own document `id` is the thread.
    New,
    /// Opens a thread whose root id the VTC has already committed to (a
    /// presentation challenge is keyed by it): the document takes this `id`, and
    /// the holder's answer carries it as `threadId`.
    Root(&'a str),
    /// Continues an existing thread — carried as the document's `threadId`.
    Reply(&'a str),
}

/// Sign `payload` as a `type_uri` Trust Task from this VTC to `holder_did` and
/// push it (see the module docs). Returns the pushed document's `id`.
///
/// This is the single outbound funnel for VTC-originated exchange steps. The
/// document is signed with the VTC's operational key under `authentication`
/// (VTI-KEY-106): the VTC composed it, and the holder's consumer binds that
/// proof to the transport sender.
pub(crate) async fn push_document(
    state: &AppState,
    holder_did: &str,
    type_uri: &str,
    payload: JsonValue,
    thread: Thread<'_>,
) -> Result<String, AppError> {
    let vtc_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;
    let signer = state
        .credential_signer
        .as_ref()
        .ok_or_else(|| AppError::Internal("credential signer not configured".into()))?;

    let mut doc = build_document(&vtc_did, holder_did, type_uri, payload);
    match thread {
        Thread::New => {}
        Thread::Root(id) => doc.id = id.to_string(),
        Thread::Reply(thread_id) => doc.thread_id = Some(thread_id.to_string()),
    }
    let id = doc.id.clone();
    // One key for every attempt at this step (VTI-OPS-064): the push engine
    // issues a new attempt — a fresh `id` — when the step outlives its
    // acceptance window, and an `issue` delivered twice would otherwise leave
    // the holder two copies of one credential.
    doc.extra
        .insert("idempotencyKey".to_string(), JsonValue::String(id.clone()));
    let mut doc_value = serde_json::to_value(&doc)
        .map_err(|e| AppError::Internal(format!("serialise {type_uri} document: {e}")))?;
    signer.sign_operational_doc(&mut doc_value).await?;

    crate::member_push::push_trust_task(
        state,
        holder_did,
        doc_value,
        crate::server::EXCHANGE_DELIVER_BY,
    )
    .await?;
    Ok(id)
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
    /// two — the VMC and the role VAC — so a transient failure on the second
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
        let vac: VerifiableCredential = serde_json::from_value(json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "AuthorityCredential"],
            "issuer": "did:web:vtc.example",
            "credentialSubject": { "id": "did:key:zHolder" },
        }))
        .expect("parse VAC");

        let err = deliver_credentials(&tv.state, "did:key:zHolder", &[&vmc, &vac])
            .await
            .expect_err("messaging is not running, so both pushes fail");
        let msg = err.to_string();

        assert!(
            msg.contains("MembershipCredential"),
            "the first credential must be named: {msg}"
        );
        assert!(
            msg.contains("AuthorityCredential"),
            "the second must be attempted too — naming only the first is the \
             short-circuit this test exists to catch: {msg}"
        );
        assert!(
            msg.contains("2 of 2"),
            "the summary should say how many of how many failed: {msg}"
        );
    }
}
