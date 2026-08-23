//! Telling a member the community removed them
//! (`spec/vtc/members/removal-notice/0.1`).
//!
//! Removal is the most consequential thing a community does to a member and,
//! before this, the one it delivered with the least information — none. The
//! only signal a removed member could observe was a side effect: the revocation
//! bit on their membership credential flipping. They inferred their own removal
//! from a status list and learned nothing about why.
//!
//! ## Not a receipt
//!
//! [`MEMBER_SELF_REMOVE_RECEIPT_TYPE`](vta_sdk::protocols::join_requests::MEMBER_SELF_REMOVE_RECEIPT_TYPE)
//! answers a request the member made, correlated to it by `thid`, and the member
//! is already waiting. This answers nothing: the member did not ask, is not
//! waiting, and may be offline. [`send`] is therefore an unsolicited push rather
//! than a reply, and it must never fire for a self-leave — telling somebody who
//! chose to leave that they were removed is worse than silence.
//!
//! ## Signed, because the recipient is not the audience
//!
//! Authcrypt already proves the sender to the *member*. But this is the one
//! member-facing message whose value lies in showing it to somebody else — an
//! appeal, a dispute, another community weighing a rejected applicant. An
//! unsigned notice, forwarded, is an assertion anyone could have written. So the
//! notice is a Trust Task document carrying a Data Integrity proof, packed in
//! the trust-task envelope, exactly as [`crate::hooks::writer`] does.
//!
//! Note the envelope type is [`TRUST_TASK_ENVELOPE_TYPE`], **not** the task URI.
//! Hand-building a DIDComm message with the task URI as its `type` is a mistake
//! this workspace has made before, and a conformant peer rejects it silently.
//!
//! ## Delivery, and the member who cannot ask
//!
//! The act this reports is the act that ends the member's ability to ask about
//! it. Removal hard-deletes their ACL row and
//! [`resolve_auth_role`](crate::acl::resolve_auth_role) refuses any DID without
//! one, so every authenticated route — including any poll that might have
//! served the notice — is closed to them from the moment the removal lands. The
//! push is the only channel, which is why it goes out under
//! `REMOVAL_NOTICE_DELIVER_BY` rather than the ordinary one-day window.
//!
//! ## Best-effort, deliberately
//!
//! [`send`] never fails the removal. The removal has already happened and is
//! durable; refusing to complete the operator's request because the notice
//! could not be *queued* would leave the member removed and the operator
//! believing they were not. A failure is logged loudly and audited instead.

use tracing::{info, warn};

use vta_sdk::protocols::members::{MEMBER_REMOVAL_NOTICE_TYPE, RemovalCode, RemovalNoticeBody};
use vti_common::capability_client::{TRUST_TASK_ENVELOPE_TYPE, build_document};

use crate::error::AppError;
use crate::server::AppState;

/// Send a removal notice, best-effort.
///
/// Call **after** the removal has taken effect — a notice for a removal that
/// then fails is worse than none. `decided_at` is that moment, not the send
/// time; the two diverge whenever the member is offline, and it is the decision
/// a member or a third party needs to place in time.
///
/// `reason` is `None` when the operator gave none, which is a different claim
/// from an empty string and stays distinguishable on the wire.
///
/// Errors are logged and swallowed: see the module docs for why the removal
/// must not be undone by a delivery problem.
pub async fn send(
    state: &AppState,
    target_did: &str,
    code: RemovalCode,
    disposition: &str,
    reason: Option<String>,
    decided_at: &str,
    decided_by: &str,
) {
    if let Err(e) = try_send(
        state,
        target_did,
        code,
        disposition,
        reason,
        decided_at,
        decided_by,
    )
    .await
    {
        // Loud, because the member is now removed and does not know it, and
        // nothing downstream will retry beyond the delivery layer's own window.
        warn!(
            error = %e,
            target = target_did,
            ?code,
            "removal notice could not be queued — the member was removed without being told"
        );
    }
}

/// The fallible body of [`send`], separated so the error can be logged in one
/// place and tested directly.
async fn try_send(
    state: &AppState,
    target_did: &str,
    code: RemovalCode,
    disposition: &str,
    reason: Option<String>,
    decided_at: &str,
    decided_by: &str,
) -> Result<(), AppError> {
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

    let body = RemovalNoticeBody {
        did: target_did.to_string(),
        code,
        disposition: disposition.to_string(),
        // An operator who typed nothing and an operator who gave no reason are
        // the same thing to a member, and neither is "reason: \"\"".
        reason: reason.filter(|r| !r.trim().is_empty()),
        decided_at: decided_at.to_string(),
        decided_by: decided_by.to_string(),
    };
    let payload = serde_json::to_value(&body)
        .map_err(|e| AppError::Internal(format!("serialise removal notice: {e}")))?;

    let doc = build_document(&vtc_did, target_did, MEMBER_REMOVAL_NOTICE_TYPE, payload);
    let mut doc_value = serde_json::to_value(&doc)
        .map_err(|e| AppError::Internal(format!("serialise removal-notice document: {e}")))?;
    signer.sign_doc(&mut doc_value).await?;

    let envelope = affinidi_messaging_didcomm::Message::build(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        TRUST_TASK_ENVELOPE_TYPE.to_string(),
        doc_value,
    )
    .from(vtc_did)
    .to(target_did.to_string())
    .finalize();

    state
        .send_to_member_by(
            target_did,
            envelope,
            crate::server::REMOVAL_NOTICE_DELIVER_BY,
        )
        .await?;

    info!(
        target = target_did,
        ?code,
        disposition,
        "removal notice queued"
    );
    Ok(())
}

/// Build the notice payload without sending it. Split out so the wire shape can
/// be asserted without a running mediator.
#[cfg(test)]
fn notice_payload(
    target_did: &str,
    code: RemovalCode,
    disposition: &str,
    reason: Option<String>,
    decided_at: &str,
    decided_by: &str,
) -> serde_json::Value {
    serde_json::to_value(RemovalNoticeBody {
        did: target_did.to_string(),
        code,
        disposition: disposition.to_string(),
        reason: reason.filter(|r| !r.trim().is_empty()),
        decided_at: decided_at.to_string(),
        decided_by: decided_by.to_string(),
    })
    .expect("RemovalNoticeBody serialises")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn payload_carries_every_question_a_removed_member_has() {
        let p = notice_payload(
            "did:key:zRemoved",
            RemovalCode::AdminRemoved,
            "tombstone",
            Some("Repeated code-of-conduct breach.".into()),
            "2026-08-23T09:14:02Z",
            "did:key:zAdmin",
        );
        assert_eq!(
            p,
            json!({
                "did": "did:key:zRemoved",
                "code": "adminRemoved",
                "disposition": "tombstone",
                "reason": "Repeated code-of-conduct breach.",
                "decidedAt": "2026-08-23T09:14:02Z",
                "decidedBy": "did:key:zAdmin"
            }),
            "what happened, to what, when, and on whose say-so — camelCase per SPEC §4.10"
        );
    }

    /// "No reason given" and "reason: empty string" are different claims. The
    /// operator route accepts an absent body and defaults `reason` to `""`, so
    /// without this the common case would ship a meaningless empty string.
    #[test]
    fn an_absent_or_blank_reason_is_omitted_rather_than_sent_empty() {
        for blank in [None, Some(String::new()), Some("   ".into())] {
            let p = notice_payload(
                "did:key:zRemoved",
                RemovalCode::Purged,
                "purge",
                blank.clone(),
                "2026-08-23T11:02:41Z",
                "did:key:zSuper",
            );
            assert!(
                p.get("reason").is_none(),
                "blank reason {blank:?} must be absent, not an empty string"
            );
        }
    }

    /// The two codes are distinguishable because they differ in what recourse
    /// the member has — a purge deliberately skipped the removal policy.
    #[test]
    fn the_two_removal_codes_are_distinguishable_on_the_wire() {
        assert_eq!(
            serde_json::to_value(RemovalCode::AdminRemoved).unwrap(),
            json!("adminRemoved")
        );
        assert_eq!(
            serde_json::to_value(RemovalCode::Purged).unwrap(),
            json!("purged")
        );
    }

    /// The payload must validate against the published schema. This is the
    /// check that catches the implementation drifting from the spec it claims
    /// to implement — the schema comes from `trust-tasks-rs`, which the
    /// workspace pulls with its `validate` feature on, so no local gate is
    /// needed (and `vtc-service` has no such feature to gate on).
    #[test]
    fn payload_validates_against_the_published_schema() {
        use trust_tasks_rs::validate::ValidatedPayload;
        type Notice = trust_tasks_rs::specs::vtc::members::removal_notice::v0_1::Payload;

        for (code, reason) in [
            (RemovalCode::AdminRemoved, Some("because".to_string())),
            (RemovalCode::Purged, None),
        ] {
            let p = notice_payload(
                "did:key:zRemoved",
                code,
                "tombstone",
                reason,
                "2026-08-23T09:14:02Z",
                "did:key:zAdmin",
            );
            Notice::validate_value(&p)
                .unwrap_or_else(|e| panic!("payload rejected by its own schema: {e}\n{p:#}"));
        }
    }
}
