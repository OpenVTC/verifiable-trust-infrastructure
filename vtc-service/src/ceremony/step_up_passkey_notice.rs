//! Telling a member a step-up passkey was enrolled for them or revoked from
//! them (`spec/vtc/members/step-up-passkey-notice/0.1`).
//!
//! A step-up passkey is ordinarily self-service
//! ([`crate::step_up_passkey::redeem_finish`],
//! [`crate::step_up_passkey::revoke_finish`]), but an administrator's invite
//! or revoke-on-behalf-of is exactly the shape of a silent account takeover:
//! an attacker with administrator standing — or an administrator fooled into
//! using it — can hand a member's identity a new approver, or strip the one
//! they trust, without the member ever being asked. This is how the VTC
//! closes that gap: a signed notice to the member the moment either happens,
//! naming the event, the credential, who acted and when.
//!
//! ## Sent on every enrol and revoke, self-service included
//!
//! Unlike an alert that would fire only for an administrator's action, this
//! one goes out every time, with `by` always carried. That is what lets the
//! recipient tell the two cases apart at all: `by == did` is "I did this,
//! moments ago" and a member glances past it; `by != did` is the signal this
//! task exists to carry, and the member's agent treats it as a takeover
//! prompt (spec *Consumer requirements*).
//!
//! ## Not a receipt
//!
//! Like [`crate::ceremony::removal_notice`] and
//! `git-ns/right/break-glass-notice`, this answers nothing: the recipient
//! did not ask, is not waiting, and may be offline.
//!
//! ## Signed, because the recipient is not the audience
//!
//! Authcrypt already proves the sender to the *member*. But this is exactly
//! the message whose value lies in showing it to somebody else — an
//! administrator asked to explain, another community weighing a dispute. So
//! the notice is a Trust Task document carrying a Data Integrity proof under
//! `proofPurpose: authentication` ([`crate::credentials::signer::Signer::sign_operational_doc`]),
//! packed in the trust-task envelope, exactly as [`crate::hooks::writer`] does.
//!
//! ## Best-effort, deliberately
//!
//! [`send`] never fails the enrolment or revocation. The event has already
//! taken effect and is durable; refusing to complete the operator's (or
//! member's own) request because the notice could not be *queued* would
//! leave the credential changed and nobody told why it might matter. A
//! failure is logged loudly instead.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::vtc::members::step_up_passkey_notice::v0_1 as notice;
use vti_common::capability_client::build_document;

use crate::error::AppError;
use crate::server::AppState;

/// Which change happened, matching the spec's `event` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Enrolled,
    Revoked,
}

impl Event {
    fn as_str(self) -> &'static str {
        match self {
            Event::Enrolled => "enrolled",
            Event::Revoked => "revoked",
        }
    }
}

/// Send a step-up passkey change notice, best-effort.
///
/// Call **after** the enrolment or revocation has taken effect. `at` is that
/// moment, not the send time; the two diverge whenever the member is
/// offline. `by` is the DID that acted: the member's own, for a self-service
/// change, or the administrator's, for an invite or an on-behalf-of revoke —
/// always carried, never omitted, because the recipient's whole read of the
/// notice turns on comparing it to their own DID.
///
/// `reason` is `None` when no administrator-supplied reason exists, which is
/// a different claim from an empty string and stays distinguishable on the
/// wire.
///
/// Errors are logged and swallowed: see the module docs for why the change
/// must not be undone by a delivery problem.
pub async fn send(
    state: &AppState,
    did: &str,
    event: Event,
    credential_id: &str,
    by: &str,
    at: DateTime<Utc>,
    reason: Option<&str>,
) {
    if let Err(e) = try_send(state, did, event, credential_id, by, at, reason).await {
        // Loud, because the member's step-up passkeys changed and they do not
        // know it, and nothing downstream retries beyond the delivery
        // layer's own window.
        warn!(
            error = %e,
            did,
            by,
            event = event.as_str(),
            "step-up passkey notice could not be queued"
        );
    }
}

/// The fallible body of [`send`], separated so the error can be logged in one
/// place and tested directly.
async fn try_send(
    state: &AppState,
    did: &str,
    event: Event,
    credential_id: &str,
    by: &str,
    at: DateTime<Utc>,
    reason: Option<&str>,
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

    let payload = notice_payload(did, event, credential_id, by, at, reason)?;
    let type_uri = <notice::Payload as trust_tasks_rs::Payload>::TYPE_URI;
    let doc = build_document(&vtc_did, did, type_uri, payload);
    let mut doc_value = serde_json::to_value(&doc)
        .map_err(|e| AppError::Internal(format!("serialise step-up passkey notice: {e}")))?;
    signer.sign_operational_doc(&mut doc_value).await?;

    // Over whichever transport the member speaks — TSP, DIDComm or REST —
    // with escalation to the next when one yields no evidence of delivery
    // (`crate::member_push`). The member is still a current member, so the
    // ordinary window applies — unlike `removal_notice`, which is the only
    // channel left to a member whose ACL row is already gone.
    crate::member_push::push_trust_task(state, did, doc_value, crate::server::EXCHANGE_DELIVER_BY)
        .await?;

    info!(
        did,
        by,
        event = event.as_str(),
        "step-up passkey notice queued"
    );
    Ok(())
}

/// The notice's payload, read back through the generated type so a notice
/// this VTC sends is one the specification admits.
fn notice_payload(
    did: &str,
    event: Event,
    credential_id: &str,
    by: &str,
    at: DateTime<Utc>,
    reason: Option<&str>,
) -> Result<Value, AppError> {
    let mut v = json!({
        "event": event.as_str(),
        "did": did,
        "credentialId": credential_id,
        "by": by,
        "at": at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    // An absent reason and an empty one are different claims to the member;
    // only the former is sent as absent on the wire.
    if let Some(r) = reason.filter(|r| !r.trim().is_empty()) {
        v["reason"] = json!(r);
    }
    let _checked: notice::Payload = serde_json::from_value(v.clone()).map_err(|e| {
        AppError::Internal(format!(
            "step-up passkey notice payload rejected by its own schema: {e}"
        ))
    })?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-25T09:00:01Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn enrolled_by_an_administrator_carries_every_field_the_spec_requires() {
        let p = notice_payload(
            "did:key:zCarol",
            Event::Enrolled,
            "c3RlcHVwLWNyZWQtY2Fyb2w",
            "did:key:zDana",
            at(),
            Some("Replacing the device Carol reported lost."),
        )
        .expect("payload builds");
        assert_eq!(
            p,
            json!({
                "event": "enrolled",
                "did": "did:key:zCarol",
                "credentialId": "c3RlcHVwLWNyZWQtY2Fyb2w",
                "by": "did:key:zDana",
                "at": "2026-09-25T09:00:01Z",
                "reason": "Replacing the device Carol reported lost.",
            }),
            "by differs from did: an administrator acted, and the recipient must see both"
        );
    }

    #[test]
    fn a_self_service_change_names_the_member_as_both_did_and_by() {
        let p = notice_payload(
            "did:key:zCarol",
            Event::Revoked,
            "c3RlcHVwLWNyZWQtY2Fyb2w",
            "did:key:zCarol",
            at(),
            None,
        )
        .expect("payload builds");
        assert_eq!(p["did"], p["by"], "self-service: by equals did");
        assert!(
            p.get("reason").is_none(),
            "no reason was given, so none is sent — not an empty string"
        );
    }

    #[test]
    fn a_blank_reason_is_omitted_rather_than_sent_empty() {
        for blank in [Some(""), Some("   ")] {
            let p = notice_payload(
                "did:key:zCarol",
                Event::Revoked,
                "c3RlcHVwLWNyZWQtY2Fyb2w",
                "did:key:zDana",
                at(),
                blank,
            )
            .expect("payload builds");
            assert!(
                p.get("reason").is_none(),
                "blank reason {blank:?} must be absent"
            );
        }
    }

    /// The payload must validate against the published schema — the check
    /// that catches the implementation drifting from the spec it claims to
    /// implement.
    #[test]
    fn payload_validates_against_the_published_schema() {
        use trust_tasks_rs::validate::ValidatedPayload;

        for (event, by, reason) in [
            (Event::Enrolled, "did:key:zDana", Some("because")),
            (Event::Revoked, "did:key:zCarol", None),
        ] {
            let p = notice_payload(
                "did:key:zCarol",
                event,
                "c3RlcHVwLWNyZWQtY2Fyb2w",
                by,
                at(),
                reason,
            )
            .expect("payload builds");
            notice::Payload::validate_value(&p)
                .unwrap_or_else(|e| panic!("payload rejected by its own schema: {e}\n{p:#}"));
        }
    }
}
