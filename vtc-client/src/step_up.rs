//! The producer's half of the `step-up` trigger-link flow (VTI-LNK-125 –
//! VTI-LNK-131).
//!
//! A key acting for someone else — an assistant's delegated key — is refused a
//! gated act with the step-up inline and, where the subject's own wallet can
//! answer it, a hand-off (`details.stepUpHandoff`,
//! `auth/step-up/requests/show/0.1`'s `$defs.Handoff`). The party refused is
//! the link's producer (VTI-LNK-127): it shows the subject a `step-up` link,
//! and their wallet reads the step-up from the community, shows them the
//! operation, and answers as them. Afterwards the identical operation is sent
//! again and goes through.
//!
//! This module only builds the link from the refusal. The inline request is
//! never presented as something to approve: it carries no proof, and what the
//! person approves is what their wallet fetches.

use serde_json::Value;

/// The host of VTI's registered flows; a flow on it is written as a path.
pub const LINK_HOST: &str = "link.trustoverip.org";
/// The `step-up` flow, in the path form its own host takes (VTI-LNK-042).
pub const STEP_UP_FLOW: &str = "/vti/flow/step-up/0.1";
/// The task a hand-off names; anything else is not a hand-off this client
/// knows how to pass on.
pub const REQUESTS_SHOW: &str = "https://trusttasks.org/spec/auth/step-up/requests/show/0.1";
/// The longest a `step-up` link may live past its making (VTI-LNK-125).
const MAX_LINK_LIFE_SECS: i64 = 300;

/// A `step-up` link, and the instant it stops working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpLink {
    pub link: String,
    /// Epoch seconds.
    pub expires_at: i64,
}

/// The refusal document's hand-off, when it carries one this client can pass
/// on.
pub fn handoff_of(refusal: &Value) -> Option<&Value> {
    let handoff = refusal.pointer("/payload/details/stepUpHandoff")?;
    (handoff["show"] == REQUESTS_SHOW && handoff["handle"].is_string()).then_some(handoff)
}

/// The inline step-up request a refusal carries — for its `reason` and
/// `subject`, never as something to approve.
pub fn inline_request(refusal: &Value) -> Option<&Value> {
    refusal.pointer("/payload/details/stepUpRequest")
}

/// The `step-up` link for `handoff`, whose contact is `community_did` — the
/// community the refused operation was sent to (VTI-LNK-127). `_exp` is the
/// hand-off's own expiry, and never more than 300 seconds after `now`
/// (VTI-LNK-125). `None` for a hand-off with no usable handle or expiry, or
/// one already expired: nothing a wallet could act on.
pub fn link(community_did: &str, handoff: &Value, now: i64) -> Option<StepUpLink> {
    let handle = handoff["handle"]
        .as_str()
        .filter(|h| (22..=86).contains(&h.len()))
        .filter(|h| {
            h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })?;
    let handoff_exp = handoff["expiresAt"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp())?;
    let expires_at = handoff_exp.min(now + MAX_LINK_LIFE_SECS);
    if expires_at <= now {
        return None;
    }
    let link = format!(
        "https://{LINK_HOST}/t#_from={}&_id={handle}&_exp={expires_at}&_type={STEP_UP_FLOW}",
        crate::signin::encode_from(community_did),
    );
    Some(StepUpLink { link, expires_at })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VTC: &str = "did:webvh:Qm1:vtc.example.com";

    fn refusal(expires_at: &str) -> Value {
        json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.3",
            "payload": {
                "code": "permissionDenied",
                "details": {
                    "stepUpRequest": { "subject": "did:key:z6Mkadmin", "reason": "Invite" },
                    "stepUpHandoff": {
                        "handle": "Hk2pQ9xV4mT7rW1sZ8yN3A",
                        "expiresAt": expires_at,
                        "show": REQUESTS_SHOW,
                    }
                }
            }
        })
    }

    #[test]
    fn vti_lnk_125_a_step_up_link_expires_with_its_hand_off_and_within_300_seconds() {
        let now = 1_791_460_800;
        let doc = refusal("2026-10-08T12:03:20Z"); // now + 200
        let link = link(VTC, handoff_of(&doc).unwrap(), now).unwrap();
        assert_eq!(link.expires_at, now + 200);
        assert_eq!(
            link.link,
            format!(
                "https://link.trustoverip.org/t#_from={VTC}&_id=Hk2pQ9xV4mT7rW1sZ8yN3A\
                 &_exp={}&_type=/vti/flow/step-up/0.1",
                now + 200
            )
        );

        let far = refusal("2026-10-08T13:00:00Z");
        assert_eq!(
            super::link(VTC, handoff_of(&far).unwrap(), now)
                .unwrap()
                .expires_at,
            now + 300
        );

        let past = refusal("2026-10-08T11:00:00Z");
        assert!(super::link(VTC, handoff_of(&past).unwrap(), now).is_none());
    }

    #[test]
    fn a_hand_off_naming_another_task_or_a_malformed_handle_is_not_passed_on() {
        let mut doc = refusal("2026-10-08T12:03:20Z");
        doc["payload"]["details"]["stepUpHandoff"]["show"] = json!("https://evil.example/x");
        assert!(handoff_of(&doc).is_none());

        let mut doc = refusal("2026-10-08T12:03:20Z");
        doc["payload"]["details"]["stepUpHandoff"]["handle"] = json!("short&_from=x");
        let handoff = handoff_of(&doc).unwrap();
        assert!(link(VTC, handoff, 1_791_460_800).is_none());
    }
}
