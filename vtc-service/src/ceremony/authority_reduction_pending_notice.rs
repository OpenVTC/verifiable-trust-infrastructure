//! Telling an administrator a reduction of their authority is cooling off
//! (`spec/vtc/members/authority-reduction-pending-notice/0.1`) — **VTI-APV-019**.
//!
//! With nobody but the requester and the subject able to consent, a reduction
//! of an unrestricted administrator is parked for a cooling-off and lands by
//! itself at `landsAt` unless its requester cancels it
//! (`docs/05-design-notes/vtc-action-list.md` §8.2). The subject cannot block
//! it — a veto held by the subject would protect a compromised subject — but
//! must learn of it before it takes effect, not only from the console banner.
//! This is that notice, sent **when the reduction is parked**. When it lands,
//! [`crate::ceremony::authority_reduced_notice`] reports the landing (agreement
//! `unopposed`); if the requester cancels it, nothing is reduced and nothing
//! further is sent.
//!
//! Like the reduced notice it is a Trust Task document the VTC signs, pushed
//! durably over whichever transport the subject speaks
//! ([`crate::member_push`]), best-effort: the action list is the record, and
//! a delivery problem neither blocks parking nor delays the landing.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::vtc::members::authority_reduction_pending_notice::v0_1 as notice;
use vti_common::capability_client::build_document;

use crate::acl::VtcAclEntry;
use crate::error::AppError;
use crate::server::AppState;

/// `vtc/members/authority-reduction-pending-notice/0.1` — outbound only: this
/// VTC sends it and never serves it.
pub const NOTICE_TYPE: &str = <notice::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// What the parked operation will do to `prior` when it lands, in the notice's
/// vocabulary (`revoked` | `demoted` | `narrowed`, the same set as the reduced
/// notice), with the role the subject will then hold (`None` exactly when
/// `revoked`). Read off the parked operation's own payload: the reduction has
/// not happened yet, so there is no resulting entry to compare with.
#[must_use]
pub fn pending_outcome(
    type_uri: &str,
    payload: &Value,
    prior: &VtcAclEntry,
) -> (&'static str, Option<String>) {
    // The administrative role, as the reduced notice names it.
    let prior_role = crate::routes::acl::role_string(prior);
    // A payload naming the role the entry already holds — or the 0.1 wire's
    // `admin`, which spells every administrative role — keeps it: narrowed.
    let lands_as = |role: Option<&str>| match role.filter(|r| !r.is_empty()) {
        Some(r) if r != prior_role && r != "admin" => ("demoted", Some(r.to_string())),
        _ => ("narrowed", Some(prior_role.clone())),
    };
    if type_uri.contains("/vtc/members/admin-remove/") {
        return ("revoked", None);
    }
    if type_uri.contains("/acl/revoke/") {
        // A scope revoke (0.1 `scopes`) or an act-scope narrowing (0.2
        // `revocation.kind: act`) narrows; anything else removes the entry.
        let scoped = payload["scopes"].as_array().is_some_and(|s| !s.is_empty())
            || payload["revocation"]["kind"] == "act";
        return if scoped {
            ("narrowed", Some(prior_role))
        } else {
            ("revoked", None)
        };
    }
    if type_uri.contains("/acl/change-role/") {
        return lands_as(payload["toRole"].as_str().or(payload["role"].as_str()));
    }
    if type_uri.contains("/acl/grant/") {
        return lands_as(payload["entry"]["role"].as_str());
    }
    lands_as(payload["role"].as_str())
}

/// Send the notice, best-effort. Call once the reduction has been parked.
#[allow(clippy::too_many_arguments)]
pub async fn send(
    state: &AppState,
    action_id: &str,
    prior: &VtcAclEntry,
    type_uri: &str,
    payload: &Value,
    decided_by: &str,
    requested_at: DateTime<Utc>,
    lands_at: DateTime<Utc>,
) {
    if let Err(e) = try_send(
        state,
        action_id,
        prior,
        type_uri,
        payload,
        decided_by,
        requested_at,
        lands_at,
    )
    .await
    {
        warn!(
            error = %e,
            subject = %prior.did,
            action = action_id,
            "authority-reduction-pending notice could not be queued; the action list has it"
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_send(
    state: &AppState,
    action_id: &str,
    prior: &VtcAclEntry,
    type_uri: &str,
    payload: &Value,
    decided_by: &str,
    requested_at: DateTime<Utc>,
    lands_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let body = notice_payload(
        action_id,
        prior,
        type_uri,
        payload,
        decided_by,
        requested_at,
        lands_at,
    )?;
    #[cfg(any(test, feature = "test-support"))]
    record_for_test(&prior.did, &body);
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
    let doc = build_document(&vtc_did, &prior.did, NOTICE_TYPE, body);
    let mut doc_value = serde_json::to_value(&doc).map_err(|e| {
        AppError::Internal(format!("serialise authority-reduction-pending notice: {e}"))
    })?;
    signer.sign_operational_doc(&mut doc_value).await?;

    // Deliverable until the reduction lands, and a little past it: after the
    // landing the reduced notice is what is true.
    let window = lands_at
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or_default()
        .max(std::time::Duration::from_secs(3600))
        .saturating_add(std::time::Duration::from_secs(3600));
    crate::member_push::push_trust_task(state, &prior.did, doc_value, window).await?;
    info!(
        subject = %prior.did,
        decided_by,
        action = action_id,
        "authority-reduction-pending notice queued"
    );
    Ok(())
}

/// Every notice composed in this process, by subject — so a test can see
/// which notice a park sent without a live transport to carry it.
#[cfg(any(test, feature = "test-support"))]
static SENT: std::sync::LazyLock<std::sync::Mutex<Vec<(String, Value)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[cfg(any(test, feature = "test-support"))]
fn record_for_test(subject: &str, payload: &Value) {
    SENT.lock()
        .unwrap_or_else(|p| p.into_inner())
        .push((subject.to_string(), payload.clone()));
}

/// The pending notices composed for `subject` in this process, oldest first.
/// Test support only.
#[cfg(any(test, feature = "test-support"))]
pub fn sent_for_test(subject: &str) -> Vec<Value> {
    SENT.lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter(|(s, _)| s == subject)
        .map(|(_, p)| p.clone())
        .collect()
}

/// The notice's payload, held to its published schema.
pub(crate) fn notice_payload(
    action_id: &str,
    prior: &VtcAclEntry,
    type_uri: &str,
    payload: &Value,
    decided_by: &str,
    requested_at: DateTime<Utc>,
    lands_at: DateTime<Utc>,
) -> Result<Value, AppError> {
    use trust_tasks_rs::validate::ValidatedPayload as _;
    let (code, resulting) = pending_outcome(type_uri, payload, prior);
    let mut v = json!({
        "actionId": action_id,
        "did": prior.did,
        "code": code,
        "previousRole": prior.role.to_string(),
        "decidedBy": decided_by,
        "requestedAt": requested_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "landsAt": lands_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    // Absent exactly when revoked.
    if let Some(r) = resulting {
        v["resultingRole"] = json!(r);
    }
    // Absent and empty are different claims; only a given reason is carried.
    if let Some(r) = payload["reason"].as_str().filter(|r| !r.trim().is_empty()) {
        v["reason"] = json!(r.chars().take(1024).collect::<String>());
    }
    notice::Payload::validate_value(&v).map_err(|e| {
        AppError::Internal(format!(
            "authority-reduction-pending notice rejected by its own schema: {e}"
        ))
    })?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::VtcRole;

    fn admin() -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zCarol".into(),
            role: VtcRole::Admin,
            label: None,
            admin: crate::acl::legacy_seed_authority::<&str>(&VtcRole::Admin, &[]),
            delegated_by: None,
            created_at: 0,
            created_by: "did:key:zDana".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    const SPEC: &str = "https://trusttasks.org/spec";

    /// Each reduction that can cool off reads as the code it will land as.
    #[test]
    fn each_parked_reduction_names_what_it_will_do() {
        let prior = admin();
        let cases = [
            (
                format!("{SPEC}/acl/revoke/0.1"),
                json!({ "subject": "did:key:zCarol" }),
                ("revoked", None),
            ),
            (
                format!("{SPEC}/vtc/members/admin-remove/0.1"),
                json!({ "did": "did:key:zCarol" }),
                ("revoked", None),
            ),
            (
                format!("{SPEC}/acl/change-role/0.1"),
                json!({ "subject": "did:key:zCarol", "fromRole": "admin", "toRole": "member" }),
                ("demoted", Some("member".to_string())),
            ),
            (
                format!("{SPEC}/acl/update/0.1"),
                json!({ "subject": "did:key:zCarol", "scopes": ["ctx-a"] }),
                ("narrowed", Some("community-admin".to_string())),
            ),
            (
                format!("{SPEC}/acl/grant/0.1"),
                json!({ "entry": { "subject": "did:key:zCarol", "role": "admin", "scopes": ["a"] } }),
                ("narrowed", Some("community-admin".to_string())),
            ),
        ];
        for (uri, payload, expected) in cases {
            assert_eq!(pending_outcome(&uri, &payload, &prior), expected, "{uri}");
        }
    }

    /// VTI-APV-019: the notice this VTC sends is one the specification admits —
    /// `resultingRole` absent exactly when revoked, a blank reason not carried.
    #[test]
    fn the_payload_validates_against_the_published_schema() {
        let prior = admin();
        let p = notice_payload(
            "act-5b8f1d4e9c2a4f6b8e317a0c5d9e2f14",
            &prior,
            &format!("{SPEC}/acl/revoke/0.1"),
            &json!({ "subject": "did:key:zCarol", "reason": "compromised laptop" }),
            "did:key:zDana",
            at("2026-10-03T09:00:00Z"),
            at("2026-10-04T09:00:00Z"),
        )
        .expect("payload builds");
        assert_eq!(p["code"], "revoked");
        assert!(p.get("resultingRole").is_none());
        assert_eq!(p["reason"], "compromised laptop");
        assert_eq!(p["landsAt"], "2026-10-04T09:00:00Z");

        let p = notice_payload(
            "act-0f3e2d1c4b5a69788796a5b4c3d2e1f0",
            &prior,
            &format!("{SPEC}/acl/change-role/0.1"),
            &json!({ "subject": "did:key:zCarol", "fromRole": "admin", "toRole": "member", "reason": "  " }),
            "did:key:zDana",
            at("2026-10-03T09:00:00Z"),
            at("2026-10-04T09:00:00Z"),
        )
        .expect("payload builds");
        assert_eq!(p["resultingRole"], "member");
        assert!(p.get("reason").is_none());
    }
}
