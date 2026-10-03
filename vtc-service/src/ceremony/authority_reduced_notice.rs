//! Telling an administrator their authority was reduced
//! (`spec/vtc/members/authority-reduced-notice/0.1`) — **VTI-APV-019**.
//!
//! Every gated reduction of an administrator's entry — `acl/revoke`, a
//! downward `acl/change-role`, a narrowing `acl/update` or `acl/grant`
//! rewrite — sends this once it has landed, whether it ran on another
//! administrator's consent (`agreement: consented`), after a cooling-off with
//! nobody else able to consent, or on the requester's step-up alone
//! (`agreement: unopposed`). VTI-APV-019 requires the subject be told of an
//! unopposed removal; telling them of every one is what lets the subject read
//! `unopposed` as the exception it is.
//!
//! **Not for a removal from the community.** `vtc/members/admin-remove` sends
//! [`crate::ceremony::removal_notice`], which already says who, when and why;
//! the two are never both sent for one act.
//!
//! Like the removal notice it is a Trust Task document the VTC signs (the
//! subject may need to show it to somebody else), pushed durably over whichever
//! transport the subject speaks ([`crate::member_push`]), best-effort: the
//! reduction has already happened, and a delivery problem must not undo it or
//! make the requester believe it failed.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::vtc::members::authority_reduced_notice::v0_1 as notice;
use vti_common::capability_client::build_document;

use crate::acl::VtcAclEntry;
use crate::acl::admin_consent::Agreement;
use crate::error::AppError;
use crate::server::AppState;

/// `vtc/members/authority-reduced-notice/0.1` — outbound only: this VTC sends
/// it and never serves it.
pub const NOTICE_TYPE: &str = <notice::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// What happened, matching the specification's `code`: the entry removed
/// (`revoked`), its role lowered (`demoted`), or its role kept and what it
/// allows reduced (`narrowed`).
#[must_use]
pub fn code_for(prior: &VtcAclEntry, after: Option<&VtcAclEntry>) -> &'static str {
    match after {
        None => "revoked",
        // Its administrative role (or its community role) moved.
        Some(a)
            if crate::routes::acl::role_string(a) != crate::routes::acl::role_string(prior)
                || a.role != prior.role =>
        {
            "demoted"
        }
        Some(_) => "narrowed",
    }
}

/// Send the notice, best-effort. Call **after** the reduction has landed;
/// `decided_at` is that moment, not the send time.
pub async fn send(
    state: &AppState,
    prior: &VtcAclEntry,
    after: Option<&VtcAclEntry>,
    agreement: Agreement,
    decided_by: &str,
    decided_at: DateTime<Utc>,
    reason: Option<&str>,
) {
    if let Err(e) = try_send(
        state, prior, after, agreement, decided_by, decided_at, reason,
    )
    .await
    {
        warn!(
            error = %e,
            subject = %prior.did,
            decided_by,
            "authority-reduced notice could not be queued"
        );
    }
}

async fn try_send(
    state: &AppState,
    prior: &VtcAclEntry,
    after: Option<&VtcAclEntry>,
    agreement: Agreement,
    decided_by: &str,
    decided_at: DateTime<Utc>,
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

    let payload = notice_payload(prior, after, agreement, decided_by, decided_at, reason)?;
    #[cfg(any(test, feature = "test-support"))]
    record_for_test(&prior.did, &payload);
    let doc = build_document(&vtc_did, &prior.did, NOTICE_TYPE, payload);
    let mut doc_value = serde_json::to_value(&doc)
        .map_err(|e| AppError::Internal(format!("serialise authority-reduced notice: {e}")))?;
    signer.sign_operational_doc(&mut doc_value).await?;

    // A revoked subject has no ACL row left, so — like the removal notice — it
    // is given the longer window: this may be the only thing that tells them.
    let deliver_by = if after.is_none() {
        crate::server::REMOVAL_NOTICE_DELIVER_BY
    } else {
        crate::server::EXCHANGE_DELIVER_BY
    };
    crate::member_push::push_trust_task(state, &prior.did, doc_value, deliver_by).await?;
    info!(
        subject = %prior.did,
        decided_by,
        code = code_for(prior, after),
        agreement = agreement.wire(),
        "authority-reduced notice queued"
    );
    Ok(())
}

/// Every notice composed in this process, by subject — so a test can see which
/// notice an act sent without a live transport to carry it.
#[cfg(any(test, feature = "test-support"))]
static SENT: std::sync::LazyLock<std::sync::Mutex<Vec<(String, Value)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[cfg(any(test, feature = "test-support"))]
fn record_for_test(subject: &str, payload: &Value) {
    SENT.lock()
        .unwrap_or_else(|p| p.into_inner())
        .push((subject.to_string(), payload.clone()));
}

/// The notices composed for `subject` in this process, oldest first. Test
/// support only.
#[cfg(any(test, feature = "test-support"))]
pub fn sent_for_test(subject: &str) -> Vec<Value> {
    SENT.lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter(|(s, _)| s == subject)
        .map(|(_, p)| p.clone())
        .collect()
}

/// The notice's payload, read back through the generated type so a notice this
/// VTC sends is one the specification admits.
pub(crate) fn notice_payload(
    prior: &VtcAclEntry,
    after: Option<&VtcAclEntry>,
    agreement: Agreement,
    decided_by: &str,
    decided_at: DateTime<Utc>,
    reason: Option<&str>,
) -> Result<Value, AppError> {
    let mut v = json!({
        "did": prior.did,
        "code": code_for(prior, after),
        // The administrative role (`member` for none): what the reduction
        // was of (vtc-admin-roles.md §6).
        "previousRole": crate::routes::acl::role_string(prior),
        "agreement": agreement.wire(),
        "decidedAt": decided_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "decidedBy": decided_by,
    });
    // Absent exactly when revoked.
    if let Some(a) = after {
        v["resultingRole"] = json!(crate::routes::acl::role_string(a));
    }
    // Absent and empty are different claims; only a given reason is carried.
    if let Some(r) = reason.filter(|r| !r.trim().is_empty()) {
        v["reason"] = json!(r);
    }
    let _checked: notice::Payload = serde_json::from_value(v.clone()).map_err(|e| {
        AppError::Internal(format!(
            "authority-reduced notice payload rejected by its own schema: {e}"
        ))
    })?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::VtcRole;

    fn entry(role: VtcRole, scopes: &[&str]) -> VtcAclEntry {
        VtcAclEntry {
            did: "did:key:zCarol".into(),
            role: role.clone(),
            label: None,
            admin: crate::acl::legacy_seed_authority(&role, scopes),
            delegated_by: None,
            created_at: 0,
            created_by: "did:key:zDana".into(),
            updated_at: None,
            updated_by: None,
            expires_at: None,
        }
    }

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-03T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn each_code_follows_from_the_entry_before_and_after() {
        let admin = entry(VtcRole::Admin, &[]);
        assert_eq!(code_for(&admin, None), "revoked");
        assert_eq!(
            code_for(&admin, Some(&entry(VtcRole::Member, &[]))),
            "demoted"
        );
        // The same administrative role, fewer capabilities under it.
        let mut narrower = entry(VtcRole::Admin, &[]);
        narrower.admin.capabilities = crate::acl::CapabilityScope::Listed {
            grants: vec![crate::acl::CapabilityGrant {
                capability: crate::acl::Capability::AuditRead,
                resource: None,
                additive: false,
            }],
        };
        assert_eq!(code_for(&admin, Some(&narrower)), "narrowed");
    }

    /// VTI-APV-019: a revoked subject carries no `resultingRole`; a step-up
    /// alone reads `unopposed`, and only a third party's consent `consented`.
    #[test]
    fn the_payload_validates_against_the_published_schema() {
        use trust_tasks_rs::validate::ValidatedPayload;
        let admin = entry(VtcRole::Admin, &[]);
        let member = entry(VtcRole::Member, &[]);
        for (after, agreement, reason) in [
            (None, Agreement::Unopposed, Some("compromised")),
            (Some(&member), Agreement::Consented, None),
            (Some(&admin), Agreement::StepUpOnly, Some("   ")),
        ] {
            let p = notice_payload(&admin, after, agreement, "did:key:zDana", at(), reason)
                .expect("payload builds");
            notice::Payload::validate_value(&p)
                .unwrap_or_else(|e| panic!("payload rejected by its own schema: {e}\n{p:#}"));
            assert_eq!(p.get("resultingRole").is_none(), after.is_none());
        }
        let p = notice_payload(
            &admin,
            None,
            Agreement::StepUpOnly,
            "did:key:zDana",
            at(),
            None,
        )
        .unwrap();
        assert_eq!(p["agreement"], "unopposed");
        assert!(p.get("reason").is_none());
    }
}
