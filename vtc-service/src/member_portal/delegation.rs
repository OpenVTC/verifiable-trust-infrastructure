//! Delegated signing for the member portal (`auth/oob/grant/0.3`, consumer
//! item 4).
//!
//! A member who approves a portal sign-in with a 0.2 grant carrying
//! `signingScope` lets the browser's sign-in key `K_b` sign documents of those
//! task families as them, for that session. At `redeem` the VTC records the
//! delegation here, keyed by `K_b`; a document `K_b` signs is then read as the
//! member's while all of these hold:
//!
//! 1. the task's slug is a family the scope lists, or lies under one, matched
//!    on whole segments;
//! 2. the session `redeem` created is live — present, authenticated, not past
//!    its `notAfter` and still carrying `K_b`. Signing out or a revocation
//!    deletes the session, which disarms the key at once. A delegated document
//!    never touches the session, so it cannot keep it alive;
//! 3. the task is not excluded (item 6): nothing under `auth`, `acl`,
//!    `consent`, `task-consent` or `confirm`, whatever the scope says.
//!
//! Every document accepted this way is audited against the member before it
//! takes effect, naming the key and the grant (item 7, [`accept`]); one that
//! cannot be audited is refused. The prechecks that only ask whether a key
//! stands for someone (the admission budget, the size gate) read
//! [`member_for`] and audit nothing, because they accept nothing.
//!
//! The delegation confers no standing of its own: every caller here still
//! reads the member's standing at execution time, and a task that needs the
//! member's own `assertionMethod` key, or that publishes their data beyond the
//! community, refuses a delegated signer itself (`card/update` widening a
//! value to `public`).

//! The generic half — the scope match, the exclusions, recording the row and
//! reading it back as armed or not — is [`vti_oob_server::delegation`]. What
//! stays here is the VTC's: the row's shape (it names the session), the
//! session that keeps it live, and the audit row item 7 requires.

use serde::{Deserialize, Serialize};
use vti_common::audit::{AuditEvent, MemberPortalKeyUsedData};
use vti_common::auth::session::{SessionState, get_session, now_epoch};
use vti_common::store::KeyspaceHandle;
use vti_oob_server::delegation::{self as shared, DelegatedKey, DelegationLiveness, Liveness};

use crate::error::AppError;

pub use vti_oob_server::delegation::covers;

/// One armed delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delegation {
    /// The member the key signs as.
    pub member_did: String,
    /// The session `redeem` created from the grant.
    pub session_id: String,
    /// The families the member signed, as slug prefixes.
    pub scope: Vec<String>,
    /// The grant's `notAfter`, epoch seconds.
    pub not_after: u64,
    /// The grant's `id`: the authority each delegated document is audited
    /// under. Absent only on a delegation armed before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

impl DelegatedKey for Delegation {
    fn approver(&self) -> &str {
        &self.member_did
    }
    fn scope(&self) -> &[String] {
        &self.scope
    }
    fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// A delegation is live while the session `redeem` created is: present,
/// authenticated, the member's, not past its `notAfter` or refresh end, and
/// still carrying `K_b`. A session that is gone disarms the key for good.
struct SessionLiveness<'a> {
    ks: &'a KeyspaceHandle,
}

#[async_trait::async_trait]
impl DelegationLiveness<Delegation> for SessionLiveness<'_> {
    async fn liveness(&self, signer: &str, d: &Delegation) -> Result<Liveness, AppError> {
        let now = now_epoch();
        let Some(s) = get_session(self.ks, &d.session_id).await? else {
            return Ok(Liveness::Gone);
        };
        let live = s.state == SessionState::Authenticated
            && s.did == d.member_did
            && s.not_after.is_none_or(|end| end > now)
            && s.refresh_expires_at.is_none_or(|end| end > now)
            && s.session_pubkey_b58btc.as_deref()
                == crate::member_portal::oob::did_key_multikey(signer);
        Ok(if live {
            Liveness::Live
        } else {
            Liveness::Paused
        })
    }
}

/// Arm the delegation `redeem` just issued a session for.
pub async fn record(
    ks: &KeyspaceHandle,
    start_key: &str,
    delegation: &Delegation,
) -> Result<(), AppError> {
    shared::record(ks, start_key, delegation).await
}

/// The member `signer` signs as for `type_uri`, if `signer` is a portal
/// sign-in key whose delegation covers it and whose session is live. `None`
/// otherwise — exactly as for a key the community does not know (item 4).
pub async fn member_for(
    ks: &KeyspaceHandle,
    signer: &str,
    type_uri: &str,
) -> Result<Option<String>, AppError> {
    Ok(armed(ks, signer, type_uri).await?.map(|d| d.member_did))
}

/// Accept the document `document_id` of `type_uri` that `signer` signed as the
/// member it is delegated by: [`member_for`], with the audit row item 7
/// requires written first. `None` for a key that stands for nobody here.
/// When the row cannot be written the document is refused: a delegated
/// document is never unaudited.
pub async fn accept(
    state: &crate::server::AppState,
    signer: &str,
    type_uri: &str,
    document_id: &str,
) -> Result<Option<String>, AppError> {
    let Some(d) = armed(&state.member_sessions_ks, signer, type_uri).await? else {
        return Ok(None);
    };
    let writer = state
        .audit_writer
        .as_ref()
        .ok_or_else(|| AppError::ServiceError {
            status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
            message: "audit writer not configured: a document the portal's sign-in key signed \
                      is refused rather than accepted unaudited"
                .into(),
        })?;
    writer
        .write(
            &d.member_did,
            Some(&d.member_did),
            AuditEvent::MemberPortalKeyUsed(MemberPortalKeyUsedData {
                member: d.member_did.clone(),
                start_key_did: signer.to_string(),
                grant_id: d.grant_id.clone(),
                task_type: type_uri.to_string(),
                document_id: document_id.to_string(),
            }),
        )
        .await?;
    Ok(Some(d.member_did))
}

/// The live delegation `signer` holds for `type_uri`, if any.
async fn armed(
    ks: &KeyspaceHandle,
    signer: &str,
    type_uri: &str,
) -> Result<Option<Delegation>, AppError> {
    shared::armed(ks, signer, type_uri, &SessionLiveness { ks }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "https://trusttasks.org/spec";

    #[test]
    fn a_scope_covers_whole_segments_only() {
        let scope = vec!["vtc/directory".to_string()];
        assert!(covers(
            &scope,
            &format!("{S}/vtc/directory/card/update/0.1")
        ));
        assert!(covers(&scope, &format!("{S}/vtc/directory/query/0.1")));
        assert!(!covers(
            &scope,
            &format!("{S}/vtc/directoryx/card/update/0.1")
        ));
        assert!(!covers(&scope, &format!("{S}/vtc/groups/join/0.1")));
    }

    #[test]
    fn exclusions_hold_whatever_the_scope_says() {
        let scope = vec![
            "auth".to_string(),
            "acl".to_string(),
            "task-consent".to_string(),
        ];
        assert!(!covers(&scope, &format!("{S}/auth/oob/grant/0.3")));
        assert!(!covers(&scope, &format!("{S}/acl/grant/0.2")));
        assert!(!covers(&scope, &format!("{S}/task-consent/decision/0.2")));
    }
}
