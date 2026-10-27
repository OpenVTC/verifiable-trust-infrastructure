//! Renewing a group's credentials before they lapse (`vtc/groups/create` item
//! 5: the community **MUST** renew a group's authority credential well before
//! it lapses; a member's group credential is renewed while they stay).
//!
//! # What is renewed
//!
//! For each group that issues credentials:
//!
//! - **Its authority.** Within `[groups] authority_renew_within_days` of the
//!   authority credential's expiry, the community's VTA signs a fresh one, as
//!   the community, valid `authority_valid_days` from now. It reuses the slot
//!   in the community's revocation list the group already holds, so every
//!   authority the group was ever issued is revoked by the one bit its deletion
//!   flips. The old credential is not revoked: members still present it until
//!   their own credential is renewed, which hands them the new one.
//! - **Each active member's credential.** Within a third of its life of its
//!   expiry (ten days of a 30-day credential), the VTA signs a fresh one as the
//!   group, and it is offered with the group's current authority, exactly as an
//!   admission offers it. A member no longer active in the community is not
//!   renewed: their membership ends with their departure, and expiry is the
//!   revocation (VTI-CRD-014).
//!
//! The authority's window is at least a member credential's life by default, so
//! every member is offered the new authority before the old one lapses.
//!
//! # Remote first, and crash-safe
//!
//! Nothing is recorded before the VTA has signed. The one local write — the
//! group's new authority, or the membership's new credential — comes last,
//! re-read under the directory's write lock so a change made while the VTA was
//! asked is never written back stale, and dropped if the group or the
//! membership went meanwhile. A process that dies before it finds the item
//! still due on its next pass, and renews again.
//!
//! # One retry owner
//!
//! The sweeper is the only thing that retries a renewal: at most one attempt
//! per due item per pass, and a failure waits a capped exponential backoff with
//! jitter (1 minute doubling to 6 hours), recorded beside the group
//! (`grenew:`), never inside it. A failure is logged at `warn` every time and
//! audited when a run of failures begins; a renewal is audited by reference.
//!
//! There is no "renew now" task: no specification defines one.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vti_common::audit::{AuditEvent, GroupChangedData, GroupMembershipChangedData};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::identity::{self, Failure};
use super::{Group, Membership};
use crate::rooms::community::HolderError;
use crate::server::AppState;

/// How often the sweeper looks.
const TICK: Duration = Duration::from_secs(600);
/// The wait before its first pass, so it never competes with startup.
const FIRST_PASS: Duration = Duration::from_secs(90);
const RETRY_BASE: Duration = Duration::from_secs(60);
const RETRY_CAP: Duration = Duration::from_secs(6 * 60 * 60);

/// The retry schedule of one renewal: a group's authority, or one member's
/// credential.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Retry {
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

fn authority_key(group_id: &str) -> Vec<u8> {
    format!("grenew:{group_id}").into_bytes()
}

fn credential_key(group_id: &str, entry_id: &str) -> Vec<u8> {
    format!("grenew:{group_id}:{entry_id}").into_bytes()
}

async fn retry(ks: &KeyspaceHandle, key: &[u8]) -> Result<Retry, AppError> {
    Ok(ks.get(key.to_vec()).await?.unwrap_or_default())
}

/// Forget every retry schedule of `group_id`, as its deletion does.
pub async fn forget(ks: &KeyspaceHandle, group_id: &str) -> Result<(), AppError> {
    ks.remove(authority_key(group_id)).await?;
    for (key, _) in ks
        .prefix_iter_raw(format!("grenew:{group_id}:").into_bytes())
        .await?
    {
        ks.remove(key).await?;
    }
    Ok(())
}

/// Forget the retry schedule of `entry_id`'s credential of `group_id`, as the
/// membership's end does.
pub async fn forget_credential(
    ks: &KeyspaceHandle,
    group_id: &str,
    entry_id: &str,
) -> Result<(), AppError> {
    ks.remove(credential_key(group_id, entry_id)).await
}

/// The wait after `attempts` consecutive failures: half the capped exponential
/// ceiling, plus up to the other half at random, so renewals that failed
/// together do not retry together.
fn backoff(attempts: u32) -> chrono::Duration {
    use rand::RngExt as _;
    let factor = 1u32
        .checked_shl(attempts.saturating_sub(1))
        .unwrap_or(u32::MAX);
    let ceiling = RETRY_BASE.saturating_mul(factor).min(RETRY_CAP).as_secs();
    let half = ceiling / 2;
    let secs = half + rand::rng().random_range(0..=ceiling - half);
    chrono::Duration::seconds(secs as i64)
}

fn failure_text(f: &Failure) -> String {
    match f {
        Failure::Local(e) => e.to_string(),
        Failure::Holder(HolderError::Unavailable(why), _) => format!("no answer: {why}"),
        Failure::Holder(HolderError::Refused { code, .. }, _) => format!("refused: {code}"),
    }
}

/// What a pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Groups whose authority was renewed.
    pub authorities: Vec<String>,
    /// Member credentials renewed, as `(groupId, entryId)`.
    pub credentials: Vec<(String, String)>,
    /// Renewals attempted that failed, by their schedule key.
    pub failed: Vec<String>,
}

/// Run the sweeper until shutdown. Always spawned: it does nothing while
/// groups are off or there is no VTA link.
pub fn spawn(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut wait = FIRST_PASS;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            wait = TICK;
            if let Err(e) = sweep(&state, Utc::now()).await {
                tracing::warn!(error = %e, "group credential renewal pass failed");
            }
        }
    });
}

/// One pass at `now`: renew every authority and member credential that is due
/// and not waiting out a failure.
pub async fn sweep(state: &AppState, now: DateTime<Utc>) -> Result<SweepReport, AppError> {
    let mut report = SweepReport::default();
    let Some(config) = state.config.read().await.groups.clone() else {
        return Ok(report);
    };
    // No link, no DID, no signer: nothing to ask, and nothing failed.
    let Ok(setup) = identity::setup(state).await else {
        return Ok(report);
    };
    let ks = state.directory.ks();
    for group in super::all(ks).await? {
        if !group.issues_credentials {
            continue;
        }
        let Some(group) = renew_authority(state, &setup, &config, group, now, &mut report).await?
        else {
            continue;
        };
        for m in super::members_of(ks, &group.group_id).await? {
            renew_credential(state, &config, &group, m, now, &mut report).await?;
        }
    }
    Ok(report)
}

/// Renew `group`'s authority if it is due. Answers the group as it now stands,
/// `None` where it went while the VTA was asked.
async fn renew_authority(
    state: &AppState,
    setup: &identity::Setup,
    config: &crate::config::GroupsConfig,
    group: Group,
    now: DateTime<Utc>,
    report: &mut SweepReport,
) -> Result<Option<Group>, AppError> {
    let Some(authority) = group.authority.clone() else {
        return Ok(Some(group));
    };
    if authority.valid_until - now > config.authority_renew_within() {
        return Ok(Some(group));
    }
    let ks = state.directory.ks();
    let key = authority_key(&group.group_id);
    let mut rec = retry(ks, &key).await?;
    if rec.next_attempt_at.is_some_and(|next| next > now) {
        return Ok(Some(group));
    }
    match identity::issue_authority(
        state,
        setup,
        &group.group_did,
        now,
        Some(authority.status_list_index),
    )
    .await
    {
        Ok((renewed, credential)) => {
            let current = {
                let _guard = crate::directory::WRITE_LOCK.lock().await;
                let Some(mut current) = super::get(ks, &group.group_id).await? else {
                    return Ok(None);
                };
                // The group stopped issuing, or was given a new authority,
                // while the VTA was asked: that stands.
                if !current.issues_credentials
                    || current.authority.as_ref().map(|a| &a.credential_id)
                        != Some(&authority.credential_id)
                {
                    return Ok(Some(current));
                }
                current.authority = Some(renewed);
                current.authority_credential = Some(credential);
                current.updated_at = now;
                super::put(ks, &current).await?;
                current
            };
            ks.remove(key).await?;
            audit(
                state,
                AuditEvent::GroupChanged(GroupChangedData {
                    group_id: group.group_id.clone(),
                    change: "authorityRenewed".into(),
                    fields: Vec::new(),
                    reason: None,
                }),
            )
            .await;
            report.authorities.push(group.group_id.clone());
            Ok(Some(current))
        }
        Err(f) => {
            let why = failure_text(&f);
            tracing::warn!(group = %group.group_id, error = %why,
                "a group's authority credential could not be renewed; retrying later");
            rec.attempts += 1;
            rec.next_attempt_at = Some(now + backoff(rec.attempts));
            rec.last_error = Some(why.clone());
            ks.insert(key, &rec).await?;
            if rec.attempts == 1 {
                audit(
                    state,
                    AuditEvent::GroupChanged(GroupChangedData {
                        group_id: group.group_id.clone(),
                        change: "authorityRenewalFailed".into(),
                        fields: Vec::new(),
                        reason: Some(why),
                    }),
                )
                .await;
            }
            report.failed.push(group.group_id.clone());
            Ok(Some(group))
        }
    }
}

/// Renew `m`'s credential of `group` if it is due and its member is still an
/// active member of the community.
async fn renew_credential(
    state: &AppState,
    config: &crate::config::GroupsConfig,
    group: &Group,
    m: Membership,
    now: DateTime<Utc>,
    report: &mut SweepReport,
) -> Result<(), AppError> {
    if m.state != "active" {
        return Ok(());
    }
    let (Some(credential_id), Some(until)) = (m.credential_id.clone(), m.credential_valid_until)
    else {
        return Ok(());
    };
    if until - now > config.credential_renew_within() {
        return Ok(());
    }
    let ks = state.directory.ks();
    let key = credential_key(&group.group_id, &m.entry_id);
    let mut rec = retry(ks, &key).await?;
    if rec.next_attempt_at.is_some_and(|next| next > now) {
        return Ok(());
    }
    let Some(card) = crate::directory::cards::get(ks, &m.entry_id).await? else {
        return Ok(());
    };
    if crate::member_portal::active::active_member(state, &card.did)
        .await?
        .is_none()
    {
        return Ok(());
    }
    match super::credential::issue(state, group, &card.did).await {
        Ok(issued) => {
            super::credential::offer(state, group, &card.did, &issued).await;
            {
                let _guard = crate::directory::WRITE_LOCK.lock().await;
                let Some(mut current) = super::membership(ks, &group.group_id, &m.entry_id).await?
                else {
                    return Ok(());
                };
                if current.credential_id.as_deref() != Some(credential_id.as_str()) {
                    return Ok(());
                }
                current.credential_id = Some(issued.credential_id);
                current.credential_valid_until = Some(issued.valid_until);
                super::put_membership(ks, &current).await?;
            }
            ks.remove(key).await?;
            audit(
                state,
                AuditEvent::GroupMembershipChanged(GroupMembershipChangedData {
                    group_id: group.group_id.clone(),
                    entry_id: m.entry_id.clone(),
                    change: "credentialRenewed".into(),
                    reason: None,
                }),
            )
            .await;
            report
                .credentials
                .push((group.group_id.clone(), m.entry_id));
        }
        Err(f) => {
            let why = failure_text(&f);
            tracing::warn!(group = %group.group_id, entry = %m.entry_id, error = %why,
                "a member's group credential could not be renewed; retrying later");
            rec.attempts += 1;
            rec.next_attempt_at = Some(now + backoff(rec.attempts));
            rec.last_error = Some(why.clone());
            ks.insert(key, &rec).await?;
            if rec.attempts == 1 {
                audit(
                    state,
                    AuditEvent::GroupMembershipChanged(GroupMembershipChangedData {
                        group_id: group.group_id.clone(),
                        entry_id: m.entry_id.clone(),
                        change: "credentialRenewalFailed".into(),
                        reason: Some(why),
                    }),
                )
                .await;
            }
            report
                .failed
                .push(format!("{}:{}", group.group_id, m.entry_id));
        }
    }
    Ok(())
}

/// Audit as the community. A renewal is never undone for want of an audit
/// row: a missing writer is logged.
async fn audit(state: &AppState, event: AuditEvent) {
    let Some(writer) = state.audit_writer.as_ref() else {
        tracing::warn!("audit writer not configured: a group renewal went unaudited");
        return;
    };
    let actor = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .unwrap_or_else(|| "vtc".into());
    if let Err(e) = writer.write(&actor, None, event).await {
        tracing::warn!(error = %e, "a group renewal could not be audited");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_capped_and_grows() {
        for a in 1..40 {
            let d = backoff(a);
            assert!(d <= chrono::Duration::from_std(RETRY_CAP).unwrap());
            assert!(d >= chrono::Duration::seconds(30));
        }
        assert!(backoff(30) >= chrono::Duration::from_std(RETRY_CAP / 2).unwrap());
    }

    #[test]
    fn windows_default_and_bound() {
        let c = crate::config::GroupsConfig {
            context: None,
            webvh_server: None,
            authority_valid_days: None,
            credential_valid_days: None,
            authority_renew_within_days: None,
        };
        assert_eq!(c.authority_renew_within(), chrono::Duration::days(30));
        assert_eq!(c.credential_renew_within(), chrono::Duration::days(10));
        let long = crate::config::GroupsConfig {
            credential_valid_days: Some(90),
            authority_valid_days: Some(120),
            ..c.clone()
        };
        // A member credential's life, bounded by half the authority's.
        assert_eq!(long.authority_renew_within(), chrono::Duration::days(60));
        let asked = crate::config::GroupsConfig {
            authority_renew_within_days: Some(400),
            ..c
        };
        assert_eq!(asked.authority_renew_within(), chrono::Duration::days(182));
    }
}
