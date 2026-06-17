//! Background pruning of expired consent records.
//!
//! Called from the storage thread's interval loop. Removes pending consent
//! requests that were never answered before their TTL — the main unbounded-
//! growth risk, since `vti_common::consent::consume_pending_consent` only prunes
//! on access — and grants whose optional TTL has lapsed. Each removal is
//! recorded in the audit log as `consent.expire` (actor `system:sweeper`), the
//! same trail the ACL sweeper leaves.

use tracing::{debug, info, warn};

use vti_common::consent::{ConsentGrant, PendingConsent};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sweep the consent keyspace: delete expired pending requests and lapsed
/// grants. Audit-record failures are warn-logged but don't abort the sweep.
pub async fn sweep_expired(
    consent_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
) -> Result<(), AppError> {
    let now = now_epoch();
    let mut pruned = 0usize;

    // Expired pending requests (raised but never answered).
    for (key, value) in consent_ks.prefix_iter_raw("consent_pending:").await? {
        let pending: PendingConsent = match serde_json::from_slice(&value) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "consent sweeper: skipping unreadable pending row");
                continue;
            }
        };
        if now >= pending.expires_at {
            consent_ks.remove(key).await?;
            pruned += 1;
            audit_expire(audit_ks, &pending.subject.agent).await;
        }
    }

    // Grants whose optional TTL has lapsed.
    for (key, value) in consent_ks.prefix_iter_raw("grant:").await? {
        let grant: ConsentGrant = match serde_json::from_slice(&value) {
            Ok(g) => g,
            Err(e) => {
                debug!(error = %e, "consent sweeper: skipping unreadable grant row");
                continue;
            }
        };
        if grant.is_expired(now) {
            consent_ks.remove(key).await?;
            pruned += 1;
            audit_expire(audit_ks, &grant.subject.agent).await;
        }
    }

    if pruned > 0 {
        info!(
            consent_pruned = pruned,
            "consent sweeper pruned expired records"
        );
    }
    Ok(())
}

async fn audit_expire(audit_ks: &KeyspaceHandle, agent: &str) {
    if let Err(e) = crate::audit::record(
        audit_ks,
        "consent.expire",
        "system:sweeper",
        Some(agent),
        "success",
        None,
        None,
    )
    .await
    {
        warn!(error = %e, "consent sweeper: deletion succeeded but audit::record failed");
    }
}
