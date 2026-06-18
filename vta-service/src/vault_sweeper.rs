//! Background hard-purge of grace-expired vault tombstones.
//!
//! Both the password vault (`vault:` → [`StoredVaultEntry`]) and the
//! credential store (`cred:` → [`StoredCredential`]) soft-delete to a
//! `Deleted` tombstone carrying a `grace_until` deadline. This sweeper — run
//! from the storage thread's interval loop alongside the ACL/consent sweepers
//! — hard-purges any tombstone whose grace window has elapsed: the password
//! entry's secret is zeroised by the keyspace `remove`, and a credential's
//! secondary index is torn down by [`crate::vault::storage::delete`].
//!
//! Each purge is audited as `vault.purge` / `vault.cred.purge` (actor
//! `system:sweeper`, outcome `success:grace-expired`) — the same trail shape
//! the ACL and consent sweepers leave. Audit-record failures are warn-logged
//! but never abort the sweep.

use tracing::{debug, info, warn};

use vti_common::vault::{StoredVaultEntry, VaultStatus, delete_vault_entry};

use crate::error::AppError;
use crate::store::KeyspaceHandle;
use crate::vault::model::StoredCredential;
use crate::vault::storage as cred_storage;

/// Sweep the shared `vault` keyspace, hard-purging every soft-deleted password
/// entry and credential whose grace window has elapsed.
pub async fn sweep_expired(
    vault_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
) -> Result<(), AppError> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut purged = 0usize;

    // Password-vault tombstones (`vault:` records).
    for (_key, value) in vault_ks.prefix_iter_raw("vault:").await? {
        let stored: StoredVaultEntry = match serde_json::from_slice(&value) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "vault sweeper: skipping unreadable vault row");
                continue;
            }
        };
        if is_purgeable(
            stored.entry.status,
            stored.entry.grace_until.as_deref(),
            &now,
        ) {
            delete_vault_entry(vault_ks, &stored.entry.id).await?;
            purged += 1;
            audit_purge(
                audit_ks,
                "vault.purge",
                &stored.entry.id,
                Some(stored.entry.context_id.as_str()),
            )
            .await;
        }
    }

    // Credential-store tombstones (`cred:` records). `cred_storage::delete`
    // removes the record AND its secondary-index rows.
    for (_key, value) in vault_ks.prefix_iter_raw("cred:").await? {
        let cred: StoredCredential = match serde_json::from_slice(&value) {
            Ok(c) => c,
            Err(e) => {
                debug!(error = %e, "vault sweeper: skipping unreadable cred row");
                continue;
            }
        };
        if is_purgeable(cred.lifecycle, cred.grace_until.as_deref(), &now) {
            cred_storage::delete(vault_ks, &cred.id).await?;
            purged += 1;
            audit_purge(
                audit_ks,
                "vault.cred.purge",
                &cred.id,
                cred.community_did.as_deref(),
            )
            .await;
        }
    }

    if purged > 0 {
        info!(
            vault_purged = purged,
            "vault sweeper purged grace-expired tombstones"
        );
    }
    Ok(())
}

/// A tombstone is purgeable once it is `Deleted` and `now >= grace_until`.
/// Lexical RFC 3339 comparison, consistent with the rest of the vault layer.
fn is_purgeable(status: VaultStatus, grace_until: Option<&str>, now: &str) -> bool {
    matches!(status, VaultStatus::Deleted) && grace_until.is_some_and(|g| now >= g)
}

async fn audit_purge(audit_ks: &KeyspaceHandle, action: &str, id: &str, context_id: Option<&str>) {
    if let Err(e) = crate::audit::record(
        audit_ks,
        action,
        "system:sweeper",
        Some(id),
        "success:grace-expired",
        None,
        context_id,
    )
    .await
    {
        warn!(error = %e, action, "vault sweeper: purge succeeded but audit::record failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purgeable_only_when_deleted_and_past_grace() {
        let now = "2026-06-18T12:00:00+00:00";
        // Active / archived are never purged regardless of any stray grace.
        assert!(!is_purgeable(VaultStatus::Active, None, now));
        assert!(!is_purgeable(
            VaultStatus::Archived,
            Some("2020-01-01T00:00:00+00:00"),
            now
        ));
        // Deleted but still inside the window → keep.
        assert!(!is_purgeable(
            VaultStatus::Deleted,
            Some("2026-07-18T12:00:00+00:00"),
            now
        ));
        // Deleted and past the window → purge.
        assert!(is_purgeable(
            VaultStatus::Deleted,
            Some("2026-06-01T00:00:00+00:00"),
            now
        ));
        // Deleted with no grace recorded → not purgeable (defensive).
        assert!(!is_purgeable(VaultStatus::Deleted, None, now));
    }
}
