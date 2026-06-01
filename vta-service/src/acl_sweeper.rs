//! Background pruning of expired ACL rows.
//!
//! Called from the storage thread's interval loop. Walks the ACL keyspace
//! once and deletes any rows whose `expires_at` has passed.
//!
//! Every deletion is logged at `info!` AND recorded in the audit log as
//! an `acl.expire` event so operators can correlate "DID not in ACL"
//! errors with the deletion that caused them. Without this trail, the
//! sweeper's removals are invisible — there's nothing for the operator
//! to grep / SIEM-query when an entry mysteriously stops working.

use tracing::{debug, info, warn};

use crate::acl::{AclEntry, delete_acl_entry};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sweep the ACL keyspace and delete any row whose `expires_at` has
/// passed. Each deletion produces:
///
/// - one `info!` line with `did`, `role`, `expired_at`, and a
///   `reason = "expired"` field so operators can grep
///   `acl_sweeper` lines and see WHICH DIDs were pruned, not just
///   the aggregate count;
/// - one `audit::record(acl.expire, system:sweeper, <did>, ...)`
///   entry so the removal is queryable from the audit log alongside
///   `acl.create` / `acl.swap` / `acl.revoke`.
///
/// Audit-record failures are warn-logged but don't abort the sweep
/// — the deletion has already happened; losing the audit row is
/// strictly worse if it would cause the keyspace to keep an
/// expired entry around.
pub async fn sweep_expired(
    acl_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
) -> Result<(), AppError> {
    let now = now_epoch();
    let mut pruned = 0usize;

    let rows = acl_ks.prefix_iter_raw("acl:").await?;
    for (key, value) in rows {
        let entry: AclEntry = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(e) => {
                debug!(
                    key = %String::from_utf8_lossy(&key),
                    error = %e,
                    "sweeper: skipping unreadable acl row",
                );
                continue;
            }
        };
        if entry.is_expired(now) {
            let did = entry.did.clone();
            let role = entry.role.to_string();
            let expired_at = entry.expires_at;

            delete_acl_entry(acl_ks, &did).await?;
            pruned += 1;

            info!(
                did = %did,
                role = %role,
                expired_at = ?expired_at,
                now_epoch = now,
                reason = "expired",
                "acl sweeper deleted expired entry"
            );

            // Audit-log the removal so operators can correlate
            // "DID not in ACL" errors with the sweeper's prior
            // deletion. The actor is `system:sweeper` (synthetic,
            // matches the format `cli:vault-seed` uses elsewhere)
            // because no human / consumer triggered this — it's a
            // background timer firing on a previously-set TTL.
            if let Err(e) = crate::audit::record(
                audit_ks,
                "acl.expire",
                "system:sweeper",
                Some(&did),
                "success",
                None,
                None,
            )
            .await
            {
                warn!(
                    did = %did,
                    error = %e,
                    "acl sweeper: deletion succeeded but audit::record failed; audit log will be missing this removal"
                );
            }
        }
    }

    if pruned > 0 {
        info!(acl_pruned = pruned, "acl sweeper pruned expired rows");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{Role, store_acl_entry};
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    async fn fresh_store() -> (Store, KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).unwrap();
        let acl_ks = store.keyspace("acl").unwrap();
        let audit_ks = store.keyspace("audit").unwrap();
        (store, acl_ks, audit_ks, dir)
    }

    fn entry(did: &str, expires_at: Option<u64>) -> AclEntry {
        AclEntry::new(did, Role::Admin, "test").with_expires_at(expires_at)
    }

    /// Expired entries get deleted; permanent (no `expires_at`)
    /// entries are untouched. This is the core invariant — without
    /// it, either the wallet's long-term DID would be permanently
    /// orphaned by stale entries, or every entry would be at risk.
    #[tokio::test]
    async fn sweeper_deletes_expired_and_preserves_permanent() {
        let (_store, acl_ks, audit_ks, _dir) = fresh_store().await;

        let now = now_epoch();
        let expired = entry("did:key:zExpired", Some(now - 1));
        let live_ttl = entry("did:key:zLiveTtl", Some(now + 3600));
        let permanent = entry("did:key:zPermanent", None);
        store_acl_entry(&acl_ks, &expired).await.unwrap();
        store_acl_entry(&acl_ks, &live_ttl).await.unwrap();
        store_acl_entry(&acl_ks, &permanent).await.unwrap();

        sweep_expired(&acl_ks, &audit_ks).await.unwrap();

        // Expired entry: gone.
        assert!(
            crate::acl::get_acl_entry(&acl_ks, &expired.did)
                .await
                .unwrap()
                .is_none(),
            "expired entry must be pruned"
        );
        // Live-TTL + permanent: still there.
        assert!(
            crate::acl::get_acl_entry(&acl_ks, &live_ttl.did)
                .await
                .unwrap()
                .is_some(),
            "live-TTL entry must NOT be pruned"
        );
        assert!(
            crate::acl::get_acl_entry(&acl_ks, &permanent.did)
                .await
                .unwrap()
                .is_some(),
            "permanent entry must NOT be pruned"
        );

        // Audit-log entry for the deletion exists under
        // `log:<timestamp>:<uuid>`. Without this, the sweeper's
        // removals would be invisible to forensic queries.
        let audit_rows = audit_ks.prefix_iter_raw("log:").await.unwrap();
        let mut found_expire_row_for_did = false;
        for (_, value) in audit_rows {
            let s = String::from_utf8_lossy(&value);
            if s.contains("acl.expire") && s.contains(&expired.did) {
                found_expire_row_for_did = true;
                break;
            }
        }
        assert!(
            found_expire_row_for_did,
            "audit log must contain an acl.expire entry for the pruned DID"
        );
    }

    /// Sweep over an empty keyspace is a no-op + does not panic.
    #[tokio::test]
    async fn sweeper_handles_empty_keyspace() {
        let (_store, acl_ks, audit_ks, _dir) = fresh_store().await;
        sweep_expired(&acl_ks, &audit_ks).await.unwrap();
    }
}
