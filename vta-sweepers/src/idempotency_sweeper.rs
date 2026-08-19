//! Background pruning of expired idempotency records.
//!
//! Called from the storage thread's interval loop. The records
//! (`vti_common::idempotency`) are read-through-expiry — a stale one is already
//! treated as absent at lookup time, so nothing incorrect is served between
//! sweeps. This exists purely to reclaim the space, which without it grows with
//! every keyed request forever.
//!
//! Deliberately **not** audited, unlike the ACL and consent sweepers. Those
//! remove a *grant* — the expiry is a security event an operator may need to
//! reconstruct. An idempotency record is retry bookkeeping; a row per expiry
//! would bury the audit log in noise carrying no security meaning.

use tracing::{debug, info, warn};

use vti_common::error::AppError;
use vti_common::idempotency::CacheEntry;
use vti_common::store::KeyspaceHandle;

/// Storage-key prefix every idempotency record shares. Must match
/// `vti_common::idempotency::store::storage_key`.
const RECORD_PREFIX: &str = "idem:";

/// Delete every record past its `expires_at`.
///
/// An unreadable row is deleted rather than skipped. A record whose shape no
/// longer parses can never be served — `get` deserialises before it can filter
/// — so leaving it in place keeps a row that is permanently dead weight *and*
/// permanently blocks its key, because a claim on that key reads it, fails to
/// decode, and surfaces as a store error.
pub async fn sweep_expired(idempotency_ks: &KeyspaceHandle) -> Result<(), AppError> {
    let now = chrono::Utc::now();
    let mut pruned = 0usize;
    let mut unreadable = 0usize;

    for (key, value) in idempotency_ks.prefix_iter_raw(RECORD_PREFIX).await? {
        match serde_json::from_slice::<CacheEntry>(&value) {
            Ok(entry) => {
                if entry.is_expired(now) {
                    idempotency_ks.remove(key).await?;
                    pruned += 1;
                }
            }
            Err(e) => {
                debug!(error = %e, "idempotency sweeper: removing an unreadable record");
                idempotency_ks.remove(key).await?;
                unreadable += 1;
            }
        }
    }

    if pruned > 0 || unreadable > 0 {
        info!(pruned, unreadable, "idempotency sweeper pruned records");
    }
    Ok(())
}

/// Sweep, logging rather than propagating a failure.
///
/// The interval loop must not stop because one pass failed: the records expire
/// on read regardless, so a missed sweep costs space and nothing else.
pub async fn sweep_expired_logged(idempotency_ks: &KeyspaceHandle) {
    if let Err(e) = sweep_expired(idempotency_ks).await {
        warn!(error = %e, "idempotency sweep failed; retrying next tick");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use vti_common::config::StoreConfig;
    use vti_common::idempotency::{EntryState, IdempotencyClass};
    use vti_common::store::Store;

    fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store");
        let ks = store.keyspace("idempotency-sweeper-test").expect("ks");
        (ks, dir)
    }

    fn entry(key: &str, expires_in: Duration) -> CacheEntry {
        let now = chrono::Utc::now();
        CacheEntry {
            state: EntryState::Completed,
            idempotency_key: key.into(),
            request_hash: [7u8; 32],
            response_status: 200,
            response_headers: vec![],
            response_body: b"{}".to_vec(),
            class: IdempotencyClass::NonDestructive,
            created_at: now,
            expires_at: now + expires_in,
        }
    }

    #[tokio::test]
    async fn expired_records_go_and_live_ones_stay() {
        let (ks, _d) = temp_ks();
        ks.insert(
            format!("{RECORD_PREFIX}aa:live").into_bytes(),
            &entry("live", Duration::hours(1)),
        )
        .await
        .expect("insert");
        ks.insert(
            format!("{RECORD_PREFIX}aa:dead").into_bytes(),
            &entry("dead", -Duration::hours(1)),
        )
        .await
        .expect("insert");

        sweep_expired(&ks).await.expect("sweep");

        let remaining = ks.prefix_iter_raw(RECORD_PREFIX).await.expect("iter");
        assert_eq!(remaining.len(), 1, "only the live record should survive");
        let survivor: CacheEntry = serde_json::from_slice(&remaining[0].1).expect("decode");
        assert_eq!(survivor.idempotency_key, "live");
    }

    /// An undecodable row blocks its key forever if left in place — a claim on
    /// it reads, fails to decode, and errors out. Removing it frees the key.
    #[tokio::test]
    async fn unreadable_records_are_removed_rather_than_skipped() {
        let (ks, _d) = temp_ks();
        ks.insert_raw(
            format!("{RECORD_PREFIX}aa:junk").into_bytes(),
            b"not a cache entry".to_vec(),
        )
        .await
        .expect("insert");

        sweep_expired(&ks).await.expect("sweep");

        assert!(
            ks.prefix_iter_raw(RECORD_PREFIX)
                .await
                .expect("iter")
                .is_empty()
        );
    }

    /// The sweep must not walk rows that are not its own.
    #[tokio::test]
    async fn records_outside_the_prefix_are_untouched() {
        let (ks, _d) = temp_ks();
        ks.insert_raw(b"other:row".to_vec(), b"keep me".to_vec())
            .await
            .expect("insert");

        sweep_expired(&ks).await.expect("sweep");

        assert_eq!(
            ks.get_raw(b"other:row".to_vec()).await.expect("get"),
            Some(b"keep me".to_vec())
        );
    }

    #[tokio::test]
    async fn an_empty_keyspace_sweeps_cleanly() {
        let (ks, _d) = temp_ks();
        sweep_expired(&ks).await.expect("sweep");
    }
}
