//! A secondary index over the audit log (#2599).
//!
//! The audit log is the one keyspace that only grows (retention is
//! indefinite), and a few reads want a sliver of it — the git-namespace
//! operations (`git-ns/activity/list`, a namespace's administrator history).
//! Each used to read and decode every envelope ever written. This index names
//! those rows, so a read decodes only the rows it shows.
//!
//! **A projection, caught up before it is read.** The envelopes are written by
//! `vtc_audit::AuditWriter`, shared with the VTA, into a keyspace whose
//! every row must be an envelope (chain-head recovery reads its last key, and
//! verification counts any other row as unparseable). So the index cannot ride
//! in the writer's batch. Instead it is a projection of the log with a cursor,
//! like the registry tail and the hook relay (`registry::tail`, `hooks`):
//! [`catch_up`] reads the envelopes after the cursor and writes their index
//! rows **and the advanced cursor in one store batch**, so the index always
//! describes exactly the log up to its cursor; every reader catches up before
//! it reads, so it sees every row written before it asked. Boot catches up
//! (the backfill of a log written before the index existed), and a restore
//! clears it ([`reset`]) to be rebuilt against the restored log.
//!
//! Audit keys are `<rfc3339-ts>:<event_id>` and sort in write order, which the
//! cursor relies on — as the registry tail does. Only keys are indexed, never
//! envelope content: a reader fetches the envelope by key, so an erasure that
//! rewrites one in place is seen.
//!
//! Catching up takes no lock: the rows it writes are a function of the log,
//! and the cursor is advanced conditionally, so two concurrent catch-ups
//! write the same rows and the one that loses the cursor race resumes from
//! the winner's cursor.

use vtc_audit::{AuditEnvelope, AuditEvent};
use vti_common::error::AppError;
use vti_common::store::{Batch, KeyspaceHandle, ScanOpts};

/// The last audit key indexed.
const CURSOR_KEY: &[u8] = b"cursor";
/// `gitns:<audit-key>` → the namespace the operation names (empty for none).
const GITNS_PREFIX: &[u8] = b"gitns:";
/// Audit rows read per step of a catch-up.
const CATCH_UP_PAGE: usize = 512;

/// Index every audit row written after the cursor. Returns how many rows it
/// read.
pub async fn catch_up(
    audit_ks: &KeyspaceHandle,
    index_ks: &KeyspaceHandle,
) -> Result<usize, AppError> {
    let mut read = 0usize;
    'restart: loop {
        let mut cursor = index_ks.get_raw(CURSOR_KEY.to_vec()).await?;
        let mut opts = ScanOpts::new(Vec::new(), CATCH_UP_PAGE);
        if let Some(c) = &cursor {
            opts = opts.after(c.clone());
        }
        let mut pager = audit_ks.scan_pager(opts);
        loop {
            let rows = pager.next_page().await?;
            let Some((last, _)) = rows.last() else {
                return Ok(read);
            };
            let last = last.clone();
            read += rows.len();
            let mut batch = Batch::new();
            match &cursor {
                Some(c) => batch.require_unchanged(CURSOR_KEY.to_vec(), c.clone()),
                None => batch.require_absent(CURSOR_KEY.to_vec()),
            };
            for (key, value) in &rows {
                // A row that does not decode indexes nothing; it is reported
                // where it matters, by `audit/verify`.
                let Ok(env) = serde_json::from_slice::<AuditEnvelope>(value) else {
                    continue;
                };
                if let AuditEvent::GitNsOperation(d) = &env.event {
                    let mut k = GITNS_PREFIX.to_vec();
                    k.extend_from_slice(key);
                    batch.insert_raw(k, d.namespace.clone().unwrap_or_default().into_bytes());
                }
            }
            batch.insert_raw(CURSOR_KEY.to_vec(), last.clone());
            if !index_ks.apply_batch(batch).await?.is_applied() {
                // Another catch-up advanced the cursor: resume from its.
                continue 'restart;
            }
            cursor = Some(last);
        }
    }
}

/// Clear the index, so the next [`catch_up`] rebuilds it from the log as it
/// is now — after a restore replaced the log.
pub async fn reset(index_ks: &KeyspaceHandle) -> Result<(), AppError> {
    let keys = index_ks.prefix_keys(Vec::new()).await?;
    let mut batch = Batch::new();
    for k in keys {
        batch.remove(k);
    }
    if !batch.is_empty() {
        index_ks.apply_batch(batch).await?;
    }
    Ok(())
}

/// Every git-namespace operation in the audit log, oldest first, decoded —
/// caught up first, so none written before the call is missing. `namespace`
/// narrows to the rows naming that namespace.
pub async fn git_ns_operations(
    audit_ks: &KeyspaceHandle,
    index_ks: &KeyspaceHandle,
    namespace: Option<&str>,
) -> Result<Vec<AuditEnvelope>, AppError> {
    catch_up(audit_ks, index_ks).await?;
    let mut out = Vec::new();
    for (key, ns) in index_ks.prefix_iter_raw(GITNS_PREFIX.to_vec()).await? {
        if namespace.is_some_and(|n| n.as_bytes() != ns.as_slice()) {
            continue;
        }
        let Some(raw) = audit_ks.get_raw(key[GITNS_PREFIX.len()..].to_vec()).await? else {
            continue;
        };
        if let Ok(env) = serde_json::from_slice::<AuditEnvelope>(&raw) {
            out.push(env);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vtc_audit::{AuditKeyStore, AuditWriter, GitNsOperationData};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn git_op(ns: Option<&str>, action: &str) -> AuditEvent {
        AuditEvent::GitNsOperation(GitNsOperationData {
            action: action.into(),
            namespace: ns.map(str::to_string),
            resource: None,
            right: None,
            policy_version: None,
            detail: None,
        })
    }

    async fn fixture() -> (
        tempfile::TempDir,
        KeyspaceHandle,
        KeyspaceHandle,
        AuditWriter,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let audit = store.keyspace("audit").unwrap();
        let index = store.keyspace("audit_index").unwrap();
        let keys = AuditKeyStore::new(store.keyspace("audit_key").unwrap());
        keys.ensure_initial_random().await.unwrap();
        let writer = AuditWriter::new(audit.clone(), keys);
        (dir, audit, index, writer)
    }

    #[tokio::test]
    async fn backfills_an_existing_log_and_follows_new_rows() {
        let (_dir, audit, index, writer) = fixture().await;
        // Written before anything indexed: the backfill finds them.
        writer
            .write(
                "did:key:zA",
                None,
                git_op(Some("gh/acme"), "gitNs.right.granted"),
            )
            .await
            .unwrap();
        writer
            .write("did:key:zA", None, git_op(None, "gitNs.drift.reported"))
            .await
            .unwrap();
        let all = git_ns_operations(&audit, &index, None).await.unwrap();
        assert_eq!(all.len(), 2);

        // Written after: the next read catches up before answering.
        writer
            .write(
                "did:key:zB",
                None,
                git_op(Some("gh/other"), "gitNs.right.revoked"),
            )
            .await
            .unwrap();
        let acme = git_ns_operations(&audit, &index, Some("gh/acme"))
            .await
            .unwrap();
        assert_eq!(acme.len(), 1);
        let all = git_ns_operations(&audit, &index, None).await.unwrap();
        assert_eq!(all.len(), 3, "a row written after the backfill is indexed");
        // A second catch-up with nothing new reads nothing.
        assert_eq!(catch_up(&audit, &index).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn reset_rebuilds_against_the_log() {
        let (_dir, audit, index, writer) = fixture().await;
        writer
            .write(
                "did:key:zA",
                None,
                git_op(Some("gh/acme"), "gitNs.right.granted"),
            )
            .await
            .unwrap();
        catch_up(&audit, &index).await.unwrap();
        reset(&index).await.unwrap();
        assert!(index.prefix_keys(Vec::new()).await.unwrap().is_empty());
        assert_eq!(
            git_ns_operations(&audit, &index, None).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn racing_catch_ups_index_each_row_once() {
        let (_dir, audit, index, writer) = fixture().await;
        for i in 0..20 {
            writer
                .write(
                    "did:key:zA",
                    None,
                    git_op(Some("gh/acme"), &format!("op{i}")),
                )
                .await
                .unwrap();
        }
        let (a, b) = tokio::join!(catch_up(&audit, &index), catch_up(&audit, &index));
        a.unwrap();
        b.unwrap();
        assert_eq!(
            git_ns_operations(&audit, &index, None).await.unwrap().len(),
            20
        );
    }
}
