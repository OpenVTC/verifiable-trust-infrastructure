//! Background TTL sweepers for the VTA's core keyspaces, extracted from
//! `vta-service` so the periodic-maintenance logic lives below the service
//! rather than inside it.
//!
//! - [`acl_sweeper`] — expires time-limited ACL grants (`expires_at`).
//! - [`consent_sweeper`] — expires stale pending-consent rows and consumed
//!   consent grants (the DTTE ceremony state).
//! - [`vault_sweeper`] — hard-purges grace-expired soft-deleted vault entries.
//! - [`idempotency_sweeper`] — reclaims expired Trust-Task idempotency records.
//!
//! Each depends only on the foundation/leaf crates (`vti-common`, `vta-audit`,
//! `vta-keyspaces`, and — for the vault sweeper — `vta-vault`), never on
//! `vta-service`. `vta-service` re-exports each as `crate::<module>`, so the
//! storage-thread sweep loop in `server.rs` and the other call sites are
//! unchanged.
//!
//! The backup-bundle sweeper stays in `vta-service` for now: it is coupled to
//! `backup_bundle_store`, part of the backup subsystem, and moves with that.

pub mod acl_sweeper;
pub mod consent_sweeper;
pub mod idempotency_sweeper;
mod rows;
pub mod vault_sweeper;

/// No sweeper reads a whole prefix in one call (#2626).
///
/// A sweeper runs on a timer against a keyspace that grows with use, and
/// `prefix_iter_raw` / `prefix_keys` answer in one piece: over vsock that is
/// one response frame, and past 16 MiB the sweep fails on every tick, nothing
/// is pruned and the keyspace only grows. Sweepers read through `rows::rows`
/// (bounded pages) or an expiry index instead.
#[cfg(test)]
mod no_unbounded_reads {
    #[test]
    fn sweepers_read_in_bounded_pages() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let source = std::fs::read_to_string(&path).unwrap();
            // Tests may read whatever they like; this module names the calls.
            let code = source.split("#[cfg(test)]").next().unwrap_or_default();
            for needle in [".prefix_iter_raw(", ".prefix_keys("] {
                assert!(
                    !code.contains(needle),
                    "{} calls `{needle}` outside its tests; read through `rows::rows` \
                     or an expiry index instead (#2626)",
                    path.display()
                );
            }
        }
    }
}
