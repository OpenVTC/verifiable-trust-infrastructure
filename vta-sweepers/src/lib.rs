//! Background TTL sweepers for the VTA's core keyspaces, extracted from
//! `vta-service` so the periodic-maintenance logic lives below the service
//! rather than inside it.
//!
//! - [`acl_sweeper`] — expires time-limited ACL grants (`expires_at`).
//! - [`consent_sweeper`] — expires stale pending-consent rows and consumed
//!   consent grants (the DTTE ceremony state).
//! - [`vault_sweeper`] — hard-purges grace-expired soft-deleted vault entries.
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
pub mod vault_sweeper;
