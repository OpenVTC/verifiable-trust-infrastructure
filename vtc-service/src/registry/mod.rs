//! Trust-registry integration surface — Phase 3 M3.1.
//!
//! Spec §8 + §13. The VTC publishes member records to the
//! configured trust registry asynchronously: every
//! `MemberAdded` / `MemberRemoved` / `RoleChanged` audit event
//! drives a `SyncJob` against the registry, with exponential
//! backoff and boot-time replay.
//!
//! ## Transport split (planning outcome)
//!
//! The upstream `affinidi-trust-registry-rs` ships a server +
//! a TRQP-v2.0-compliant HTTP query surface (`POST
//! /recognition`, `POST /authorization`) **plus** a DIDComm-only
//! admin protocol for record mutations (URIs under
//! `https://affinidi.com/didcomm/protocols/tr-admin/1.0/`). The
//! upstream does **not** publish a Rust client crate.
//!
//! Phase 3 D1 originally proposed a git-dep on the upstream;
//! that turned out to mean depending on the server crate, which
//! pulls in an `affinidi-tdk = "0.4"` that conflicts with our
//! workspace's `0.7`. Decision (per user, this PR) is to write
//! an in-tree client wrapping both transports:
//!
//! - **Reads** (cross-community recognition / authorization
//!   queries) → HTTP via `reqwest`. Lands in M3.10.
//! - **Writes** (create / update / delete record) → DIDComm
//!   against the upstream's `tr-admin/1.0/*` message types.
//!   Lands in M3.2 + M3.4.
//!
//! [`TrustRegistryClient`] is the trait both transports route
//! through. M3.1 lands the trait + the in-memory
//! [`MockRegistryClient`] for tests; the live HTTP +
//! DIDComm clients land alongside their consumers.
//!
//! ## Storage shape
//!
//! Three new keyspaces (spec §13):
//!
//! - `registry_records:<member_did>` — local mirror of what
//!   the registry knows about each member. Updated when a
//!   `SyncJob` completes successfully so the daemon can detect
//!   divergence at boot.
//! - `sync_queue:<job_id>` — pending / in-flight / failed
//!   sync jobs. Drained by `MembershipSyncer` (M3.4).
//! - `sync_cursor` — singleton row tracking the audit-log
//!   tail's last-seen timestamp so a daemon restart picks up
//!   exactly where the prior run left off (M3.3).

pub mod client;
pub mod health;
pub mod model;
pub mod policy;
pub mod storage;
pub mod syncer;
pub mod tail;
pub mod upstream;

pub use client::{MockRegistryClient, RegistryError, TrustRegistryClient};
pub use health::{HealthStatus, RegistryHealth, SyncerHealth, SyncerHealthSnapshot};
pub use model::{
    DEFAULT_MAX_ATTEMPTS, MAX_BACKOFF_SECONDS, RegistryRecord, RegistryStatus, SyncJob,
    SyncJobKind, SyncJobState, exponential_backoff_seconds,
};
pub use policy::{
    ClampOutcome, PublishOnJoinDecision, clamp_disposition, evaluate_publish_on_join,
    is_rtbf_purge, read_min_disposition,
};
pub use storage::{
    REGISTRY_RECORDS_PREFIX, SYNC_QUEUE_PREFIX, clear_sync_cursor, delete_record, delete_sync_job,
    get_record, get_sync_cursor, get_sync_job, list_records, list_sync_jobs, set_sync_cursor,
    store_record, store_sync_job,
};
pub use syncer::MembershipSyncer;
pub use tail::{WalkOutcome, walk as walk_audit_tail};
pub use upstream::UpstreamRegistryClient;
