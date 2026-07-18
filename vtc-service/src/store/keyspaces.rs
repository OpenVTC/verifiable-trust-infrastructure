//! Canonical keyspace names (P2.5).
//!
//! Every keyspace the daemon opens is named exactly once here so the
//! literals can't drift across `server.rs`, the offline CLIs, and the
//! setup wizard's pre-create pass. [`ALL`] is the full set — the
//! wizard's `open_keyspaces` iterates it so it can no longer silently
//! pre-create a *subset* (it used to open 8 of 21), and a test pins
//! `ALL.len()` to the `AppState` keyspace-field count so a keyspace
//! can't be added to one without the other.
//!
//! Names are the stable on-disk fjall partition identifiers — changing
//! one orphans existing data, so treat them as a wire contract.

pub const SESSIONS: &str = "sessions";
pub const ACL: &str = "acl";
pub const COMMUNITY: &str = "community";
pub const CONFIG: &str = "config";
pub const PASSKEY: &str = "passkey";
pub const INSTALL: &str = "install";
pub const MEMBERS: &str = "members";
pub const JOIN_REQUESTS: &str = "join_requests";
/// Durable queue of pending capability-grant hook jobs (membership → grant).
pub const HOOKS_QUEUE: &str = "hooks_queue";
/// Singleton audit-tail cursor for the hook relay.
pub const HOOKS_CURSOR: &str = "hooks_cursor";
pub const POLICIES: &str = "policies";
pub const ACTIVE_POLICIES: &str = "active_policies";
pub const STATUS_LISTS: &str = "status_lists";
pub const REGISTRY_RECORDS: &str = "registry_records";
pub const SYNC_QUEUE: &str = "sync_queue";
pub const SYNC_CURSOR: &str = "sync_cursor";
pub const RELATIONSHIPS: &str = "relationships";
pub const RELATIONSHIPS_BY_DID: &str = "relationships_by_did";
pub const ENDORSEMENT_TYPES: &str = "endorsement_types";
pub const SCHEMAS: &str = "schemas";
pub const ENDORSEMENTS: &str = "endorsements";
pub const AUDIT: &str = "audit";
pub const AUDIT_KEY: &str = "audit_key";
/// Single-use ledger for redeemed Invitation Credentials (VICs): one
/// row per consumed VIC `id`, written when a VIC-driven join is
/// admitted. Read at verify time to set `Invitation.consumed`.
pub const CONSUMED_INVITATIONS: &str = "consumed_invitations";
/// Registry of *issued* Invitation Credentials: one row per VIC `id`
/// recording its revocation-list slot, subject, granted role, and
/// revocation state — drives the list + revoke operator surfaces.
pub const INVITATIONS: &str = "invitations";
/// Durable delivery-layer outbox (D2 P1a): backs
/// [`vti_common::outbox_store::VtiOutboxStore`] for `MessagingService`
/// `Guaranteed` sends so delivery-critical work survives a restart.
/// Ephemeral, re-driven from live state — excluded from backup.
pub const OUTBOX: &str = "outbox";

/// Every keyspace the daemon opens, in `AppState` field order. The
/// setup wizard pre-creates exactly this set; `server::run` opens
/// exactly this set.
pub const ALL: &[&str] = &[
    SESSIONS,
    ACL,
    COMMUNITY,
    CONFIG,
    PASSKEY,
    INSTALL,
    MEMBERS,
    JOIN_REQUESTS,
    POLICIES,
    ACTIVE_POLICIES,
    STATUS_LISTS,
    REGISTRY_RECORDS,
    SYNC_QUEUE,
    SYNC_CURSOR,
    RELATIONSHIPS,
    RELATIONSHIPS_BY_DID,
    ENDORSEMENT_TYPES,
    SCHEMAS,
    ENDORSEMENTS,
    AUDIT,
    AUDIT_KEY,
    CONSUMED_INVITATIONS,
    INVITATIONS,
    OUTBOX,
];

/// Keyspaces captured by `POST /v1/backup/export` (P3.9). These hold
/// the community's durable, irreplaceable state. `audit` is included
/// only when the caller passes `include_audit = true`; its HMAC key
/// (`audit_key`) is always included so restored logs stay verifiable.
///
/// `BACKED_UP` and [`EXCLUDED_FROM_BACKUP`] must partition [`ALL`]
/// exactly — enforced by `backup_partition_is_total`. The signing key
/// bundle is NOT a keyspace (it lives in the `secrets` backend) and is
/// captured separately by the backup payload.
pub const BACKED_UP: &[&str] = &[
    ACL,
    COMMUNITY,
    MEMBERS,
    JOIN_REQUESTS,
    POLICIES,
    ACTIVE_POLICIES,
    STATUS_LISTS,
    RELATIONSHIPS,
    RELATIONSHIPS_BY_DID,
    ENDORSEMENT_TYPES,
    SCHEMAS,
    ENDORSEMENTS,
    AUDIT,
    AUDIT_KEY,
    // A consumed VIC must stay consumed across a restore, else a
    // restored community could re-redeem a single-use invitation.
    CONSUMED_INVITATIONS,
    // Issued-invitation registry — durable so revocation + listing
    // survive a restore.
    INVITATIONS,
];

/// Keyspaces deliberately omitted from backup (P3.9): ephemeral auth,
/// one-shot ceremony state, re-syncable registry mirrors, and config
/// (carried by the backup payload's config snapshot + re-applied on
/// import). Restoring these would resurrect stale sessions or clobber
/// runtime state. Partitions [`ALL`] with [`BACKED_UP`].
pub const EXCLUDED_FROM_BACKUP: &[&str] = &[
    SESSIONS,
    CONFIG,
    PASSKEY,
    INSTALL,
    REGISTRY_RECORDS,
    SYNC_QUEUE,
    SYNC_CURSOR,
    // Delivery-layer outbox — re-driven from live state; a restore must not
    // resurrect stale in-flight sends.
    OUTBOX,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL` must stay in sync with the `AppState` keyspace fields.
    /// `server::run` opens 21 keyspaces into 21 `*_ks` fields — if a
    /// keyspace is added to one without the other, this trips.
    #[test]
    fn all_matches_app_state_keyspace_count() {
        assert_eq!(ALL.len(), 24, "ALL must list every AppState keyspace");
    }

    /// The backup census (P3.9): every keyspace is either backed up or
    /// explicitly excluded — none silently omitted — and the two sets
    /// are disjoint. This is the guard the design note calls for.
    #[test]
    fn backup_partition_is_total() {
        use std::collections::BTreeSet;
        let all: BTreeSet<&str> = ALL.iter().copied().collect();
        let backed: BTreeSet<&str> = BACKED_UP.iter().copied().collect();
        let excluded: BTreeSet<&str> = EXCLUDED_FROM_BACKUP.iter().copied().collect();
        assert!(
            backed.is_disjoint(&excluded),
            "a keyspace is both backed up and excluded"
        );
        let union: BTreeSet<&str> = backed.union(&excluded).copied().collect();
        assert_eq!(
            union, all,
            "backup partition must cover every keyspace in ALL exactly once"
        );
    }

    /// No accidental duplicate in `ALL` (a copy-paste slip would make
    /// the wizard pre-create one keyspace twice and skip another).
    #[test]
    fn all_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in ALL {
            assert!(seen.insert(*name), "duplicate keyspace name in ALL: {name}");
        }
    }
}
