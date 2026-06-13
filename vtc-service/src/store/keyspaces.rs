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
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL` must stay in sync with the `AppState` keyspace fields.
    /// `server::run` opens 21 keyspaces into 21 `*_ks` fields — if a
    /// keyspace is added to one without the other, this trips.
    #[test]
    fn all_matches_app_state_keyspace_count() {
        assert_eq!(ALL.len(), 21, "ALL must list every AppState keyspace");
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
