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

/// Data rooms: one row per room at `rooms:<roomId>`.
///
/// Holds an owner, a visibility, an epoch and a retention period — and deliberately **no
/// member list**. Membership is decided by credentials the room itself issued, so a roster
/// here would make the room unmovable and make this service part of its membership.
pub use vti_rooms::ROOMS_KEYSPACE as ROOMS;

/// Room records at `room_records:<roomId>:<key>`. Ciphertext on the sealed tiers.
pub use vti_rooms::ROOM_RECORDS_KEYSPACE as ROOM_RECORDS;

/// The epoch key chain at `room_epoch_links:<roomId>:<epoch>`. Wrapped key material this
/// service cannot read — the key that opens a rung is a storage key no host ever holds.
///
/// **Backed up, and not optionally.** A room's records survive a restore as ciphertext; the
/// chain is what makes anything written before the last membership change openable at all.
/// Restoring the records without it hands the members a room they can see the shape of and
/// cannot read.
pub use vti_rooms::ROOM_EPOCH_LINKS_KEYSPACE as ROOM_EPOCH_LINKS;
pub const AUDIT: &str = "audit";
pub const AUDIT_KEY: &str = "audit_key";
/// Signed audit checkpoints (#708) — periodic Ed25519-signed commitments to
/// the audit chain head *and its entry count*, which is what makes truncation
/// detectable. Separate from [`AUDIT`] so a checkpoint is not just another row
/// in the keyspace an adversary is assumed to control.
pub const AUDIT_CHECKPOINT: &str = "audit_checkpoint";
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

/// Durable TSP relationship state (`vti_common::relationship_store`) — the Rev 3
/// §7.2.2 recovery store, keyed and serialised by the SDK. Transport state, not
/// community data: excluded from backup, like [`OUTBOX`]. Distinct from
/// [`RELATIONSHIPS`], which is the community's social graph.
pub const TSP_RELATIONSHIPS: &str = "tsp_relationships";
/// Vetting statement withdrawal notices (`vtc/vetting/revoke-statement/0.1`):
/// one row per (issuer, statement id, statement digest), written when a vetter
/// withdraws a statement and read whenever presented statements are counted.
pub const VETTING_REVOCATIONS: &str = "vetting_revocations";
/// Vetter profiles (`vtc/vetting/vetters/profile/0.1`): one row per vetter DID,
/// written by the vetter, deleted when they no longer hold a live grant, and
/// read by the vetter listing.
pub const VETTER_PROFILES: &str = "vetter_profiles";
/// The accepted-document-id record (VTI-OPS-025…027, SPEC §7.2 item 11): one
/// row per Trust Task document `id` accepted for execution, carrying the
/// digest of the document accepted under it and the instant the record may be
/// dropped. In the store rather than in a process-local map because VTI-OPS-027
/// requires the record to be **shared across every binding** — see
/// `crate::trust_tasks::accepted_ids`.
pub const ACCEPTED_IDS: &str = "accepted_ids";

/// Console signing-key delegations (#1684): one row per console `did:key` at
/// `console_key:<consoleDid>`, saying which admin DID that key may act as.
///
/// A *credential* of an existing admin identity, the way a registered passkey
/// is — it carries no role and confers nothing on its own, so a console key
/// never appears in `acl list`. See `crate::acl::console_key`.
pub const CONSOLE_KEYS: &str = "console_keys";

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
    TSP_RELATIONSHIPS,
    ENDORSEMENT_TYPES,
    SCHEMAS,
    ENDORSEMENTS,
    ROOMS,
    ROOM_RECORDS,
    ROOM_EPOCH_LINKS,
    AUDIT,
    AUDIT_KEY,
    AUDIT_CHECKPOINT,
    CONSUMED_INVITATIONS,
    INVITATIONS,
    OUTBOX,
    VETTING_REVOCATIONS,
    VETTER_PROFILES,
    ACCEPTED_IDS,
    CONSOLE_KEYS,
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
    ROOMS,
    ROOM_RECORDS,
    ROOM_EPOCH_LINKS,
    AUDIT,
    AUDIT_KEY,
    // Required, not optional: restoring the audit log without its
    // checkpoints reads as mass truncation — every signed checkpoint would
    // attest to more entries than the restored log holds, so a legitimate
    // restore would look exactly like the attack this mechanism detects.
    AUDIT_CHECKPOINT,
    // A consumed VIC must stay consumed across a restore, else a
    // restored community could re-redeem a single-use invitation.
    CONSUMED_INVITATIONS,
    // Issued-invitation registry — durable so revocation + listing
    // survive a restore.
    INVITATIONS,
    // A withdrawn vetting statement must stay withdrawn across a restore, or a
    // restored community would count a statement its vetter took back.
    VETTING_REVOCATIONS,
    // A vetter's published profile is theirs to replace, not the community's to
    // reconstruct: a restore without it would silently unlist every vetter.
    VETTER_PROFILES,
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
    // TSP relationship state is transport recovery state, local to this
    // deployment's mediator socket — a restore into a different environment
    // must not resurrect handshakes; peers re-relate on demand.
    TSP_RELATIONSHIPS,
    // The accepted-document-id record. Its whole horizon is the acceptance
    // window — minutes — so a restored row is all but certainly expired
    // already, and an expired row refuses nothing. Carrying it would also put
    // recorded task *responses* into an export whose scope is the community's
    // durable state, which this is not: it is execution bookkeeping, local to
    // the deployment that did the executing.
    ACCEPTED_IDS,
    // Console signing-key delegations. Excluded deliberately, and it is the
    // one exclusion here that is a security decision rather than a
    // housekeeping one: a delegation names a browser profile on a particular
    // machine, and a restore — into a rebuilt host, a staging clone, or a
    // different operator's hands — must not hand that browser the ability to
    // sign as an administrator again. The operator re-enrols, behind the
    // step-up, from the browser they are actually sitting at — one passkey
    // gesture. Nothing else goes with it: the ACL rows, the passkeys and the
    // bearer login all come back with the backup.
    CONSOLE_KEYS,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL` must stay in sync with the `AppState` keyspace fields.
    /// `server::run` opens every one of them into a `*_ks` field — if a
    /// keyspace is added to one without the other, this trips.
    #[test]
    fn all_matches_app_state_keyspace_count() {
        assert_eq!(ALL.len(), 33, "ALL must list every AppState keyspace");
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
