//! Central registry of the VTA's keyspace names.
//!
//! Every `store.keyspace(..)` call in the VTA (`vta-service` server, offline
//! CLIs, backup, tests) names its keyspace through a `const` here rather than a
//! bare string literal. This is the single source of truth that killed the
//! `"imported"` / `"imported_secrets"` test-vs-production divergence (a test
//! opened a *different*, empty keyspace than the one production writes). The
//! `no_bare_keyspace_literals` guard in `vta-service` keeps it that way by
//! scanning that crate's source for bare `.keyspace("…")` literals.
//!
//! Keyspace *names* live here; per-keyspace *key formats* (the `key:`, `seed:`,
//! `path_counter:` … record families inside a keyspace) are a separate concern
//! and are not yet centralised.
//!
//! A near-leaf crate: it holds the shared keyspace vocabulary (the name
//! constants) plus the [`Keyspaces`] handle bundle, so that every VTA subsystem
//! crate can name and pass keyspaces without depending on `vta-service`. Its
//! only dependency is `vti-common` (for `KeyspaceHandle`).

use vti_common::store::KeyspaceHandle;

/// Shared bundle of borrowed keyspace handles passed to operations that need
/// several keyspaces at once.
///
/// The struct is a pure field bundle — the constructors that borrow it from a
/// concrete `AppState` / `VtaState` live in `vta-service` (they know those
/// types), so this stays free of any `vta-service` dependency.
pub struct Keyspaces<'a> {
    pub keys: &'a KeyspaceHandle,
    pub acl: &'a KeyspaceHandle,
    pub contexts: &'a KeyspaceHandle,
    pub did_templates: &'a KeyspaceHandle,
    pub audit: &'a KeyspaceHandle,
    pub imported: &'a KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh: &'a KeyspaceHandle,
}

/// Master seed + key records (`key:`, `seed:`, `path_counter:`,
/// `active_seed_id`, `imported_kek_salt`, …) and the backup import sentinel.
pub const KEYS: &str = "keys";
/// Auth sessions + challenges.
pub const SESSIONS: &str = "sessions";
/// ACL entries + the seal record + the integrity-anchor root.
pub const ACL: &str = "acl";
/// Trust contexts (the BIP-32 key hierarchy roots).
pub const CONTEXTS: &str = "contexts";
/// Stored DID templates (global + context-scoped).
pub const DID_TEMPLATES: &str = "did_templates";
/// Audit log.
pub const AUDIT: &str = "audit";
/// Imported secret material (KEK-wrapped). Named `imported_secrets`, **not**
/// `imported` — the latter was a long-standing test-only typo that operated on
/// an empty keyspace disjoint from production. Always reference this const.
pub const IMPORTED_SECRETS: &str = "imported_secrets";
/// Non-extractable internal signing keys.
///
/// Deliberately **not** [`IMPORTED_SECRETS`]: that keyspace wraps its contents
/// under a KEK derived from the BIP-39 master seed, so anything stored there is
/// reconstructible by whoever holds the mnemonic. Internal keys exist precisely
/// to have no such path — their material is generated from the system CSPRNG,
/// never derived, and lives here instead.
///
/// In [`EXCLUDED_FROM_BACKUP`] by design, not by omission. A backup containing
/// this keyspace would be an export of keys the VTA promises never to export.
pub const INTERNAL_KEYS: &str = "internal_keys";
/// Ephemeral cache (resolver/auth caches).
pub const CACHE: &str = "cache";
/// Holder credential vault (third-party secrets stored on this VTA).
pub const VAULT: &str = "vault";
/// Persistent runtime service-enable state (`operations::protocol::runtime_state`).
pub const SERVICE_STATE: &str = "service_state";
/// Sealed-bootstrap anti-replay nonce log.
pub const SEALED_NONCES: &str = "sealed_nonces";
/// In-flight backup-bundle control-plane records.
pub const BACKUP_BUNDLES: &str = "backup_bundles";
/// WebVH DID records + `did.jsonl` state.
pub const WEBVH: &str = "webvh";
/// In-flight passkey-as-verificationMethod enrolment state.
pub const PASSKEY_VMS: &str = "passkey_vms";
/// Persisted protocol-management drain set.
pub const DRAINS: &str = "drains";
/// Per-kind previous-config snapshots for fail-forward rollback.
/// (Historically `operations::protocol::snapshot::KEYSPACE_NAME`.)
pub const SNAPSHOT: &str = "service_prev_config";
/// KMS-protected, unencrypted boot keyspace (TEE integrity manifest, etc.).
pub const BOOTSTRAP: &str = "bootstrap";
/// Inbound-messaging consent: durable grants + TTL'd pending requests
/// (`vti_common::consent`). The VTA is the first gate for bridged conversations.
pub const CONSENT: &str = "consent";
/// Per-(platform, context) approver bindings — who decides consent and how the
/// prompt routes (`vti_common::consent::ApproverBinding`).
pub const CONSENT_APPROVERS: &str = "consent_approvers";
/// VTA-issued credentials (minted by `vta/credentials/issue/0.1`, revoked by
/// `vta/credentials/revoke/0.1`). One record per credential keyed `cred:<id>`;
/// revocation is a tombstone (`revokedAt` set in place), not a delete. Distinct
/// from [`VAULT`] (which stores credentials the holder *holds*).
pub const ISSUED_CREDENTIALS: &str = "issued_credentials";

/// Per-context key/value store for AI-agent memory (`vta/memory/{put,list,
/// delete}/0.1`). One record per `(contextId, key)` pair, keyed
/// `mem:<contextId>:<key>`; `list` is a `mem:<contextId>:` prefix scan. Durable
/// user data → in [`BACKED_UP`].
pub const MEMORY: &str = "memory";

/// Rego policy modules for the Policy Decision Point (`policy/{upsert,list,
/// delete,evaluate}`). One `policy::PolicyModule` per id, keyed `policy:<id>`;
/// the active set is every enabled row, priority-ordered. Durable operator
/// security config → in [`BACKED_UP`] (a lost policy set would silently drop
/// enforcement on restore).
pub const POLICY: &str = "policy";

/// Task-execution consent for the PDP's `requireConsent` disposition: pending
/// approvals keyed by payload digest, and granted consents a re-submitted task
/// consumes. Distinct from [`CONSENT`] (messaging-bridge conversation consent).
/// One `policy::consent::PendingTaskConsent` per `pending:<digest>` and
/// `policy::consent::TaskConsentGrant` per `grant:<digest>:<requester>`.
/// Durable operator-facing security state → [`BACKED_UP`].
pub const TASK_CONSENT: &str = "task_consent";

/// Durable reliable-messaging outbox backing `vti_common::outbox_store::`
/// `VtiOutboxStore` for the delivery-layer `MessagingService` (D2 P2a
/// cut-over). Holds `Guaranteed`-delivery outbox entries; dormant in P2a (all
/// current sends are `BestEffort`) but wired so the drain/confirmation loops
/// persist across restarts once P2b adds guaranteed VTA pushes. Runtime state,
/// not backed up.
pub const OUTBOX: &str = "outbox";

/// Idempotency records for keyed Trust Tasks — one row per
/// `(actor, idempotency-key)`, holding the request digest and, for tasks whose
/// response may be replayed, the original response. Lets a client's retry of a
/// lost reply converge on the first execution instead of producing a second
/// durable effect.
///
/// Persistent rather than in-memory (unlike the `(actor, envelope-id)` replay
/// cache it sits beside) because the window that matters is exactly the one a
/// restart falls inside: the VTA processed the request, the reply was lost, and
/// the client is still retrying. Swept on TTL by
/// `vta_sweepers::idempotency_sweeper`. Runtime state, not backed up.
pub const IDEMPOTENCY: &str = "idempotency";

/// Every production keyspace. Partitioned by [`BACKED_UP`] +
/// [`EXCLUDED_FROM_BACKUP`]; the [`tests::backup_partition_is_total`] guard
/// asserts the partition stays exhaustive so a newly-added keyspace can't be
/// silently omitted from the backup decision.
pub const ALL: &[&str] = &[
    INTERNAL_KEYS,
    KEYS,
    SESSIONS,
    ACL,
    CONTEXTS,
    DID_TEMPLATES,
    AUDIT,
    IMPORTED_SECRETS,
    CACHE,
    VAULT,
    SERVICE_STATE,
    SEALED_NONCES,
    BACKUP_BUNDLES,
    WEBVH,
    PASSKEY_VMS,
    DRAINS,
    SNAPSHOT,
    BOOTSTRAP,
    CONSENT,
    CONSENT_APPROVERS,
    ISSUED_CREDENTIALS,
    MEMORY,
    POLICY,
    TASK_CONSENT,
    OUTBOX,
    IDEMPOTENCY,
];

/// Keyspaces whose contents a full `export_backup` captures (as typed
/// collections — see `operations::backup`).
pub const BACKED_UP: &[&str] = &[
    KEYS,
    ACL,
    CONTEXTS,
    AUDIT,
    IMPORTED_SECRETS,
    WEBVH,
    CONSENT,
    CONSENT_APPROVERS,
    // Durable agent memory is user data and must survive a restore.
    MEMORY,
    // Operator security policy — must survive a restore, else enforcement
    // silently reverts to whatever defaults boot-install provides.
    POLICY,
    // Task-consent grants are durable authorizations a re-submitted task
    // consumes; losing them on restore would strand in-flight approvals.
    TASK_CONSENT,
];

/// Keyspaces deliberately **not** in a backup.
///
/// Most are ephemeral / runtime / re-derivable: [`SESSIONS`], [`CACHE`],
/// [`SEALED_NONCES`], [`SERVICE_STATE`], [`BACKUP_BUNDLES`], [`PASSKEY_VMS`],
/// [`DRAINS`], [`SNAPSHOT`], [`BOOTSTRAP`]. [`DID_TEMPLATES`] and [`VAULT`]
/// hold durable operator/holder state and are **known backup gaps** — a
/// backup-fidelity follow-up should move them into [`BACKED_UP`], not leave
/// them silently dropped.
pub const EXCLUDED_FROM_BACKUP: &[&str] = &[
    // Non-extractable internal signing keys. Excluding them is the feature:
    // a backup that carried them would export keys the VTA guarantees never
    // to export, and restoring one elsewhere would silently clone a signer.
    INTERNAL_KEYS,
    SESSIONS,
    DID_TEMPLATES,
    CACHE,
    VAULT,
    SERVICE_STATE,
    SEALED_NONCES,
    BACKUP_BUNDLES,
    PASSKEY_VMS,
    DRAINS,
    SNAPSHOT,
    BOOTSTRAP,
    // Durable VTA-issued holder credentials. Like [`VAULT`], a known backup
    // gap — a backup-fidelity follow-up should move it into [`BACKED_UP`].
    ISSUED_CREDENTIALS,
    // Reliable-messaging outbox: runtime delivery state, re-driven from live
    // sends, not part of a state backup.
    OUTBOX,
    // Trust-Task idempotency records. Short-lived by construction (a retry
    // window, not durable state) and scoped to the VTA that served the original
    // request — restoring one elsewhere would claim to have already performed
    // operations that instance never did.
    IDEMPOTENCY,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The backup partition must be total and disjoint: every production
    /// keyspace is either backed up or explicitly excluded. Adding a keyspace
    /// to [`ALL`] without classifying it fails here — that's the point.
    #[test]
    fn backup_partition_is_total() {
        let all: BTreeSet<&str> = ALL.iter().copied().collect();
        let backed: BTreeSet<&str> = BACKED_UP.iter().copied().collect();
        let excluded: BTreeSet<&str> = EXCLUDED_FROM_BACKUP.iter().copied().collect();

        assert_eq!(all.len(), ALL.len(), "ALL has a duplicate");
        assert!(
            backed.is_disjoint(&excluded),
            "a keyspace is both backed up and excluded: {:?}",
            backed.intersection(&excluded).collect::<Vec<_>>()
        );
        let union: BTreeSet<&str> = backed.union(&excluded).copied().collect();
        assert_eq!(
            union, all,
            "backup partition is not exhaustive — every keyspace in ALL must be in \
             exactly one of BACKED_UP / EXCLUDED_FROM_BACKUP"
        );
    }
}
