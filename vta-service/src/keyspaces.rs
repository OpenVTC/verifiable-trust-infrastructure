//! Central registry of the VTA's keyspace names.
//!
//! Every `store.keyspace(..)` call in `vta-service` (server, offline CLIs,
//! backup, tests) names its keyspace through a `const` here rather than a bare
//! string literal. This is the single source of truth that killed the
//! `"imported"` / `"imported_secrets"` test-vs-production divergence (a test
//! opened a *different*, empty keyspace than the one production writes), and
//! the [`tests::no_bare_keyspace_literals`] guard keeps it that way.
//!
//! Keyspace *names* live here; per-keyspace *key formats* (the `key:`, `seed:`,
//! `path_counter:` … record families inside a keyspace) are a separate concern
//! and are not yet centralised.

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
/// delete,evaluate}`). One [`crate::policy::PolicyModule`] per id, keyed
/// `policy:<id>`; the active set is every enabled row, priority-ordered.
/// Durable operator security config → in [`BACKED_UP`] (a lost policy set
/// would silently drop enforcement on restore).
pub const POLICY: &str = "policy";

/// Task-execution consent for the PDP's `requireConsent` disposition: pending
/// approvals keyed by payload digest, and granted consents a re-submitted task
/// consumes. Distinct from [`CONSENT`] (messaging-bridge conversation consent).
/// One [`crate::policy::consent::PendingTaskConsent`] per `pending:<digest>` and
/// [`crate::policy::consent::TaskConsentGrant`] per `grant:<requester>:<digest>`.
/// Durable operator-facing security state → [`BACKED_UP`].
pub const TASK_CONSENT: &str = "task_consent";

/// Every production keyspace. Partitioned by [`BACKED_UP`] +
/// [`EXCLUDED_FROM_BACKUP`]; the [`tests::backup_partition_is_total`] guard
/// asserts the partition stays exhaustive so a newly-added keyspace can't be
/// silently omitted from the backup decision.
pub const ALL: &[&str] = &[
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
];

/// Test-only keyspaces (descriptor sweeper tests open isolated keyspaces so a
/// run can't clobber the shared `backup_bundles`).
#[cfg(test)]
pub const BACKUP_BUNDLES_TEST: &str = "backup_bundles_test";
#[cfg(test)]
pub const BACKUP_BUNDLES_SWEEPER_TEST: &str = "backup_bundles_sweeper_test";

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

    /// Guard (the "CI grep"): no bare `.keyspace("literal")` anywhere in the
    /// crate source except this registry. New code must name keyspaces through
    /// a `crate::keyspaces::*` const.
    #[test]
    fn no_bare_keyspace_literals() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        visit(&src, &mut |path, content| {
            if path.file_name().and_then(|n| n.to_str()) == Some("keyspaces.rs") {
                return;
            }
            for (lineno, line) in content.lines().enumerate() {
                if line.contains(".keyspace(\"") {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "bare keyspace string literal(s) found — use a crate::keyspaces::* const:\n{}",
            offenders.join("\n")
        );
    }

    fn visit(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, f);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
                && let Ok(content) = std::fs::read_to_string(&path)
            {
                f(&path, &content);
            }
        }
    }
}
