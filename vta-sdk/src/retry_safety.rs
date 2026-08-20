//! Retry safety classification for every Trust Task the VTA serves.
//!
//! A client that retries a timed-out request is doing the right thing: the
//! dominant transport fault is a request that never arrived. The dangerous case
//! is the other one — the VTA *did* process it and only the reply was lost — and
//! whether that case is harmful depends entirely on the operation. Deleting an
//! already-deleted DID is free. Creating a second auto-assigned `did:webvh` is
//! not: the first is published in the log with nobody holding a reference to it.
//!
//! Today a caller cannot tell those apart, so it has to guess, and
//! [`crate::client::VtaClient`]'s own retry helpers guess conservatively for
//! everything. This module makes the property explicit and machine-readable, so
//! a retry layer can consult it instead of guessing, and so no new task can be
//! added without someone deciding which case it is.
//!
//! # The classification is about *lost replies*, not about mutation
//!
//! [`RetrySafety::RetrySafe`] does not mean "read-only". It means **a second
//! execution does no harm** — either because the operation converges on the same
//! end state (revoke, disable, delete) or because the duplicate artefact is inert
//! and self-expiring (a spare auth challenge). Both are safe to blind-retry, and
//! that is the only question a retry layer is asking.
//!
//! [`RetrySafety::Keyed`] means the opposite: a second execution leaves a
//! *second durable artefact that persists and matters*. These are the operations
//! that need an idempotency key the VTA dedups on.
//!
//! # Conservative by construction
//!
//! Where an operation's convergence is not obvious from its contract, it is
//! classified [`Keyed`](RetrySafety::Keyed) rather than
//! [`RetrySafe`](RetrySafety::RetrySafe). The asymmetry is deliberate and nearly
//! free: an over-classified task costs one dedup record, while an
//! under-classified one silently loses the protection in exactly the rare
//! lost-reply case the classification exists for. When you tighten one of these,
//! say why in the entry's comment.
//!
//! # This does not gate anything on its own
//!
//! Classification changes how a *keyed* request is handled. A request carrying no
//! idempotency key behaves exactly as it always has, on every task in the table —
//! so adding an entry here can never reject traffic that used to work.

use crate::trust_tasks;

/// What a second execution of a Trust Task costs, when the first one landed and
/// only its reply was lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetrySafety {
    /// No durable effect at all. Retry freely; no dedup record is worth keeping.
    ReadOnly,

    /// Mutating, but a repeat is harmless — it either converges on the same end
    /// state or leaves an inert, self-expiring duplicate. Safe to blind-retry
    /// with no idempotency key.
    RetrySafe,

    /// Non-convergent: a second execution leaves a second durable artefact that
    /// persists and matters. Needs an idempotency key; the response is cached
    /// and replayed to the retry.
    Keyed,

    /// As [`Keyed`](Self::Keyed), but the response carries secret material
    /// (mnemonics, sealed bundles, private keys), so the response is **not**
    /// cached. A replay is recognised and refused with a typed "already
    /// performed" answer rather than a stored copy of the secret — deduping the
    /// effect without turning the dedup store into a second place secrets live.
    KeyedSecret,
}

impl RetrySafety {
    /// Whether a caller may retry this task without an idempotency key.
    pub fn is_blind_retry_safe(self) -> bool {
        matches!(self, Self::ReadOnly | Self::RetrySafe)
    }

    /// Whether the VTA should dedup this task on an idempotency key when one is
    /// supplied.
    pub fn needs_key(self) -> bool {
        matches!(self, Self::Keyed | Self::KeyedSecret)
    }

    /// Whether a replayed request may be answered from the cached response.
    /// False for [`KeyedSecret`](Self::KeyedSecret), whose body is never stored.
    pub fn response_is_replayable(self) -> bool {
        !matches!(self, Self::KeyedSecret)
    }
}

use RetrySafety::{Keyed, KeyedSecret, ReadOnly, RetrySafe};

/// Every URI in [`trust_tasks::ALL_URIS`], with what a lost reply costs it.
///
/// Pinned exhaustively by `every_uri_is_classified` — a new task cannot reach
/// the catalog without an entry here, which is the point. Same discipline as
/// [`trust_tasks::REST_ROUTED_URIS`].
#[allow(deprecated)] // names the deprecated 0.1 URIs on purpose — they are still served
pub const RETRY_SAFETY: &[(&str, RetrySafety)] = &[
    // ── Auth ────────────────────────────────────────────────────────────
    // A spare challenge is inert and expires on its own.
    (trust_tasks::TASK_AUTH_CHALLENGE_0_1, RetrySafe),
    // Consumes the challenge, mints a session. A repeat fails deterministically
    // (challenge spent) or leaves a spare expiring session.
    (trust_tasks::TASK_AUTH_AUTHENTICATE_0_1, RetrySafe),
    // Refresh-token *rotation*: the old token is consumed as the new one is
    // issued, so a lost reply leaves the caller holding a spent token and no
    // replacement — locked out until re-auth. The one auth task that genuinely
    // needs the key.
    (trust_tasks::TASK_AUTH_REFRESH_0_1, Keyed),
    (trust_tasks::TASK_AUTH_REVOKE_SESSION_0_1, RetrySafe),
    (trust_tasks::TASK_AUTH_WHOAMI_0_1, ReadOnly),
    (trust_tasks::TASK_AUTH_SESSIONS_LIST_0_1, ReadOnly),
    (trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_0_1, RetrySafe),
    (trust_tasks::TASK_AUTH_PASSKEY_LOGIN_START_0_2, RetrySafe),
    (trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1, RetrySafe),
    (trust_tasks::TASK_AUTH_PASSKEY_LOGIN_FINISH_0_2, RetrySafe),
    // Consumes a one-shot step-up approval. A lost reply spends the approval
    // without the caller learning it was granted.
    (trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1, Keyed),
    (trust_tasks::TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2, Keyed),
    // ── Device ──────────────────────────────────────────────────────────
    // Registration is keyed by a caller-supplied device identity, so a repeat
    // lands on the same record — but it also mints device credentials, and
    // whether those are re-minted is not visible from the contract. Conservative.
    (trust_tasks::TASK_DEVICE_REGISTER_0_1, Keyed),
    (trust_tasks::TASK_DEVICE_REGISTER_0_2, Keyed),
    (trust_tasks::TASK_DEVICE_HEARTBEAT_0_1, RetrySafe),
    (trust_tasks::TASK_DEVICE_HEARTBEAT_0_2, RetrySafe),
    (trust_tasks::TASK_DEVICE_LIST_0_1, ReadOnly),
    (trust_tasks::TASK_DEVICE_LIST_0_2, ReadOnly),
    (trust_tasks::TASK_DEVICE_DISABLE_0_1, RetrySafe),
    (trust_tasks::TASK_DEVICE_WIPE_0_1, RetrySafe),
    (trust_tasks::TASK_DEVICE_SET_WAKE_0_1, RetrySafe),
    (trust_tasks::TASK_DEVICE_SET_WAKE_0_2, RetrySafe),
    // ── Messaging ───────────────────────────────────────────────────────
    (trust_tasks::TASK_MESSAGING_PING_0_1, ReadOnly),
    // ── ACL ─────────────────────────────────────────────────────────────
    (trust_tasks::TASK_ACL_LIST_0_1, ReadOnly),
    // Grant is addressed by subject DID + context, so a repeat overwrites the
    // same entry rather than adding a second.
    (trust_tasks::TASK_ACL_GRANT_0_1, RetrySafe),
    (trust_tasks::TASK_ACL_SHOW_0_1, ReadOnly),
    (trust_tasks::TASK_ACL_UPDATE_0_1, RetrySafe),
    (trust_tasks::TASK_ACL_CHANGE_ROLE_0_1, RetrySafe),
    (trust_tasks::TASK_ACL_REVOKE_0_1, RetrySafe),
    // Swap deletes the current subject's entry as it creates the new one. A lost
    // reply strands the caller: old entry gone, new one unknown to them. This is
    // remediation-plan F6 seen from the wire.
    (trust_tasks::TASK_ACL_SWAP_KEY_0_1, Keyed),
    // ── Contexts ────────────────────────────────────────────────────────
    (trust_tasks::TASK_CONTEXTS_LIST_1_0, ReadOnly),
    // Allocates an immutable BIP-32 base path. A second create is a second
    // context with a second path — the caller only ever hears about one.
    (trust_tasks::TASK_CONTEXTS_CREATE_1_0, Keyed),
    (trust_tasks::TASK_CONTEXTS_GET_1_0, ReadOnly),
    (trust_tasks::TASK_CONTEXTS_UPDATE_1_0, RetrySafe),
    (trust_tasks::TASK_CONTEXTS_UPDATE_DID_1_0, RetrySafe),
    (trust_tasks::TASK_CONTEXTS_PREVIEW_DELETE_1_0, ReadOnly),
    (trust_tasks::TASK_CONTEXTS_DELETE_1_0, RetrySafe),
    // ── Services ────────────────────────────────────────────────────────
    //
    // Every mutation here republishes the agent's did:webvh log, and that log
    // is append-only history. The question is therefore not "does the end state
    // converge" — it does — but "does a repeat leave a second entry", and for
    // an operation that writes one unconditionally it can.
    //
    // `enable` refuses a transport already enabled, so a repeat is a conflict
    // rather than a duplicate, which reads like RetrySafe. It is Keyed anyway:
    // the caller who lost the reply cannot tell that conflict apart from "it
    // never landed", and the cached response is exactly what resolves that.
    (trust_tasks::TASK_SERVICES_LIST_1_0, ReadOnly),
    (trust_tasks::TASK_SERVICES_GET_1_0, ReadOnly),
    (trust_tasks::TASK_SERVICES_ENABLE_1_0, Keyed),
    (trust_tasks::TASK_SERVICES_UPDATE_1_0, Keyed),
    // Disable schedules a drain, and a repeat inside the window would restart
    // it — extending the life of a mediator the operator is decommissioning.
    (trust_tasks::TASK_SERVICES_DISABLE_1_0, Keyed),
    (trust_tasks::TASK_SERVICES_ROLLBACK_1_0, Keyed),
    (trust_tasks::TASK_SERVICES_DRAIN_LIST_1_0, ReadOnly),
    // Destructive and not undoable: the messages the cancelled drain was
    // protecting are already gone by the time a retry arrives.
    (trust_tasks::TASK_SERVICES_DRAIN_CANCEL_1_0, Keyed),
    // ── Keys ────────────────────────────────────────────────────────────
    (trust_tasks::TASK_KEYS_LIST_0_1, ReadOnly),
    // The orphan-key case the OpenVTC retry helper already documents: a lost
    // reply mints a second key nobody references.
    (trust_tasks::TASK_KEYS_CREATE_0_1, Keyed),
    (trust_tasks::TASK_KEYS_IMPORT_0_1, Keyed),
    (trust_tasks::TASK_KEYS_SHOW_0_1, ReadOnly),
    (trust_tasks::TASK_KEYS_RENAME_0_1, RetrySafe),
    (trust_tasks::TASK_KEYS_REVOKE_0_1, RetrySafe),
    // Signing is a pure function of key + payload; the same request signs the
    // same bytes. No durable effect beyond the audit row.
    (trust_tasks::TASK_KEYS_SIGN_0_1, ReadOnly),
    (trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_0_1, ReadOnly),
    (
        trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_DOCUMENT_0_1,
        ReadOnly,
    ),
    // ── Seeds ───────────────────────────────────────────────────────────
    (trust_tasks::TASK_SEEDS_LIST_1_0, ReadOnly),
    // Rotation re-parents the key hierarchy. A second rotation on a lost reply
    // rotates again, past the seed the caller thinks it landed on.
    (trust_tasks::TASK_SEEDS_ROTATE_1_0, Keyed),
    // Response is the mnemonic itself, and the export guard is one-shot.
    (trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0, KeyedSecret),
    // ── Audit ───────────────────────────────────────────────────────────
    (trust_tasks::TASK_AUDIT_LIST_0_1, ReadOnly),
    (trust_tasks::TASK_AUDIT_GET_RETENTION_1_0, ReadOnly),
    (trust_tasks::TASK_AUDIT_UPDATE_RETENTION_1_0, RetrySafe),
    // ── Discovery ───────────────────────────────────────────────────────
    (trust_tasks::TASK_DISCOVERY_CAPABILITIES_1_0, ReadOnly),
    // ── Password vault ──────────────────────────────────────────────────
    (trust_tasks::TASK_VAULT_LIST_0_1, ReadOnly),
    (trust_tasks::TASK_VAULT_LIST_0_2, ReadOnly),
    (trust_tasks::TASK_VAULT_GET_0_1, ReadOnly),
    (trust_tasks::TASK_VAULT_GET_0_2, ReadOnly),
    // Upsert is addressed by entry id — a repeat writes the same value.
    (trust_tasks::TASK_VAULT_UPSERT_0_1, RetrySafe),
    (trust_tasks::TASK_VAULT_UPSERT_0_2, RetrySafe),
    (trust_tasks::TASK_VAULT_DELETE_0_1, RetrySafe),
    (trust_tasks::TASK_VAULT_ARCHIVE_0_1, RetrySafe),
    (trust_tasks::TASK_VAULT_UNARCHIVE_0_1, RetrySafe),
    (trust_tasks::TASK_VAULT_RESTORE_0_1, RetrySafe),
    (trust_tasks::TASK_VAULT_PURGE_0_1, RetrySafe),
    // Release and proxy-login read stored secrets and seal them to the caller.
    // No durable mutation, so a repeat is a repeat read — but the *response* is
    // secret-bearing, which matters to anything that would cache it.
    (trust_tasks::TASK_VAULT_RELEASE_0_1, ReadOnly),
    (trust_tasks::TASK_VAULT_RELEASE_0_2, ReadOnly),
    (trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1, ReadOnly),
    (trust_tasks::TASK_VAULT_PROXY_LOGIN_0_2, ReadOnly),
    (trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1, ReadOnly),
    (trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_2, ReadOnly),
    // ── did-management (remote DID-hosting control plane) ───────────────
    // Register/publish create a hosted record and a log entry respectively.
    (trust_tasks::TASK_DID_MANAGEMENT_DID_REGISTER_0_1, Keyed),
    (trust_tasks::TASK_DID_MANAGEMENT_DID_PUBLISH_0_1, Keyed),
    (trust_tasks::TASK_DID_MANAGEMENT_DID_DELETE_0_1, RetrySafe),
    (trust_tasks::TASK_DID_MANAGEMENT_DID_ENABLE_0_1, RetrySafe),
    (trust_tasks::TASK_DID_MANAGEMENT_DID_DISABLE_0_1, RetrySafe),
    (trust_tasks::TASK_DID_MANAGEMENT_DID_LIST_0_1, ReadOnly),
    (trust_tasks::TASK_DID_MANAGEMENT_DID_INFO_0_1, ReadOnly),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DID_CHECK_NAME_0_1,
        ReadOnly,
    ),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DID_CHANGE_OWNER_0_1,
        RetrySafe,
    ),
    // Rollback is a *relative* step — applying it twice rewinds twice.
    (trust_tasks::TASK_DID_MANAGEMENT_DID_ROLLBACK_0_1, Keyed),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DID_PROBLEM_REPORT_0_1,
        RetrySafe,
    ),
    (trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_CREATE_0_1, Keyed),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_UPDATE_0_1,
        RetrySafe,
    ),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_DISABLE_0_1,
        RetrySafe,
    ),
    (trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_PURGE_0_1, RetrySafe),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_SET_DEFAULT_0_1,
        RetrySafe,
    ),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_ASSIGN_0_1,
        RetrySafe,
    ),
    (
        trust_tasks::TASK_DID_MANAGEMENT_DOMAIN_UNASSIGN_0_1,
        RetrySafe,
    ),
    (trust_tasks::TASK_DID_MANAGEMENT_SERVER_REGISTER_0_1, Keyed),
    (trust_tasks::TASK_DID_MANAGEMENT_SERVER_HEALTH_0_1, ReadOnly),
    (
        trust_tasks::TASK_DID_MANAGEMENT_SERVER_STATS_SYNC_0_1,
        RetrySafe,
    ),
    (
        trust_tasks::TASK_DID_MANAGEMENT_REGISTRY_ADMIN_REGISTER_0_1,
        Keyed,
    ),
    (
        trust_tasks::TASK_DID_MANAGEMENT_REGISTRY_DEREGISTER_0_1,
        RetrySafe,
    ),
    // ── Config + management ─────────────────────────────────────────────
    (trust_tasks::TASK_CONFIG_SHOW_0_1, ReadOnly),
    (trust_tasks::TASK_CONFIG_PATCH_0_1, RetrySafe),
    (trust_tasks::TASK_MANAGEMENT_RELOAD_SERVICES_1_0, RetrySafe),
    // ── Passkey VMs ─────────────────────────────────────────────────────
    (
        trust_tasks::TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
        RetrySafe,
    ),
    // Enrolment adds a verification method to the DID document — a second
    // submission adds a second.
    (trust_tasks::TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1, Keyed),
    (trust_tasks::TASK_PASSKEY_VMS_LIST_0_1, ReadOnly),
    (trust_tasks::TASK_PASSKEY_VMS_REVOKE_0_1, RetrySafe),
    // ── Provisioning ────────────────────────────────────────────────────
    // Mints a DID, keys, an ACL grant and an authorization VC, and returns them
    // HPKE-sealed. Non-convergent in every one of those, and the response is the
    // secret bundle. Remediation-plan F3.
    (trust_tasks::TASK_PROVISION_INTEGRATION_0_2, KeyedSecret),
    // ── WebVH servers ───────────────────────────────────────────────────
    (trust_tasks::TASK_WEBVH_SERVERS_LIST_1_0, ReadOnly),
    (trust_tasks::TASK_WEBVH_SERVERS_REGISTER_1_0, Keyed),
    (trust_tasks::TASK_WEBVH_SERVERS_REMOVE_1_0, RetrySafe),
    (trust_tasks::TASK_WEBVH_SERVERS_DOMAINS_0_1, ReadOnly),
    (trust_tasks::TASK_WEBVH_SERVERS_RECONCILE_0_1, RetrySafe),
    // ── WebVH DIDs ──────────────────────────────────────────────────────
    (trust_tasks::TASK_WEBVH_DIDS_LIST_1_0, ReadOnly),
    // The finding that opened all of this. Production callers use
    // `WebvhPathMode::AutoAssign`, so a retried create is assigned a *different*
    // path: the first DID stays published in the log with no local reference.
    // An explicit path would collide and surface as a Conflict; auto-assign
    // silently orphans.
    (trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0, Keyed),
    (trust_tasks::TASK_WEBVH_DIDS_GET_1_0, ReadOnly),
    // Deleting an already-deleted DID answers not-found, which is deterministic
    // and therefore never retried.
    (trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0, RetrySafe),
    // Each update appends a log entry; two updates append two.
    (trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0, Keyed),
    (trust_tasks::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0, Keyed),
    (trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0, Keyed),
    (trust_tasks::TASK_WEBVH_AGENT_NAME_LIST_1_0, ReadOnly),
    (trust_tasks::TASK_WEBVH_AGENT_NAME_CHECK_1_0, ReadOnly),
    (trust_tasks::TASK_WEBVH_AGENT_NAME_SET_1_0, RetrySafe),
    (trust_tasks::TASK_WEBVH_AGENT_NAME_REMOVE_1_0, RetrySafe),
    (trust_tasks::TASK_WEBVH_AGENT_NAME_DISABLE_1_0, RetrySafe),
    (trust_tasks::TASK_WEBVH_AGENT_NAME_ENABLE_1_0, RetrySafe),
    // ── DID templates ───────────────────────────────────────────────────
    (trust_tasks::TASK_DID_TEMPLATES_LIST_2_0, ReadOnly),
    // Addressed by template name, so a repeat overwrites rather than duplicates.
    (trust_tasks::TASK_DID_TEMPLATES_CREATE_2_0, RetrySafe),
    (trust_tasks::TASK_DID_TEMPLATES_GET_2_0, ReadOnly),
    (trust_tasks::TASK_DID_TEMPLATES_UPDATE_2_0, RetrySafe),
    (trust_tasks::TASK_DID_TEMPLATES_DELETE_2_0, RetrySafe),
    // Render is a pure function of template + variables.
    (trust_tasks::TASK_DID_TEMPLATES_RENDER_2_0, ReadOnly),
    // ── Backup ──────────────────────────────────────────────────────────
    // The two-phase descriptor flow: initiate allocates a bundle, complete
    // returns the encrypted state. Both are non-convergent, and the completed
    // export is the whole VTA under a passphrase.
    (trust_tasks::TASK_BACKUP_INITIATE_EXPORT_1_0, Keyed),
    (trust_tasks::TASK_BACKUP_COMPLETE_EXPORT_1_0, KeyedSecret),
    (trust_tasks::TASK_BACKUP_INITIATE_IMPORT_1_0, Keyed),
    (trust_tasks::TASK_BACKUP_FINALIZE_IMPORT_1_0, Keyed),
    (trust_tasks::TASK_BACKUP_ABORT_1_0, RetrySafe),
    // ── Attestation ─────────────────────────────────────────────────────
    (trust_tasks::TASK_ATTESTATION_STATUS_1_0, ReadOnly),
    (trust_tasks::TASK_ATTESTATION_REPORT_1_0, ReadOnly),
    // ── Consent (DTTE) ──────────────────────────────────────────────────
    // A consent request is addressed by the payload digest it binds, so a
    // repeat lands on the same pending request.
    (trust_tasks::TASK_CONSENT_REQUEST_1_0, RetrySafe),
    (trust_tasks::TASK_CONSENT_DECISION_1_0, RetrySafe),
    (trust_tasks::TASK_TASK_CONSENT_DECISION_0_1, RetrySafe),
    (trust_tasks::TASK_CONSENT_REVOKE_1_0, RetrySafe),
    (trust_tasks::TASK_CONSENT_LIST_1_0, ReadOnly),
    (trust_tasks::TASK_CONSENT_APPROVER_SET_1_0, RetrySafe),
    (trust_tasks::TASK_CONSENT_APPROVER_LIST_1_0, ReadOnly),
    // ── Credentials ─────────────────────────────────────────────────────
    // Every issuance mints a new credential id; a lost reply leaves one issued
    // and unknown to the holder.
    (trust_tasks::TASK_VTA_CREDENTIALS_ISSUE_0_1, Keyed),
    (trust_tasks::TASK_VTA_CREDENTIALS_REVOKE_0_1, RetrySafe),
    // ── Memory ──────────────────────────────────────────────────────────
    (trust_tasks::TASK_VTA_MEMORY_PUT_0_1, RetrySafe),
    (trust_tasks::TASK_VTA_MEMORY_LIST_0_1, ReadOnly),
    (trust_tasks::TASK_VTA_MEMORY_DELETE_0_1, RetrySafe),
    // ── Policy ──────────────────────────────────────────────────────────
    (trust_tasks::TASK_POLICY_LIST_0_2, ReadOnly),
    (trust_tasks::TASK_POLICY_GET_0_1, ReadOnly),
    (trust_tasks::TASK_POLICY_UPSERT_0_2, RetrySafe),
    (trust_tasks::TASK_POLICY_DELETE_0_1, RetrySafe),
];

/// The retry-safety class of `uri`, or `None` if it is not a task this VTA
/// serves.
///
/// `None` means "unknown task", never "safe" — a caller deciding whether to
/// retry should treat it as [`Keyed`](RetrySafety::Keyed) and supply a key. The
/// census test guarantees `None` cannot mean "we forgot to classify it".
pub fn retry_safety(uri: &str) -> Option<RetrySafety> {
    RETRY_SAFETY
        .iter()
        .find(|(u, _)| *u == uri)
        .map(|(_, s)| *s)
}

/// Every task that needs an idempotency key, in catalog order. Handy for
/// operator tooling and for the VTA's own dispatch-side table.
pub fn keyed_uris() -> Vec<&'static str> {
    RETRY_SAFETY
        .iter()
        .filter(|(_, s)| s.needs_key())
        .map(|(u, _)| *u)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The census. A task cannot join the catalog without someone deciding what
    /// a lost reply costs it — which is the entire value of the table.
    #[test]
    fn every_uri_is_classified() {
        let classified: HashSet<&str> = RETRY_SAFETY.iter().map(|(u, _)| *u).collect();
        let missing: Vec<_> = trust_tasks::ALL_URIS
            .iter()
            .filter(|u| !classified.contains(*u))
            .collect();
        assert!(
            missing.is_empty(),
            "these tasks have no retry-safety classification — add them to \
             RETRY_SAFETY (when unsure, `Keyed` is the conservative answer): {missing:#?}"
        );
    }

    /// The other direction: a stale entry for a URI the catalog dropped is dead
    /// weight that reads like coverage.
    #[test]
    fn no_classification_without_a_task() {
        let catalog: HashSet<&str> = trust_tasks::ALL_URIS.iter().copied().collect();
        let orphans: Vec<_> = RETRY_SAFETY
            .iter()
            .map(|(u, _)| *u)
            .filter(|u| !catalog.contains(u))
            .collect();
        assert!(
            orphans.is_empty(),
            "classified URIs that are no longer in ALL_URIS: {orphans:#?}"
        );
    }

    #[test]
    fn no_duplicate_entries() {
        let mut seen = HashSet::new();
        for (u, _) in RETRY_SAFETY {
            assert!(seen.insert(*u), "duplicate classification for {u}");
        }
    }

    /// The two questions a retry layer actually asks, kept consistent: anything
    /// that needs a key is by definition not safe to blind-retry, and vice versa.
    #[test]
    fn needs_key_and_blind_retry_safe_partition_the_space() {
        for class in [
            RetrySafety::ReadOnly,
            RetrySafety::RetrySafe,
            RetrySafety::Keyed,
            RetrySafety::KeyedSecret,
        ] {
            assert_ne!(
                class.is_blind_retry_safe(),
                class.needs_key(),
                "{class:?} is both or neither"
            );
        }
    }

    #[test]
    fn secret_bearing_responses_are_never_replayable() {
        assert!(!RetrySafety::KeyedSecret.response_is_replayable());
        assert!(RetrySafety::Keyed.response_is_replayable());
    }

    /// The findings that opened the issue, pinned so a later edit cannot quietly
    /// downgrade them.
    #[test]
    fn the_operations_that_prompted_this_are_keyed() {
        for uri in [
            trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
            trust_tasks::TASK_KEYS_CREATE_0_1,
            trust_tasks::TASK_CONTEXTS_CREATE_1_0,
            trust_tasks::TASK_ACL_SWAP_KEY_0_1,
        ] {
            assert_eq!(
                retry_safety(uri).map(|s| s.needs_key()),
                Some(true),
                "{uri} must stay keyed"
            );
        }
        assert_eq!(
            retry_safety(trust_tasks::TASK_PROVISION_INTEGRATION_0_2),
            Some(RetrySafety::KeyedSecret)
        );
    }

    /// Deliberately *not* a `trusttasks.org/spec/` URI. The workspace manifest
    /// test treats every bound `spec/` URI as an assertion that the upstream
    /// registry publishes it, so a plausible-looking fake here fails that check
    /// rather than this one.
    #[test]
    fn unknown_uris_are_none() {
        assert_eq!(retry_safety("https://example.invalid/not-a-task/0.1"), None);
    }

    #[test]
    fn keyed_uris_are_a_subset_of_the_catalog() {
        let catalog: HashSet<&str> = trust_tasks::ALL_URIS.iter().copied().collect();
        let keyed = keyed_uris();
        assert!(!keyed.is_empty());
        for u in keyed {
            assert!(catalog.contains(u), "{u} not in ALL_URIS");
        }
    }
}
