//! Canonical Trust-Task URIs for every VTA operation.
//!
//! One `pub const` per registered URI; grep `TASK_*` to enumerate the
//! full wire surface. Each URI is routed both on REST (via the
//! trust-task envelope's `type` field on `POST /api/trust-tasks` or
//! a dedicated unauth route) and on DIDComm (via the inbound message
//! `type`).
//!
//! ## URI shape (framework-canonical)
//!
//! ```text
//! https://trusttasks.org/spec/{namespace}/{op-path}/{maj}.{min}
//! ```
//!
//! Per framework SPEC.md §6.1 + the `slug` grammar in
//! `dtgwg-trust-tasks-tf/specs/spec.meta.schema.json` — hierarchical
//! slugs with `/`-delimited path segments are supported (the spec's
//! own example is `acl/grant`). The `/spec/` segment is mandatory;
//! `TypeUri::from_str` rejects URIs missing it (pinned by the
//! `framework_requires_canonical_uri_in_wire_type_field` test in
//! `vta-service::routes::trust_tasks`).
//!
//! Earlier drafts of this workspace used a flat form (no `/spec/`),
//! which deserialised cleanly as a Rust `&'static str` but failed
//! `serde_json::from_slice::<TrustTask<Value>>`. Resolved by adopting
//! the framework's canonical hierarchical-slug form throughout —
//! breaking change made before any external clients existed.
//!
//! ## Namespace
//!
//! - `https://trusttasks.org/spec/vta/...` — VTA operations (this module).
//! - `https://trusttasks.org/spec/did-hosting/...` — webvh-service.
//! - `https://trusttasks.org/spec/webvh/...` — webvh-protocol ops.
//!
//! ## Versioning
//!
//! `{maj}.{min}` only per the canonical Trust-Tasks spec — no patch
//! component. Bumping requires registering a NEW const at a new URL;
//! the old URL keeps routing to its handler until removed in a future
//! release. The router does NOT do version-family matching — `1.0` and
//! `1.1` are completely separate identifiers.
//!
//! ## Cross-crate consistency
//!
//! Every const here is reflected in the migration mapping in
//! `docs/05-design-notes/trust-task-uri-registry.md`. A parity harness
//! in `vta-service::routes::trust_tasks` confirms the dispatcher knows
//! about every const declared here.
//!
//! ## What lives here vs is planned
//!
//! v0.1 of this module ships the **auth slice only** — the six URIs
//! needed for the trust-task migration's Phase 2 "first-light" gate.
//! Remaining slices (keys, contexts, ACL, services, etc., ~70 more
//! URIs) land in Phase 3 of the migration initiative.

// ─── Auth slice — canonical cross-cutting specs ──────────────────────────
//
// These point at the framework's `spec/auth/*/0.1` canonical specs in the
// trusttasks-tf registry. VTA was the first implementer; the constant names
// keep their `_1_0` suffix for cargo-grep continuity but the URIs are now
// the canonical 0.1 specs. When the canonical specs cure to candidate /
// standard the constants will follow with a `_0_1` rename pass.

/// `spec/auth/challenge/0.1` — request a one-time nonce for a subject DID.
pub const TASK_AUTH_CHALLENGE_0_1: &str = "https://trusttasks.org/spec/auth/challenge/0.1";

/// `spec/auth/authenticate/0.1` — present the signed challenge inside a
/// proof-bearing Trust Task document; the proof IS the authentication.
pub const TASK_AUTH_AUTHENTICATE_0_1: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";

/// `spec/auth/refresh/0.1` — exchange a refresh token for a fresh access
/// token. Scope-monotonic.
pub const TASK_AUTH_REFRESH_0_1: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

/// `spec/auth/revoke-session/0.1` — revoke a session by id (or every
/// session for the producer's subject).
pub const TASK_AUTH_REVOKE_SESSION_0_1: &str =
    "https://trusttasks.org/spec/auth/revoke-session/0.1";

/// `spec/auth/whoami/0.1` — introspect the caller's current session: the
/// live `acr`/`amr` (reflecting any step-up since the token was minted) plus
/// freshly-resolved roles/scopes. Authenticated (bearer JWT); no token re-issue.
pub const TASK_AUTH_WHOAMI_0_1: &str = "https://trusttasks.org/spec/auth/whoami/0.1";

/// `spec/auth/sessions/list/0.1` — enumerate every active session the VTA
/// holds for the caller's subject (multi-device management). Companion to
/// whoami (single-session). Authenticated (bearer JWT); read-only.
pub const TASK_AUTH_SESSIONS_LIST_0_1: &str = "https://trusttasks.org/spec/auth/sessions/list/0.1";

/// `spec/auth/passkey/login/start/0.1` — begin a WebAuthn assertion
/// ceremony. Same wire form serves initial login AND AAL step-up via the
/// payload's `purpose` field.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (the `purpose` \
    enum uses the camelCase `stepUp` value). The VTA still accepts 0.1 during \
    the migration window but it will be removed in a future release — prefer \
    TASK_AUTH_PASSKEY_LOGIN_START_0_2.")]
pub const TASK_AUTH_PASSKEY_LOGIN_START_0_1: &str =
    "https://trusttasks.org/spec/auth/passkey/login/start/0.1";

/// `spec/auth/passkey/login/start/0.2` — successor to
/// [`TASK_AUTH_PASSKEY_LOGIN_START_0_1`]; `purpose: stepUp` (camelCase).
pub const TASK_AUTH_PASSKEY_LOGIN_START_0_2: &str =
    "https://trusttasks.org/spec/auth/passkey/login/start/0.2";

/// `spec/auth/passkey/login/finish/0.1` — submit the WebAuthn assertion.
/// On success the consumer issues a session (for `purpose: login`) or
/// elevates an existing session's acr (for `purpose: step-up`).
#[deprecated(note = "0.1 is superseded by the 0.2 wire form. The VTA still \
    accepts 0.1 during the migration window but it will be removed in a future \
    release — prefer TASK_AUTH_PASSKEY_LOGIN_FINISH_0_2.")]
pub const TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1: &str =
    "https://trusttasks.org/spec/auth/passkey/login/finish/0.1";

/// `spec/auth/passkey/login/finish/0.2` — successor to
/// [`TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1`].
pub const TASK_AUTH_PASSKEY_LOGIN_FINISH_0_2: &str =
    "https://trusttasks.org/spec/auth/passkey/login/finish/0.2";

/// `spec/auth/step-up/approve-response/0.1` — an approver's signed
/// ratification of a pending AAL step-up. The relying party verifies the
/// carried gate (did-signed Data Integrity proof, or a WebAuthn assertion)
/// and elevates the session's `amr`/`acr`.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (the evidence \
    enum uses the camelCase `didSigned` value). The VTA still accepts 0.1 \
    during the migration window but it will be removed in a future release — \
    prefer TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2.")]
pub const TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1: &str =
    "https://trusttasks.org/spec/auth/step-up/approve-response/0.1";

/// `spec/auth/step-up/approve-response/0.2` — successor to
/// [`TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1`]; camelCase `didSigned` evidence.
pub const TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2: &str =
    "https://trusttasks.org/spec/auth/step-up/approve-response/0.2";

/// `spec/auth/step-up/policy/0.2` — an administrator setting the maintainer's
/// AAL2 step-up policy (per-operation-class floors + the master `enabled`
/// switch). The maintainer validates, refuses a self-lockout, applies it
/// atomically, and returns the effective (canonicalized) policy. Authorized to
/// a super-admin; ships disabled. There is no 0.1 management wire form (the
/// policy was config-only before), so only 0.2 is dispatched.
pub const TASK_AUTH_STEP_UP_POLICY_0_2: &str =
    "https://trusttasks.org/spec/auth/step-up/policy/0.2";

// ─── Device slice (spec/device/*) ────────────────────────────────────────
// Canonical Trust Task registry shapes (dtgwg `device/*`). Companion/Service
// lifecycle on the VTA: register a device, heartbeat, list, disable, wipe, and
// set the push wake channel (the opaque gateway handle conveyed by the device).

/// `device/register/0.1` — a Companion/Service claims its DeviceBinding after
/// the provision-integration + acl/swap-key bootstrap.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (camelCase enum \
    values). The VTA still accepts 0.1 during the migration window but it will \
    be removed in a future release — prefer TASK_DEVICE_REGISTER_0_2.")]
pub const TASK_DEVICE_REGISTER_0_1: &str = "https://trusttasks.org/spec/device/register/0.1";

/// `device/register/0.2` — successor to [`TASK_DEVICE_REGISTER_0_1`]; identical
/// Rust shape, camelCase enum values on the wire.
pub const TASK_DEVICE_REGISTER_0_2: &str = "https://trusttasks.org/spec/device/register/0.2";

/// `device/heartbeat/0.1` — periodic check-in; refreshes `lastSeenAt` and
/// delivers queued operations.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (camelCase enum \
    values). The VTA still accepts 0.1 during the migration window but it will \
    be removed in a future release — prefer TASK_DEVICE_HEARTBEAT_0_2.")]
pub const TASK_DEVICE_HEARTBEAT_0_1: &str = "https://trusttasks.org/spec/device/heartbeat/0.1";

/// `device/heartbeat/0.2` — successor to [`TASK_DEVICE_HEARTBEAT_0_1`].
pub const TASK_DEVICE_HEARTBEAT_0_2: &str = "https://trusttasks.org/spec/device/heartbeat/0.2";

/// `device/list/0.1` — list the maintainer's registered devices.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (camelCase enum \
    values). The VTA still accepts 0.1 during the migration window but it will \
    be removed in a future release — prefer TASK_DEVICE_LIST_0_2.")]
pub const TASK_DEVICE_LIST_0_1: &str = "https://trusttasks.org/spec/device/list/0.1";

/// `device/list/0.2` — successor to [`TASK_DEVICE_LIST_0_1`]. The `capabilityFilter`
/// (`Capability`) enum carries camelCase values on the wire.
pub const TASK_DEVICE_LIST_0_2: &str = "https://trusttasks.org/spec/device/list/0.2";

/// `device/disable/0.1` — disable a device (cannot authenticate; record kept).
/// No 0.2 spec exists upstream; this stays on 0.1.
pub const TASK_DEVICE_DISABLE_0_1: &str = "https://trusttasks.org/spec/device/disable/0.1";

/// `device/wipe/0.1` — issue a wipe instruction for a device. No 0.2 spec
/// exists upstream; this stays on 0.1.
pub const TASK_DEVICE_WIPE_0_1: &str = "https://trusttasks.org/spec/device/wipe/0.1";

/// `device/set-wake/0.1` — the device conveys its opaque push `WakeHandle` to
/// the VTA, which owns the trigger allowlist and provisions the push gateway.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form. The VTA still \
    accepts 0.1 during the migration window but it will be removed in a future \
    release — prefer TASK_DEVICE_SET_WAKE_0_2.")]
pub const TASK_DEVICE_SET_WAKE_0_1: &str = "https://trusttasks.org/spec/device/set-wake/0.1";

/// `device/set-wake/0.2` — successor to [`TASK_DEVICE_SET_WAKE_0_1`]. No enum
/// values changed; the bump is the canonical-version alignment.
pub const TASK_DEVICE_SET_WAKE_0_2: &str = "https://trusttasks.org/spec/device/set-wake/0.2";

// ─── ACL slice (spec/vta/acl/*) ──────────────────────────────────────────

/// `spec/vta/acl/list/1.0` — list ACL entries, optionally filtered by
/// context. Payload: [`crate::protocols::acl_management::list::ListAclBody`].
pub const TASK_ACL_LIST_1_0: &str = "https://trusttasks.org/spec/vta/acl/list/1.0";

/// `spec/vta/acl/create/1.0` — add an ACL entry. Payload:
/// [`crate::protocols::acl_management::create::CreateAclBody`].
/// Auth: Admin or Initiator.
pub const TASK_ACL_CREATE_1_0: &str = "https://trusttasks.org/spec/vta/acl/create/1.0";

/// `spec/vta/acl/get/1.0` — retrieve a single entry. Payload:
/// [`crate::protocols::acl_management::get::GetAclBody`].
pub const TASK_ACL_GET_1_0: &str = "https://trusttasks.org/spec/vta/acl/get/1.0";

/// `spec/vta/acl/update/1.0` — patch role, label, or allowed contexts.
/// Payload: [`crate::protocols::acl_management::update::UpdateAclBody`].
/// Auth: Admin only.
pub const TASK_ACL_UPDATE_1_0: &str = "https://trusttasks.org/spec/vta/acl/update/1.0";

/// `spec/vta/acl/delete/1.0` — remove an entry. Payload:
/// [`crate::protocols::acl_management::delete::DeleteAclBody`].
/// Auth: Admin or Initiator.
pub const TASK_ACL_DELETE_1_0: &str = "https://trusttasks.org/spec/vta/acl/delete/1.0";

// ─── Contexts slice (spec/vta/contexts/*) ────────────────────────────────

/// `spec/vta/contexts/list/1.0` — list contexts visible to caller.
/// Payload: [`crate::protocols::context_management::list::ListContextsBody`]
/// (empty). Auth: any authenticated user.
pub const TASK_CONTEXTS_LIST_1_0: &str = "https://trusttasks.org/spec/vta/contexts/list/1.0";

/// `spec/vta/contexts/create/1.0` — create a new context. Payload:
/// [`crate::protocols::context_management::create::CreateContextBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_CREATE_1_0: &str = "https://trusttasks.org/spec/vta/contexts/create/1.0";

/// `spec/vta/contexts/get/1.0` — retrieve a context by id. Payload:
/// [`crate::protocols::context_management::get::GetContextBody`].
pub const TASK_CONTEXTS_GET_1_0: &str = "https://trusttasks.org/spec/vta/contexts/get/1.0";

/// `spec/vta/contexts/update/1.0` — update name/did/description.
/// Payload: [`crate::protocols::context_management::update::UpdateContextBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_UPDATE_1_0: &str = "https://trusttasks.org/spec/vta/contexts/update/1.0";

/// `spec/vta/contexts/update-did/1.0` — set the context's bound DID.
/// Payload:
/// [`crate::protocols::context_management::update_did::UpdateContextDidBody`].
/// Auth: Admin with context access.
pub const TASK_CONTEXTS_UPDATE_DID_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/update-did/1.0";

/// `spec/vta/contexts/preview-delete/1.0` — preview resources affected
/// by deletion. Payload:
/// [`crate::protocols::context_management::delete::DeleteContextPreviewBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_PREVIEW_DELETE_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/preview-delete/1.0";

/// `spec/vta/contexts/delete/1.0` — delete a context and its
/// associated resources. Payload:
/// [`crate::protocols::context_management::delete::DeleteContextBody`].
/// Auth: Super Admin only.
pub const TASK_CONTEXTS_DELETE_1_0: &str = "https://trusttasks.org/spec/vta/contexts/delete/1.0";

// ─── Keys slice (spec/vta/keys/*) ────────────────────────────────────────

/// `spec/vta/keys/list/1.0` — list key records (paginated, filterable).
/// Payload: [`crate::protocols::key_management::list::ListKeysBody`].
pub const TASK_KEYS_LIST_1_0: &str = "https://trusttasks.org/spec/vta/keys/list/1.0";

/// `spec/vta/keys/create/1.0` — derive a new key from the active seed.
/// Payload: [`crate::protocols::key_management::create::CreateKeyBody`].
/// Auth: Admin.
pub const TASK_KEYS_CREATE_1_0: &str = "https://trusttasks.org/spec/vta/keys/create/1.0";

/// `spec/vta/keys/get/1.0` — retrieve a single key record.
/// Payload: [`crate::protocols::key_management::get::GetKeyBody`].
pub const TASK_KEYS_GET_1_0: &str = "https://trusttasks.org/spec/vta/keys/get/1.0";

/// `spec/vta/keys/rename/1.0` — rename a key's identifier.
/// Payload: [`crate::protocols::key_management::rename::RenameKeyBody`].
/// Auth: Admin.
pub const TASK_KEYS_RENAME_1_0: &str = "https://trusttasks.org/spec/vta/keys/rename/1.0";

/// `spec/vta/keys/revoke/1.0` — invalidate a key.
/// Payload: [`crate::protocols::key_management::revoke::RevokeKeyBody`].
/// Auth: Admin.
pub const TASK_KEYS_REVOKE_1_0: &str = "https://trusttasks.org/spec/vta/keys/revoke/1.0";

/// `spec/vta/keys/sign/1.0` — sign a base64url-encoded payload with a
/// stored key (raw-bytes signing oracle).
/// Payload: [`crate::protocols::key_management::sign::SignRequestBody`].
/// Auth: write (Application or higher).
pub const TASK_KEYS_SIGN_1_0: &str = "https://trusttasks.org/spec/vta/keys/sign/1.0";

// ─── Seeds slice (spec/vta/seeds/*) ──────────────────────────────────────

/// `spec/vta/seeds/list/1.0` — list all seed records.
/// Payload: [`crate::protocols::seed_management::list::ListSeedsBody`]
/// (empty). Auth: Admin.
pub const TASK_SEEDS_LIST_1_0: &str = "https://trusttasks.org/spec/vta/seeds/list/1.0";

/// `spec/vta/seeds/rotate/1.0` — rotate the active seed, optionally
/// supplying a new mnemonic.
/// Payload: [`crate::protocols::seed_management::rotate::RotateSeedBody`].
/// Auth: Admin.
pub const TASK_SEEDS_ROTATE_1_0: &str = "https://trusttasks.org/spec/vta/seeds/rotate/1.0";

/// `spec/vta/seeds/export-mnemonic/1.0` — one-shot BIP-39 mnemonic
/// export under `MnemonicExportGuard`. Was `/keys/{id}/secret` in
/// the legacy REST surface — relocated to the seeds slice because it
/// operates on the seed identifier, not an individual key.
/// Payload: [`crate::protocols::key_management::secret::GetKeySecretBody`].
/// Auth: Admin only. Zeroized on drop.
pub const TASK_SEEDS_EXPORT_MNEMONIC_1_0: &str =
    "https://trusttasks.org/spec/vta/seeds/export-mnemonic/1.0";

// ─── Audit slice (spec/vta/audit/*) ──────────────────────────────────────

/// `spec/vta/audit/list-logs/1.0` — list audit log entries (paginated,
/// filterable). Payload:
/// [`crate::protocols::audit_management::list::ListAuditLogsBody`].
/// Auth: Admin.
pub const TASK_AUDIT_LIST_LOGS_1_0: &str = "https://trusttasks.org/spec/vta/audit/list-logs/1.0";

/// `spec/vta/audit/get-retention/1.0` — read the current retention
/// period. Payload:
/// [`crate::protocols::audit_management::retention::GetRetentionBody`]
/// (empty). Auth: Admin.
pub const TASK_AUDIT_GET_RETENTION_1_0: &str =
    "https://trusttasks.org/spec/vta/audit/get-retention/1.0";

/// `spec/vta/audit/update-retention/1.0` — update retention period.
/// Payload:
/// [`crate::protocols::audit_management::retention::UpdateRetentionBody`].
/// Auth: Super Admin only.
pub const TASK_AUDIT_UPDATE_RETENTION_1_0: &str =
    "https://trusttasks.org/spec/vta/audit/update-retention/1.0";

/// `spec/vta/discovery/capabilities/1.0` — describe VTA features,
/// services, and configured webvh hosts. Payload: empty
/// (`ListSeedsBody`-style — no input required). Auth: any
/// authenticated user.
pub const TASK_DISCOVERY_CAPABILITIES_1_0: &str =
    "https://trusttasks.org/spec/vta/discovery/capabilities/1.0";

// ─── Vault slice (spec/vault/*/0.1) ──────────────────────────────────────
//
// Canonical public Trust Tasks from the dtgwg-trust-tasks-tf registry.
// M1 ships the two read-only tasks (list + get); upsert, delete, sync,
// proxy-login, release, usage land in M2+.

/// `spec/vault/list/0.1` — query the metadata view of stored vault
/// entries, filtered by context, target, secret-kind, tag, etc. Secret
/// material is never returned by this task. Auth: any caller with the
/// derived `VaultRead` capability (i.e. role ∈ {Admin, Initiator,
/// Application, Reader}).
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (secretKind and \
    related enums use camelCase values). The VTA still accepts 0.1 during the \
    migration window but it will be removed in a future release — prefer \
    TASK_VAULT_LIST_0_2.")]
pub const TASK_VAULT_LIST_0_1: &str = "https://trusttasks.org/spec/vault/list/0.1";

/// `spec/vault/list/0.2` — successor to [`TASK_VAULT_LIST_0_1`]; camelCase
/// enum values (e.g. `secretKind: oauthTokens`).
pub const TASK_VAULT_LIST_0_2: &str = "https://trusttasks.org/spec/vault/list/0.2";

/// `spec/vault/get/0.1` — fetch the metadata view of a single entry by
/// id. Same auth as vault/list.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (response enums \
    use camelCase values). The VTA still accepts 0.1 during the migration \
    window but it will be removed in a future release — prefer TASK_VAULT_GET_0_2.")]
pub const TASK_VAULT_GET_0_1: &str = "https://trusttasks.org/spec/vault/get/0.1";

/// `spec/vault/get/0.2` — successor to [`TASK_VAULT_GET_0_1`].
pub const TASK_VAULT_GET_0_2: &str = "https://trusttasks.org/spec/vault/get/0.2";

/// `spec/vault/upsert/0.1` — create a new vault entry or update an
/// existing one. Secret material rides inside a pluggable cipher
/// envelope (see vault/_shared/0.1/sealed-envelope). Auth: VaultWrite.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (secretKind / \
    sealed-envelope / target enums use camelCase values). The VTA still \
    accepts 0.1 during the migration window but it will be removed in a future \
    release — prefer TASK_VAULT_UPSERT_0_2.")]
pub const TASK_VAULT_UPSERT_0_1: &str = "https://trusttasks.org/spec/vault/upsert/0.1";

/// `spec/vault/upsert/0.2` — successor to [`TASK_VAULT_UPSERT_0_1`].
pub const TASK_VAULT_UPSERT_0_2: &str = "https://trusttasks.org/spec/vault/upsert/0.2";

/// `spec/vault/delete/0.1` — soft-delete (tombstone) an entry with a
/// maintainer-defined grace window; the entry stays recoverable via
/// [`TASK_VAULT_RESTORE_0_1`] until the sweeper hard-purges it at
/// `grace_until`. A `force: true` body bypasses the window and hard-deletes
/// immediately (no recovery), equivalent to [`TASK_VAULT_PURGE_0_1`]. Auth:
/// VaultWrite. No 0.2 spec exists upstream; stays on 0.1.
pub const TASK_VAULT_DELETE_0_1: &str = "https://trusttasks.org/spec/vault/delete/0.1";

/// `spec/vault/archive/0.1` — soft-disable an entry: it is hidden from the
/// default `vault/list` and refused for use (release / proxy-login /
/// sign-trust-task) but fully restorable via [`TASK_VAULT_UNARCHIVE_0_1`].
/// Auth: VaultWrite. openvtc lifecycle extension (no upstream 0.2).
pub const TASK_VAULT_ARCHIVE_0_1: &str = "https://trusttasks.org/spec/vault/archive/0.1";

/// `spec/vault/unarchive/0.1` — return an `Archived` entry to `Active`.
/// Auth: VaultWrite. openvtc lifecycle extension.
pub const TASK_VAULT_UNARCHIVE_0_1: &str = "https://trusttasks.org/spec/vault/unarchive/0.1";

/// `spec/vault/restore/0.1` — undelete a soft-deleted (`Deleted`) entry back
/// to `Active`, allowed only while still inside the grace window. Auth:
/// VaultWrite. openvtc lifecycle extension.
pub const TASK_VAULT_RESTORE_0_1: &str = "https://trusttasks.org/spec/vault/restore/0.1";

/// `spec/vault/purge/0.1` — irreversibly hard-delete an entry (typically an
/// already-`Deleted` tombstone, but valid on any entry), skipping the grace
/// window. The secret bytes are zeroised on removal; no recovery. Auth:
/// VaultWrite. openvtc lifecycle extension.
pub const TASK_VAULT_PURGE_0_1: &str = "https://trusttasks.org/spec/vault/purge/0.1";

/// `spec/vault/release/0.1` — release the cleartext secret material of an
/// entry inside a pluggable cipher envelope sealed to the requesting
/// consumer. Auth: FillRelease.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (secretKind / \
    sealed-envelope / step-up-proof enums use camelCase values). The VTA still \
    accepts 0.1 during the migration window but it will be removed in a future \
    release — prefer TASK_VAULT_RELEASE_0_2.")]
pub const TASK_VAULT_RELEASE_0_1: &str = "https://trusttasks.org/spec/vault/release/0.1";

/// `spec/vault/release/0.2` — successor to [`TASK_VAULT_RELEASE_0_1`].
pub const TASK_VAULT_RELEASE_0_2: &str = "https://trusttasks.org/spec/vault/release/0.2";

/// `spec/vault/proxy-login/0.1` — the VTA performs an authentication at
/// the third-party site on the holder's behalf using the entry's secret
/// material and returns a SessionBlob (cookies + headers + optional
/// localStorage) wrapped in a pluggable cipher envelope sealed to the
/// requesting consumer. The long-term credential never leaves the VTA.
/// Auth: ProxyLogin.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (site-target / \
    step-up-proof enums use camelCase values). The VTA still accepts 0.1 \
    during the migration window but it will be removed in a future release — \
    prefer TASK_VAULT_PROXY_LOGIN_0_2.")]
pub const TASK_VAULT_PROXY_LOGIN_0_1: &str = "https://trusttasks.org/spec/vault/proxy-login/0.1";

/// `spec/vault/proxy-login/0.2` — successor to [`TASK_VAULT_PROXY_LOGIN_0_1`].
pub const TASK_VAULT_PROXY_LOGIN_0_2: &str = "https://trusttasks.org/spec/vault/proxy-login/0.2";

/// `spec/vault/sign-trust-task/0.1` — the VTA attaches an eddsa-jcs-2022
/// Data Integrity proof to a Trust Task envelope, signing as the
/// principal DID of a `did-self-issued` or `didcomm-peer` vault entry.
/// The long-term signing key never leaves the VTA. Per-envelope signing
/// complement to proxy-login's session-credential minting — used when a
/// consumer needs to issue follow-up tasks during a proxy-login'd
/// session and the RP expects them signed by the session DID.
/// Auth: SignTrustTask capability.
#[deprecated(note = "0.1 is superseded by the 0.2 wire form (step-up-proof \
    enums use camelCase values). The VTA still accepts 0.1 during the \
    migration window but it will be removed in a future release — prefer \
    TASK_VAULT_SIGN_TRUST_TASK_0_2.")]
pub const TASK_VAULT_SIGN_TRUST_TASK_0_1: &str =
    "https://trusttasks.org/spec/vault/sign-trust-task/0.1";

/// `spec/vault/sign-trust-task/0.2` — successor to
/// [`TASK_VAULT_SIGN_TRUST_TASK_0_1`].
pub const TASK_VAULT_SIGN_TRUST_TASK_0_2: &str =
    "https://trusttasks.org/spec/vault/sign-trust-task/0.2";

// ─── Credential-vault slice (spec/vault/credentials/*) ───────────────────
//
// The VTA's *credential* vault — the W3C / SD-JWT-VC credentials a holder
// holds (invitations, memberships, roles, …), distinct from the
// password-manager vault above (same keyspace, disjoint `cred:` namespace).
// Receive verifies + stores; query is a DCQL-shaped filtered search
// (no-enumeration); get fetches one credential's body for presentation.

/// `spec/vault/credentials/receive/0.1` — verify + store a received credential
/// (requires `VaultWrite`).
pub const TASK_VAULT_CREDENTIALS_RECEIVE_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/receive/0.1";

/// `spec/vault/credentials/query/0.1` — filtered (DCQL-shaped) search returning
/// body-free descriptors (requires `VaultRead`).
pub const TASK_VAULT_CREDENTIALS_QUERY_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/query/0.1";

/// `spec/vault/credentials/get/0.1` — fetch one stored credential's full body by
/// id, for presentation (requires `VaultRead`).
pub const TASK_VAULT_CREDENTIALS_GET_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/get/0.1";

// Credential archival lifecycle (openvtc extension). Mirrors the
// password-vault lifecycle above but gated on `CredentialWrite` (not
// `VaultWrite`) — removing a holder's credentials is a higher-trust action
// than receiving them. The archival `lifecycle` state is orthogonal to a
// credential's `CredentialStatus` (validity, status-list driven); query/get
// exclude non-Active credentials by default.

/// `spec/vault/credentials/archive/0.1` — soft-disable a credential (hidden
/// from default query, refused for presentation, restorable). Auth:
/// CredentialWrite.
pub const TASK_VAULT_CREDENTIALS_ARCHIVE_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/archive/0.1";

/// `spec/vault/credentials/unarchive/0.1` — return an archived credential to
/// `Active`. Auth: CredentialWrite.
pub const TASK_VAULT_CREDENTIALS_UNARCHIVE_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/unarchive/0.1";

/// `spec/vault/credentials/delete/0.1` — soft-delete (tombstone) a credential
/// with a grace window; recoverable via restore until the sweeper purges it.
/// `force: true` hard-deletes immediately (tears down the `idx:` secondary
/// index too). Auth: CredentialWrite.
pub const TASK_VAULT_CREDENTIALS_DELETE_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/delete/0.1";

/// `spec/vault/credentials/restore/0.1` — undelete a soft-deleted credential
/// while still inside the grace window. Auth: CredentialWrite.
pub const TASK_VAULT_CREDENTIALS_RESTORE_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/restore/0.1";

/// `spec/vault/credentials/purge/0.1` — irreversibly hard-delete a credential
/// (and its index rows), skipping the grace window. Auth: CredentialWrite.
pub const TASK_VAULT_CREDENTIALS_PURGE_0_1: &str =
    "https://trusttasks.org/spec/vault/credentials/purge/0.1";

// ─── DID-management slice (spec/did-management/*) ────────────────────────
//
// Canonical Trust Tasks for DID + domain + server + registry management
// from `dtgwg-trust-tasks-tf/specs/did-management/`. The VTA used to
// expose its own `vta/webvh/dids/*/1.0` namespace and the did-hosting
// service used its own `did-hosting/did/*` namespace — neither
// consumed the canonical spec. These URIs are the shared vocabulary
// both sides should speak going forward; the old namespaces stay
// dispatchable during the migration window and are deprecated once
// every consumer (plugin, pnm-cli) has cut over.

// ─── DID-management — did/* (11 tasks) ───────────────────────────────────

/// `spec/did-management/did/register/0.1` — claim a path on a hosting
/// server and publish the first DID document atomically. The producer
/// (DID owner via VTA) ships the DID document + initial keys; the
/// consumer (did-hosting service) verifies the path is free, writes the
/// `did.jsonl` log, and registers the DID in its persistent store.
pub const TASK_DID_MANAGEMENT_DID_REGISTER_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/register/0.1";

/// `spec/did-management/did/publish/0.1` — publish a new log entry for
/// an existing DID. Used for key rotation, service-endpoint updates,
/// and any other did-document mutation the owner needs to record.
pub const TASK_DID_MANAGEMENT_DID_PUBLISH_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/publish/0.1";

/// `spec/did-management/did/delete/0.1` — soft-delete a DID. The
/// `did.jsonl` log is preserved (the chain is append-only); the
/// resolved endpoint returns a tombstone. Hard-delete requires
/// `did-management/domain/purge/0.1` once the domain is disabled.
pub const TASK_DID_MANAGEMENT_DID_DELETE_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/delete/0.1";

/// `spec/did-management/did/enable/0.1` — re-enable a previously
/// disabled DID. The owner reclaims operational control without
/// re-registering.
pub const TASK_DID_MANAGEMENT_DID_ENABLE_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/enable/0.1";

/// `spec/did-management/did/disable/0.1` — temporarily disable a DID.
/// Resolution returns a `disabled` marker; the owner can re-enable
/// later. Distinct from delete: delete is final, disable is reversible.
pub const TASK_DID_MANAGEMENT_DID_DISABLE_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/disable/0.1";

/// `spec/did-management/did/list/0.1` — list DIDs owned by the caller
/// at the hosting service. Paginated; supports filtering by domain
/// and status.
pub const TASK_DID_MANAGEMENT_DID_LIST_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/list/0.1";

/// `spec/did-management/did/info/0.1` — fetch metadata for a specific
/// owned DID (current did-document, log digest, status, owner DID,
/// domain). Read-only.
pub const TASK_DID_MANAGEMENT_DID_INFO_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/info/0.1";

/// `spec/did-management/did/check-name/0.1` — test whether a path is
/// available for `did/register/0.1`. Returns `available | taken | reserved`.
/// Idempotent + side-effect-free.
pub const TASK_DID_MANAGEMENT_DID_CHECK_NAME_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/check-name/0.1";

/// `spec/did-management/did/change-owner/0.1` — atomic owner-transfer
/// between two consenting DIDs. Both parties countersign; the hosting
/// service rebinds the DID's owner record on commit.
pub const TASK_DID_MANAGEMENT_DID_CHANGE_OWNER_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/change-owner/0.1";

/// `spec/did-management/did/rollback/0.1` — append a new log entry that
/// reverts the document to a prior state. The chain stays append-only;
/// the new entry just re-asserts an earlier verification-method /
/// service-endpoint set.
pub const TASK_DID_MANAGEMENT_DID_ROLLBACK_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/rollback/0.1";

/// `spec/did-management/did/problem-report/0.1` — async error envelope
/// the hosting service emits when a deferred operation (a published log
/// entry that fails witness verification, a registry sync that
/// regresses, etc.) needs to surface to the owner.
pub const TASK_DID_MANAGEMENT_DID_PROBLEM_REPORT_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/problem-report/0.1";

// ─── DID-management — domain/* (7 tasks) ─────────────────────────────────

/// `spec/did-management/domain/create/0.1` — register a new domain on
/// the hosting service. Multi-tenant ops; the operator chooses the
/// FQDN. The hosting service writes the domain entry and provisions
/// any per-domain key material it needs.
pub const TASK_DID_MANAGEMENT_DOMAIN_CREATE_0_1: &str =
    "https://trusttasks.org/spec/did-management/domain/create/0.1";

/// `spec/did-management/domain/update/0.1` — mutate domain metadata
/// (display name, contact info, registry pointer). Does NOT rename the
/// domain — that would invalidate every DID's identifier under it.
pub const TASK_DID_MANAGEMENT_DOMAIN_UPDATE_0_1: &str =
    "https://trusttasks.org/spec/did-management/domain/update/0.1";

/// `spec/did-management/domain/disable/0.1` — freeze a domain. Existing
/// DIDs resolve as `disabled`; no new DIDs can be registered under it.
/// Required precondition for `domain/purge/0.1`.
pub const TASK_DID_MANAGEMENT_DOMAIN_DISABLE_0_1: &str =
    "https://trusttasks.org/spec/did-management/domain/disable/0.1";

/// `spec/did-management/domain/purge/0.1` — hard-delete a disabled
/// domain + every DID under it. Irreversible. Grace window enforced
/// server-side.
pub const TASK_DID_MANAGEMENT_DOMAIN_PURGE_0_1: &str =
    "https://trusttasks.org/spec/did-management/domain/purge/0.1";

/// `spec/did-management/domain/set-default/0.1` — choose the default
/// domain for DID-create operations that omit a domain parameter.
pub const TASK_DID_MANAGEMENT_DOMAIN_SET_DEFAULT_0_1: &str =
    "https://trusttasks.org/spec/did-management/domain/set-default/0.1";

/// `spec/did-management/domain/assign/0.1` — grant a caller the right
/// to register DIDs under a domain. Per-owner ACL on top of the domain
/// entry.
pub const TASK_DID_MANAGEMENT_DOMAIN_ASSIGN_0_1: &str =
    "https://trusttasks.org/spec/did-management/domain/assign/0.1";

/// `spec/did-management/domain/unassign/0.1` — revoke a previously
/// assigned domain grant.
pub const TASK_DID_MANAGEMENT_DOMAIN_UNASSIGN_0_1: &str =
    "https://trusttasks.org/spec/did-management/domain/unassign/0.1";

// ─── DID-management — server/* (3 tasks) ─────────────────────────────────

/// `spec/did-management/server/register/0.1` — register a new hosting
/// server with a control plane. Control-plane → server bootstrap path
/// for distributed deployments.
pub const TASK_DID_MANAGEMENT_SERVER_REGISTER_0_1: &str =
    "https://trusttasks.org/spec/did-management/server/register/0.1";

/// `spec/did-management/server/health/0.1` — control-plane → server
/// health probe. Returns aliveness + outstanding-sync metrics so the
/// control plane can flag stale instances.
pub const TASK_DID_MANAGEMENT_SERVER_HEALTH_0_1: &str =
    "https://trusttasks.org/spec/did-management/server/health/0.1";

/// `spec/did-management/server/stats-sync/0.1` — periodic stats push
/// from a server to its control plane (DID counts, resolution
/// throughput, error rates). Replaces the ad-hoc HTTP stats sync the
/// standalone server used pre-trust-task.
pub const TASK_DID_MANAGEMENT_SERVER_STATS_SYNC_0_1: &str =
    "https://trusttasks.org/spec/did-management/server/stats-sync/0.1";

// ─── DID-management — registry/* (2 tasks) ───────────────────────────────

/// `spec/did-management/registry/admin-register/0.1` — admin-side
/// registration of a server into the trust registry. Used by operators
/// to seed a deployment.
pub const TASK_DID_MANAGEMENT_REGISTRY_ADMIN_REGISTER_0_1: &str =
    "https://trusttasks.org/spec/did-management/registry/admin-register/0.1";

/// `spec/did-management/registry/deregister/0.1` — remove a server
/// from the registry. The server's DIDs continue to resolve from cache
/// but no new ones are accepted.
pub const TASK_DID_MANAGEMENT_REGISTRY_DEREGISTER_0_1: &str =
    "https://trusttasks.org/spec/did-management/registry/deregister/0.1";

// ─── Config slice (spec/vta/config/*) ────────────────────────────────────

/// `spec/vta/config/get/1.0` — read the current VTA configuration
/// (VTA DID, name, public URL).
/// Payload: [`crate::protocols::vta_management::get_config::GetConfigBody`]
/// (empty). Auth: any authenticated user.
pub const TASK_CONFIG_GET_1_0: &str = "https://trusttasks.org/spec/vta/config/get/1.0";

/// `spec/vta/config/update/1.0` — patch VTA DID, name, or public URL.
/// Payload: [`crate::protocols::vta_management::update_config::UpdateConfigBody`].
/// Auth: Super Admin only.
pub const TASK_CONFIG_UPDATE_1_0: &str = "https://trusttasks.org/spec/vta/config/update/1.0";

// ─── Management slice (spec/vta/management/*) ────────────────────────────

/// `spec/vta/management/reload-services/1.0` — tear down and
/// re-initialise REST + DIDComm + storage threads with the current
/// config. Does NOT restart the process. Use after a
/// `config/update/1.0` to pick up the new values.
/// Payload: [`crate::protocols::vta_management::restart::ReloadServicesBody`]
/// (empty). Auth: Super Admin only.
pub const TASK_MANAGEMENT_RELOAD_SERVICES_1_0: &str =
    "https://trusttasks.org/spec/vta/management/reload-services/1.0";

// ─── Passkey-VMs slice (spec/vta/passkey-vms/*) ──────────────────────────
//
// Feature-gated: handlers require BOTH `webvh` (DID-doc mutation +
// log entries) AND `didcomm` (mediator push for the updated DID).
// URIs are declared unconditionally here so client SDKs can probe;
// the dispatcher's `KNOWN_FEATURE_GATED_URIS` allowlist tracks them
// for builds where the features are off.
//
// Versioning: the canonical registry publishes this family at `0.1`
// (framework 0.2). The `…/1.0` URIs predate the published spec; they
// are retained for a deprecation window so the browser plugin (still
// on `/1.0`) keeps working. Payload/response shapes are byte-identical
// across the two versions — only the URI version label differs — so
// the VTA dual-accepts both and replies under whichever version the
// request used (`success_response` echoes the request type). Prefer
// the `…_0_1` constants in new code. Retirement plan: drop the `…_1_0`
// URIs once the plugin has cut over to `…/0.1`.

/// `spec/vta/passkey-vms/enroll-challenge/0.1` — request a fresh
/// WebAuthn registration challenge for a DID (canonical version).
/// Payload:
/// [`crate::protocols::did_management::passkey_vms::EnrollPasskeyChallengeBody`].
/// Auth: Admin role on the DID's context.
pub const TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1: &str =
    "https://trusttasks.org/spec/vta/passkey-vms/enroll-challenge/0.1";

/// `spec/vta/passkey-vms/enroll-submit/0.1` — finalise enrolment with
/// the browser-supplied attestation bundle (canonical version).
/// Payload:
/// [`crate::protocols::did_management::passkey_vms::EnrollPasskeySubmitBody`].
pub const TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1: &str =
    "https://trusttasks.org/spec/vta/passkey-vms/enroll-submit/0.1";

/// `spec/vta/passkey-vms/list/0.1` — list every passkey VM currently
/// published on a DID (canonical version). Payload:
/// [`crate::protocols::did_management::passkey_vms::ListPasskeyVmsBody`].
pub const TASK_PASSKEY_VMS_LIST_0_1: &str = "https://trusttasks.org/spec/vta/passkey-vms/list/0.1";

/// `spec/vta/passkey-vms/revoke/0.1` — remove a passkey VM by fragment
/// (canonical version). Payload:
/// [`crate::protocols::did_management::passkey_vms::RevokePasskeyVmBody`].
pub const TASK_PASSKEY_VMS_REVOKE_0_1: &str =
    "https://trusttasks.org/spec/vta/passkey-vms/revoke/0.1";

// ─── Provision-integration (spec/vta/provision-integration/*) ───────────
//
// Feature-gated: handler requires `webvh` (DID-doc mutation + log
// entries). The legacy REST handler is at
// `POST /bootstrap/provision-integration`; the trust-task envelope
// carries the same request/response shapes the SDK already exports
// under `vta_sdk::provision_integration::http`.

/// `spec/vta/provision-integration/request/1.0` — submit a VP-framed
/// `BootstrapRequest` plus provisioning options to the VTA; receive a
/// sealed `TemplateBootstrap` bundle back. Payload:
/// [`crate::provision_integration::http::ProvisionIntegrationRequest`].
/// Auth: Admin role on the target context (super-admin to use
/// `create_context: true`).
pub const TASK_PROVISION_INTEGRATION_REQUEST_1_0: &str =
    "https://trusttasks.org/spec/vta/provision-integration/request/1.0";

// ─── WebVH-DID-lifecycle slice (spec/vta/webvh/*) ────────────────────────
//
// Feature-gated: every handler requires `webvh` (the entire op layer
// for DID-doc creation, update, deletion, and host registration lives
// under `cfg(feature = "webvh")`). URIs are still declared here
// unconditionally so client SDKs can probe; the dispatcher's
// `KNOWN_FEATURE_GATED_URIS` allowlist tracks them for builds where
// `webvh` is off.
//
// The boundary between `spec/vta/webvh/*` (VTA-controlled WebVH ops)
// and `spec/did-hosting/*` (webvh-service hosting ops) is in
// `docs/05-design-notes/trust-task-uri-registry.md` §"Boundary".
//
// Note: `GET /did/{did}/log` (public, unauth) is intentionally NOT
// reified as a trust task — it stays plain REST so any DID resolver
// can fall back to the minting VTA when the hosting server drops a
// LogEntry. The authed admin equivalent IS migrated (see
// `TASK_WEBVH_DIDS_GET_LOG_1_0` below).

// Server CRUD on the VTA's known-webvh-hosts table.

/// `spec/vta/webvh/servers/list/1.0` — list registered webvh hosts.
/// Payload:
/// [`crate::protocols::did_management::servers::ListWebvhServersBody`]
/// (empty). Auth: any authenticated user.
pub const TASK_WEBVH_SERVERS_LIST_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/servers/list/1.0";

/// `spec/vta/webvh/servers/add/1.0` — register a new webvh host.
/// Payload:
/// [`crate::protocols::did_management::servers::AddWebvhServerBody`].
/// Auth: Super Admin.
pub const TASK_WEBVH_SERVERS_ADD_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/servers/add/1.0";

/// `spec/vta/webvh/servers/update/1.0` — patch a registered webvh
/// host's label. Payload:
/// [`crate::protocols::did_management::servers::UpdateWebvhServerBody`].
/// Auth: Super Admin.
pub const TASK_WEBVH_SERVERS_UPDATE_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/servers/update/1.0";

/// `spec/vta/webvh/servers/remove/1.0` — deregister a webvh host.
/// Payload:
/// [`crate::protocols::did_management::servers::RemoveWebvhServerBody`].
/// Auth: Super Admin.
pub const TASK_WEBVH_SERVERS_REMOVE_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/servers/remove/1.0";

// DID lifecycle on the VTA's known-DIDs table. Every mutation appends
// a fresh WebVH LogEntry to the DID's `did.jsonl` and (when the DID is
// hosted) publishes the entry to the registered server.

/// `spec/vta/webvh/dids/list/1.0` — list DIDs known to this VTA,
/// optionally filtered by context or server. Payload:
/// [`crate::protocols::did_management::list::ListDidsWebvhBody`].
/// Auth: any authenticated user.
pub const TASK_WEBVH_DIDS_LIST_1_0: &str = "https://trusttasks.org/spec/vta/webvh/dids/list/1.0";

/// `spec/vta/webvh/dids/create/1.0` — mint a new DID via a DID
/// template and (optionally) register it with a webvh host. Payload:
/// [`crate::protocols::did_management::create::CreateDidWebvhBody`].
/// Auth: Admin role on the target context.
pub const TASK_WEBVH_DIDS_CREATE_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/dids/create/1.0";

/// `spec/vta/webvh/dids/get/1.0` — fetch the local record (context,
/// server, key handles) for a DID this VTA knows. Payload:
/// [`crate::protocols::did_management::get::GetDidWebvhBody`].
/// Auth: any authenticated user with access to the DID's context.
pub const TASK_WEBVH_DIDS_GET_1_0: &str = "https://trusttasks.org/spec/vta/webvh/dids/get/1.0";

/// `spec/vta/webvh/dids/get-log/1.0` — fetch the raw `did.jsonl`
/// log for an authed caller. The unauthenticated public mirror
/// (`GET /did/{did}/log`) is deliberately NOT trust-task-wrapped —
/// it's load-bearing as the DID-resolver failover path and stays
/// plain REST forever (see §"Why REST stays" in the registry doc).
/// Payload:
/// [`crate::protocols::did_management::lifecycle::GetDidWebvhLogBody`].
/// Auth: any authenticated user with access to the DID's context.
pub const TASK_WEBVH_DIDS_GET_LOG_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/dids/get-log/1.0";

/// `spec/vta/webvh/dids/delete/1.0` — delete a DID locally and, if
/// hosted, on the webvh server. Payload:
/// [`crate::protocols::did_management::delete::DeleteDidWebvhBody`].
/// Auth: Admin role on the DID's context.
pub const TASK_WEBVH_DIDS_DELETE_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/dids/delete/1.0";

/// `spec/vta/webvh/dids/update/1.0` — apply a generic DID-document
/// patch (rotate update_keys, swap pre-rotation commitments, change
/// witnesses / watchers / ttl). Payload:
/// [`crate::protocols::did_management::update::UpdateDidWebvhBody`].
/// The `payload` carries a wire-format witnesses field (opaque
/// JSON); the handler deserialises it into the typed
/// `didwebvh_rs::Witnesses` enum at intake. Auth: Admin role on the
/// DID's context.
pub const TASK_WEBVH_DIDS_UPDATE_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/dids/update/1.0";

/// `spec/vta/webvh/dids/rotate-keys/1.0` — rotate every
/// verificationMethod's key bytes on a DID and apply the
/// resulting document change as a single update. Payload:
/// [`crate::protocols::did_management::update::RotateDidWebvhKeysBody`].
/// Auth: Admin role on the DID's context.
pub const TASK_WEBVH_DIDS_ROTATE_KEYS_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/dids/rotate-keys/1.0";

/// `spec/vta/webvh/dids/register-with-server/1.0` — promote a
/// serverless DID to a server-managed one, atomically pushing the
/// existing local `did.jsonl` to the host and flipping the local
/// record's `server_id` from `"serverless"` to the registered host
/// id. One-way (re-pointing a hosted DID at a different host is
/// intentionally out of scope). Payload:
/// [`crate::protocols::did_management::servers::RegisterDidWithServerBody`].
/// Auth: Super Admin.
pub const TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0: &str =
    "https://trusttasks.org/spec/vta/webvh/dids/register-with-server/1.0";

// ─── DID-templates slice (spec/vta/did-templates/*) ──────────────────────
//
// Global-scope template CRUD + render. Mirrored under
// `spec/vta/contexts/did-templates/*` below for the context-scoped
// resource. The two URI hierarchies are intentionally separate —
// global templates and context templates have different owners and
// lifecycles (super-admin vs context-admin), and the URI carries
// that distinction directly so the auth contract is self-evident
// from the wire `type` field.

/// `spec/vta/did-templates/list/1.0` — list all global templates.
/// Payload:
/// [`crate::protocols::did_template_management::list::ListDidTemplatesBody`]
/// (empty). Auth: any authenticated user.
pub const TASK_DID_TEMPLATES_LIST_1_0: &str =
    "https://trusttasks.org/spec/vta/did-templates/list/1.0";

/// `spec/vta/did-templates/create/1.0` — create a new global
/// template. Payload:
/// [`crate::protocols::did_template_management::create::CreateDidTemplateBody`].
/// Auth: Super Admin only.
pub const TASK_DID_TEMPLATES_CREATE_1_0: &str =
    "https://trusttasks.org/spec/vta/did-templates/create/1.0";

/// `spec/vta/did-templates/get/1.0` — fetch one global template by
/// name. Payload:
/// [`crate::protocols::did_template_management::get::GetDidTemplateBody`].
/// Auth: any authenticated user.
pub const TASK_DID_TEMPLATES_GET_1_0: &str =
    "https://trusttasks.org/spec/vta/did-templates/get/1.0";

/// `spec/vta/did-templates/update/1.0` — replace a global template.
/// Payload:
/// [`crate::protocols::did_template_management::update::UpdateDidTemplateBody`].
/// Auth: Super Admin only.
pub const TASK_DID_TEMPLATES_UPDATE_1_0: &str =
    "https://trusttasks.org/spec/vta/did-templates/update/1.0";

/// `spec/vta/did-templates/delete/1.0` — delete a global template.
/// Payload:
/// [`crate::protocols::did_template_management::delete::DeleteDidTemplateBody`].
/// Auth: Super Admin only.
pub const TASK_DID_TEMPLATES_DELETE_1_0: &str =
    "https://trusttasks.org/spec/vta/did-templates/delete/1.0";

/// `spec/vta/did-templates/render/1.0` — render a global template
/// with caller-supplied variables. Server injects ambient vars
/// (`VTA_DID`, `NOW`, …). Payload:
/// [`crate::protocols::did_template_management::render::RenderDidTemplateBody`].
/// Auth: any authenticated user.
pub const TASK_DID_TEMPLATES_RENDER_1_0: &str =
    "https://trusttasks.org/spec/vta/did-templates/render/1.0";

// ─── Context-scoped DID-templates (spec/vta/contexts/did-templates/*) ────

/// `spec/vta/contexts/did-templates/list/1.0` — list templates
/// scoped to a specific context. Payload:
/// [`crate::protocols::did_template_management::list::ListContextDidTemplatesBody`].
/// Auth: any authenticated user with access to the context.
pub const TASK_CONTEXTS_DID_TEMPLATES_LIST_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/did-templates/list/1.0";

/// `spec/vta/contexts/did-templates/create/1.0` — create a
/// context-scoped template. Payload:
/// [`crate::protocols::did_template_management::create::CreateContextDidTemplateBody`].
/// Auth: Super Admin OR Admin-with-context.
pub const TASK_CONTEXTS_DID_TEMPLATES_CREATE_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/did-templates/create/1.0";

/// `spec/vta/contexts/did-templates/get/1.0` — fetch one
/// context-scoped template. Payload:
/// [`crate::protocols::did_template_management::get::GetContextDidTemplateBody`].
/// Auth: any authenticated user with access to the context.
pub const TASK_CONTEXTS_DID_TEMPLATES_GET_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/did-templates/get/1.0";

/// `spec/vta/contexts/did-templates/update/1.0` — replace a
/// context-scoped template. Payload:
/// [`crate::protocols::did_template_management::update::UpdateContextDidTemplateBody`].
/// Auth: Super Admin OR Admin-with-context.
pub const TASK_CONTEXTS_DID_TEMPLATES_UPDATE_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/did-templates/update/1.0";

/// `spec/vta/contexts/did-templates/delete/1.0` — delete a
/// context-scoped template. Payload:
/// [`crate::protocols::did_template_management::delete::DeleteContextDidTemplateBody`].
/// Auth: Super Admin OR Admin-with-context.
pub const TASK_CONTEXTS_DID_TEMPLATES_DELETE_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/did-templates/delete/1.0";

/// `spec/vta/contexts/did-templates/render/1.0` — render a
/// context-scoped template (or fall through to a global template
/// of the same name, per the op layer's scope-fallback rule).
/// Payload:
/// [`crate::protocols::did_template_management::render::RenderContextDidTemplateBody`].
/// Auth: any authenticated user with access to the context.
pub const TASK_CONTEXTS_DID_TEMPLATES_RENDER_1_0: &str =
    "https://trusttasks.org/spec/vta/contexts/did-templates/render/1.0";

// ─── Backup slice (spec/vta/backup/*) ────────────────────────────────────
//
// 3-phase descriptor pattern — see
// `docs/05-design-notes/backup-descriptor-pattern.md`. The
// trust-task envelope carries the control plane only; the bulk
// encrypted bytes flow over `GET / POST /backup/blob/{bundle_id}`
// (deliberately REST-only, like the public DID log mirror —
// bulk transport is wrong on top of a JSON envelope).
//
// All five URIs require super-admin authentication. Additionally
// every non-`initiate-*` URI checks caller-DID-owns-bundle so a
// second super-admin can't snoop on the first's in-flight backup.
//
// Slice handlers, op-layer functions, blob REST routes, and the
// background sweeper land in follow-on commits per the rollout
// plan in the design doc. URIs are declared here unconditionally
// so client SDKs can probe; the dispatcher's
// `KNOWN_FEATURE_GATED_URIS` allowlist will track them until the
// slice ships.

/// `spec/vta/backup/initiate-export/1.0` — mint an export bundle;
/// return a [`BundleDescriptor`](crate::protocols::backup_management::descriptors::BundleDescriptor)
/// pointing at the blob endpoint. Payload:
/// [`crate::protocols::backup_management::descriptors::InitiateExportBody`].
/// Auth: super-admin.
pub const TASK_BACKUP_INITIATE_EXPORT_1_0: &str =
    "https://trusttasks.org/spec/vta/backup/initiate-export/1.0";

/// `spec/vta/backup/complete-export/1.0` — optional ack from the
/// client after a successful download. Payload:
/// [`crate::protocols::backup_management::descriptors::CompleteExportBody`].
/// Auth: super-admin (must match the initiator's DID).
pub const TASK_BACKUP_COMPLETE_EXPORT_1_0: &str =
    "https://trusttasks.org/spec/vta/backup/complete-export/1.0";

/// `spec/vta/backup/initiate-import/1.0` — mint an upload slot;
/// return a descriptor for the client to POST bytes to. Payload:
/// [`crate::protocols::backup_management::descriptors::InitiateImportBody`].
/// Auth: super-admin.
pub const TASK_BACKUP_INITIATE_IMPORT_1_0: &str =
    "https://trusttasks.org/spec/vta/backup/initiate-import/1.0";

/// `spec/vta/backup/finalize-import/1.0` — apply uploaded bytes
/// (or run in preview mode). Payload:
/// [`crate::protocols::backup_management::descriptors::FinalizeImportBody`].
/// Auth: super-admin (must match the initiator's DID).
pub const TASK_BACKUP_FINALIZE_IMPORT_1_0: &str =
    "https://trusttasks.org/spec/vta/backup/finalize-import/1.0";

/// `spec/vta/backup/abort/1.0` — cancel an in-flight bundle in
/// any non-terminal state. Payload:
/// [`crate::protocols::backup_management::descriptors::AbortBundleBody`].
/// Auth: super-admin (must match the initiator's DID).
pub const TASK_BACKUP_ABORT_1_0: &str = "https://trusttasks.org/spec/vta/backup/abort/1.0";

// ─── Attestation slice (spec/vta/attestation/*) ──────────────────────────
//
// TEE-feature-gated and DELIBERATELY UNAUTHENTICATED on the wire
// (the existing legacy `/attestation/status` + `/attestation/report`
// REST routes don't take `AuthClaims`). Operators rely on TEE proofs
// being publicly verifiable. These URIs live on the REST_ROUTED
// allowlist for the parity harness; the dispatcher never sees them.

/// `spec/vta/attestation/status/1.0` — return the VTA's TEE detection
/// status (`tee_present`, attestation provider, etc.). No request
/// body. Unauthenticated. TEE-feature-gated; returns
/// `tee_attestation_error` when the binary lacks the `tee` feature.
pub const TASK_ATTESTATION_STATUS_1_0: &str =
    "https://trusttasks.org/spec/vta/attestation/status/1.0";

/// `spec/vta/attestation/report/1.0` — produce a fresh attestation
/// report with a client-supplied nonce. Unauthenticated.
/// TEE-feature-gated.
pub const TASK_ATTESTATION_REPORT_1_0: &str =
    "https://trusttasks.org/spec/vta/attestation/report/1.0";

// ─── Consent slice (spec/consent/*) ──────────────────────────────────────
//
// Generic, platform-agnostic consent gating for inbound messaging: a bridge
// asks the VTA whether an inbound conversation (DM / group / channel, on any
// platform) may reach an AI agent — default-deny, with operator consent on
// first contact. The decision is recorded as a grant the bridge enforces.
// Canonical specs: the `consent/*` family in the dtgwg-trust-tasks-tf registry.

/// `consent/request/1.0` — a bridge asks the VTA to gate an inbound
/// conversation; the message is held until an operator decision lands.
/// Auth: an enrolled bridge permitted to gate the named agent.
pub const TASK_CONSENT_REQUEST_1_0: &str = "https://trusttasks.org/spec/consent/request/1.0";

/// `consent/decision/1.0` — an approver allows/denies a conversation; the VTA
/// records a [`ConsentGrant`](https://trusttasks.org/spec/consent/_shared).
/// Auth: an approver for the subject's platform/context (operator-signed, or
/// bridge-attested).
pub const TASK_CONSENT_DECISION_1_0: &str = "https://trusttasks.org/spec/consent/decision/1.0";

/// `consent/revoke/1.0` — an operator withdraws a standing grant, reverting the
/// conversation to default-deny.
pub const TASK_CONSENT_REVOKE_1_0: &str = "https://trusttasks.org/spec/consent/revoke/1.0";

/// `consent/list/1.0` — a bridge syncs / point-checks the grants it enforces,
/// so steady-state inbound is a local Allow/Deny lookup. Read-only.
pub const TASK_CONSENT_LIST_1_0: &str = "https://trusttasks.org/spec/consent/list/1.0";

/// `consent/approver-set/1.0` — an admin binds the operator who approves consent
/// for a platform within a context (and how the prompt routes). Admin-gated.
pub const TASK_CONSENT_APPROVER_SET_1_0: &str =
    "https://trusttasks.org/spec/consent/approver-set/1.0";

/// `consent/approver-list/1.0` — read the approver bindings (optionally filtered).
pub const TASK_CONSENT_APPROVER_LIST_1_0: &str =
    "https://trusttasks.org/spec/consent/approver-list/1.0";

// ─── Future slices ───────────────────────────────────────────────────────
//
// attestation, services, webvh, did-templates, passkey-vms, backup,
// config, management, join-requests, bootstrap. Keys import + wrapping-
// key defer to follow-on work (transport-unwrap complexity).
//
// Each slice ships in its own Phase 3 PR. The migration mapping table
// in docs/05-design-notes/trust-task-uri-registry.md enumerates the
// full target surface (~75 URIs).

/// Every URI registered in this module — handy for the dispatcher's
/// parity harness and for operator tooling that wants to enumerate
/// the VTA's wire surface programmatically.
///
/// Lists both the deprecated `*_0_1` URIs (still dual-accepted) and their
/// `*_0_2` successors — the VTA's live wire surface is the union during the
/// migration window. `#[allow(deprecated)]` because naming the 0.1 constants
/// here is intentional, not a migration miss.
#[allow(deprecated)]
pub const ALL_URIS: &[&str] = &[
    // Auth slice
    TASK_AUTH_CHALLENGE_0_1,
    TASK_AUTH_AUTHENTICATE_0_1,
    TASK_AUTH_REFRESH_0_1,
    TASK_AUTH_REVOKE_SESSION_0_1,
    TASK_AUTH_WHOAMI_0_1,
    TASK_AUTH_SESSIONS_LIST_0_1,
    TASK_AUTH_PASSKEY_LOGIN_START_0_1,
    TASK_AUTH_PASSKEY_LOGIN_START_0_2,
    TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1,
    TASK_AUTH_PASSKEY_LOGIN_FINISH_0_2,
    TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_1,
    TASK_AUTH_STEP_UP_APPROVE_RESPONSE_0_2,
    TASK_AUTH_STEP_UP_POLICY_0_2,
    // Device slice
    TASK_DEVICE_REGISTER_0_1,
    TASK_DEVICE_REGISTER_0_2,
    TASK_DEVICE_HEARTBEAT_0_1,
    TASK_DEVICE_HEARTBEAT_0_2,
    TASK_DEVICE_LIST_0_1,
    TASK_DEVICE_LIST_0_2,
    TASK_DEVICE_DISABLE_0_1,
    TASK_DEVICE_WIPE_0_1,
    TASK_DEVICE_SET_WAKE_0_1,
    TASK_DEVICE_SET_WAKE_0_2,
    // ACL slice
    TASK_ACL_LIST_1_0,
    TASK_ACL_CREATE_1_0,
    TASK_ACL_GET_1_0,
    TASK_ACL_UPDATE_1_0,
    TASK_ACL_DELETE_1_0,
    // Contexts slice
    TASK_CONTEXTS_LIST_1_0,
    TASK_CONTEXTS_CREATE_1_0,
    TASK_CONTEXTS_GET_1_0,
    TASK_CONTEXTS_UPDATE_1_0,
    TASK_CONTEXTS_UPDATE_DID_1_0,
    TASK_CONTEXTS_PREVIEW_DELETE_1_0,
    TASK_CONTEXTS_DELETE_1_0,
    // Keys slice
    TASK_KEYS_LIST_1_0,
    TASK_KEYS_CREATE_1_0,
    TASK_KEYS_GET_1_0,
    TASK_KEYS_RENAME_1_0,
    TASK_KEYS_REVOKE_1_0,
    TASK_KEYS_SIGN_1_0,
    // Seeds slice
    TASK_SEEDS_LIST_1_0,
    TASK_SEEDS_ROTATE_1_0,
    TASK_SEEDS_EXPORT_MNEMONIC_1_0,
    // Audit slice
    TASK_AUDIT_LIST_LOGS_1_0,
    TASK_AUDIT_GET_RETENTION_1_0,
    TASK_AUDIT_UPDATE_RETENTION_1_0,
    // Discovery
    TASK_DISCOVERY_CAPABILITIES_1_0,
    // Vault slice (0.1 + 0.2 dual-accept; delete is 0.1-only upstream)
    TASK_VAULT_LIST_0_1,
    TASK_VAULT_LIST_0_2,
    TASK_VAULT_GET_0_1,
    TASK_VAULT_GET_0_2,
    TASK_VAULT_UPSERT_0_1,
    TASK_VAULT_UPSERT_0_2,
    TASK_VAULT_DELETE_0_1,
    // Vault archival lifecycle (openvtc 0.1 extension).
    TASK_VAULT_ARCHIVE_0_1,
    TASK_VAULT_UNARCHIVE_0_1,
    TASK_VAULT_RESTORE_0_1,
    TASK_VAULT_PURGE_0_1,
    TASK_VAULT_RELEASE_0_1,
    TASK_VAULT_RELEASE_0_2,
    TASK_VAULT_PROXY_LOGIN_0_1,
    TASK_VAULT_PROXY_LOGIN_0_2,
    TASK_VAULT_SIGN_TRUST_TASK_0_1,
    TASK_VAULT_SIGN_TRUST_TASK_0_2,
    // DID-management slice (canonical spec/did-management/*)
    TASK_DID_MANAGEMENT_DID_REGISTER_0_1,
    TASK_DID_MANAGEMENT_DID_PUBLISH_0_1,
    TASK_DID_MANAGEMENT_DID_DELETE_0_1,
    TASK_DID_MANAGEMENT_DID_ENABLE_0_1,
    TASK_DID_MANAGEMENT_DID_DISABLE_0_1,
    TASK_DID_MANAGEMENT_DID_LIST_0_1,
    TASK_DID_MANAGEMENT_DID_INFO_0_1,
    TASK_DID_MANAGEMENT_DID_CHECK_NAME_0_1,
    TASK_DID_MANAGEMENT_DID_CHANGE_OWNER_0_1,
    TASK_DID_MANAGEMENT_DID_ROLLBACK_0_1,
    TASK_DID_MANAGEMENT_DID_PROBLEM_REPORT_0_1,
    TASK_DID_MANAGEMENT_DOMAIN_CREATE_0_1,
    TASK_DID_MANAGEMENT_DOMAIN_UPDATE_0_1,
    TASK_DID_MANAGEMENT_DOMAIN_DISABLE_0_1,
    TASK_DID_MANAGEMENT_DOMAIN_PURGE_0_1,
    TASK_DID_MANAGEMENT_DOMAIN_SET_DEFAULT_0_1,
    TASK_DID_MANAGEMENT_DOMAIN_ASSIGN_0_1,
    TASK_DID_MANAGEMENT_DOMAIN_UNASSIGN_0_1,
    TASK_DID_MANAGEMENT_SERVER_REGISTER_0_1,
    TASK_DID_MANAGEMENT_SERVER_HEALTH_0_1,
    TASK_DID_MANAGEMENT_SERVER_STATS_SYNC_0_1,
    TASK_DID_MANAGEMENT_REGISTRY_ADMIN_REGISTER_0_1,
    TASK_DID_MANAGEMENT_REGISTRY_DEREGISTER_0_1,
    // Config slice
    TASK_CONFIG_GET_1_0,
    TASK_CONFIG_UPDATE_1_0,
    // Management slice
    TASK_MANAGEMENT_RELOAD_SERVICES_1_0,
    // Passkey-VMs slice (feature-gated: webvh + didcomm). Dual-accept
    // canonical 0.1 + retained pre-spec 1.0.
    TASK_PASSKEY_VMS_ENROLL_CHALLENGE_0_1,
    TASK_PASSKEY_VMS_ENROLL_SUBMIT_0_1,
    TASK_PASSKEY_VMS_LIST_0_1,
    TASK_PASSKEY_VMS_REVOKE_0_1,
    // Provision-integration (feature-gated: webvh)
    TASK_PROVISION_INTEGRATION_REQUEST_1_0,
    // WebVH-DID-lifecycle slice (feature-gated: webvh)
    TASK_WEBVH_SERVERS_LIST_1_0,
    TASK_WEBVH_SERVERS_ADD_1_0,
    TASK_WEBVH_SERVERS_UPDATE_1_0,
    TASK_WEBVH_SERVERS_REMOVE_1_0,
    TASK_WEBVH_DIDS_LIST_1_0,
    TASK_WEBVH_DIDS_CREATE_1_0,
    TASK_WEBVH_DIDS_GET_1_0,
    TASK_WEBVH_DIDS_GET_LOG_1_0,
    TASK_WEBVH_DIDS_DELETE_1_0,
    TASK_WEBVH_DIDS_UPDATE_1_0,
    TASK_WEBVH_DIDS_ROTATE_KEYS_1_0,
    TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0,
    // DID-templates slice (global)
    TASK_DID_TEMPLATES_LIST_1_0,
    TASK_DID_TEMPLATES_CREATE_1_0,
    TASK_DID_TEMPLATES_GET_1_0,
    TASK_DID_TEMPLATES_UPDATE_1_0,
    TASK_DID_TEMPLATES_DELETE_1_0,
    TASK_DID_TEMPLATES_RENDER_1_0,
    // DID-templates slice (context-scoped)
    TASK_CONTEXTS_DID_TEMPLATES_LIST_1_0,
    TASK_CONTEXTS_DID_TEMPLATES_CREATE_1_0,
    TASK_CONTEXTS_DID_TEMPLATES_GET_1_0,
    TASK_CONTEXTS_DID_TEMPLATES_UPDATE_1_0,
    TASK_CONTEXTS_DID_TEMPLATES_DELETE_1_0,
    TASK_CONTEXTS_DID_TEMPLATES_RENDER_1_0,
    // Backup slice (descriptor pattern). URIs land in ALL_URIS now
    // that the trust-task slice is wired in vta-service.
    TASK_BACKUP_INITIATE_EXPORT_1_0,
    TASK_BACKUP_COMPLETE_EXPORT_1_0,
    TASK_BACKUP_INITIATE_IMPORT_1_0,
    TASK_BACKUP_FINALIZE_IMPORT_1_0,
    TASK_BACKUP_ABORT_1_0,
    // Attestation slice (REST-routed, unauthenticated)
    TASK_ATTESTATION_STATUS_1_0,
    TASK_ATTESTATION_REPORT_1_0,
    // Consent slice
    TASK_CONSENT_REQUEST_1_0,
    TASK_CONSENT_DECISION_1_0,
    TASK_CONSENT_REVOKE_1_0,
    TASK_CONSENT_LIST_1_0,
    TASK_CONSENT_APPROVER_SET_1_0,
    TASK_CONSENT_APPROVER_LIST_1_0,
];

/// The subset of [`ALL_URIS`] served by **dedicated REST routes** rather than
/// the `/api/trust-tasks` dispatcher: pre-login auth (challenge / authenticate /
/// refresh), passkey-login, and TEE attestation.
///
/// These are **not** reachable through the generic dispatcher
/// ([`crate::client::VtaClient::dispatch_trust_task`]) — pre-login auth has no
/// session to carry, and attestation is unauthenticated/public. A generic
/// "invoke any operation" surface (e.g. an MCP `vta_call` gateway) should
/// exclude them; use [`dispatch_routed_uris`].
///
/// Canonical list: `vta-service`'s dispatcher consumes this as its `REST_ROUTED`
/// allowlist, so the two can't drift.
#[allow(deprecated)] // intentionally names the deprecated passkey-login 0.1 URIs
pub const REST_ROUTED_URIS: &[&str] = &[
    TASK_AUTH_CHALLENGE_0_1,
    TASK_AUTH_AUTHENTICATE_0_1,
    TASK_AUTH_REFRESH_0_1,
    TASK_AUTH_PASSKEY_LOGIN_START_0_1,
    TASK_AUTH_PASSKEY_LOGIN_FINISH_0_1,
    TASK_AUTH_PASSKEY_LOGIN_START_0_2,
    TASK_AUTH_PASSKEY_LOGIN_FINISH_0_2,
    TASK_ATTESTATION_STATUS_1_0,
    TASK_ATTESTATION_REPORT_1_0,
];

/// The operations reachable through the generic `/api/trust-tasks` dispatcher —
/// [`ALL_URIS`] minus [`REST_ROUTED_URIS`]. Use this to drive a generic
/// "invoke any operation" surface so the advertised catalog matches what the
/// dispatcher can actually route.
pub fn dispatch_routed_uris() -> Vec<&'static str> {
    ALL_URIS
        .iter()
        .copied()
        .filter(|u| !REST_ROUTED_URIS.contains(u))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)] // references the deprecated 0.1 URIs by const on purpose
    fn rest_routed_uris_partition_all_uris() {
        // Every REST-routed URI must be a real catalog entry, else the filter is
        // a silent no-op against ALL_URIS.
        for u in REST_ROUTED_URIS {
            assert!(ALL_URIS.contains(u), "REST_ROUTED uri not in ALL_URIS: {u}");
        }
        let dispatch = dispatch_routed_uris();
        // Pre-login auth + attestation are excluded …
        assert!(!dispatch.contains(&TASK_AUTH_CHALLENGE_0_1));
        assert!(!dispatch.contains(&TASK_ATTESTATION_STATUS_1_0));
        // … but dispatched auth + management ops remain reachable.
        assert!(dispatch.contains(&TASK_AUTH_WHOAMI_0_1));
        assert!(dispatch.contains(&TASK_AUTH_SESSIONS_LIST_0_1));
        assert!(dispatch.contains(&TASK_CONTEXTS_LIST_1_0));
        assert_eq!(dispatch.len(), ALL_URIS.len() - REST_ROUTED_URIS.len());
    }

    #[test]
    fn every_uri_in_canonical_namespace() {
        // VTA's wire surface canonically lives under
        // `https://trusttasks.org/spec/<family>/`. Five families are
        // currently represented:
        //
        // - `spec/vta/`            — VTA-specific operations (this
        //                            module is the source of truth).
        // - `spec/auth/`           — cross-cutting auth primitives
        //                            shared with did-hosting / VTC.
        // - `spec/did-management/` — canonical DID-hosting protocol
        //                            (PR #139 added the constants;
        //                            Phase 3 migration consumed them).
        // - `spec/vault/`          — the secret-bearing vault family
        //                            (PR #138 + follow-ups).
        // - `spec/webvh/`          — did:webvh protocol mechanics
        //                            (witness / sync).
        const ALLOWED_PREFIXES: &[&str] = &[
            "https://trusttasks.org/spec/vta/",
            "https://trusttasks.org/spec/auth/",
            "https://trusttasks.org/spec/device/",
            "https://trusttasks.org/spec/did-management/",
            "https://trusttasks.org/spec/vault/",
            "https://trusttasks.org/spec/webvh/",
            "https://trusttasks.org/spec/consent/",
        ];
        for uri in ALL_URIS {
            assert!(
                ALLOWED_PREFIXES.iter().any(|p| uri.starts_with(p)),
                "URI must live under one of {ALLOWED_PREFIXES:?}: {uri}"
            );
        }
    }

    #[test]
    fn every_uri_has_maj_min_version_suffix() {
        for uri in ALL_URIS {
            let tail = uri.rsplit('/').next().unwrap();
            let parts: Vec<&str> = tail.split('.').collect();
            assert_eq!(parts.len(), 2, "version must be maj.min only: {uri}");
            assert!(
                parts[0].chars().all(|c| c.is_ascii_digit())
                    && parts[1].chars().all(|c| c.is_ascii_digit()),
                "version components must be digits: {uri}"
            );
        }
    }

    #[test]
    fn no_duplicate_uris() {
        let mut sorted: Vec<&str> = ALL_URIS.to_vec();
        sorted.sort();
        for window in sorted.windows(2) {
            assert_ne!(window[0], window[1], "duplicate URI: {}", window[0]);
        }
    }

    /// Every URI must round-trip through the framework's TypeUri
    /// deserialiser — the wire-format `type` field on a trust-task
    /// document goes through this path. Catches a regression where a
    /// future const is added that doesn't match the framework's
    /// canonical shape.
    #[test]
    fn every_uri_parses_as_framework_type_uri() {
        use std::str::FromStr;
        for uri in ALL_URIS {
            let parsed = trust_tasks_rs::TypeUri::from_str(uri);
            assert!(
                parsed.is_ok(),
                "URI must parse as framework TypeUri: {uri}, error: {:?}",
                parsed.err()
            );
            let parsed = parsed.unwrap();
            // Round-trip via Display must equal the input byte-for-byte.
            assert_eq!(
                parsed.to_string(),
                *uri,
                "URI must round-trip through TypeUri::Display unchanged"
            );
        }
    }
}
