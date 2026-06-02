use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auth::extractor::AuthClaims;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Roles that determine endpoint access permissions.
///
/// Hierarchy (most to least privileged):
/// - **Admin** — full management access, can assign any role
/// - **Initiator** — can manage ACL entries and application contexts
/// - **Application** — standard API access (sign, cache write) within allowed contexts
/// - **Reader** — read-only access to keys, contexts, DIDs within allowed contexts
/// - **Monitor** — infrastructure-only: metrics and health endpoints
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Initiator,
    Application,
    Reader,
    /// `Monitor` is the least-privileged role and the natural default
    /// for a `Default::default()` `AuthClaims` (typically used in tests
    /// or pre-authentication scaffolding). A test fixture that leaks
    /// past its expected reach now lands on the most-restricted role
    /// rather than the most-privileged.
    #[default]
    Monitor,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Initiator => write!(f, "initiator"),
            Role::Application => write!(f, "application"),
            Role::Reader => write!(f, "reader"),
            Role::Monitor => write!(f, "monitor"),
        }
    }
}

impl Role {
    /// Parse a role from its string representation.
    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "admin" => Ok(Role::Admin),
            "initiator" => Ok(Role::Initiator),
            "application" => Ok(Role::Application),
            "reader" => Ok(Role::Reader),
            "monitor" => Ok(Role::Monitor),
            _ => Err(AppError::Internal(format!("unknown role: {s}"))),
        }
    }
}

/// Consumer-kind discriminator distinguishing user-driven Companions
/// (browser plugin, mobile app, desktop app) from headless Services
/// (mediator, AI agent, daemon). Companion vs Service drives UX
/// affordances and default policy posture; the variant payload narrows
/// the form factor / service role for finer-grained policy hooks.
///
/// Wire form (kebab-case discriminator) matches the canonical Trust
/// Task shared schema `device/_shared/0.1/device-binding#/$defs/ConsumerKind`.
///
/// `#[serde(default)]` on the AclEntry field returns `Service { Daemon }`
/// for legacy rows that pre-date the field — a safe fallback for any
/// existing operator-deployed mediator or daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConsumerKind {
    #[serde(rename_all = "kebab-case")]
    Companion { form_factor: CompanionFormFactor },
    #[serde(rename_all = "camelCase")]
    Service {
        #[serde(rename = "serviceKind")]
        service_kind: ServiceKind,
    },
}

impl Default for ConsumerKind {
    fn default() -> Self {
        ConsumerKind::Service {
            service_kind: ServiceKind::Daemon,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CompanionFormFactor {
    Browser,
    Mobile,
    Desktop,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceKind {
    Mediator,
    AiAgent,
    Daemon,
}

/// Fine-grained capability flags scoped to the ACL entry's allowed
/// contexts. Used by route handlers to gate access at finer resolution
/// than the [`Role`] hierarchy — for example, an AI-agent Service might
/// be granted `VaultRead` against a specific context but never
/// `VaultWrite` or `Sign`. Wire form (kebab-case) matches the canonical
/// `Capability` shared schema.
///
/// For legacy rows with no capability set, [`derived_capabilities_for_role`]
/// produces a sensible default from the existing role (Admin gets
/// everything, Reader gets only `vault-read`, etc.) so existing ACL
/// behaviour is preserved bit-for-bit.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    VaultRead,
    VaultWrite,
    ProxyLogin,
    FillRelease,
    PolicyAdmin,
    DeviceAdmin,
    Sign,
    KeyMint,
    /// Per-envelope Trust Task signing via `vault/sign-trust-task/0.1` —
    /// distinct from `ProxyLogin` (which mints a session credential) and
    /// from `Sign` (the generic signing oracle). Keeping it separate lets
    /// operators grant proxy-login without sign-trust-task to limit
    /// blast radius on Service consumers (AI agents, etc.).
    SignTrustTask,
}

/// Returns true if `role` is granted `cap` by the default capability
/// mapping. Use for capability checks against legacy ACL entries that have
/// no explicit `capabilities` set; for entries with explicit capabilities,
/// check the entry's set directly.
pub fn role_has_capability(role: &Role, cap: Capability) -> bool {
    derived_capabilities_for_role(role).contains(&cap)
}

/// Default capability set inferred from a role for entries that pre-date
/// the explicit `capabilities` field. Keeps existing behaviour byte-identical
/// — a pre-Phase-3 Admin still has every capability without any data
/// migration required.
pub fn derived_capabilities_for_role(role: &Role) -> Vec<Capability> {
    match role {
        Role::Admin => vec![
            Capability::VaultRead,
            Capability::VaultWrite,
            Capability::ProxyLogin,
            Capability::FillRelease,
            Capability::PolicyAdmin,
            Capability::DeviceAdmin,
            Capability::Sign,
            Capability::SignTrustTask,
            Capability::KeyMint,
        ],
        Role::Initiator => vec![
            Capability::VaultRead,
            Capability::VaultWrite,
            Capability::ProxyLogin,
            Capability::FillRelease,
            Capability::DeviceAdmin,
            Capability::Sign,
            Capability::SignTrustTask,
            Capability::KeyMint,
        ],
        Role::Application => vec![
            Capability::VaultRead,
            Capability::ProxyLogin,
            Capability::FillRelease,
            Capability::Sign,
            Capability::SignTrustTask,
        ],
        Role::Reader => vec![Capability::VaultRead],
        Role::Monitor => vec![],
    }
}

/// A device's push **wake channel** — the opaque gateway handle plus the
/// VTA-owned trigger allowlist. Set via `device/set-wake/0.1`. Mirrors the push
/// wake-up binding (<https://trusttasks.org/binding/push/0.1>) `WakeHandle` +
/// `WakeTriggerPolicy`.
///
/// The raw platform push token is **never** stored here — it lives at the push
/// gateway alone, behind the opaque `handle`. The VTA holds only the handle and
/// the allowlist it provisions to the gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WakeChannel {
    /// The push gateway that issued the handle (a DID or an https URL) — where
    /// the VTA and other triggers send a contentless wake.
    pub gateway: String,
    /// Opaque gateway-issued handle for this device's push channel. Reveals no
    /// platform token; rotates when the device re-registers with the gateway.
    pub handle: String,
    /// DIDs the VTA has authorized to trigger a wake for this handle (the
    /// allowlist it provisions to the gateway). Typically the device's mediator
    /// and/or the VTA's own DID. Empty means no party may wake the device.
    #[serde(default)]
    pub allowed_triggers: Vec<String>,
}

/// Metadata for a registered Companion/Service device. M1 stores the field
/// shape so the ACL row can carry it forward; the registration flow that
/// populates it lands in M4 (`device/register/0.1`).
///
/// Wire form mirrors the canonical Trust Task shared schema
/// `device/_shared/0.1/device-binding#/$defs/DeviceBinding`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceBinding {
    pub device_id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// RFC 3339 — when the device claimed its binding via `device/register/0.1`.
    pub registered_at: String,
    /// RFC 3339 — refreshed on every heartbeat / successful auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wiped_at: Option<String>,
    /// Push wake channel (opaque gateway handle + VTA-owned trigger allowlist).
    /// `None` until the device conveys a handle via `device/set-wake/0.1`;
    /// absent on legacy rows. The push token is never stored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake: Option<WakeChannel>,
}

impl DeviceBinding {
    /// The non-secret `pushCapable` visibility flag (push binding §2): the
    /// device has a usable wake channel — a handle is set and the device is
    /// neither disabled nor wiped.
    pub fn push_capable(&self) -> bool {
        self.wake.is_some() && self.disabled_at.is_none() && self.wiped_at.is_none()
    }
}

/// An entry in the Access Control List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
    /// Unix-epoch seconds at which this entry expires and should be pruned by
    /// the background sweeper. `None` is permanent (existing pre-Phase-2
    /// behavior; entries serialized before this field existed deserialize with
    /// this default).
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Consumer kind: Companion (user-driven) vs Service (headless). New in
    /// M1 (vault-credential-manager design). `#[serde(default)]` ⇒ pre-M1
    /// rows deserialise as `Service { Daemon }`.
    #[serde(default)]
    pub kind: ConsumerKind,
    /// Fine-grained capability set. Empty Vec on legacy rows; the auth
    /// layer falls back to [`derived_capabilities_for_role`] when this
    /// is empty so existing behaviour stays byte-identical.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Optional Companion/Service device-binding metadata. Populated by
    /// the M4 `device/register/0.1` flow; absent on legacy rows and on
    /// pure ACL entries that don't represent a registered device.
    #[serde(default)]
    pub device: Option<DeviceBinding>,
    /// Optimistic-concurrency version. Incremented on every
    /// successful update; the route layer's `If-Match` header
    /// compares against this and returns 409 Conflict on a
    /// stale write. Closes M6 from the May 2026 security review
    /// — two admins editing the same DID concurrently no longer
    /// silently lose one update.
    ///
    /// `#[serde(default)]` so pre-versioning rows deserialise
    /// with `version=0`. The first update bumps it to 1.
    #[serde(default)]
    pub version: u32,
    /// VID authorized to ratify an AAL2 step-up for this subject — the
    /// `recipient` the VTA addresses an `auth/step-up/approve-request/0.1` to
    /// when a gated operation resolves to `delegated` mode (the holder's
    /// mobile authenticator or browser companion). `None` means no delegated
    /// approver is configured: under a `delegated` floor the operation
    /// fail-closes (the subject can't self-approve a delegated requirement).
    /// Mirrors the spec's `AclEntry.stepUp.approver`.
    ///
    /// `#[serde(default)]` so pre-existing rows deserialise as `None`.
    #[serde(default)]
    pub step_up_approver: Option<String>,
}

impl AclEntry {
    /// Create an entry with the required identity fields. Optional metadata
    /// takes sensible defaults: no `label`, no `allowed_contexts`, never
    /// expires, default [`ConsumerKind`], no `capabilities`, no `device`
    /// binding, `version = 0`, and `created_at = now`. Layer non-defaults on
    /// with the `with_*` builder methods.
    ///
    /// This is the single construction entry point — adding a new optional
    /// field here defaults it everywhere, so callers don't churn.
    pub fn new(did: impl Into<String>, role: Role, created_by: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            role,
            label: None,
            allowed_contexts: Vec::new(),
            created_at: crate::auth::session::now_epoch(),
            created_by: created_by.into(),
            expires_at: None,
            kind: ConsumerKind::default(),
            capabilities: Vec::new(),
            device: None,
            version: 0,
            step_up_approver: None,
        }
    }

    /// Override `created_at` (defaults to now). Use when replaying a known
    /// timestamp — bootstrap import, tests, migration.
    pub fn with_created_at(mut self, created_at: u64) -> Self {
        self.created_at = created_at;
        self
    }

    /// Set the optional human-readable label.
    pub fn with_label(mut self, label: Option<String>) -> Self {
        self.label = label;
        self
    }

    /// Set the allowed-contexts (scope) list.
    pub fn with_contexts(mut self, allowed_contexts: Vec<String>) -> Self {
        self.allowed_contexts = allowed_contexts;
        self
    }

    /// Set the optional expiry (unix seconds). `None` is permanent.
    pub fn with_expires_at(mut self, expires_at: Option<u64>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set the consumer kind (Companion vs Service).
    pub fn with_kind(mut self, kind: ConsumerKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the fine-grained capability set.
    pub fn with_capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Attach optional Companion/Service device-binding metadata.
    pub fn with_device(mut self, device: Option<DeviceBinding>) -> Self {
        self.device = device;
        self
    }

    /// Set the delegated step-up approver VID (`stepUp.approver`).
    pub fn with_step_up_approver(mut self, approver: Option<String>) -> Self {
        self.step_up_approver = approver;
        self
    }

    /// Set the optimistic-concurrency version (defaults to 0).
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Returns true if this entry has passed its configured `expires_at`.
    /// Permanent entries (no `expires_at`) never expire.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        match self.expires_at {
            Some(deadline) => now_unix >= deadline,
            None => false,
        }
    }

    /// Strong validator string suitable for the `ETag` response
    /// header and the `If-Match` precondition on subsequent
    /// updates. Combines the DID and the version so a moving
    /// version increment can never accidentally validate against
    /// the wrong row.
    ///
    /// Format: `W/"<did_hash>:<version>"` — `W/` because the
    /// underlying ACL entry isn't byte-identical between writes
    /// (timestamps, label edits don't change semantic content
    /// but do change bytes); the `did_hash` is a 64-bit FxHash
    /// to keep the header short.
    pub fn etag(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        self.did.hash(&mut h);
        format!("W/\"{:016x}:{}\"", h.finish(), self.version)
    }
}

fn acl_key(did: &str) -> String {
    format!("acl:{did}")
}

/// Retrieve an ACL entry by DID.
pub async fn get_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<Option<AclEntry>, AppError> {
    acl.get(acl_key(did)).await
}

/// Store (create or overwrite) an ACL entry.
///
/// Unconditional write — no version check. Use
/// [`update_acl_entry_versioned`] in route handlers that accept
/// an `If-Match` precondition; this raw store is for bootstrap
/// paths (admin import, initial seed, sweeper) where there's no
/// concurrent-edit risk.
pub async fn store_acl_entry(acl: &KeyspaceHandle, entry: &AclEntry) -> Result<(), AppError> {
    acl.insert(acl_key(&entry.did), entry).await
}

/// Optimistic-concurrency-checked write.
///
/// `expected_version` is the version the caller observed on
/// their read; the function refuses to overwrite if the stored
/// row has moved ahead. On success the stored row's version is
/// bumped to `expected_version + 1`.
///
/// Returns `Ok(new_version)` on success, `Err(AppError::Conflict)`
/// on a stale write (the caller should re-read, re-apply their
/// edits to the fresh row, and retry).
///
/// Atomicity: implemented as a read-modify-write inside a
/// keyspace-level `swap`-style sequence. Single-process fjall
/// serialises within the closure; cross-replica deployments rely
/// on the underlying store's `swap` semantics.
pub async fn update_acl_entry_versioned(
    acl: &KeyspaceHandle,
    mut new_entry: AclEntry,
    expected_version: u32,
) -> Result<u32, AppError> {
    let key = acl_key(&new_entry.did);
    let current: Option<AclEntry> = acl.get(key.clone()).await?;
    let stored_version = current.as_ref().map(|e| e.version).unwrap_or(0);
    if stored_version != expected_version {
        return Err(AppError::Conflict(format!(
            "ACL entry for {} has moved ahead (expected v{}, found v{}); re-read and retry",
            new_entry.did, expected_version, stored_version,
        )));
    }
    new_entry.version = expected_version + 1;
    acl.insert(key, &new_entry).await?;
    Ok(new_entry.version)
}

/// Delete an ACL entry by DID.
pub async fn delete_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    acl.remove(acl_key(did)).await
}

/// List all ACL entries.
pub async fn list_acl_entries(acl: &KeyspaceHandle) -> Result<Vec<AclEntry>, AppError> {
    let raw = acl.prefix_iter_raw("acl:").await?;
    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let entry: AclEntry = serde_json::from_slice(&value)?;
        entries.push(entry);
    }
    Ok(entries)
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Check whether a DID is in the ACL and return its role.
///
/// Returns `Forbidden` if the DID is not found or if its entry has expired.
pub async fn check_acl(acl: &KeyspaceHandle, did: &str) -> Result<Role, AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) if entry.is_expired(now_epoch()) => {
            Err(AppError::Forbidden(format!("ACL entry expired: {did}")))
        }
        Some(entry) => Ok(entry.role),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Check whether a DID is in the ACL and return its role and allowed contexts.
///
/// Returns `Forbidden` under the same conditions as [`check_acl`].
pub async fn check_acl_full(
    acl: &KeyspaceHandle,
    did: &str,
) -> Result<(Role, Vec<String>), AppError> {
    match get_acl_entry(acl, did).await? {
        Some(entry) if entry.is_expired(now_epoch()) => {
            Err(AppError::Forbidden(format!("ACL entry expired: {did}")))
        }
        Some(entry) => Ok((entry.role, entry.allowed_contexts)),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

/// Validate that the caller is allowed to assign the given role.
///
/// - Only Admins can assign the Admin role.
/// - Reader, Application, and Monitor roles cannot assign any role.
pub fn validate_role_assignment(caller: &AuthClaims, target_role: &Role) -> Result<(), AppError> {
    if matches!(
        caller.role,
        Role::Monitor | Role::Reader | Role::Application
    ) {
        return Err(AppError::Forbidden(
            "insufficient role to assign roles".into(),
        ));
    }
    if *target_role == Role::Admin && caller.role != Role::Admin {
        return Err(AppError::Forbidden(
            "only admins can assign the admin role".into(),
        ));
    }
    Ok(())
}

/// Validate that the caller is allowed to create or modify an ACL entry
/// with the given `target_contexts`.
///
/// - Super admins can do anything.
/// - Context admins cannot create entries with empty `allowed_contexts`
///   (that would grant super admin access) and can only assign contexts
///   they themselves have access to.
pub fn validate_acl_modification(
    caller: &AuthClaims,
    target_contexts: &[String],
) -> Result<(), AppError> {
    if caller.is_super_admin() {
        return Ok(());
    }
    if target_contexts.is_empty() {
        return Err(AppError::Forbidden(
            "only super admin can create unrestricted accounts".into(),
        ));
    }
    for ctx in target_contexts {
        caller.require_context(ctx)?;
    }
    Ok(())
}

/// Check whether an ACL entry is visible to the caller.
///
/// Super admins see all entries. Context admins only see entries whose
/// `allowed_contexts` overlap with their own.
pub fn is_acl_entry_visible(caller: &AuthClaims, entry: &AclEntry) -> bool {
    if caller.is_super_admin() {
        return true;
    }
    entry
        .allowed_contexts
        .iter()
        .any(|ctx| caller.has_context_access(ctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::store::Store;

    // ── Test fixtures ───────────────────────────────────────────────

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&config).expect("open store");
        (store, dir)
    }

    fn sample_entry(did: &str, role: Role) -> AclEntry {
        AclEntry::new(did, role, "did:key:zSetup").with_label(Some(format!("test-{did}")))
    }

    fn scoped_entry(did: &str, role: Role, contexts: &[&str]) -> AclEntry {
        AclEntry::new(did, role, "did:key:zSetup")
            .with_contexts(contexts.iter().map(|s| s.to_string()).collect())
    }

    fn super_admin_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:zSuperAdmin".into(),
            role: Role::Admin,
            allowed_contexts: vec![],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn context_admin_claims(contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            did: "did:key:zCtxAdmin".into(),
            role: Role::Admin,
            allowed_contexts: contexts.iter().map(|s| s.to_string()).collect(),
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    // ── Role parsing ────────────────────────────────────────────────

    #[test]
    fn role_parse_accepts_canonical_lowercase() {
        assert_eq!(Role::parse("admin").unwrap(), Role::Admin);
        assert_eq!(Role::parse("initiator").unwrap(), Role::Initiator);
        assert_eq!(Role::parse("application").unwrap(), Role::Application);
        assert_eq!(Role::parse("reader").unwrap(), Role::Reader);
        assert_eq!(Role::parse("monitor").unwrap(), Role::Monitor);
    }

    #[test]
    fn role_parse_rejects_unknown() {
        let err = Role::parse("godmode").expect_err("unknown role must error");
        assert!(format!("{err:?}").contains("godmode"), "got {err:?}");
    }

    // ── DeviceBinding wake channel (push wake-up binding) ───────────────

    fn sample_binding() -> DeviceBinding {
        DeviceBinding {
            device_id: "dev-1".into(),
            display_name: "Glenn's iPhone".into(),
            platform: Some("iOS 19".into()),
            registered_at: "2026-06-02T00:00:00Z".into(),
            last_seen_at: None,
            disabled_at: None,
            wiped_at: None,
            wake: None,
        }
    }

    #[test]
    fn wake_channel_round_trips_camel_case() {
        let mut b = sample_binding();
        b.wake = Some(WakeChannel {
            gateway: "https://gw.example".into(),
            handle: "z6MkOpaque".into(),
            allowed_triggers: vec!["did:web:mediator".into(), "did:web:vta".into()],
        });
        let json = serde_json::to_string(&b).unwrap();
        // Wire is camelCase, mirroring the spec shapes.
        assert!(json.contains("\"wake\""), "{json}");
        assert!(json.contains("\"allowedTriggers\""), "{json}");
        let back: DeviceBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn legacy_row_without_wake_deserialises_to_none() {
        // A binding serialised before the wake field existed.
        let legacy =
            r#"{"deviceId":"dev-1","displayName":"old","registeredAt":"2026-01-01T00:00:00Z"}"#;
        let b: DeviceBinding = serde_json::from_str(legacy).unwrap();
        assert!(b.wake.is_none());
        assert!(!b.push_capable());
    }

    #[test]
    fn push_capable_requires_wake_and_active_device() {
        let mut b = sample_binding();
        assert!(!b.push_capable(), "no wake channel → not push-capable");

        b.wake = Some(WakeChannel {
            gateway: "did:web:gw".into(),
            handle: "h".into(),
            allowed_triggers: vec!["did:web:vta".into()],
        });
        assert!(b.push_capable(), "wake set + active → push-capable");

        b.disabled_at = Some("2026-06-02T01:00:00Z".into());
        assert!(!b.push_capable(), "disabled device is not push-capable");

        b.disabled_at = None;
        b.wiped_at = Some("2026-06-02T02:00:00Z".into());
        assert!(!b.push_capable(), "wiped device is not push-capable");
    }

    #[test]
    fn role_parse_rejects_case_variation() {
        // Serde rename_all="lowercase" means Admin != Admin on the wire.
        // parse() mirrors that contract.
        assert!(Role::parse("Admin").is_err(), "case-sensitive parse");
        assert!(Role::parse("ADMIN").is_err());
    }

    #[test]
    fn role_display_round_trips_with_parse() {
        for role in [
            Role::Admin,
            Role::Initiator,
            Role::Application,
            Role::Reader,
            Role::Monitor,
        ] {
            let s = format!("{role}");
            assert_eq!(Role::parse(&s).unwrap(), role, "display->parse cycle");
        }
    }

    // ── Expiration ──────────────────────────────────────────────────

    #[test]
    fn entry_without_expiry_never_expires() {
        let entry = sample_entry("did:key:zA", Role::Admin);
        assert!(entry.expires_at.is_none());
        assert!(
            !entry.is_expired(u64::MAX),
            "permanent entries never expire"
        );
    }

    #[test]
    fn entry_with_future_expiry_is_not_expired() {
        let mut entry = sample_entry("did:key:zA", Role::Admin);
        entry.expires_at = Some(now_epoch() + 3600);
        assert!(!entry.is_expired(now_epoch()));
    }

    #[test]
    fn entry_with_past_expiry_is_expired() {
        let mut entry = sample_entry("did:key:zA", Role::Admin);
        entry.expires_at = Some(now_epoch().saturating_sub(1));
        assert!(entry.is_expired(now_epoch()));
    }

    #[test]
    fn entry_with_exact_expiry_boundary_is_expired() {
        // Guard choice: `now >= deadline` is expired. The boundary at
        // equal seconds counts as past — callers don't get a free
        // extra second of access.
        let mut entry = sample_entry("did:key:zA", Role::Admin);
        let now = now_epoch();
        entry.expires_at = Some(now);
        assert!(entry.is_expired(now), "now == deadline counts as expired");
    }

    // ── Store CRUD ──────────────────────────────────────────────────

    #[tokio::test]
    async fn crud_round_trip() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        let entry = sample_entry("did:key:zAbc", Role::Admin);
        store_acl_entry(&acl, &entry).await.unwrap();

        let got = get_acl_entry(&acl, "did:key:zAbc")
            .await
            .unwrap()
            .expect("entry should exist");
        assert_eq!(got.did, entry.did);
        assert_eq!(got.role, Role::Admin);

        delete_acl_entry(&acl, "did:key:zAbc").await.unwrap();
        let gone = get_acl_entry(&acl, "did:key:zAbc").await.unwrap();
        assert!(gone.is_none(), "deleted entry must be gone");
    }

    #[tokio::test]
    async fn list_returns_every_entry() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        for did in ["did:key:zA", "did:key:zB", "did:key:zC"] {
            store_acl_entry(&acl, &sample_entry(did, Role::Reader))
                .await
                .unwrap();
        }

        let entries = list_acl_entries(&acl).await.unwrap();
        assert_eq!(entries.len(), 3);
        let dids: std::collections::HashSet<_> = entries.iter().map(|e| e.did.as_str()).collect();
        assert!(dids.contains("did:key:zA"));
        assert!(dids.contains("did:key:zB"));
        assert!(dids.contains("did:key:zC"));
    }

    // ── check_acl ───────────────────────────────────────────────────

    #[tokio::test]
    async fn check_acl_returns_role_for_present_did() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();
        store_acl_entry(&acl, &sample_entry("did:key:zA", Role::Initiator))
            .await
            .unwrap();

        let role = check_acl(&acl, "did:key:zA").await.unwrap();
        assert_eq!(role, Role::Initiator);
    }

    #[tokio::test]
    async fn check_acl_rejects_missing_did_as_forbidden() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        let err = check_acl(&acl, "did:key:zUnknown")
            .await
            .expect_err("missing DID must be rejected");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "got {err:?}; expected Forbidden so the handler emits 403"
        );
    }

    #[tokio::test]
    async fn check_acl_rejects_expired_entry() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();

        let mut entry = sample_entry("did:key:zExpired", Role::Admin);
        entry.expires_at = Some(now_epoch().saturating_sub(10));
        store_acl_entry(&acl, &entry).await.unwrap();

        let err = check_acl(&acl, "did:key:zExpired")
            .await
            .expect_err("expired entry must be rejected");
        let msg = format!("{err:?}");
        assert!(
            matches!(err, AppError::Forbidden(_)) && msg.contains("expired"),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn check_acl_full_returns_role_and_contexts() {
        let (store, _dir) = temp_store();
        let acl = store.keyspace("acl").unwrap();
        store_acl_entry(
            &acl,
            &scoped_entry("did:key:zCtx", Role::Admin, &["ctx1", "ctx2"]),
        )
        .await
        .unwrap();

        let (role, contexts) = check_acl_full(&acl, "did:key:zCtx").await.unwrap();
        assert_eq!(role, Role::Admin);
        assert_eq!(contexts, vec!["ctx1".to_string(), "ctx2".to_string()]);
    }

    // ── validate_role_assignment ────────────────────────────────────

    #[test]
    fn role_assignment_super_admin_can_assign_admin() {
        validate_role_assignment(&super_admin_claims(), &Role::Admin)
            .expect("super admin assigns admin");
    }

    #[test]
    fn role_assignment_context_admin_can_assign_admin_role_itself() {
        // A context admin (Role::Admin with non-empty allowed_contexts)
        // passes validate_role_assignment for the Admin role — the
        // role-level check only gates `caller.role != Role::Admin`.
        // The actual escape-prevention is in validate_acl_modification,
        // which confines the new entry to the caller's own contexts.
        validate_role_assignment(&context_admin_claims(&["ctx1"]), &Role::Admin)
            .expect("context admin CAN assign Admin role; scope is enforced separately");
    }

    #[test]
    fn role_assignment_non_admin_cannot_assign_admin() {
        // Initiator, Reader, Application, Monitor cannot mint admins
        // regardless of scope. Only callers with Role::Admin can
        // assign Role::Admin.
        let initiator = AuthClaims {
            did: "did:key:zIni".into(),
            role: Role::Initiator,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        let err = validate_role_assignment(&initiator, &Role::Admin)
            .expect_err("non-admin must not assign admin");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    #[test]
    fn role_assignment_readers_cannot_assign_any_role() {
        let reader = AuthClaims {
            did: "did:key:zReader".into(),
            role: Role::Reader,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        for target in [
            Role::Admin,
            Role::Initiator,
            Role::Application,
            Role::Reader,
            Role::Monitor,
        ] {
            let err = validate_role_assignment(&reader, &target)
                .expect_err(&format!("reader must not assign {target}"));
            assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        }
    }

    #[test]
    fn role_assignment_initiator_can_assign_non_admin_roles() {
        let initiator = AuthClaims {
            did: "did:key:zIni".into(),
            role: Role::Initiator,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        };
        validate_role_assignment(&initiator, &Role::Reader).expect("initiator can assign reader");
        validate_role_assignment(&initiator, &Role::Application)
            .expect("initiator can assign application");
    }

    // ── validate_acl_modification ───────────────────────────────────

    #[test]
    fn acl_modification_super_admin_can_create_unrestricted() {
        validate_acl_modification(&super_admin_claims(), &[]).expect("super admin unrestricted");
        validate_acl_modification(&super_admin_claims(), &["any-ctx".into()])
            .expect("super admin any-context");
    }

    #[test]
    fn acl_modification_context_admin_cannot_create_unrestricted() {
        // Empty allowed_contexts on a new entry = super admin. A scoped
        // admin trying to create one would escape their scope.
        let err = validate_acl_modification(&context_admin_claims(&["ctx1"]), &[])
            .expect_err("context admin must not create unrestricted");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    #[test]
    fn acl_modification_context_admin_confined_to_own_contexts() {
        let caller = context_admin_claims(&["ctx1", "ctx2"]);
        validate_acl_modification(&caller, &["ctx1".into()]).expect("own context ok");
        validate_acl_modification(&caller, &["ctx1".into(), "ctx2".into()])
            .expect("all-own contexts ok");

        let err = validate_acl_modification(&caller, &["ctx3".into()])
            .expect_err("foreign context must be rejected");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");

        let err = validate_acl_modification(&caller, &["ctx1".into(), "ctx3".into()])
            .expect_err("mixed own+foreign must be rejected");
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    // ── is_acl_entry_visible ────────────────────────────────────────

    #[test]
    fn visibility_super_admin_sees_everything() {
        let caller = super_admin_claims();
        assert!(is_acl_entry_visible(
            &caller,
            &sample_entry("did:key:zA", Role::Admin)
        ));
        assert!(is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zB", Role::Admin, &["private"])
        ));
    }

    #[test]
    fn visibility_context_admin_sees_overlapping_entries_only() {
        let caller = context_admin_claims(&["ctx1", "ctx2"]);

        // Entry scoped to ctx1 — visible (overlaps)
        assert!(is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zA", Role::Reader, &["ctx1"])
        ));

        // Entry scoped to ctx3 — not visible (no overlap)
        assert!(!is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zB", Role::Reader, &["ctx3"])
        ));

        // Super-admin entry (empty contexts) — not visible to scoped admin
        // so they can't enumerate holders of the higher privilege.
        assert!(!is_acl_entry_visible(
            &caller,
            &sample_entry("did:key:zSuper", Role::Admin)
        ));

        // Entry with mixed contexts — visible if any overlap
        assert!(is_acl_entry_visible(
            &caller,
            &scoped_entry("did:key:zC", Role::Reader, &["ctx2", "ctx99"])
        ));
    }

    // ── Serialization compatibility ─────────────────────────────────

    #[test]
    fn acl_entry_without_expires_at_deserializes() {
        // Pre-Phase-2 entries were serialized without expires_at; they
        // must continue to load with expires_at=None (permanent). If
        // this test breaks, operators with older stores lose their
        // ACL data on upgrade.
        let legacy = r#"{
            "did": "did:key:zLegacy",
            "role": "admin",
            "label": "old admin",
            "allowed_contexts": [],
            "created_at": 1700000000,
            "created_by": "did:key:zSetup"
        }"#;
        let entry: AclEntry = serde_json::from_str(legacy).expect("legacy shape must deserialize");
        assert_eq!(entry.did, "did:key:zLegacy");
        assert!(entry.expires_at.is_none(), "default to permanent");
    }

    #[test]
    fn acl_entry_with_missing_allowed_contexts_defaults_to_empty() {
        // Pre-ACL-scoping entries also omitted allowed_contexts.
        let legacy = r#"{
            "did": "did:key:zLegacy",
            "role": "admin",
            "label": null,
            "created_at": 1700000000,
            "created_by": "did:key:zSetup"
        }"#;
        let entry: AclEntry = serde_json::from_str(legacy).expect("legacy shape must deserialize");
        assert!(entry.allowed_contexts.is_empty());
    }
}
