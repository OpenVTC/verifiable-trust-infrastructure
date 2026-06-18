//! Vault entries — third-party credentials the holder has stored on the
//! VTA, used by Companions and Services to authenticate against external
//! sites and apps. M1 ships the metadata view + read-only store helpers;
//! upsert, delete, sync, proxy-login, and release land in later milestones.
//!
//! Wire format mirrors the canonical Trust Task spec
//! `https://trusttasks.org/spec/vault/_shared/0.1/vault-entry` field-for-field
//! — `#[serde(rename_all = "camelCase")]` lines the JSON up with the
//! schema's camelCase wire form. Timestamps are RFC 3339 strings rather
//! than Unix epoch (unlike [`crate::acl::AclEntry`]); this matches the spec
//! directly and avoids a separate wire/domain conversion. The slight
//! ergonomic loss versus `u64` is fine for v0.1.
//!
//! **No secret material lives in this module.** [`VaultEntry`] is the
//! metadata projection — the `secret_kind` discriminator is present, but
//! the bytes only ever transit through HPKE-sealed envelopes carried by
//! the vault/release/0.1 task (which lands in M2).

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Lifecycle state of a vault entry (and, reused, of a stored credential).
/// This is **archival** state — orthogonal to a credential's *validity*
/// (`CredentialStatus`) and to a password entry's `breached_at`/`expires_at`.
///
/// - `Active` — the normal, usable state. Default for any record persisted
///   before this field existed (`#[serde(default)]` → [`default_active`]).
/// - `Archived` — hidden from default listing and refused for use
///   (release / proxy-login / sign / present), but fully restorable.
/// - `Deleted` — a recoverable tombstone: the row (and its secret) is
///   retained but blocked from use, restorable until `grace_until`, after
///   which the vault sweeper hard-purges it. `delete --force` / `purge`
///   skip this state and erase immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultStatus {
    #[default]
    Active,
    Archived,
    Deleted,
}

impl VaultStatus {
    /// `true` for the normal usable state — the only state from which a
    /// secret may be released / a credential presented.
    pub fn is_active(&self) -> bool {
        matches!(self, VaultStatus::Active)
    }
}

/// Serde default for the `status` field so records persisted before the
/// lifecycle existed (which lack the key) deserialize as [`VaultStatus::Active`].
/// Named rather than relying on `#[serde(default)]` + `Default` so the intent
/// is explicit at the field.
pub fn default_active() -> VaultStatus {
    VaultStatus::Active
}

/// Public metadata view of a single vault entry. Direct wire-form match for
/// the `VaultEntry` `$def` in the canonical Trust Task shared schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    /// Opaque maintainer-assigned id (ULID recommended).
    pub id: String,
    /// Trust context (persona) this entry belongs to.
    pub context_id: String,
    /// Binding targets. A request from any matching target uses this entry.
    pub targets: Vec<SiteTarget>,
    /// User-facing display name.
    pub label: String,
    /// Discriminator for the kind of secret bytes; never the bytes themselves.
    pub secret_kind: SecretKind,
    /// User-defined tags for filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Non-sensitive notes (sensitive notes live inside the secret payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Optional icon URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    /// Opaque policy-engine selector strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    /// Names of custom fields (values live in the secret payload).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_field_names: Vec<String>,
    /// References to encrypted blobs (recovery codes, key files, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentRef>,
    /// Expected expiry (e.g. OAuth refresh-token expiry, time-limited tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Set when HIBP (or equivalent) detects this credential in a breach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breached_at: Option<String>,
    /// Last password rotation timestamp (for password-kind entries).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_changed_at: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// DID of the consumer that created the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// RFC 3339 last-modification timestamp.
    pub updated_at: String,
    /// DID of the consumer that last modified the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    /// Most recent use (proxy-login or release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// Monotonic version for optimistic concurrency + sync seq baseline.
    pub version: u32,
    /// Cached "principal DID" the entry will act AS for DID-shaped flows.
    /// Mirrors the `did` field of `did-self-issued` / `didcomm-peer`
    /// secrets; absent for kinds without a DID concept. MAINTAINER-DERIVED:
    /// recomputed from the secret at every upsert / rotation; a producer-
    /// supplied value on the wire is ignored. Exposed so consumers can
    /// drive RP-side flows (e.g. an RP page fetching `/auth/challenge`
    /// keyed on the principal DID before requesting a proxy-login)
    /// without releasing the secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_did: Option<String>,
    /// Archival lifecycle state. Absent on the wire for `Active` entries
    /// (`skip_serializing_if`) and defaulted in for records written before
    /// the lifecycle existed. See [`VaultStatus`].
    #[serde(
        default = "default_active",
        skip_serializing_if = "VaultStatus::is_active"
    )]
    pub status: VaultStatus,
    /// RFC 3339 timestamp the entry was archived (set iff `status == Archived`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    /// RFC 3339 timestamp the entry was (soft-)deleted (set iff `status == Deleted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    /// RFC 3339 deadline after which the sweeper hard-purges a `Deleted`
    /// entry. Restorable while `now < grace_until`. Set iff `status == Deleted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_until: Option<String>,
}

impl VaultEntry {
    /// Derive `principal_did` from a freshly-unsealed `VaultSecret`. The
    /// maintainer calls this at every upsert + secret rotation; the
    /// resulting value overrides whatever the producer wrote on the
    /// wire (the canonical schema declares the field read-only on the
    /// upsert path).
    pub fn principal_did_from_secret(secret: &VaultSecret) -> Option<String> {
        match secret {
            VaultSecret::DidSelfIssued { did, .. } => Some(did.clone()),
            VaultSecret::DidcommPeer { peer_did, .. } => Some(peer_did.clone()),
            VaultSecret::Password { .. }
            | VaultSecret::Passkey { .. }
            | VaultSecret::OauthTokens { .. }
            | VaultSecret::BearerToken { .. }
            | VaultSecret::SshKey { .. }
            | VaultSecret::Custom { .. } => None,
        }
    }

    /// Bump the optimistic-concurrency version + modification stamps. Every
    /// lifecycle transition is a user-visible mutation, so it advances
    /// `version` (the M5 sync seq baseline) and `updated_at`/`updated_by`.
    fn bump_revision(&mut self, now: &str, actor: Option<&str>) {
        self.version = self.version.saturating_add(1);
        self.updated_at = now.to_string();
        if let Some(a) = actor {
            self.updated_by = Some(a.to_string());
        }
    }

    /// `Active → Archived`. Refused (`NotActive`) for any other source state.
    pub fn archive(&mut self, now: &str, actor: Option<&str>) -> Result<(), LifecycleError> {
        if self.status != VaultStatus::Active {
            return Err(LifecycleError::NotActive);
        }
        self.status = VaultStatus::Archived;
        self.archived_at = Some(now.to_string());
        self.bump_revision(now, actor);
        Ok(())
    }

    /// `Archived → Active`. Refused (`NotArchived`) for any other source state.
    pub fn unarchive(&mut self, now: &str, actor: Option<&str>) -> Result<(), LifecycleError> {
        if self.status != VaultStatus::Archived {
            return Err(LifecycleError::NotArchived);
        }
        self.status = VaultStatus::Active;
        self.archived_at = None;
        self.bump_revision(now, actor);
        Ok(())
    }

    /// `Active|Archived → Deleted` (recoverable tombstone). `grace_until` is
    /// the caller-computed `now + grace_days` deadline. Refused
    /// (`AlreadyDeleted`) if the entry is already a tombstone — the operator
    /// should `restore` or `purge` instead (a hard `delete --force` bypasses
    /// this method entirely).
    pub fn soft_delete(
        &mut self,
        now: &str,
        grace_until: &str,
        actor: Option<&str>,
    ) -> Result<(), LifecycleError> {
        if self.status == VaultStatus::Deleted {
            return Err(LifecycleError::AlreadyDeleted);
        }
        self.status = VaultStatus::Deleted;
        self.archived_at = None;
        self.deleted_at = Some(now.to_string());
        self.grace_until = Some(grace_until.to_string());
        self.bump_revision(now, actor);
        Ok(())
    }

    /// `Deleted → Active`, but only while still inside the grace window.
    /// Refused `NotDeleted` if the entry isn't a tombstone, or `GraceExpired`
    /// if `now >= grace_until` (the sweeper has purged it or is about to).
    /// The `now >= grace_until` comparison is lexical over RFC 3339 strings —
    /// consistent with the rest of this module's timestamp handling (both
    /// stamps are produced by `chrono::Utc::now().to_rfc3339()`).
    pub fn restore(&mut self, now: &str, actor: Option<&str>) -> Result<(), LifecycleError> {
        if self.status != VaultStatus::Deleted {
            return Err(LifecycleError::NotDeleted);
        }
        if let Some(grace) = self.grace_until.as_deref()
            && now >= grace
        {
            return Err(LifecycleError::GraceExpired);
        }
        self.status = VaultStatus::Active;
        self.deleted_at = None;
        self.grace_until = None;
        self.bump_revision(now, actor);
        Ok(())
    }
}

/// Why an archival-lifecycle transition on a [`VaultEntry`] (or stored
/// credential) was refused. Handlers map each variant to a Trust-Task reject
/// reason; `code()` gives the stable token used in those messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    /// `archive` on an entry that isn't `Active`.
    NotActive,
    /// `unarchive` on an entry that isn't `Archived`.
    NotArchived,
    /// soft `delete` on an entry that is already a `Deleted` tombstone.
    AlreadyDeleted,
    /// `restore` on an entry that isn't a `Deleted` tombstone.
    NotDeleted,
    /// `restore` after the grace window elapsed.
    GraceExpired,
}

impl LifecycleError {
    /// Stable token embedded in handler reject messages (e.g. `not_active`).
    pub fn code(&self) -> &'static str {
        match self {
            LifecycleError::NotActive => "not_active",
            LifecycleError::NotArchived => "not_archived",
            LifecycleError::AlreadyDeleted => "already_deleted",
            LifecycleError::NotDeleted => "not_deleted",
            LifecycleError::GraceExpired => "grace_expired",
        }
    }
}

/// Binding target for a vault entry. Tagged union over the discriminator
/// `kind`. Wire form (kebab-case discriminator) matches the canonical
/// `SiteTarget` shared schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SiteTarget {
    WebOrigin {
        origin: String,
    },
    Did {
        did: String,
    },
    #[serde(rename_all = "camelCase")]
    IosApp {
        bundle_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        team_id: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    AndroidApp {
        package_name: String,
        sha256_cert_fingerprints: Vec<String>,
    },
}

/// Discriminator for the kind of secret stored. Emitted as kebab-case
/// (`oauth-tokens`, `did-self-issued`, …) for the 0.1 wire form; the
/// `vault/*/0.2` edge transform up-converts these to the canonical
/// lowerCamelCase 0.2 values. To stay backwards-compatible while also
/// accepting a spec-0.2 producer that sends camelCase directly, each
/// multi-word value carries a camelCase `alias` (Postel's law: liberal in
/// what we accept, conservative in what we emit). See issue #517.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretKind {
    Password,
    Passkey,
    #[serde(alias = "oauthTokens")]
    OauthTokens,
    #[serde(alias = "didSelfIssued")]
    DidSelfIssued,
    #[serde(alias = "didcommPeer")]
    DidcommPeer,
    #[serde(alias = "bearerToken")]
    BearerToken,
    #[serde(alias = "sshKey")]
    SshKey,
    Custom,
}

/// Descriptor for an encrypted blob associated with a vault entry. The blob
/// itself is fetched via a separate mechanism; this struct carries only the
/// metadata projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRef {
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 of the encrypted blob bytes.
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Filter criteria for [`list_vault_entries`]. All populated fields are
/// AND-combined. Matches the `payload.schema.json` of `vault/list/0.1`
/// minus pagination (`cursor` / `page_size`), which is applied in the
/// route layer rather than the store helper.
#[derive(Debug, Default)]
pub struct VaultListFilter<'a> {
    pub context_id: Option<&'a str>,
    pub target_origin_prefix: Option<&'a str>,
    pub target_did: Option<&'a str>,
    pub target_ios_bundle_id: Option<&'a str>,
    pub target_android_package: Option<&'a str>,
    pub secret_kind: Option<SecretKind>,
    pub tag: Option<&'a str>,
    pub used_since: Option<&'a str>,
    /// When `Some(true)`, return only entries with no `lastUsedAt`. Mutually
    /// exclusive with `used_since` at the caller level.
    pub never_used: Option<bool>,
    pub expires_before: Option<&'a str>,
    pub breached: Option<bool>,
    /// Archival-lifecycle filter. `None` (the default) returns only
    /// [`VaultStatus::Active`] entries — archived and (soft-)deleted entries
    /// are hidden from normal listing. Pass `Some(status)` to list a specific
    /// state (e.g. the trash view via `Some(Deleted)`), or use
    /// [`VaultListFilter::any_status`] to include every state.
    pub status: Option<VaultStatus>,
    /// When `true`, the `status` filter is ignored and entries of every
    /// lifecycle state are returned (the explicit "show all" view). Defaults
    /// to `false` so callers get the Active-only behaviour for free.
    pub any_status: bool,
}

impl VaultListFilter<'_> {
    /// The lifecycle state this filter selects, applying the Active-only
    /// default. Returns `None` when every state is requested (`any_status`).
    fn status_selector(&self) -> Option<VaultStatus> {
        if self.any_status {
            None
        } else {
            Some(self.status.unwrap_or(VaultStatus::Active))
        }
    }
}

/// Full record persisted in the `vault:` keyspace. `VaultEntry` is the
/// metadata projection that ships on the wire via vault/list/0.1 and
/// vault/get/0.1; the cleartext secret material lives ONLY inside this
/// stored form and crosses the wire only via vault/release/0.1's pluggable
/// `sealedSecret` envelope.
///
/// Encrypted at rest via the keyspace's transparent AES-256-GCM wrapper
/// when `storage_encryption_key` is configured (TEE deployments). In
/// local-dev / non-TEE mode the secret is plaintext on disk — same threat
/// model as every other secret-bearing keyspace today (the OS account
/// running the daemon is the security boundary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVaultEntry {
    /// Metadata view — the only half that ships on the wire by default.
    pub entry: VaultEntry,
    /// Cleartext secret material. Per the canonical
    /// `vault/_shared/0.1/vault-secret` shared schema.
    pub secret: VaultSecret,
}

/// Cleartext secret material. Field-for-field mirror of
/// [`vault/_shared/0.2/vault-secret#/$defs/VaultSecret`](https://trusttasks.org/spec/vault/_shared/0.2/vault-secret).
/// Discriminated by `kind`. This secret rides **inside** the opaque
/// authcrypt JWE (`vault/upsert`'s `sealedSecret`), so the `vault/*/0.2`
/// edge transform cannot reach it — the discriminator is parsed verbatim
/// here. To accept both a 0.1 producer (kebab `did-self-issued`) and a
/// spec-0.2 producer (camelCase `didSelfIssued`) without a breaking wire
/// change, each multi-word variant carries a camelCase `alias`; the
/// emitted form stays kebab for backwards compatibility (Postel's law).
/// This is the fix for the half-completed migration in issue #517 — the
/// variant *fields* were camelCased in `76287a5`, the *discriminator* was
/// not.
///
/// Sensitive fields (`password`, `private_key`, `refresh_token`,
/// `secure_notes`, `token`, etc.) MUST be zeroised by handlers as soon as
/// their use is complete; this enum derives `Debug` for diagnostic
/// convenience but production logs MUST NOT format `VaultSecret` via
/// `{:?}` — the strings would leak straight in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VaultSecret {
    // `rename_all = "camelCase"` on each variant aligns Rust's
    // default snake_case field names with the canonical wire shape
    // in `vault/_shared/0.1/vault-secret` (which uses camelCase
    // throughout: `secureNotes`, `loginConfig`, `signingKeyId`,
    // `credentialId`, etc.). Without these, every camelCase-emitting
    // consumer (the browser plugin's `vault/upsert` path is the live
    // example) silently loses optional fields on deserialize and
    // emits the wrong shape on serialize. The two new tests in this
    // file's `mod tests` exercise password + did-self-issued
    // round-trips and would have caught this earlier.
    #[serde(rename_all = "camelCase")]
    Password {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        totp: Option<TotpSeed>,
        /// Optional driver config for `vault/proxy-login/0.1` against
        /// this entry. When present, the maintainer performs an HTTP
        /// POST against `loginConfig.loginUrl` with the entry's
        /// credentials. When absent, proxy-login returns
        /// `not_proxyable` and the consumer falls back to vault/release
        /// for browser-fill. See `vault/_shared/0.1/vault-secret#/$defs/PasswordLoginConfig`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        login_config: Option<PasswordLoginConfig>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        custom_fields: Vec<CustomField>,
    },
    #[serde(rename_all = "camelCase")]
    Passkey {
        credential_id: String,
        private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        algorithm: Option<String>,
        rp_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    #[serde(rename_all = "camelCase", alias = "oauthTokens")]
    OauthTokens {
        provider: String,
        refresh_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_token_expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    #[serde(rename_all = "camelCase", alias = "didSelfIssued")]
    DidSelfIssued {
        did: String,
        signing_key_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    #[serde(rename_all = "camelCase", alias = "didcommPeer")]
    DidcommPeer {
        peer_did: String,
        signing_key_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    #[serde(rename_all = "camelCase", alias = "bearerToken")]
    BearerToken {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_prefix: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    #[serde(rename_all = "camelCase", alias = "sshKey")]
    SshKey {
        private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Custom {
        fields: Vec<CustomField>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
}

impl VaultSecret {
    /// Returns the [`SecretKind`] that matches this variant. The metadata
    /// view's `secret_kind` field MUST equal this on every persisted
    /// `StoredVaultEntry`; an inconsistency is a programming error and
    /// callers can use [`VaultSecret::matches_kind`] to assert at the
    /// upsert / release boundary.
    pub fn kind(&self) -> SecretKind {
        match self {
            VaultSecret::Password { .. } => SecretKind::Password,
            VaultSecret::Passkey { .. } => SecretKind::Passkey,
            VaultSecret::OauthTokens { .. } => SecretKind::OauthTokens,
            VaultSecret::DidSelfIssued { .. } => SecretKind::DidSelfIssued,
            VaultSecret::DidcommPeer { .. } => SecretKind::DidcommPeer,
            VaultSecret::BearerToken { .. } => SecretKind::BearerToken,
            VaultSecret::SshKey { .. } => SecretKind::SshKey,
            VaultSecret::Custom { .. } => SecretKind::Custom,
        }
    }

    /// Convenience: assert that this secret's variant matches `expected`.
    /// Used by handler code to fail loudly when the metadata view's
    /// `secret_kind` disagrees with the unsealed secret's discriminator.
    pub fn matches_kind(&self, expected: SecretKind) -> bool {
        self.kind() == expected
    }
}

/// RFC 6238 TOTP seed for entries that pair a TOTP with a password.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSeed {
    /// Base32 (RFC 4648) shared secret.
    pub secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<TotpAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TotpAlgorithm {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

/// Driver config for HTTP-POST proxy-login against a Password-kind
/// entry. Mirrors `vault/_shared/0.1/vault-secret#/$defs/PasswordLoginConfig`.
///
/// When this struct is present on a Password secret, the maintainer
/// performs an HTTP POST against `login_url` carrying the entry's
/// credentials and captures the resulting Set-Cookie headers into the
/// SessionBlob. When absent, vault/proxy-login returns `not_proxyable`
/// and the consumer falls back to vault/release for a browser-fill
/// flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordLoginConfig {
    /// Absolute URL the maintainer POSTs credentials to. MUST be
    /// `https://` for any non-loopback host — see the canonical spec
    /// for the loopback carve-out.
    pub login_url: String,
    /// Request-body encoding. `Json` → `application/json`,
    /// `FormUrlEncoded` → `application/x-www-form-urlencoded`.
    #[serde(default)]
    pub format: PasswordLoginFormat,
    /// Field name carrying the username. Default `"username"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_field: Option<String>,
    /// Field name carrying the password. Default `"password"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_field: Option<String>,
    /// Optional field name carrying the TOTP code. When set AND the
    /// entry's `totp` is populated, the maintainer computes the
    /// current code and includes it in the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_field: Option<String>,
    /// Constant field/value pairs the maintainer MUST include
    /// alongside the credentials. Useful for fixed selectors the site
    /// expects (e.g. `grantType: password`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_fields: Option<std::collections::BTreeMap<String, String>>,
    /// HTTP status codes the maintainer treats as login success.
    /// Default `[200, 204]` (set via accessor when None — keeps the
    /// wire shape clean).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_status: Option<Vec<u16>>,
}

impl PasswordLoginConfig {
    /// The set of HTTP statuses the maintainer treats as success,
    /// falling back to the canonical default `[200, 204]` when the
    /// caller didn't override.
    pub fn effective_success_status(&self) -> Vec<u16> {
        self.success_status
            .clone()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![200, 204])
    }

    pub fn effective_username_field(&self) -> &str {
        self.username_field.as_deref().unwrap_or("username")
    }

    pub fn effective_password_field(&self) -> &str {
        self.password_field.as_deref().unwrap_or("password")
    }
}

/// Emitted kebab-case for the 0.1 wire form; accepts the spec-0.2
/// camelCase `formUrlencoded` via alias. Rides inside the JWE, so the 0.2
/// edge transform can't reach it — dual-accept here keeps it
/// backwards-compatible (issue #517).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PasswordLoginFormat {
    #[default]
    Json,
    #[serde(alias = "formUrlencoded")]
    FormUrlencoded,
}

/// Free-form user-defined field on Password / Custom variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CustomFieldKind>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CustomFieldKind {
    Text,
    Url,
    Email,
    Phone,
    Number,
    Date,
}

/// Storage key for a vault entry — `"vault:<id>"`. Prefix scans on
/// `"vault:"` enumerate every entry in this VTA's keyspace.
fn vault_key(id: &str) -> String {
    format!("vault:{id}")
}

/// Read a single vault entry's metadata view by id. Returns `Ok(None)`
/// for absent ids so callers can map to a not_found / permission_denied
/// response per their enumeration-resistance policy. Skips the secret —
/// use [`get_stored_vault_entry`] when the secret bytes are needed
/// (vault/release/0.1's handler is the only caller in M2A).
pub async fn get_vault_entry(
    vault: &KeyspaceHandle,
    id: &str,
) -> Result<Option<VaultEntry>, AppError> {
    Ok(get_stored_vault_entry(vault, id).await?.map(|s| s.entry))
}

/// Read the full stored record (metadata + secret) by id. Use sparingly —
/// only the release handler and admin tooling have a legitimate need for
/// the secret bytes. All other reads go through [`get_vault_entry`].
pub async fn get_stored_vault_entry(
    vault: &KeyspaceHandle,
    id: &str,
) -> Result<Option<StoredVaultEntry>, AppError> {
    vault.get(vault_key(id)).await
}

/// Store (create or overwrite) a full vault record. Unconditional write —
/// version + optimistic-concurrency checks are the caller's responsibility
/// (the upsert handler implements them).
pub async fn put_stored_vault_entry(
    vault: &KeyspaceHandle,
    record: &StoredVaultEntry,
) -> Result<(), AppError> {
    debug_assert!(
        record.secret.matches_kind(record.entry.secret_kind),
        "StoredVaultEntry mismatch: entry.secret_kind={:?} but secret.kind()={:?}",
        record.entry.secret_kind,
        record.secret.kind()
    );
    vault.insert(vault_key(&record.entry.id), record).await
}

/// Delete a vault entry by id. Use the upcoming `vault/delete/0.1` handler
/// (M2A) for the tombstone-aware path; this helper exists for tests and
/// administrative scripts.
pub async fn delete_vault_entry(vault: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    vault.remove(vault_key(id)).await
}

// ───────────────────────────────────────────────────────────────────────
// SessionBlob — the cleartext payload of vault/proxy-login/0.1's sealed
// response (M2B). Mirrors `vault/_shared/0.1/session-blob` schema field
// for field. Wallet consumers receive this inside a SealedEnvelope and
// inject the contents into their browser session for the bound origin.
//
// Sensitive fields here are server-managed (the VTA issues the session
// bytes), so unlike VaultSecret these aren't user-typed — but the
// `headers[].value` and `cookies[].value` carry bearer tokens / session
// IDs and MUST be zeroised at TTL by the consumer just like VaultSecret.
// ───────────────────────────────────────────────────────────────────────

/// Cleartext session material returned by vault/proxy-login/0.1 — the
/// VTA performs the login at the third party, captures the resulting
/// session credentials, and ships them in this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionBlob {
    /// Maintainer-assigned opaque id for this session — used by future
    /// `vault/session/{revoke, refresh}/0.1` tasks (post-M2B) to act on
    /// the session without re-identifying it by content.
    pub session_id: String,
    /// RFC 3339. The consumer MUST discard the blob (cookies + headers)
    /// at this time even if the user hasn't finished interacting.
    pub expires_at: String,
    /// Cookies the consumer injects into the bound origin's cookie jar.
    /// Order is significant for sites that set multiple cookies with the
    /// same name on different paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<CookieJarEntry>,
    /// HTTP request headers the consumer attaches to outbound requests
    /// for the bound origin. Typically `Authorization: Bearer …` for
    /// the SIOP / OAuth paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<RequestHeader>,
    /// Optional localStorage entries to set on the origin (SPAs that
    /// store session material there rather than in cookies).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_storage: Vec<StorageEntry>,
    /// Optional sessionStorage entries to set on the origin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_storage: Vec<StorageEntry>,
    /// The web origin this session is for. Consumers MUST refuse to
    /// inject the session into any other origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_origin: Option<String>,
    /// Refresh policy hint for the consumer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hint: Option<RefreshHint>,
}

/// Emitted kebab-case for the 0.1 wire form; accepts the spec-0.2
/// camelCase variants (`maintainerOnly`/`on401`/`beforeExpiry`) via alias.
/// Inside the sealed session blob, so the 0.2 edge transform can't reach
/// it — dual-accept keeps it backwards-compatible (issue #517).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RefreshHint {
    /// Don't refresh on your own; the maintainer drives renewal.
    #[serde(alias = "maintainerOnly")]
    MaintainerOnly,
    /// Call back to vault/proxy-login when the third party returns 401.
    /// (kebab-case renders this `on401` — already equal to the spec-0.2
    /// camelCase form, so no alias is needed.)
    On401,
    /// Pre-emptively refresh shortly before `expiresAt`.
    #[serde(alias = "beforeExpiry")]
    BeforeExpiry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieJarEntry {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<SameSite>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub key: String,
    pub value: String,
}

/// List vault entries matching `filter`, ordered by `last_used_at`
/// descending (entries without `last_used_at` sort last). Returns the
/// metadata projection only — secrets stay in the keyspace.
pub async fn list_vault_entries(
    vault: &KeyspaceHandle,
    filter: &VaultListFilter<'_>,
) -> Result<Vec<VaultEntry>, AppError> {
    let raw = vault.prefix_iter_raw("vault:").await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_, bytes) in raw {
        let stored: StoredVaultEntry = serde_json::from_slice(&bytes)?;
        if !matches_filter(&stored.entry, filter) {
            continue;
        }
        out.push(stored.entry);
    }
    out.sort_by(|a, b| {
        // Most-recently-used first; absent last_used_at sorts last.
        match (b.last_used_at.as_deref(), a.last_used_at.as_deref()) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    Ok(out)
}

fn matches_filter(entry: &VaultEntry, filter: &VaultListFilter<'_>) -> bool {
    // Archival lifecycle first: by default only Active entries are listed, so
    // archived / soft-deleted entries never leak into a normal `vault/list`.
    if let Some(want) = filter.status_selector()
        && entry.status != want
    {
        return false;
    }
    if let Some(ctx) = filter.context_id
        && entry.context_id != ctx
    {
        return false;
    }
    if let Some(kind) = filter.secret_kind
        && entry.secret_kind != kind
    {
        return false;
    }
    if let Some(tag) = filter.tag
        && !entry.tags.iter().any(|t| t == tag)
    {
        return false;
    }
    if let Some(since) = filter.used_since {
        match entry.last_used_at.as_deref() {
            Some(last) if last >= since => {}
            _ => return false,
        }
    }
    if filter.never_used == Some(true) && entry.last_used_at.is_some() {
        return false;
    }
    if let Some(before) = filter.expires_before {
        match entry.expires_at.as_deref() {
            Some(ts) if ts < before => {}
            _ => return false,
        }
    }
    if let Some(want_breached) = filter.breached {
        let is_breached = entry.breached_at.is_some();
        if is_breached != want_breached {
            return false;
        }
    }
    // Target filters: an entry matches when AT LEAST ONE target satisfies the
    // criterion. Each target filter is independent — passing multiple narrows
    // the result to entries that have a target matching every criterion (a
    // single target need not satisfy all of them).
    if let Some(prefix) = filter.target_origin_prefix {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::WebOrigin { origin } => origin.starts_with(prefix),
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    if let Some(did) = filter.target_did {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::Did { did: d } => d == did,
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    if let Some(bid) = filter.target_ios_bundle_id {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::IosApp { bundle_id, .. } => bundle_id == bid,
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    if let Some(pkg) = filter.target_android_package {
        let ok = entry.targets.iter().any(|t| match t {
            SiteTarget::AndroidApp { package_name, .. } => package_name == pkg,
            _ => false,
        });
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, ctx: &str, last_used: Option<&str>) -> VaultEntry {
        VaultEntry {
            id: id.to_string(),
            context_id: ctx.to_string(),
            targets: vec![SiteTarget::WebOrigin {
                origin: "https://github.com".to_string(),
            }],
            label: format!("entry {id}"),
            secret_kind: SecretKind::Password,
            tags: vec!["work".to_string()],
            notes: None,
            favicon: None,
            selectors: vec![],
            custom_field_names: vec![],
            attachments: vec![],
            expires_at: None,
            breached_at: None,
            password_changed_at: None,
            created_at: "2026-05-26T10:00:00Z".to_string(),
            created_by: None,
            updated_at: "2026-05-26T10:00:00Z".to_string(),
            updated_by: None,
            last_used_at: last_used.map(String::from),
            version: 1,
            principal_did: None,
            status: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        }
    }

    #[test]
    fn site_target_round_trip_matches_canonical_wire_form() {
        let cases = vec![
            (
                SiteTarget::WebOrigin {
                    origin: "https://github.com".to_string(),
                },
                r#"{"kind":"web-origin","origin":"https://github.com"}"#,
            ),
            (
                SiteTarget::Did {
                    did: "did:web:rp.example".to_string(),
                },
                r#"{"kind":"did","did":"did:web:rp.example"}"#,
            ),
            (
                SiteTarget::IosApp {
                    bundle_id: "com.example.app".to_string(),
                    team_id: Some("ABCD123456".to_string()),
                },
                r#"{"kind":"ios-app","bundleId":"com.example.app","teamId":"ABCD123456"}"#,
            ),
            (
                SiteTarget::AndroidApp {
                    package_name: "com.example.app".to_string(),
                    sha256_cert_fingerprints: vec!["AA:BB".to_string()],
                },
                r#"{"kind":"android-app","packageName":"com.example.app","sha256CertFingerprints":["AA:BB"]}"#,
            ),
        ];
        for (val, expected) in cases {
            let json = serde_json::to_string(&val).unwrap();
            assert_eq!(json, expected, "encode {val:?}");
            let back: SiteTarget = serde_json::from_str(expected).unwrap();
            assert_eq!(back, val, "round-trip {expected}");
        }
    }

    #[test]
    fn secret_kind_serialises_to_canonical_kebab_case() {
        let cases = vec![
            (SecretKind::Password, "\"password\""),
            (SecretKind::OauthTokens, "\"oauth-tokens\""),
            (SecretKind::DidSelfIssued, "\"did-self-issued\""),
            (SecretKind::DidcommPeer, "\"didcomm-peer\""),
            (SecretKind::BearerToken, "\"bearer-token\""),
            (SecretKind::SshKey, "\"ssh-key\""),
        ];
        for (val, expected) in cases {
            assert_eq!(serde_json::to_string(&val).unwrap(), expected);
            let back: SecretKind = serde_json::from_str(expected).unwrap();
            assert_eq!(back, val);
        }
    }

    #[test]
    fn secret_kind_also_accepts_spec_0_2_camel_case() {
        // Backwards-compat dual-accept (issue #517): the 0.2 spec uses
        // lowerCamelCase discriminator values. Emission stays kebab (above),
        // but every multi-word camelCase form must deserialize too.
        let cases = vec![
            ("\"oauthTokens\"", SecretKind::OauthTokens),
            ("\"didSelfIssued\"", SecretKind::DidSelfIssued),
            ("\"didcommPeer\"", SecretKind::DidcommPeer),
            ("\"bearerToken\"", SecretKind::BearerToken),
            ("\"sshKey\"", SecretKind::SshKey),
        ];
        for (camel, expected) in cases {
            let back: SecretKind = serde_json::from_str(camel).expect(camel);
            assert_eq!(back, expected, "camelCase {camel}");
        }
    }

    #[test]
    fn filter_matches_intersection_of_criteria() {
        let entry = sample("v1", "ctx_a", Some("2026-05-20T00:00:00Z"));

        // Match-all empty filter
        assert!(matches_filter(&entry, &VaultListFilter::default()));

        // Single criterion that matches
        assert!(matches_filter(
            &entry,
            &VaultListFilter {
                context_id: Some("ctx_a"),
                ..Default::default()
            }
        ));

        // Single criterion that misses
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                context_id: Some("ctx_b"),
                ..Default::default()
            }
        ));

        // never_used excludes used entries
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                never_used: Some(true),
                ..Default::default()
            }
        ));

        // used_since accepts a timestamp at or before last_used_at
        assert!(matches_filter(
            &entry,
            &VaultListFilter {
                used_since: Some("2026-05-19T00:00:00Z"),
                ..Default::default()
            }
        ));
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                used_since: Some("2026-05-21T00:00:00Z"),
                ..Default::default()
            }
        ));

        // Origin prefix matches any web-origin target
        assert!(matches_filter(
            &entry,
            &VaultListFilter {
                target_origin_prefix: Some("https://github."),
                ..Default::default()
            }
        ));
        assert!(!matches_filter(
            &entry,
            &VaultListFilter {
                target_origin_prefix: Some("https://gitlab."),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn password_secret_round_trips_camel_case_wire_form() {
        // The canonical spec (vault/_shared/0.1/vault-secret) uses
        // camelCase field names (`secureNotes`, `loginConfig`,
        // `signingKeyId`). Verify the Rust implementation deserializes
        // the spec-form wire input AND re-emits it in the same shape
        // — i.e. neither side requires snake_case translation. If
        // this test fails, every camelCase-emitting consumer (the
        // browser plugin's vault/upsert path is the live example)
        // would silently lose optional fields.
        let camel = r#"{"kind":"password","password":"x","secureNotes":"hi"}"#;
        let v: VaultSecret = serde_json::from_str(camel).expect("parse camelCase");
        match &v {
            VaultSecret::Password { secure_notes, .. } => {
                assert_eq!(secure_notes.as_deref(), Some("hi"));
            }
            _ => panic!("expected Password variant"),
        }
        let re = serde_json::to_string(&v).expect("re-emit");
        assert!(
            re.contains("\"secureNotes\":\"hi\""),
            "re-emitted JSON must use camelCase secureNotes; got {re}"
        );
    }

    #[test]
    fn did_self_issued_secret_round_trips_camel_case_wire_form() {
        let camel = r#"{"kind":"did-self-issued","did":"did:webvh:foo","signingKeyId":"did:webvh:foo#key-0"}"#;
        let v: VaultSecret = serde_json::from_str(camel).expect("parse camelCase");
        match &v {
            VaultSecret::DidSelfIssued {
                did,
                signing_key_id,
                ..
            } => {
                assert_eq!(did, "did:webvh:foo");
                assert_eq!(signing_key_id, "did:webvh:foo#key-0");
            }
            _ => panic!("expected DidSelfIssued variant"),
        }
        let re = serde_json::to_string(&v).expect("re-emit");
        assert!(
            re.contains("\"signingKeyId\":\"did:webvh:foo#key-0\""),
            "re-emitted JSON must use camelCase signingKeyId; got {re}"
        );
    }

    #[test]
    fn vault_secret_discriminator_accepts_both_casings() {
        // Regression for issue #517: the inner sealed `VaultSecret` rides in
        // the opaque authcrypt JWE, so the 0.2 edge transform can't camelCase
        // its `kind`. A spec-0.2 producer (e.g. the browser plugin) seals
        // `{"kind":"didSelfIssued", …}`; before the alias fix this was
        // rejected with `unknown variant didSelfIssued`. Both the legacy
        // kebab and the spec-0.2 camelCase discriminator must parse, for every
        // multi-word kind.
        let cases: Vec<(&str, &str, SecretKind)> = vec![
            (
                r#"{"kind":"oauth-tokens","provider":"google","refreshToken":"r"}"#,
                r#"{"kind":"oauthTokens","provider":"google","refreshToken":"r"}"#,
                SecretKind::OauthTokens,
            ),
            (
                r#"{"kind":"did-self-issued","did":"did:webvh:x","signingKeyId":"did:webvh:x#k"}"#,
                r#"{"kind":"didSelfIssued","did":"did:webvh:x","signingKeyId":"did:webvh:x#k"}"#,
                SecretKind::DidSelfIssued,
            ),
            (
                r#"{"kind":"didcomm-peer","peerDid":"did:peer:2","signingKeyId":"did:peer:2#k"}"#,
                r#"{"kind":"didcommPeer","peerDid":"did:peer:2","signingKeyId":"did:peer:2#k"}"#,
                SecretKind::DidcommPeer,
            ),
            (
                r#"{"kind":"bearer-token","token":"t"}"#,
                r#"{"kind":"bearerToken","token":"t"}"#,
                SecretKind::BearerToken,
            ),
            (
                r#"{"kind":"ssh-key","privateKey":"p"}"#,
                r#"{"kind":"sshKey","privateKey":"p"}"#,
                SecretKind::SshKey,
            ),
        ];
        for (kebab, camel, expected) in cases {
            let from_kebab: VaultSecret = serde_json::from_str(kebab).expect(kebab);
            assert_eq!(from_kebab.kind(), expected, "kebab {kebab}");
            let from_camel: VaultSecret = serde_json::from_str(camel).expect(camel);
            assert_eq!(from_camel.kind(), expected, "camel {camel}");
            // Conservative emission: we still serialize the legacy kebab form
            // so existing 0.1 openers keep working.
            let re = serde_json::to_string(&from_camel).unwrap();
            let kebab_kind = serde_json::to_string(&expected).unwrap();
            assert!(
                re.contains(&format!("\"kind\":{kebab_kind}")),
                "emitted form must keep kebab kind {kebab_kind}; got {re}"
            );
        }
    }

    #[test]
    fn password_login_format_and_refresh_hint_accept_both_casings() {
        // Both ride inside the JWE / sealed session blob (issue #517).
        assert_eq!(
            serde_json::from_str::<PasswordLoginFormat>("\"form-urlencoded\"").unwrap(),
            PasswordLoginFormat::FormUrlencoded
        );
        assert_eq!(
            serde_json::from_str::<PasswordLoginFormat>("\"formUrlencoded\"").unwrap(),
            PasswordLoginFormat::FormUrlencoded
        );
        // Emission stays kebab.
        assert_eq!(
            serde_json::to_string(&PasswordLoginFormat::FormUrlencoded).unwrap(),
            "\"form-urlencoded\""
        );

        for (kebab, camel, val) in [
            (
                "\"maintainer-only\"",
                "\"maintainerOnly\"",
                RefreshHint::MaintainerOnly,
            ),
            // kebab-case of `On401` is `on401` — already the spec-0.2 form.
            ("\"on401\"", "\"on401\"", RefreshHint::On401),
            (
                "\"before-expiry\"",
                "\"beforeExpiry\"",
                RefreshHint::BeforeExpiry,
            ),
        ] {
            assert_eq!(serde_json::from_str::<RefreshHint>(kebab).unwrap(), val);
            assert_eq!(serde_json::from_str::<RefreshHint>(camel).unwrap(), val);
        }
        assert_eq!(
            serde_json::to_string(&RefreshHint::On401).unwrap(),
            "\"on401\""
        );
    }

    #[test]
    fn principal_did_from_secret_for_each_kind() {
        // DID-shaped kinds → Some(did)
        let did = "did:webvh:Q1:rp.example:alice";
        let s = VaultSecret::DidSelfIssued {
            did: did.to_string(),
            signing_key_id: format!("{did}#key-0"),
            secure_notes: None,
        };
        assert_eq!(
            VaultEntry::principal_did_from_secret(&s),
            Some(did.to_string())
        );

        let peer = "did:peer:2.Ez6LSc...";
        let s = VaultSecret::DidcommPeer {
            peer_did: peer.to_string(),
            signing_key_id: format!("{peer}#key-0"),
            secure_notes: None,
        };
        assert_eq!(
            VaultEntry::principal_did_from_secret(&s),
            Some(peer.to_string())
        );

        // No-DID kinds → None (sample each variant so a future
        // refactor that misses one trips this test).
        for s in [
            VaultSecret::Password {
                username: Some("u".into()),
                password: "p".into(),
                totp: None,
                login_config: None,
                secure_notes: None,
                custom_fields: vec![],
            },
            VaultSecret::Passkey {
                credential_id: "c".into(),
                private_key: "pk".into(),
                algorithm: None,
                rp_id: "rp".into(),
                user_handle: None,
                secure_notes: None,
            },
            VaultSecret::BearerToken {
                token: "t".into(),
                header_name: None,
                header_prefix: None,
                secure_notes: None,
            },
            VaultSecret::SshKey {
                private_key: "p".into(),
                public_key: None,
                comment: None,
                passphrase: None,
                secure_notes: None,
            },
            VaultSecret::Custom {
                fields: vec![],
                secure_notes: None,
            },
        ] {
            assert_eq!(
                VaultEntry::principal_did_from_secret(&s),
                None,
                "non-DID kind {:?} must yield None",
                s.kind()
            );
        }
    }

    #[test]
    fn entry_without_status_field_deserialises_as_active() {
        // Back-compat: a record persisted before the lifecycle existed has no
        // `status`/`archivedAt`/`deletedAt`/`graceUntil` keys. It MUST default
        // to Active so existing vaults keep working after upgrade.
        let legacy = r#"{
            "id":"v1","contextId":"ctx","targets":[],"label":"x",
            "secretKind":"password","createdAt":"2026-01-01T00:00:00Z",
            "updatedAt":"2026-01-01T00:00:00Z","version":1
        }"#;
        let entry: VaultEntry = serde_json::from_str(legacy).expect("parse legacy");
        assert_eq!(entry.status, VaultStatus::Active);
        assert!(entry.archived_at.is_none());
        assert!(entry.deleted_at.is_none());
        assert!(entry.grace_until.is_none());
        // And an Active entry re-emits WITHOUT the status keys (wire stays clean).
        let re = serde_json::to_string(&entry).unwrap();
        assert!(
            !re.contains("status"),
            "active entry must not emit status; got {re}"
        );
    }

    #[test]
    fn list_filter_excludes_non_active_by_default() {
        let active = sample("a", "ctx", None);
        let mut archived = sample("b", "ctx", None);
        archived.status = VaultStatus::Archived;
        let mut deleted = sample("c", "ctx", None);
        deleted.status = VaultStatus::Deleted;

        // Default filter → Active only.
        let f = VaultListFilter::default();
        assert!(matches_filter(&active, &f));
        assert!(!matches_filter(&archived, &f));
        assert!(!matches_filter(&deleted, &f));

        // Explicit status selects exactly that state.
        let f = VaultListFilter {
            status: Some(VaultStatus::Deleted),
            ..Default::default()
        };
        assert!(!matches_filter(&active, &f));
        assert!(matches_filter(&deleted, &f));

        // any_status returns everything.
        let f = VaultListFilter {
            any_status: true,
            ..Default::default()
        };
        assert!(matches_filter(&active, &f));
        assert!(matches_filter(&archived, &f));
        assert!(matches_filter(&deleted, &f));
    }

    #[test]
    fn lifecycle_transitions_follow_the_state_table() {
        let t0 = "2026-06-18T10:00:00+00:00";
        let t1 = "2026-06-18T11:00:00+00:00";
        let grace = "2026-07-18T10:00:00+00:00";

        // archive: Active → Archived, bumps version, stamps archived_at.
        let mut e = sample("v", "ctx", None);
        let v0 = e.version;
        e.archive(t0, Some("did:key:op")).unwrap();
        assert_eq!(e.status, VaultStatus::Archived);
        assert_eq!(e.archived_at.as_deref(), Some(t0));
        assert_eq!(e.version, v0 + 1);
        assert_eq!(e.updated_by.as_deref(), Some("did:key:op"));
        // double-archive refused.
        assert_eq!(e.archive(t1, None), Err(LifecycleError::NotActive));
        // unarchive: Archived → Active.
        e.unarchive(t1, None).unwrap();
        assert_eq!(e.status, VaultStatus::Active);
        assert!(e.archived_at.is_none());
        // unarchive of Active refused.
        assert_eq!(e.unarchive(t1, None), Err(LifecycleError::NotArchived));

        // soft delete: Active → Deleted with grace, restorable in-window.
        let mut e = sample("v", "ctx", None);
        e.soft_delete(t0, grace, None).unwrap();
        assert_eq!(e.status, VaultStatus::Deleted);
        assert_eq!(e.deleted_at.as_deref(), Some(t0));
        assert_eq!(e.grace_until.as_deref(), Some(grace));
        // re-delete refused.
        assert_eq!(
            e.soft_delete(t1, grace, None),
            Err(LifecycleError::AlreadyDeleted)
        );
        // restore inside the window.
        e.restore(t1, None).unwrap();
        assert_eq!(e.status, VaultStatus::Active);
        assert!(e.deleted_at.is_none() && e.grace_until.is_none());
        // restore of a non-deleted entry refused.
        assert_eq!(e.restore(t1, None), Err(LifecycleError::NotDeleted));

        // restore AFTER grace is refused (the sweeper owns it now).
        let mut e = sample("v", "ctx", None);
        e.soft_delete(t0, grace, None).unwrap();
        let after_grace = "2026-08-01T00:00:00+00:00";
        assert_eq!(
            e.restore(after_grace, None),
            Err(LifecycleError::GraceExpired)
        );
        assert_eq!(e.status, VaultStatus::Deleted, "failed restore is a no-op");

        // delete is reachable from Archived too (Archived → Deleted).
        let mut e = sample("v", "ctx", None);
        e.archive(t0, None).unwrap();
        e.soft_delete(t1, grace, None).unwrap();
        assert_eq!(e.status, VaultStatus::Deleted);
        assert!(e.archived_at.is_none(), "archived_at cleared on delete");
    }
}
