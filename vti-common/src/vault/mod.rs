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

/// Discriminator for the kind of secret stored. Wire values are kebab-case
/// (`oauth-tokens`, `did-self-issued`, etc.) per the canonical schema.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretKind {
    Password,
    Passkey,
    OauthTokens,
    DidSelfIssued,
    DidcommPeer,
    BearerToken,
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
/// [`vault/_shared/0.1/vault-secret#/$defs/VaultSecret`](https://trusttasks.org/spec/vault/_shared/0.1/vault-secret).
/// Discriminated by `kind`; wire values are kebab-case per the canonical
/// schema (`oauth-tokens`, `did-self-issued`, `didcomm-peer`,
/// `bearer-token`, `ssh-key`).
///
/// Sensitive fields (`password`, `private_key`, `refresh_token`,
/// `secure_notes`, `token`, etc.) MUST be zeroised by handlers as soon as
/// their use is complete; this enum derives `Debug` for diagnostic
/// convenience but production logs MUST NOT format `VaultSecret` via
/// `{:?}` — the strings would leak straight in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VaultSecret {
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
    DidSelfIssued {
        did: String,
        signing_key_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    DidcommPeer {
        peer_did: String,
        signing_key_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
    BearerToken {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_prefix: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secure_notes: Option<String>,
    },
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PasswordLoginFormat {
    #[default]
    Json,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RefreshHint {
    /// Don't refresh on your own; the maintainer drives renewal.
    MaintainerOnly,
    /// Call back to vault/proxy-login when the third party returns 401.
    On401,
    /// Pre-emptively refresh shortly before `expiresAt`.
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
    if let Some(ctx) = filter.context_id {
        if entry.context_id != ctx {
            return false;
        }
    }
    if let Some(kind) = filter.secret_kind {
        if entry.secret_kind != kind {
            return false;
        }
    }
    if let Some(tag) = filter.tag {
        if !entry.tags.iter().any(|t| t == tag) {
            return false;
        }
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
}
