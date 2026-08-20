//! Request and response types for [`crate::client::VtaClient`].
//!
//! Split out of `client.rs` so the file is mostly methods. All types
//! re-exported from the parent module, so callers can continue to
//! import them via `vta_sdk::client::*` (or `vta_sdk::prelude::*`).

use crate::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
use crate::protocols::key_management::sign::SignAlgorithm;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HealthResponse {
    pub status: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub mediator_url: Option<String>,
    #[serde(default)]
    pub mediator_did: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigResponse {
    /// The registry, as canonical `config/show/0.1` returns it. Read a single
    /// key with [`GetConfigResultBody::get`], or the common one with
    /// [`GetConfigResultBody::vta_did`].
    ///
    /// [`GetConfigResultBody::get`]: crate::protocols::vta_management::get_config::GetConfigResultBody::get
    /// [`GetConfigResultBody::vta_did`]: crate::protocols::vta_management::get_config::GetConfigResultBody::vta_did
    #[serde(flatten)]
    pub config: crate::protocols::vta_management::get_config::GetConfigResultBody,
}

impl ConfigResponse {
    /// The VTA's own DID, if set. Read-only — see
    /// [`UpdateConfigBody`](crate::protocols::vta_management::update_config::UpdateConfigBody)
    /// for why it cannot be patched.
    pub fn vta_did(&self) -> Option<&str> {
        self.config.vta_did()
    }

    /// The VTA's advertised public URL, if set.
    pub fn public_url(&self) -> Option<&str> {
        self.config.get("public_url").and_then(|v| v.as_str())
    }

    /// The VTA's operator-facing name, if set.
    pub fn vta_name(&self) -> Option<&str> {
        self.config.get("vta_name").and_then(|v| v.as_str())
    }
}

#[derive(Debug, Serialize)]
pub struct UpdateConfigRequest {
    /// `key → value`. Keys outside the registry, and keys immutable at
    /// runtime (`vta_did`), come back under `rejected` rather than applying.
    #[serde(flatten)]
    pub patch: crate::protocols::vta_management::update_config::UpdateConfigBody,
}

#[derive(Debug, Serialize)]
#[must_use]
pub struct CreateKeyRequest {
    pub key_type: KeyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Mint a **non-extractable internal key**. Absent or `false` is today's
    /// behaviour. `true` mints a CSPRNG key that is never exported, excluded
    /// from backup, and **cannot be recovered from the mnemonic or otherwise**.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
}

impl CreateKeyRequest {
    pub fn new(key_type: KeyType) -> Self {
        Self {
            internal: None,
            key_type,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: None,
            context_id: None,
        }
    }
    pub fn derivation_path(mut self, path: impl Into<String>) -> Self {
        self.derivation_path = Some(path.into());
        self
    }
    pub fn key_id(mut self, id: impl Into<String>) -> Self {
        self.key_id = Some(id.into());
        self
    }
    pub fn mnemonic(mut self, m: impl Into<String>) -> Self {
        self.mnemonic = Some(m.into());
        self
    }
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    pub fn context(mut self, ctx: impl Into<String>) -> Self {
        self.context_id = Some(ctx.into());
        self
    }
}

// ── Import key types ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ImportKeyRequest {
    pub key_type: KeyType,
    /// Sealed-transfer armored bundle carrying a
    /// `SealedPayloadV1::RawPrivateKey`. Preferred REST transport.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_sealed: Option<String>,
    /// Legacy JWE compact serialization of the private key. Retained for
    /// in-flight clients; new code should use `private_key_sealed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_jwe: Option<String>,
    /// Multibase-encoded private key. **DIDComm transport only** —
    /// the REST `POST /keys/import` handler rejects this field with
    /// an `unknown field` error to force callers onto the
    /// `private_key_sealed` flow (see [`Self::private_key_sealed`]).
    /// DIDComm authcrypt already provides end-to-end confidentiality,
    /// so plaintext multibase is acceptable on that transport; REST
    /// only has TLS, which terminates outside the enclave.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportKeyResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    pub origin: crate::keys::KeyOrigin,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct WrappingKeyResponse {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
}

// ── Context types ───────────────────────────────────────────────────

/// Request body for [`super::VtaClient::create_context`].
///
/// This is the ergonomic **client-side** shape — use the `.new(id, name)`
/// constructor plus the `.description(...)` builder for the common case.
/// The parallel `vta_sdk::protocols::context_management::create::CreateContextBody`
/// type is the wire shape used by DIDComm consumers; the two serialize
/// identically and either can be sent to the server, but the client
/// shape is what the SDK methods take.
#[derive(Debug, Serialize)]
#[must_use]
pub struct CreateContextRequest {
    /// The new context's id. A leaf segment when [`parent`](Self::parent) is set
    /// (the full path becomes `<parent>/<id>`); a top-level segment otherwise.
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parent context path to nest under, or `None` for a top-level context.
    /// Top-level creation is super-admin only; nesting requires admin of `parent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

impl CreateContextRequest {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            parent: None,
        }
    }
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
    /// Nest the new context under `parent` (its full path becomes `<parent>/<id>`).
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }
}

/// Sent as the `vta/contexts/update/1.0` payload, so it is bound by that
/// schema's lowerCamelCase members — `contextPolicy`, not `context_policy`.
/// Serialize-only: nothing reads this back, so it needs no intake alias.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateContextRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Set this context's policy (super-admin only). Omitted leaves it
    /// unchanged; send an unrestricted policy to clear constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_policy: Option<crate::context_policy::ContextPolicy>,
}

#[derive(Debug, Serialize)]
pub struct UpdateContextDidRequest {
    pub did: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContextResponse {
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    pub base_path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ContextListResponse {
    pub contexts: Vec<ContextResponse>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub derivation_path: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    /// How the key was produced. `Internal` means non-extractable and
    /// unrecoverable — the CLI reprints the warning off this field, so an
    /// operator scripting against the API sees it in the response too.
    #[serde(default = "default_derived_origin")]
    pub origin: KeyOrigin,
    pub created_at: DateTime<Utc>,
}

fn default_derived_origin() -> KeyOrigin {
    KeyOrigin::Derived
}

#[derive(Debug, Deserialize)]
pub struct InvalidateKeyResponse {
    pub key_id: String,
    pub status: KeyStatus,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RenameKeyResponse {
    pub key_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct GetKeySecretResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key_multibase: String,
    pub private_key_multibase: String,
}

/// Response from `POST /keys/{key_id}/sign`.
#[derive(Debug, Deserialize)]
pub struct SignResponse {
    pub key_id: String,
    pub signature: String,
    pub algorithm: SignAlgorithm,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyRecord>,
    pub total: u64,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Seed types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SeedInfoResponse {
    pub id: u32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListSeedsResponse {
    pub seeds: Vec<SeedInfoResponse>,
    pub active_seed_id: u32,
}

#[derive(Debug, Serialize)]
pub struct RotateSeedRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RotateSeedResponse {
    pub previous_seed_id: u32,
    pub new_seed_id: u32,
}

// ── ACL types ───────────────────────────────────────────────────────

/// One ACL entry as the REST surface returns it.
///
/// The **wire** names are canonical (`acl/_shared/0.1/acl-entry`); the Rust
/// field names are the maintainer's historical ones, kept so the CLI and the
/// VTC's own ACL routes did not have to move in the same change. The mapping
/// is `subject`↔`did` and `scopes`↔`allowed_contexts`, and the step-up and
/// approve members are flattened back out of their canonical nesting.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AclEntryResponse {
    #[serde(rename = "subject")]
    pub did: String,
    pub role: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(rename = "scopes", default)]
    pub allowed_contexts: Vec<String>,
    #[serde(
        default,
        deserialize_with = "de_epoch_opt",
        serialize_with = "ser_epoch"
    )]
    pub created_at: u64,
    #[serde(default)]
    pub created_by: String,
    /// When the entry expires. Canonical sends RFC 3339; this is the epoch
    /// seconds the rest of the code already speaks.
    #[serde(
        default,
        deserialize_with = "de_epoch_opt_option",
        serialize_with = "ser_epoch_opt"
    )]
    pub expires_at: Option<u64>,
    /// Signing-oracle key filter (#818). `None` = no filter; `Some([])` =
    /// authorized on no keys — keep the distinction when rendering.
    #[serde(
        default,
        rename = "allowedKeys",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_keys: Option<Vec<String>>,
    /// Flattened out of the canonical `stepUp` object.
    #[serde(default, rename = "stepUp")]
    step_up: Option<StepUpWire>,
    /// Flattened out of the canonical `approve` object.
    #[serde(default)]
    approve: Option<ApproveWire>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StepUpWire {
    #[serde(default)]
    approver: Option<String>,
    #[serde(default)]
    require: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApproveWire {
    #[serde(default)]
    all: bool,
    #[serde(default)]
    scopes: Vec<String>,
}

impl AclEntryResponse {
    /// Per-entry step-up mode override, if any.
    pub fn step_up_require(&self) -> Option<&str> {
        self.step_up.as_ref().and_then(|s| s.require.as_deref())
    }

    /// Delegated step-up approver, if any.
    pub fn step_up_approver(&self) -> Option<&str> {
        self.step_up.as_ref().and_then(|s| s.approver.as_deref())
    }

    /// True when the entry may confer **any** scope via approval.
    pub fn approve_all_contexts(&self) -> bool {
        self.approve.as_ref().is_some_and(|a| a.all)
    }

    /// Scopes the entry may confer. Empty confers nothing.
    pub fn approve_contexts(&self) -> &[String] {
        self.approve.as_ref().map_or(&[], |a| a.scopes.as_slice())
    }
}

/// Epoch seconds → RFC 3339, so a re-serialised entry stays canonical.
fn ser_epoch<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    ser_epoch_opt(&Some(*v), s)
}

/// Epoch seconds → RFC 3339, preserving absence.
fn ser_epoch_opt<S: serde::Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    use chrono::{TimeZone, Utc};
    match v.and_then(|e| {
        i64::try_from(e)
            .ok()
            .and_then(|x| Utc.timestamp_opt(x, 0).single())
    }) {
        Some(t) => s.serialize_str(&t.to_rfc3339()),
        None => s.serialize_none(),
    }
}

/// RFC 3339 → epoch seconds, defaulting to 0 when absent.
fn de_epoch_opt<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(de_epoch_opt_option(d)?.unwrap_or(0))
}

/// RFC 3339 → epoch seconds. A pre-epoch instant clamps to 0, which for an
/// expiry reads as "already expired" — the safe direction for a timestamp that
/// gates authority.
fn de_epoch_opt_option<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(d)?;
    Ok(raw.and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|t| u64::try_from(t.timestamp()).unwrap_or(0))
    }))
}

/// The `{ entry }` envelope canonical `acl/*` responses carry.
///
/// Internal: the client unwraps it so callers keep receiving the entry itself
/// rather than having to know the envelope exists.
#[derive(Debug, Deserialize)]
pub(crate) struct AclEntryEnvelope {
    pub entry: AclEntryResponse,
}

#[derive(Debug, Deserialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

/// Builder for `acl/grant/0.1`.
///
/// The builder API is unchanged by the canonical fold; only what it serialises
/// moved. Callers keep writing `CreateAclRequest::new(did, role).contexts(..)`
/// and the wire carries `{entry: {subject, role, scopes, ...}}`.
#[derive(Debug)]
#[must_use]
pub struct CreateAclRequest {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    /// Unix-epoch seconds at which this entry auto-expires. `None` = permanent.
    /// Useful for setup ACLs where the temp did:key should stop authenticating
    /// if the admin never claims it via `pnm setup` + rotation.
    pub expires_at: Option<u64>,
    /// VID authorized to ratify a **delegated** AAL2 step-up for this subject.
    pub step_up_approver: Option<String>,
    /// Per-entry step-up override (`"self"` | `"delegated"`).
    pub step_up_require: Option<String>,
    /// Approve-authority over any context (confer via approval, act nowhere).
    pub approve_all_contexts: bool,
    /// Approve-authority scoped to these contexts.
    pub approve_contexts: Vec<String>,
    /// Signing-oracle key filter (#818). `None` = no filter (every key in the
    /// entry's contexts); `Some(∅)` = **no** keys at all — the two are
    /// opposite grants and are serialized distinctly.
    pub allowed_keys: Option<Vec<String>>,
}

impl serde::Serialize for CreateAclRequest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use crate::protocols::acl_management::create::CreateAclBody;
        use crate::protocols::acl_management::entry::{AclEntry, Approve, StepUp};
        use chrono::{TimeZone, Utc};

        let step_up = StepUp {
            approver: self.step_up_approver.clone(),
            require: self.step_up_require.clone(),
        };
        let approve = Approve {
            all: self.approve_all_contexts,
            scopes: self.approve_contexts.clone(),
        };
        let has_step_up = step_up.approver.is_some() || step_up.require.is_some();
        let has_approve = approve.all || !approve.scopes.is_empty();
        let body = CreateAclBody {
            entry: AclEntry {
                subject: self.did.clone(),
                role: self.role.clone(),
                scopes: self.allowed_contexts.clone(),
                allowed_keys: self.allowed_keys.clone(),
                label: self.label.clone(),
                created_at: None,
                created_by: None,
                updated_at: None,
                updated_by: None,
                expires_at: self.expires_at.and_then(|e| {
                    i64::try_from(e)
                        .ok()
                        .and_then(|s| Utc.timestamp_opt(s, 0).single())
                }),
                step_up: has_step_up.then_some(step_up),
                approve: has_approve.then_some(approve),
            },
            reason: None,
        };
        body.serialize(s)
    }
}

impl CreateAclRequest {
    pub fn new(did: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            role: role.into(),
            label: None,
            allowed_contexts: Vec::new(),
            expires_at: None,
            step_up_approver: None,
            step_up_require: None,
            approve_all_contexts: false,
            approve_contexts: Vec::new(),
            allowed_keys: None,
        }
    }
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    pub fn contexts(mut self, contexts: Vec<String>) -> Self {
        self.allowed_contexts = contexts;
        self
    }
    pub fn expires_at(mut self, unix_secs: u64) -> Self {
        self.expires_at = Some(unix_secs);
        self
    }
    /// Set the delegated step-up approver VID (`stepUp.approver`).
    pub fn step_up_approver(mut self, approver: impl Into<String>) -> Self {
        self.step_up_approver = Some(approver.into());
        self
    }
    /// Set the per-entry step-up override (`stepUp.require`: `"self"` |
    /// `"delegated"`), which raises the system floor for this subject.
    pub fn step_up_require(mut self, require: impl Into<String>) -> Self {
        self.step_up_require = Some(require.into());
        self
    }
    /// Grant approve-authority over **all** contexts (confer via approval, act
    /// nowhere). Super-admin-only on the server.
    pub fn approve_all(mut self) -> Self {
        self.approve_all_contexts = true;
        self
    }
    /// Grant approve-authority scoped to these contexts.
    pub fn approve_contexts(mut self, contexts: Vec<String>) -> Self {
        self.approve_contexts = contexts;
        self
    }
    /// Restrict the subject to invoking the signing oracle on exactly these
    /// key ids (#818). Intersects with — never widens — the context scope.
    /// An empty vec means **no keys at all**; not calling this leaves the
    /// subject unfiltered (every key its contexts reach).
    pub fn allowed_keys(mut self, keys: Vec<String>) -> Self {
        self.allowed_keys = Some(keys);
        self
    }
}

/// Request for `swap-acl` — atomic self-service key rotation. Carries the
/// VP-JWT (compact Ed25519 JWS) proving control of the new DID; the caller's
/// own ACL entry is moved onto the new DID server-side.
#[derive(Debug, Serialize)]
#[must_use]
pub struct SwapAclRequest {
    pub presentation: String,
}

impl SwapAclRequest {
    pub fn new(presentation: impl Into<String>) -> Self {
        Self {
            presentation: presentation.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UpdateAclRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
    /// Set the delegated step-up approver VID (`Some` sets — pass an empty
    /// string to clear; `None` leaves the current value unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up_approver: Option<String>,
    /// Per-entry step-up override (`"self"` | `"delegated"`): `Some` sets — pass
    /// an empty string to clear; `None` leaves the current value unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up_require: Option<String>,
    /// Set the approve scope to exactly this value; `None` leaves it unchanged.
    /// Clearing is `Some(ApproveScope::None)` — an explicit value, since an
    /// empty list cannot mean both "confer nothing" and "leave alone".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approve_scope: Option<crate::acl::ApproveScope>,
    /// Replace the signing-oracle key filter (#818): `None` leaves it
    /// unchanged, `Some(None)` clears it (serialized as explicit `null` — a
    /// privilege increase), `Some(Some(keys))` sets it to exactly those ids
    /// (**the empty vec is "no keys at all"**, never a wildcard). Wire name
    /// pinned to the canonical `allowedKeys`.
    #[serde(rename = "allowedKeys", skip_serializing_if = "Option::is_none")]
    pub allowed_keys: Option<Option<Vec<String>>>,
}

// ── WebVH server types ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AddWebvhServerRequest {
    pub id: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateWebvhServerRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

// ── WebVH DID types ─────────────────────────────────────────────────

/// Sent as the `vta/webvh/dids/create/1.0` payload. That schema was published
/// in trust-tasks #240 and this struct predates it, which is why it carried
/// snake_case members the agent would have rejected as `malformedRequest`;
/// client-side validation only started catching it once trust-tasks-rs 0.11
/// brought the schema into the index.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidWebvhRequest {
    pub context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Legacy path selector. Prefer [`path_mode`](Self::path_mode), which
    /// distinguishes the `.well-known` root, an explicit label, and
    /// server-side auto-assignment. Retained for wire back-compat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Explicit path-selection mode for server-managed DIDs. When set it
    /// overrides [`path`](Self::path); absent falls back to `path`. See
    /// [`crate::protocols::did_management::create::WebvhPathMode`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_mode: Option<crate::protocols::did_management::create::WebvhPathMode>,
    /// Optional explicit hosting domain on the target server. See
    /// [`crate::protocols::did_management::create::CreateDidWebvhBody::domain`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub portable: bool,
    pub add_mediator_service: bool,
    /// Also publish a `#tsp` (`TSPTransport`) entry at the VTA's mediator.
    /// See [`crate::protocols::did_management::create::CreateDidWebvhBody::add_tsp_service`]
    /// for the gating rules and why this is not implied by
    /// [`add_mediator_service`](Self::add_mediator_service).
    ///
    /// Skipped on the wire when `false`, so a request from a caller that
    /// does not set it is byte-identical to one built before this field
    /// existed — the same treatment `domain` got.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub add_tsp_service: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_services: Option<Vec<serde_json::Value>>,
    pub pre_rotation_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,
    pub set_primary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ka_key_id: Option<String>,
    /// Name of a stored DID template to use for the DID document shape.
    /// Mutually exclusive with `did_document` — the template is rendered
    /// server-side with ambient + caller-supplied variables, and the result
    /// becomes the DID document. Resolution order: context scope (if
    /// `template_context` is set) → global → builtin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Scope to look the template up in. `None` means "global only"; `Some(ctx)`
    /// means "this context first, then global, then builtin". Typically
    /// matches the request's `context_id` but can differ (e.g. a VTA-wide
    /// template used by a DID being provisioned inside a context).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_context: Option<String>,
    /// Caller-supplied template variables. Server-supplied ambient vars
    /// (`DID`, `SIGNING_KEY_MB`, `KA_KEY_MB`, `VTA_DID`, `VTA_URL`,
    /// `CONTEXT_ID`, `CONTEXT_DID`, `NOW`) are injected automatically.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub template_vars: std::collections::HashMap<String, serde_json::Value>,
}

/// Request for `VtaClient::change_acl_role`.
///
/// `from_role` is the compare-and-swap: the role the caller believes the
/// subject holds. The VTA refuses the transition if its stored role differs,
/// so a race against another admin surfaces as an error rather than one
/// change silently overwriting the other.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAclRoleRequest {
    pub from_role: String,
    pub to_role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ── WebVH DID log types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetDidLogResponse {
    pub did: String,
    pub log: Option<String>,
}
