//! Request and response types for [`crate::client::VtaClient`].
//!
//! Split out of `client.rs` so the file is mostly methods. All types
//! re-exported from the parent module, so callers can continue to
//! import them via `vta_sdk::client::*` (or `vta_sdk::prelude::*`).

use crate::keys::{KeyRecord, KeyStatus, KeyType};
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
    #[serde(rename = "vta_did")]
    pub community_vta_did: Option<String>,
    #[serde(rename = "vta_name")]
    pub community_vta_name: Option<String>,
    pub public_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
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
}

impl CreateKeyRequest {
    pub fn new(key_type: KeyType) -> Self {
        Self {
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

#[derive(Debug, Serialize)]
pub struct UpdateContextRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
    pub created_at: DateTime<Utc>,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
    /// Unix-epoch seconds at which this entry expires. `None` = permanent.
    /// Pre-Phase-2 entries on the wire never carried this field, so
    /// defaults to `None` for backward compat.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Per-entry step-up override (`"self"` | `"delegated"`) raising the system
    /// floor for this subject. `None` = no override. `#[serde(default)]` for
    /// pre-existing entries on the wire.
    #[serde(default)]
    pub step_up_require: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize)]
#[must_use]
pub struct CreateAclRequest {
    pub did: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    /// Unix-epoch seconds at which this entry auto-expires. `None` = permanent.
    /// Useful for setup ACLs where the temp did:key should stop authenticating
    /// if the admin never claims it via `pnm setup` + rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// VID authorized to ratify a **delegated** AAL2 step-up for this subject
    /// (the subject's `stepUp.approver`). Omit for no delegated approver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up_approver: Option<String>,
    /// Per-entry step-up override (`"self"` | `"delegated"`) raising the system
    /// floor for this subject. Omit for none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up_require: Option<String>,
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
    pub role: Option<String>,
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

#[derive(Debug, Serialize)]
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

// ── WebVH DID log types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetDidLogResponse {
    pub did: String,
    pub log: Option<String>,
}
