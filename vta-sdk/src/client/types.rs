//! Request and response types for [`crate::client::VtaClient`].
//!
//! Split out of `client.rs` so the file is mostly methods. All types
//! re-exported from the parent module, so callers can continue to
//! import them via `vta_sdk::client::*` (or `vta_sdk::prelude::*`).
//!
//! # These are Trust-Task decode targets, not REST bodies
//!
//! The name of this file is older than what is in it. The response types here
//! are the deserialize target of a **Trust Task** — `rpc_tt` carries the same
//! document over REST, DIDComm and TSP alike, so "the REST types" has not
//! described this module since the transports converged.
//!
//! That mattered once, badly. #1000 folded Trust Task payloads to lowerCamelCase
//! per SPEC §4.10 and excluded this file as REST bodies whose casing "no
//! published schema pins". The exclusion was drawn by path, and the path was
//! stale: the agent moved to `basePath` while `ContextResponse` went on
//! demanding `base_path`, so every `pnm contexts` command failed with `missing
//! field base_path` — plus `keys sign`/`rename`/`revoke`, seed rotate/list, and
//! the MCP surface wrapping them.
//!
//! # A response type here is the agent's type, under the client's name
//!
//! The casing was the symptom; the defect was that one wire had **two structs**,
//! either of which could move alone. #1033 papered it with `serde` aliases;
//! #1035 removed it: every decode target below is now a `pub use` of the very
//! body the agent serializes. The two ends cannot disagree, because there are no
//! longer two ends — which is a stronger guarantee than any test could give.
//!
//! The re-export keeps the client-facing name, so `get_context` still returns
//! something called `ContextResponse` rather than `CreateContextResultBody`.
//!
//! **When adding a Trust-Task response type, re-export the agent's body rather
//! than declaring a struct that mirrors it.** A mirror compiles, passes review,
//! and drifts the next time someone touches the wire.
//! `vta-sdk/tests/trust_task_decode_census.rs` refuses a new one.
//!
//! Request builders are a different matter and stay local: `CreateKeyRequest`
//! and friends exist for ergonomics (`.new(..).label(..)`) and produce the wire
//! shape rather than describing it, so they cannot drift the same way.

use crate::keys::{KeyOrigin, KeyRecord, KeyStatus, KeyType};
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
#[non_exhaustive]
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

#[derive(Serialize)]
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

/// Written by hand so the mnemonic never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for CreateKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateKeyRequest")
            .field("key_type", &self.key_type)
            .field("derivation_path", &self.derivation_path)
            .field("key_id", &self.key_id)
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .field("label", &self.label)
            .field("context_id", &self.context_id)
            .field("internal", &self.internal)
            .finish()
    }
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

#[derive(Serialize)]
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

/// Written by hand so the private key never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for ImportKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportKeyRequest")
            .field("key_type", &self.key_type)
            .field(
                "private_key_sealed",
                &self.private_key_sealed.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_key_jwe",
                &self.private_key_jwe.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_key_multibase",
                &self.private_key_multibase.as_ref().map(|_| "<redacted>"),
            )
            .field("label", &self.label)
            .field("context_id", &self.context_id)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ImportKeyResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    pub origin: crate::keys::KeyOrigin,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// What [`super::VtaClient::get_wrapping_key`] returns: the generated
/// `keys/import-wrapping-key/0.1` response — `wrappingKey` (an Ed25519
/// `did:key`; seal to its X25519 counterpart), `keyId` and `expiresAt`.
pub type WrappingKeyResponse = trust_tasks_rs::specs::keys::import_wrapping_key::v0_1::Response;

/// Which sessions [`super::VtaClient::revoke_sessions`] ends — the three forms
/// of `auth/revoke-session/0.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeSessions<'a> {
    /// One named session.
    Session(&'a str),
    /// Every session of the caller itself — sign out everywhere, this client's
    /// own session included.
    AllMine,
    /// Every session of this subject. The caller's own DID, or a subject whose
    /// access it could withdraw.
    Subject(&'a str),
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

/// Decode target for the `contexts/{create,get,update,update-did}` Trust Tasks
/// — **the agent's own body type**, under the name the client API has always
/// used.
///
/// It was a separate struct with the same members until #1035. Being separate is
/// what let #1000 move the agent to `basePath` while this went on demanding
/// `base_path`, breaking every `pnm contexts` command; being the same type makes
/// that unrepresentable rather than merely tested for.
///
/// The old struct also had no `parent`, so a nested context rendered without
/// one. That is fixed here by construction — the member now exists because the
/// agent's type has it.
pub use crate::protocols::context_management::create::CreateContextResultBody as ContextResponse;

/// Decode target for `contexts/list` — the agent's own body type. See
/// [`ContextResponse`].
pub use crate::protocols::context_management::list::ListContextsResultBody as ContextListResponse;

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

/// Decode target for `keys/revoke` — the agent's own body type. See
/// [`ContextResponse`] for why these are re-exports rather than structs.
pub use crate::protocols::key_management::revoke::RevokeKeyResultBody as InvalidateKeyResponse;

#[derive(Debug, Serialize)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

/// Decode target for `keys/rename` — the agent's own body type.
pub use crate::protocols::key_management::rename::RenameKeyResultBody as RenameKeyResponse;

/// Decode target for `seeds/export-mnemonic` — the agent's own body type.
///
/// Carries a real improvement beyond deduplication: the struct this replaces
/// derived `Debug`, so `{:?}` on a response printed the **raw private key**.
/// The agent's type hand-writes `Debug` to redact it, precisely so a caller
/// cannot tracing-log it by accident.
pub use crate::protocols::key_management::secret::GetKeySecretResultBody as GetKeySecretResponse;

/// Decode target for `keys/sign` — the agent's own body type.
pub use crate::protocols::key_management::sign::SignResultBody as SignResponse;

#[derive(Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ListKeysResponse {
    pub keys: Vec<KeyRecord>,
    /// `keys/list/0.2`: present exactly when more records remain; pass it back
    /// as the next request's `cursor`.
    #[serde(
        default,
        rename = "nextCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Seed types ──────────────────────────────────────────────────────

/// Nested element of [`ListSeedsResponse`] — the agent's own body type.
///
/// Note that `SeedInfo` is the one payload struct #1000 left without
/// `rename_all`, so it still emits snake_case and its own `alias` attributes are
/// inert (#1034). Sharing the type means that when #1034 folds it, both ends
/// move together and there is nothing here to forget.
pub use crate::protocols::seed_management::list::SeedInfo as SeedInfoResponse;

/// Decode target for `seeds/list` — the agent's own body type.
pub use crate::protocols::seed_management::list::ListSeedsResultBody as ListSeedsResponse;

#[derive(Serialize)]
pub struct RotateSeedRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

/// Written by hand so the mnemonic never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for RotateSeedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateSeedRequest")
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Decode target for `seeds/rotate` — the agent's own body type.
pub use crate::protocols::seed_management::rotate::RotateSeedResultBody as RotateSeedResponse;

// ── ACL types ───────────────────────────────────────────────────────

/// One ACL entry as a VTA returns it.
///
/// Read from the canonical **AclEntry 0.2** wire (`acl/_shared/0.2`), where
/// every authority axis is explicit, into the VTA's own model: `act` becomes
/// `allowed_contexts` read through the role (empty is unrestricted for
/// `admin`, nowhere for every other role), `keys` becomes `allowed_keys`, a
/// `listed` capability scope becomes the narrowing. An entry the VTA model has
/// no form for — `act: all` on a non-admin, `act: none` on an admin — is a
/// decode error rather than the empty list that would mean its opposite.
/// [`act`](Self::act) gives the explicit scope.
///
/// It serialises (for CLI `--json` output) in that flattened form, not as 0.2.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", try_from = "WireAclEntry")]
pub struct AclEntryResponse {
    #[serde(rename = "subject")]
    pub did: String,
    pub role: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(rename = "scopes", default)]
    pub allowed_contexts: Vec<String>,
    #[serde(default, serialize_with = "ser_epoch")]
    pub created_at: u64,
    #[serde(default)]
    pub created_by: String,
    /// When the entry expires. Canonical sends RFC 3339; this is the epoch
    /// seconds the rest of the code already speaks.
    #[serde(default, serialize_with = "ser_epoch_opt")]
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
    /// Ecosystem extension members. Carries the entry's capability narrowing
    /// under `org.openvtc.capabilities`; read it through
    /// [`AclEntryResponse::capabilities`] rather than indexing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ext: Option<serde_json::Value>,
    /// The explicit act scope, as the wire stated it.
    #[serde(skip)]
    act: crate::acl::ActScope,
}

/// The two AclEntry versions a VTA answers in: 0.2 from `acl/*`, and 0.1 from
/// `acl/swap-key/0.1`, which has no later version. They cannot be confused:
/// both deny unknown members, 0.2 requires `act`/`keys`/`capabilities`, and
/// 0.1 has none of them.
#[derive(Deserialize)]
#[serde(untagged)]
enum WireAclEntry {
    V02(crate::protocols::acl_management::v0_2::AclEntry),
    V01(crate::protocols::acl_management::entry::AclEntry),
}

impl TryFrom<WireAclEntry> for AclEntryResponse {
    type Error = String;

    fn try_from(e: WireAclEntry) -> Result<Self, String> {
        match e {
            WireAclEntry::V02(e) => Self::try_from(e),
            WireAclEntry::V01(e) => {
                let admin = e.role == "admin";
                let act = if !e.scopes.is_empty() {
                    crate::acl::ActScope::Contexts(e.scopes.clone())
                } else if admin {
                    crate::acl::ActScope::All
                } else {
                    crate::acl::ActScope::None
                };
                let epoch =
                    |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp()).unwrap_or(0);
                Ok(Self {
                    did: e.subject,
                    role: e.role,
                    label: e.label,
                    allowed_contexts: e.scopes,
                    created_at: e.created_at.map(epoch).unwrap_or(0),
                    created_by: e.created_by.unwrap_or_default(),
                    expires_at: e.expires_at.map(epoch),
                    allowed_keys: e.allowed_keys,
                    step_up: e.step_up.map(|s| StepUpWire {
                        approver: s.approver,
                        require: s.require,
                    }),
                    approve: e.approve.map(|a| ApproveWire {
                        all: a.all,
                        scopes: a.scopes,
                    }),
                    ext: e.ext,
                    act,
                })
            }
        }
    }
}

impl TryFrom<crate::protocols::acl_management::v0_2::AclEntry> for AclEntryResponse {
    type Error = String;

    fn try_from(e: crate::protocols::acl_management::v0_2::AclEntry) -> Result<Self, String> {
        use crate::protocols::acl_management::entry::capabilities_into_ext;
        use crate::protocols::acl_management::v0_2::{
            ApproveCapabilityScope, AuthorityScope, CapabilityScope,
        };
        let admin = e.role == "admin";
        let allowed_contexts = match &e.act {
            AuthorityScope::Contexts { contexts } => contexts.clone(),
            AuthorityScope::All if admin => Vec::new(),
            AuthorityScope::None if !admin => Vec::new(),
            other => {
                return Err(format!(
                    "{}: act {other:?} on role {} has no form in a VTA's ACL model",
                    e.subject, e.role
                ));
            }
        };
        let capabilities: Vec<String> = match &e.capabilities {
            CapabilityScope::Ceiling => Vec::new(),
            CapabilityScope::Listed { grants } => {
                grants.iter().map(|g| g.capability.clone()).collect()
            }
            CapabilityScope::None => {
                return Err(format!(
                    "{}: `capabilities: none` has no form in a VTA's ACL model",
                    e.subject
                ));
            }
        };
        let approve_scope = match e.approve_capabilities {
            Some(ApproveCapabilityScope::Ceiling) => e.approve_scope(),
            _ => crate::acl::ApproveScope::None,
        };
        let approve = match &approve_scope {
            crate::acl::ApproveScope::None => None,
            crate::acl::ApproveScope::All => Some(ApproveWire {
                all: true,
                scopes: Vec::new(),
            }),
            crate::acl::ApproveScope::Contexts(cs) => Some(ApproveWire {
                all: false,
                scopes: cs.clone(),
            }),
        };
        let epoch = |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp()).unwrap_or(0);
        Ok(Self {
            did: e.subject,
            role: e.role,
            label: e.label,
            allowed_contexts,
            created_at: e.created_at.map(epoch).unwrap_or(0),
            created_by: e.created_by.unwrap_or_default(),
            expires_at: e.expires_at.map(epoch),
            allowed_keys: e.keys.to_allowed_keys(),
            step_up: e.step_up.map(|s| StepUpWire {
                approver: s.approver,
                require: s.require,
            }),
            approve,
            ext: capabilities_into_ext(e.ext, &capabilities),
            act: e.act.to_act_scope(),
        })
    }
}

impl AclEntryResponse {
    /// The explicit act scope the VTA stated for this entry.
    pub fn act(&self) -> &crate::acl::ActScope {
        &self.act
    }

    /// The entry's capability narrowing, as kebab-case names.
    ///
    /// Empty means the entry is not narrowed and holds everything its role
    /// implies — which is what an entry that has never been narrowed looks
    /// like, and is deliberately not distinguished from "narrowed to nothing"
    /// because narrowing to nothing is spelled by clearing the set.
    pub fn capabilities(&self) -> Vec<String> {
        crate::protocols::acl_management::entry::capabilities_from_ext(self.ext.as_ref())
            .ok()
            .flatten()
            .unwrap_or_default()
    }
    /// Whether the entry carries an unexercised one-time hand-off marker
    /// (VTI-ACL-054).
    pub fn handoff(&self) -> bool {
        crate::protocols::acl_management::entry::handoff_from_ext(self.ext.as_ref())
            .unwrap_or(false)
    }
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

/// The `{ entry }` envelope canonical `acl/*` responses carry.
///
/// Internal: the client unwraps it so callers keep receiving the entry itself
/// rather than having to know the envelope exists.
#[derive(Debug, Deserialize)]
pub(crate) struct AclEntryEnvelope {
    pub entry: AclEntryResponse,
}

/// Every entry `acl/list/0.3` returned, the client having followed
/// `nextCursor` to the last page.
#[derive(Debug, Deserialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

/// One page of an ACL listing, as `acl/list/0.3` answers it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AclListPage {
    pub entries: Vec<AclEntryResponse>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// An `{ entry }` that may be `null` — `acl/show/0.2`'s "no such entry", and
/// `acl/revoke/0.2`'s removal.
#[derive(Debug, Deserialize)]
pub(crate) struct AclShowResponse {
    pub entry: Option<AclEntryResponse>,
}

/// Builder for `acl/grant/0.2`.
///
/// Callers keep writing `CreateAclRequest::new(did, role).contexts(..)`; the
/// wire carries an AclEntry 0.2 with every axis explicit
/// ([`to_entry_v0_2`](Self::to_entry_v0_2)).
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
    /// Narrow the entry to exactly these capabilities at creation, within what
    /// its role allows. Empty leaves it holding everything the role implies.
    ///
    /// Set here rather than by a follow-up update so the entry is never briefly
    /// wider than intended — a window during which the subject may already be
    /// authenticating.
    pub capabilities: Vec<String>,
    /// Mark the entry as a one-time hand-off (VTI-ACL-054): its subject may
    /// roll over once, while the entry is live, to a successor bounded by the
    /// granter's own authority rather than by this entry's expiry. Requires an
    /// expiry. The provision-integration admin rollover needs it.
    pub handoff: bool,
}

impl CreateAclRequest {
    /// The AclEntry 0.2 this request describes, every axis stated: `act` is
    /// the contexts if any are named, else `all` for `admin` and `none` for
    /// every other role — the VTA's documented reading of an empty list
    /// (`acl/_shared/0.2` CONVENTIONS §8), now sent explicitly.
    pub fn to_entry_v0_2(&self) -> crate::protocols::acl_management::v0_2::AclEntry {
        use crate::protocols::acl_management::entry::StepUp;
        use crate::protocols::acl_management::v0_2::{
            AclEntry, ApproveCapabilityScope, AuthorityScope, KeyScope,
        };
        use chrono::{TimeZone, Utc};

        let act = act_for(&self.role, &self.allowed_contexts);
        let mut entry = AclEntry::new(
            self.did.clone(),
            self.role.clone(),
            act,
            KeyScope::from_allowed_keys(self.allowed_keys.as_deref()),
            capability_scope_for(&self.role, &self.capabilities),
        );
        entry.label = self.label.clone();
        entry.expires_at = self.expires_at.and_then(|e| {
            i64::try_from(e)
                .ok()
                .and_then(|s| Utc.timestamp_opt(s, 0).single())
        });
        let approve = if self.approve_all_contexts {
            AuthorityScope::All
        } else if self.approve_contexts.is_empty() {
            AuthorityScope::None
        } else {
            AuthorityScope::Contexts {
                contexts: self.approve_contexts.clone(),
            }
        };
        if approve != AuthorityScope::None {
            entry.approve_capabilities = Some(ApproveCapabilityScope::Ceiling);
        }
        entry.approve = Some(approve);
        if self.step_up_approver.is_some() || self.step_up_require.is_some() {
            entry.step_up = Some(StepUp {
                approver: self.step_up_approver.clone(),
                require: self.step_up_require.clone(),
            });
        }
        entry.ext = crate::protocols::acl_management::entry::handoff_into_ext(None, self.handoff);
        entry
    }
}

/// The explicit act scope of a VTA entry stated as `(role, contexts)`.
pub(crate) fn act_for(
    role: &str,
    contexts: &[String],
) -> crate::protocols::acl_management::v0_2::AuthorityScope {
    use crate::protocols::acl_management::v0_2::AuthorityScope;
    if !contexts.is_empty() {
        AuthorityScope::Contexts {
            contexts: contexts.to_vec(),
        }
    } else if role == "admin" {
        AuthorityScope::All
    } else {
        AuthorityScope::None
    }
}

/// The explicit capability scope of a VTA narrowing (kebab-case names; empty
/// is the whole role). A list naming only additive capabilities means "the
/// whole role plus these", which 0.2 spells as the role's ceiling enumerated
/// plus the additive grants ([`crate::acl::role_capability_ceiling`]).
pub(crate) fn capability_scope_for(
    role: &str,
    names: &[String],
) -> crate::protocols::acl_management::v0_2::CapabilityScope {
    use crate::protocols::acl_management::v0_2::{CapabilityGrant, CapabilityScope};
    if names.is_empty() {
        return CapabilityScope::Ceiling;
    }
    let additive = |n: &str| crate::acl::ADDITIVE_CAPABILITIES.contains(&n);
    let mut grants: Vec<CapabilityGrant> = names
        .iter()
        .filter(|n| !additive(n))
        .map(|n| CapabilityGrant::new(n.clone(), false))
        .collect();
    if grants.is_empty() {
        grants = crate::acl::role_capability_ceiling(role)
            .unwrap_or_default()
            .iter()
            .map(|n| CapabilityGrant::new(*n, false))
            .collect();
    }
    grants.extend(
        names
            .iter()
            .filter(|n| additive(n))
            .map(|n| CapabilityGrant::new(n.clone(), true)),
    );
    CapabilityScope::Listed { grants }
}

impl serde::Serialize for CreateAclRequest {
    /// The `acl/grant/0.2` payload.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        crate::protocols::acl_management::v0_2::grant_payload(&self.to_entry_v0_2(), None, false)
            .serialize(s)
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
            capabilities: Vec::new(),
            handoff: false,
        }
    }
    /// Mark the entry as a one-time hand-off. See [`CreateAclRequest::handoff`].
    pub fn handoff(mut self) -> Self {
        self.handoff = true;
        self
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

    /// Narrow the new entry to exactly these capabilities (kebab-case names),
    /// within what its role allows. A name the role does not carry is refused
    /// by the VTA rather than dropped.
    pub fn capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
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
    /// Narrow what the entry may do, within what its role allows:
    /// `None` leaves the narrowing unchanged, `Some(vec![])` clears it (the
    /// entry regains everything its role implies — a privilege increase), and
    /// `Some(names)` narrows to exactly those kebab-case capability names.
    ///
    /// Over the Trust-Task and DIDComm transports this travels in the body's
    /// `ext` under `org.openvtc.capabilities`; the REST route takes it as a
    /// member. Both spellings reach the same stored field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
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

/// Sent as the `vta/webvh/dids/create/1.2` payload. The 1.0 schema was published
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

/// The `vta/webvh/dids/create/1.2` members of a create: how the new log is
/// presented, and whether it lists its did:scid alias (VTI-VTA-036). Both
/// `None` → the VTA's `[dids]`.
///
/// Separate from [`CreateDidWebvhRequest`] so that struct, which callers build
/// as a literal, stays as it is. Pass both to
/// `VtaClient::create_did_webvh_presented`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DidPresentation {
    pub did_method: Option<crate::did_scid::DidMethod>,
    pub scid_also_known_as: Option<bool>,
}

impl DidPresentation {
    /// Present the new log as `method`.
    #[must_use]
    pub fn did_method(mut self, method: crate::did_scid::DidMethod) -> Self {
        self.did_method = Some(method);
        self
    }

    /// List, or do not list, the did:scid alias in `alsoKnownAs`.
    #[must_use]
    pub fn scid_also_known_as(mut self, listed: bool) -> Self {
        self.scid_also_known_as = Some(listed);
        self
    }

    /// Whether either member is stated, which takes a create to 1.2.
    pub fn is_stated(&self) -> bool {
        self.did_method.is_some() || self.scid_also_known_as.is_some()
    }
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
#[non_exhaustive]
pub struct GetDidLogResponse {
    pub did: String,
    pub log: Option<String>,
}
