use serde::{Deserialize, Serialize};

use crate::webvh::WebvhServerRecord;

/// Request for `spec/vta/webvh/servers/register/1.0`.
///
/// Absorbs the former `servers/update/1.0`, whose body was this one
/// minus `did` and which returned the same `WebvhServerRecord`.
///
/// Which operation runs is decided by whether `id` is already
/// registered, not by a mode flag:
///
/// - **new `id`** — `did` is required, gets validated (it must resolve
///   and advertise a WebVH service), and the registration is created.
/// - **existing `id`** — the label is updated. `did` may be omitted, or
///   repeated identically for an idempotent re-register; supplying a
///   *different* `did` is refused.
///
/// That last rule is the point of not making this a blind upsert.
/// Re-pointing a registration at another host would silently redirect
/// every DID that resolves through it, and doing so safely needs
/// coordinated teardown on the old host — the same reasoning that makes
/// `dids/register-with-server` refuse an already-server-managed DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegisterWebvhServerBody {
    pub id: String,
    /// Required when registering a new `id`; on an existing one it may
    /// be omitted or repeated identically, but never changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

pub type RegisterWebvhServerResultBody = WebvhServerRecord;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListWebvhServersBody {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListWebvhServersResultBody {
    pub servers: Vec<WebvhServerRecord>,
}

/// `list-webvh-server-domains` — relay the registered hosting
/// server's `/api/me/domains` response (caller-scoped subset of
/// hosting domains, with the system default flagged). Used by
/// `pnm did-mgmt list-domains` and the interactive `--domain`
/// prompt in `create-did` / `register-did`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListWebvhServerDomainsBody {
    pub server_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListWebvhServerDomainsResultBody {
    pub domains: Vec<WebvhServerDomainEntry>,
    /// System-default domain on the server, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WebvhServerDomainEntry {
    pub name: String,
    #[serde(default)]
    pub default_domain: bool,
    /// Server-reported status (`"active"` or `"disabled"`).
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RemoveWebvhServerBody {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RemoveWebvhServerResultBody {
    pub id: String,
    pub removed: bool,
}

/// Promote a serverless WebVH DID to a server-managed one. The
/// target server must already be registered via
/// [`AddWebvhServerBody`]; the DID's local `did.jsonl` is pushed
/// to the host atomically (single batched write — no resolver
/// gap) and the local record's `server_id` flips from
/// `"serverless"` to `server_id` so future updates auto-publish.
///
/// `force` is honoured only when the caller authenticates to the
/// host as an admin replacing a slot owned by a different DID.
/// An owner re-registering their own slot is idempotent and
/// always allowed without force.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegisterDidWithServerBody {
    pub did: String,
    pub server_id: String,
    #[serde(default)]
    pub force: bool,
    /// Optional explicit hosting domain on the target server. When
    /// the server hosts multiple tenant domains, this directs the
    /// register call at a specific one; otherwise the remote
    /// resolves via caller's ACL default → system default. An
    /// unknown domain is rejected with `did-management:unknown_domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegisterDidWithServerResultBody {
    pub did: String,
    pub server_id: String,
    pub log_entry_count: u32,
}
