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
#[serde(rename_all = "camelCase")]
pub struct ListWebvhServerDomainsBody {
    #[serde(rename = "serverId", alias = "server_id")]
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

/// Request body for `vta/webvh/servers/reconcile/0.1` — compare the DIDs a hosting
/// server holds for this VTA against the DIDs the VTA has records for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ReconcileWebvhServerDidsBody {
    #[serde(rename = "serverId", alias = "server_id")]
    pub server_id: String,
}

/// The two-sided diff between a hosting server and this VTA.
///
/// Read-only, and deliberately so: the two divergences have opposite remedies
/// (one needs a DID removed from a host, the other needs a publish or a local
/// delete) and neither is safe to guess at. Naming them precisely is the whole
/// job — the operator decides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReconcileWebvhServerDidsResultBody {
    pub server_id: String,
    /// Served by the host, unknown to this VTA — **orphans**. The usual cause
    /// is a delete whose remote leg failed: `delete_did_webvh` calls the host
    /// first and, when that call fails, drops the local record anyway
    /// ("continuing local cleanup but DID is now orphaned on the daemon"). The
    /// host keeps serving a DID whose controller has discarded its keys, so no
    /// update to it can ever be signed again.
    pub host_only: Vec<HostOnlyDid>,
    /// Recorded here as hosted on this server, but the host does not have it.
    /// A create whose publish never landed, or a DID removed on the host by
    /// another admin.
    pub agent_only: Vec<AgentOnlyDid>,
    /// How many the two agree on. Present so a clean result reads as "checked
    /// 14, all matched" rather than an empty screen that could equally mean the
    /// listing failed.
    pub in_both: u32,
}

/// A DID the host serves that this VTA has no record of.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HostOnlyDid {
    /// The host's slot identifier — what `pnm did-mgmt` and the host's own API
    /// address this DID by, and the only identifier a never-published slot has.
    pub slot_id: String,
    /// The DID served at that slot, when the slot has been published to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Whether the host has the slot disabled.
    #[serde(default)]
    pub disabled: bool,
}

/// A DID this VTA records as hosted on the server, which the server does not
/// have.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentOnlyDid {
    pub did: String,
    /// The slot this VTA believes the DID occupies on the host.
    pub slot_id: String,
    pub context_id: String,
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
    /// RFC 3339 timestamp at which the host created the domain, as the host
    /// reported it.
    ///
    /// Canonical `did-management/_shared/0.1/domain-entry#DomainEntry`
    /// **requires** this, and the VTA relays into that shape — so a response
    /// missing it is not merely thinner, it fails its own schema. `Option`
    /// only for hosts that predate the canonical shape and genuinely do not
    /// send one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
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
#[serde(rename_all = "camelCase")]
pub struct RegisterDidWithServerBody {
    pub did: String,
    #[serde(alias = "server_id")]
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
#[serde(rename_all = "camelCase")]
pub struct RegisterDidWithServerResultBody {
    pub did: String,
    #[serde(alias = "server_id")]
    pub server_id: String,
    #[serde(alias = "log_entry_count")]
    pub log_entry_count: u32,
}

/// Retire an **orphaned** slot on a hosting server — one the host serves for
/// this VTA and the VTA holds no record of.
///
/// The gap this closes is structural. Every ordinary delete addresses a DID
/// through its local record, which is what says which server to talk to and
/// which keys to sign with; an orphan is defined by that record's absence, so
/// the lookup fails before a request leaves the VTA. And the caller cannot go
/// around it, because the VTA holds the host credentials.
///
/// The safety of an operation with no undo rests on one inversion: **the VTA
/// decides whether the slot is orphaned, and the caller does not get to claim
/// it.** A live DID has a record, and the record is what makes the refusal
/// automatic. See `vta/webvh/servers/retire-orphan/0.1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetireOrphanSlotBody {
    #[serde(alias = "server_id")]
    pub server_id: String,
    /// The slot to retire, as a [`ReconcileWebvhServerDidsResultBody::host_only`]
    /// entry reports it. The slot rather than the DID, because a slot reserved
    /// but never published to has none and is exactly as orphaned.
    #[serde(alias = "slot_id")]
    pub slot_id: String,
    /// The DID the caller believes the slot serves, echoed back from the
    /// reconcile report it acted on.
    ///
    /// A reconcile response is a comparison at an instant, and a slot may be
    /// published to between the report and this request. Naming what was seen
    /// turns a stale report into a refusal rather than a surprise.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "expected_did"
    )]
    pub expected_did: Option<String>,
    /// Operator rationale, recorded in the audit trail. The act has no undo, so
    /// why it was done outlives the record of what was done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RetireOrphanSlotResultBody {
    #[serde(alias = "server_id")]
    pub server_id: String,
    #[serde(alias = "slot_id")]
    pub slot_id: String,
    /// Whether the slot is no longer served. Reported, never inferred: a VTA
    /// that could not confirm removal with the host must not claim it.
    pub retired: bool,
    /// The DID the slot was serving, echoed so the record of what was retired
    /// survives the slot's disappearance. Absent where it was never published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}
